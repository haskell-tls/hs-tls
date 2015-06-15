/*
 * a simple OpenSSL server to test interoperability with tls
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#define SSL_FAIL    -1

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define OPENSSL_RECENT
#define const_SSL_METHOD const SSL_METHOD
#else
#warning "building with old version of openSSL"
#define OPENSSL_OLD
#define TLSv1_2_server_method() SSLv3_server_method()
#define TLSv1_1_server_method() SSLv3_server_method()
#define TLSv1_server_method() SSLv3_server_method()
#define const_SSL_METHOD SSL_METHOD
#endif

void failure() { exit(0xf); }

static int listen_socket(int port)
{
	int sd;
	struct sockaddr_in addr;
	int enable = 1;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot create socket"); failure();
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("cannot set SO_REUSEADDR"); failure();
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		perror("bind failed"); failure();
	}

	if (listen(sd, 10) != 0) {
		perror("listen failed"); failure();
	}
	return sd;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *x509)
{
	printf("verify callback\n");
	return 1; /* 1 for success, 0 for fail */
}

static SSL_CTX* server_init(const_SSL_METHOD *method, int want_client_cert)
{
	SSL_CTX *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		failure();
	}

	if (want_client_cert) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback); 
	}
	return ctx;
}

static void load_server_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		failure();
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		failure();
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		failure();
	}
}

static void show_certificates(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		printf("No client certificate\n");
		return;
	}

	printf("client certificate:\n");

	line = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	printf("* Subject: %s\n", line);
	free(line);
	line = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	printf("* Issuer: %s\n", line);
	free(line);
	X509_free(cert);
}

static void process(SSL* ssl)
{
	char buf[1024];
	int sd, bytes;

	if (SSL_accept(ssl) == SSL_FAIL) {
		ERR_print_errors_fp(stderr);
		goto out;
	}

	show_certificates(ssl);
	bytes = SSL_read(ssl, buf, sizeof(buf));
	if (bytes > 0) {
		printf("received from client: \"%s\"\n", buf);
		SSL_write(ssl, buf, bytes);
	} else
		ERR_print_errors_fp(stderr);

out:
	sd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sd);
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx;
	const_SSL_METHOD *method = SSLv3_server_method();
	int server_fd;
	char *portnum;
	char *file_cert;
	char *file_key;
	int want_client_cert = 0;
	int keep_running = 0;
	int i;

	if (argc < 4) {
		printf("Usage: %s <portnum> <cert.pem> <key.pem> [opts]\n", argv[0]);
		exit(-1);
	}

	portnum = argv[1];
	file_cert = argv[2];
	file_key = argv[3];

	for (i = 4; i < argc; i++) {
		if (strcmp("tls-1.2", argv[i]) == 0) {
			method = TLSv1_2_server_method();
		} else if (strcmp("tls-1.1", argv[i]) == 0) {
			method = TLSv1_1_server_method();
		} else if (strcmp("tls-1.0", argv[i]) == 0) {
			method = TLSv1_server_method();
		} else if (strcmp("client-cert", argv[i]) == 0) {
			want_client_cert = 1;
		} else if (strcmp("keep-running", argv[i]) == 0) {
			keep_running = 1;
		} else {
			printf("warning: unknown option: \"%s\"\n", argv[i]);
		}
	}

	ctx = server_init(method, want_client_cert);

	load_server_certificates(ctx, file_cert, file_key);

	server_fd = listen_socket(atoi(portnum));

	do {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		printf("[status] accepting connection\n");
		int client = accept(server_fd, (struct sockaddr *) &addr, &len);
		printf("[log] got connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		process(ssl);
	} while (keep_running);

	close(server_fd);
	SSL_CTX_free(ctx);
	return 0;
}
