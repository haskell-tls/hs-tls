/*
 * a simple OpenSSL client to test interoperability with tls
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/time.h>
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
#define TLSv1_2_client_method() SSLv3_client_method()
#define TLSv1_1_client_method() SSLv3_client_method()
#define TLSv1_client_method() SSLv3_client_method()
#define const_SSL_METHOD SSL_METHOD
#endif

enum cipher_choice
{
	CIPHER_ALL,
	CIPHER_RC4,
	CIPHER_ECDH,
	CIPHER_AES,
};

void failure() { exit(0xf); }

static int connect_socket(const char *host, int port)
{
	int sd, r;
	struct sockaddr_in sa;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot create socket"); failure();
	}

	sa.sin_port = htons(port);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(host);

	r = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
	if (r < 0) {
		perror("cannot connect socket"); failure();
	}
	return sd;
}

void lib_init()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}

static SSL_CTX* client_init(const SSL_METHOD *method, enum cipher_choice cipher_choice)
{
	SSL_CTX *ctx;
	char *cipher_list;

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		failure();
	}

	switch (cipher_choice) {
	case CIPHER_ALL: cipher_list = "ALL:!aNULL:!eNULL"; break;
	case CIPHER_RC4: cipher_list = "RC4"; break;
	case CIPHER_ECDH: cipher_list = "ECDH"; break;
	case CIPHER_AES: cipher_list = "AES"; break;
	default:
		printf("invalid cipher choice\n");	
		failure();
	}

	/* aNULL no auth
	** eNULL null ciphers
	** AES, AESGCM, DES, RC4
	** ECDH
	*/

	SSL_CTX_set_cipher_list(ctx, cipher_list);

	return ctx;
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

int SSL_write_all(SSL *ssl, char *buf, int sz)
{
	int written = 0;
	int n;

	while (written < sz) {
		n = SSL_write(ssl, buf + written, sz - written);
		if (n > 0)
			written += n;
		else if (n < 0)
			return -1;
	}
	return 0;
}

#define BENCH_CHUNK 4096

typedef struct
{
	struct timeval v;
} record_time_t;

void record_time(record_time_t *t)
{
	int rv = gettimeofday(&t->v, NULL);
	if (rv) {
		perror("gettimeofday");
		exit(1);
	}
}

void print_time(char *label, uint64_t nb_bytes, record_time_t *t1, record_time_t *t2)
{
	int sec = t2->v.tv_sec - t1->v.tv_sec;
	int usec = t2->v.tv_usec - t1->v.tv_usec;
	int64_t f;
	int unit_index = 0;
	double val;
	char *units[] = {
		" b",
		"kb",
		"mb",
		"gb",
	};

	if (usec < 0) {
		usec += 1000000;
		sec--;
	}

	f = sec * 1000000 + usec;

	val = nb_bytes * 1000000 / f;

	while (unit_index < 3 && val > 1080) {
		val /= 1024;
		unit_index++;
	}

	printf("%s: %" PRIu64 " bytes in %" PRId64 " us => %.3f %s/s\n", label, nb_bytes, f, val, units[unit_index]);
}

static void benchmark(SSL *ssl, uint64_t send_bytes, uint64_t recv_bytes)
{
	uint64_t bytes = 0;
	char buf[BENCH_CHUNK];
	record_time_t t0, t1, t2;
	int sd;

	memset(buf, 'a', BENCH_CHUNK);

	record_time(&t0);

	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		goto out;
	}

	printf("cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

	record_time(&t1);

	if (send_bytes) {
		while (bytes < send_bytes) {
			int to_send = (send_bytes - bytes > BENCH_CHUNK) ? BENCH_CHUNK : send_bytes - bytes;
			if (SSL_write_all(ssl, buf, to_send))
				break;
			bytes += to_send;
		}
	} else {
		while (bytes < recv_bytes) {
			int to_recv = (recv_bytes - bytes > BENCH_CHUNK) ? BENCH_CHUNK : recv_bytes - bytes;
			int recved;
			recved = SSL_read(ssl, buf, sizeof(to_recv));
			if (recved > 0)
				bytes += recved;
			else
				break;
		}
	}

	record_time(&t2);
	print_time((send_bytes > 0) ? "sending" : "receiving",
	           (send_bytes > 0) ? send_bytes : recv_bytes,
	           &t1, &t2);

	SSL_shutdown(ssl);
out:
	sd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sd);
}

static void process(SSL* ssl)
{
	char buf[1024];
	int sd, bytes;

	strcpy(buf, "Hello World\n");

	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		goto out;
	}

	show_certificates(ssl);
	while (1) {
		bytes = SSL_write(ssl, buf, sizeof(buf));
		if (bytes > 0) {
			printf("received from client: \"%s\"\n", buf);
			SSL_write(ssl, buf, bytes);
		} else {
			ERR_print_errors_fp(stderr);
			break;
		}
		if (SSL_get_shutdown(ssl) == SSL_RECEIVED_SHUTDOWN) {
			SSL_shutdown(ssl);
			break;
		}
	}

out:
	sd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sd);
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx;
	const SSL_METHOD *method = SSLv3_client_method();
	int client_fd;
	char *host;
	char *portnum;
	int bench_send = 0;
	int bench_recv = 0;
	int i;
	enum cipher_choice cipher_choice = CIPHER_ALL;

	if (argc < 3) {
		printf("Usage: %s <host> <portnum> [opts]\n", argv[0]);
		exit(-1);
	}

	host = argv[1];
	portnum = argv[2];

	lib_init();

	for (i = 3; i < argc; i++) {
		if (strcmp("tls-1.2", argv[i]) == 0) {
			method = TLSv1_2_client_method();
		} else if (strcmp("tls-1.1", argv[i]) == 0) {
			method = TLSv1_1_client_method();
		} else if (strcmp("tls-1.0", argv[i]) == 0) {
			method = TLSv1_client_method();
		} else if (strcmp("ssl-3.0", argv[i]) == 0) {
			method = SSLv3_client_method();
		} else if (strcmp("bench-send", argv[i]) == 0) {
			bench_send = atoi(argv[++i]);
		} else if (strcmp("bench-recv", argv[i]) == 0) {
			bench_recv = atoi(argv[++i]);
		} else {
			printf("warning: unknown option: \"%s\"\n", argv[i]);
		}
	}

	ctx = client_init(method, cipher_choice);

	client_fd = connect_socket("127.0.0.1", atoi(portnum));

	printf("[status] connected. handshaking\n");

	SSL *ssl;
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_fd);

	if (bench_send > 0 || bench_recv > 0)
		benchmark(ssl, bench_send, bench_recv);
	else
		process(ssl);
	close(client_fd);
	SSL_CTX_free(ctx);
	return 0;
}
