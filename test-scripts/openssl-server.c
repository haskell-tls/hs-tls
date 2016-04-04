/*
 * a simple OpenSSL server to test interoperability with tls
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/engine.h>

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

static uint8_t deterministic_val = 1;
static void deterministic_seed (const void *buf, int num) { return; }
static int deterministic_bytes (unsigned char *buf, int num) { int i; for (i = 0; i < num; i++) *buf++ = deterministic_val++; return num; }
static void deterministic_cleanup (void) { return; }
static void deterministic_add (const void *buf, int num, double entropy) { return; }
static int deterministic_pseudorand (unsigned char *buf, int num) { return deterministic_bytes(buf, num); }
static int deterministic_status (void) { return 1; }

const struct rand_meth_st deterministic_rand = {
	.seed = deterministic_seed,
	.bytes = deterministic_bytes,
	.cleanup = deterministic_cleanup,
	.add = deterministic_add,
	.pseudorand = deterministic_pseudorand,
	.status = deterministic_status,
};

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

static SSL_CTX* server_init(const_SSL_METHOD *method, int want_client_cert, int want_dhe, int want_ecdhe)
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

	if (want_dhe) {
		DH *dh;

		dh = DH_new();
		if (!dh) { printf("cannot DH new\n"); failure(); }

		if (DH_generate_parameters_ex(dh, 1024, DH_GENERATOR_2, NULL) != 1) {
			printf("cannot generate DH\n");
			failure();
		}

		if (SSL_CTX_set_tmp_dh(ctx, dh) != 1) {
			printf("cannot set tmp DH\n");
			failure();
		}
		SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
	}
	if (want_ecdhe) {
		SSL_CTX_set_ecdh_auto(ctx, 1);
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
	uint64_t f;
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

	printf("%s: %lld bytes in %lld us => %.3f %s/s\n", label, nb_bytes, f, val, units[unit_index]);
}

static void benchmark(SSL *ssl, uint64_t send_bytes, uint64_t recv_bytes)
{
	uint64_t bytes = 0;
	char buf[BENCH_CHUNK];
	record_time_t t1, t2;
	int sd;

	memset(buf, 'a', BENCH_CHUNK);

	if (SSL_accept(ssl) == SSL_FAIL) {
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

	if (SSL_accept(ssl) == SSL_FAIL) {
		ERR_print_errors_fp(stderr);
		goto out;
	}

	printf("cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

	show_certificates(ssl);
	while (1) {
		bytes = SSL_read(ssl, buf, sizeof(buf));
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
	const_SSL_METHOD *method = SSLv3_server_method();
	int server_fd;
	char *portnum;
	char *file_cert;
	char *file_key;
	int want_client_cert = 0;
	int want_dhe = 0;
	int want_ecdhe = 0;
	int keep_running = 0;
	int use_ready_file = 0;
	int bench_send = 0;
	int bench_recv = 0;
	int deterministic = 0;
	char *ready_file;
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
		} else if (strcmp("ssl-3.0", argv[i]) == 0) {
			method = SSLv3_server_method();
		} else if (strcmp("client-cert", argv[i]) == 0) {
			want_client_cert = 1;
		} else if (strcmp("keep-running", argv[i]) == 0) {
			keep_running = 1;
		} else if (strcmp("dhe", argv[i]) == 0) {
			want_dhe = 1;
		} else if (strcmp("ecdhe", argv[i]) == 0) {
			want_ecdhe = 1;
		} else if (strcmp("ready-file", argv[i]) == 0) {
			use_ready_file = 1;
			ready_file = argv[++i];
		} else if (strcmp("bench-send", argv[i]) == 0) {
			bench_send = atoi(argv[++i]);
		} else if (strcmp("bench-recv", argv[i]) == 0) {
			bench_recv = atoi(argv[++i]);
		} else if (strcmp("deterministic", argv[i]) == 0) {
			deterministic = 1;
		} else {
			printf("warning: unknown option: \"%s\"\n", argv[i]);
		}
	}

	if (use_ready_file)
		printf("readyfile: %s\n", ready_file);

	if (deterministic) {
		ENGINE *engine;

		engine = ENGINE_new();
		ENGINE_set_RAND(engine, &deterministic_rand);

		RAND_set_rand_engine(engine);
	}

	ctx = server_init(method, want_client_cert, want_dhe, want_ecdhe);

	load_server_certificates(ctx, file_cert, file_key);

	server_fd = listen_socket(atoi(portnum));

	if (use_ready_file) {
		FILE *f;

		f = fopen(ready_file, "w+");
		if (f != NULL) {
			fwrite("ready\n", 6, 1, f);
			fclose(f);
		}
	}

	do {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		printf("[status] accepting connection\n");
		int client = accept(server_fd, (struct sockaddr *) &addr, &len);
		printf("[log] got connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		deterministic_val = 1;

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		if (bench_send > 0 || bench_recv > 0)
			benchmark(ssl, bench_send, bench_recv);
		else
			process(ssl);
	} while (keep_running);

	close(server_fd);
	SSL_CTX_free(ctx);
	return 0;
}
