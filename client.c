#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void ssl_die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int tcp_connect(const char *host, int port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        die("getaddrinfo");
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0) die("connect");
    return fd;
}

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) die("fopen");

    if (fseek(fp, 0, SEEK_END) != 0) die("fseek");
    long sz = ftell(fp);
    if (sz < 0) die("ftell");
    rewind(fp);

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }

    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (n != (size_t)sz) {
        fprintf(stderr, "fread failed\n");
        exit(1);
    }

    *out_len = n;
    return buf;
}

static int ssl_write_all(SSL *ssl, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

static int ssl_read_all(SSL *ssl, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl, buf + off, (int)(len - off));
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

static int verify_signature_with_peer_cert(SSL *ssl,
                                           const unsigned char *msg, size_t msg_len,
                                           const unsigned char *sig, size_t sig_len) {

    int rc = -1;

    // TODO you may fill here 

    // rc == 1 : success
    // rc == 0 : invalid signature
    // rc < 0  : error
    return rc;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <host> <port> <ca_bundle.pem> <input.txt>\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *ca_bundle = argv[3];
    const char *input_file = argv[4];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // TODO you may fill here 

    printf("[client] connected to %s:%d\n", host, port);
    printf("[client] TLS version: %s\n", SSL_get_version(ssl));
    printf("[client] cipher     : %s\n", SSL_get_cipher(ssl));
    printf("[client] received message: %s\n", msg);

    int v = verify_signature_with_peer_cert(ssl, msg, msg_len, sig, sig_len);

    if (v == 1) {
        printf("[client] signature verification succeeded.\n");
        printf("[client] No proxy exists.\n");
    } else if (v == 0) {
        printf("[client] signature verification failed.\n");
        printf("[client] Proxy exists.\n");
    } else {
        printf("[client] signature verification error.\n");
    }

    free(msg);
    free(sig);

    close(fd);
    EVP_cleanup();
    return 0;
}
