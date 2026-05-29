#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

static int create_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        die("setsockopt");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(fd, 16) < 0) die("listen");
    return fd;
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

static unsigned char *remove_stopword(const unsigned char *in, size_t in_len, size_t *out_len) {
    const char *pat = "stopword";
    const size_t pat_len = 8;

    unsigned char *out = malloc(in_len + 1);
    if (!out) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }

    size_t i = 0, j = 0;
    while (i < in_len) {
        if (i + pat_len <= in_len && memcmp(in + i, pat, pat_len) == 0) {
            i += pat_len;
        } else {
            out[j++] = in[i++];
        }
    }

    *out_len = j;
    return out;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
                "Usage: %s <proxy.crt> <proxy.key> <ca_server.pem> <listen_port> <server_host> <server_port>\n",
                argv[0]);
        return 1;
    }

    const char *proxy_crt = argv[1];
    const char *proxy_key = argv[2];
    const char *ca_server = argv[3];
    int listen_port = atoi(argv[4]);
    const char *server_host = argv[5];
    int server_port = atoi(argv[6]);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // TODO you may fill here 

    int lfd = create_listen_socket(listen_port);
    printf("[proxy] listening on %d\n", listen_port);

    while (1) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(lfd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            perror("accept");
            continue;
        }

        // TODO you may fill here 

        printf("[proxy] client->proxy TLS version: %s\n", SSL_get_version(c_ssl));
        printf("[proxy] client->proxy cipher     : %s\n", SSL_get_cipher(c_ssl));

        int sfd = tcp_connect(server_host, server_port);

        // TODO you may fill here 

        SSL_shutdown(s_ssl);
        SSL_free(s_ssl);
        close(sfd);

        SSL_shutdown(c_ssl);
        SSL_free(c_ssl);
        close(cfd);
    }

    close(lfd);
    EVP_cleanup();
    return 0;
}
