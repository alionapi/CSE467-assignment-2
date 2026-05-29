/*
 * proxy.c for CSE467 Assignment 2 about the TLS Interception Proxy
 *
 * Role of this coding & program (independently written from the assignment spec):
 *
 *   1. Terminate an incoming TLS connection from the client, presenting a
 *      certificate signed by the "proxy" root CA. The client has the proxy
 *      root CA in its trust bundle, so the handshake succeeds.
 *
 *   2. Open a *fresh* TLS connection out to the real backend server on the
 *      other side, verifying the server's certificate against the provided
 *      server root CA.
 *
 *   3. Relay application-layer traffic between the two TLS sessions. On the
 *      client-to-server leg we perform the sole interception behavior
 *      required by the spec: strip every occurrence of the ASCII literal
 *      "stopword" from the file content, then recompute the length prefix.
 *      The server-to-client leg is passed through verbatim.
 *
 *   4. Force TLS 1.2 on *both* legs (this is what makes the "No Proxy"
 *      vs "Proxy exists" detection in the client cleanly correlate with
 *      the observed TLS version in the example outputs).
 *
 * The basic concept note: the two-sided TLS termination is the textbook pattern for
 * MITM proxies discussed in Durumeric et al., NDSS '17. The code itself is
 * original, written against the OpenSSL 3.0 manpages.
 */

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

/* --- these are teh fatal-error helpers --------------------------------------------- */

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void ssl_die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* --- here's an open a passive (listening) TCP socket --------------------------- */

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

/* --- this is an active TCP connect (used to reach the backend) ------------------ */

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

/* --- now the part of full read / write loops over TLS -------------------------------- */

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

/*
 * remove_stopword
 *
 * Walk through the input buffer and copy every byte into a freshly-allocated
 * output buffer, *skipping* each exact 8-byte occurrence of "stopword".
 * Non-overlapping, case-sensitive match; this matches the spec wording
 * ("the substring 'stopword'") and the server's example "hello stopword
 * world" -> "hello  world" (note the double space, i.e. nothing else is
 * trimmed).
 */
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

    const char *proxy_crt   = argv[1];
    const char *proxy_key   = argv[2];
    const char *ca_server   = argv[3];
    int listen_port         = atoi(argv[4]);
    const char *server_host = argv[5];
    int server_port         = atoi(argv[6]);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ------------------------------------------------------------------
     * Two SSL_CTXs are prepared up front and reused for every accepted
     * client. Creating them per-connection would work but is wasteful.
     *
     *   server_ctx -- acts as a TLS *server* toward the real client.
     *                 Presents the proxy leaf certificate + key.
     *
     *   client_ctx -- acts as a TLS *client* toward the backend server.
     *                 Verifies the backend cert against ca_server.pem.
     *
     * These both contexts are pinned to TLS 1.2 as required so it works
     * ------------------------------------------------------------------ */
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    if (!server_ctx) ssl_die("SSL_CTX_new(server) failed");

    if (SSL_CTX_set_min_proto_version(server_ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(server_ctx, TLS1_2_VERSION) != 1)
        ssl_die("pin server_ctx to TLS1.2 failed");

    if (SSL_CTX_use_certificate_file(server_ctx, proxy_crt, SSL_FILETYPE_PEM) != 1)
        ssl_die("SSL_CTX_use_certificate_file(proxy_crt) failed");
    if (SSL_CTX_use_PrivateKey_file(server_ctx, proxy_key, SSL_FILETYPE_PEM) != 1)
        ssl_die("SSL_CTX_use_PrivateKey_file(proxy_key) failed");
    if (SSL_CTX_check_private_key(server_ctx) != 1)
        ssl_die("proxy cert/key mismatch");

    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    if (!client_ctx) ssl_die("SSL_CTX_new(client) failed");

    if (SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(client_ctx, TLS1_2_VERSION) != 1)
        ssl_die("pin client_ctx to TLS1.2 failed");

    if (SSL_CTX_load_verify_locations(client_ctx, ca_server, NULL) != 1)
        ssl_die("SSL_CTX_load_verify_locations(ca_server) failed");
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(client_ctx, 4);

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

        /* --------------------------------------------------------------
         * Leg 1: TLS handshake with the real client.
         *
         * We do NOT exit() on handshake failure here because it's the proxy needs
         * to stay up and ready for the next client.
         * -------------------------------------------------------------- */
        SSL *c_ssl = SSL_new(server_ctx);
        if (!c_ssl) {
            fprintf(stderr, "[proxy] SSL_new(server) failed\n");
            close(cfd);
            continue;
        }
        if (SSL_set_fd(c_ssl, cfd) != 1) {
            fprintf(stderr, "[proxy] SSL_set_fd(c) failed\n");
            SSL_free(c_ssl);
            close(cfd);
            continue;
        }
        if (SSL_accept(c_ssl) != 1) {
            fprintf(stderr, "[proxy] SSL_accept failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(c_ssl);
            close(cfd);
            continue;
        }

        printf("[proxy] client->proxy TLS version: %s\n", SSL_get_version(c_ssl));
        printf("[proxy] client->proxy cipher     : %s\n", SSL_get_cipher(c_ssl));

        /* --------------------------------------------------------------
         * Leg 2: connect out to the real backend server and complete a
         * separate TLS handshake, verifying its certificate as it should.
         * -------------------------------------------------------------- */
        int sfd = tcp_connect(server_host, server_port);

        SSL *s_ssl = SSL_new(client_ctx);
        if (!s_ssl) {
            fprintf(stderr, "[proxy] SSL_new(client) failed\n");
            close(sfd);
            SSL_shutdown(c_ssl); SSL_free(c_ssl); close(cfd);
            continue;
        }
        SSL_set_tlsext_host_name(s_ssl, server_host);
        if (SSL_set_fd(s_ssl, sfd) != 1) {
            fprintf(stderr, "[proxy] SSL_set_fd(s) failed\n");
            SSL_free(s_ssl); close(sfd);
            SSL_shutdown(c_ssl); SSL_free(c_ssl); close(cfd);
            continue;
        }
        if (SSL_connect(s_ssl) != 1) {
            fprintf(stderr, "[proxy] SSL_connect(server) failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(s_ssl); close(sfd);
            SSL_shutdown(c_ssl); SSL_free(c_ssl); close(cfd);
            continue;
        }

        /* --------------------------------------------------------------
         * Application-layer relay.
         *
         *   client -> proxy: [uint32 len][content]
         *   proxy  -> server: [uint32 new_len][content without "stopword"]
         *   server -> proxy: [uint32 msg_len][msg][uint32 sig_len][sig]
         *   proxy  -> client: same bytes, untouched.
         * -------------------------------------------------------------- */
        uint32_t net_len = 0;
        if (!ssl_read_all(c_ssl, (unsigned char *)&net_len, sizeof(net_len))) {
            fprintf(stderr, "[proxy] failed to read length from client\n");
            goto teardown;
        }
        size_t in_len = (size_t)ntohl(net_len);

        unsigned char *in_buf = NULL;
        if (in_len > 0) {
            in_buf = malloc(in_len);
            if (!in_buf) { fprintf(stderr, "malloc failed\n"); exit(1); }
            if (!ssl_read_all(c_ssl, in_buf, in_len)) {
                fprintf(stderr, "[proxy] failed to read content from client\n");
                free(in_buf);
                goto teardown;
            }
        } else {
            /* as zero-length payload is technically legal; carry on. */
            in_buf = malloc(1);
        }

        size_t out_len = 0;
        unsigned char *out_buf = remove_stopword(in_buf, in_len, &out_len);
        free(in_buf);

        uint32_t net_out_len = htonl((uint32_t)out_len);
        if (!ssl_write_all(s_ssl, (unsigned char *)&net_out_len, sizeof(net_out_len)) ||
            (out_len > 0 && !ssl_write_all(s_ssl, out_buf, out_len))) {
            fprintf(stderr, "[proxy] failed to forward content to server\n");
            free(out_buf);
            goto teardown;
        }
        free(out_buf);

        /* here relay the server's message + signature verbatim. */
        uint32_t net_msg_len = 0;
        if (!ssl_read_all(s_ssl, (unsigned char *)&net_msg_len, sizeof(net_msg_len))) {
            fprintf(stderr, "[proxy] failed to read msg length from server\n");
            goto teardown;
        }
        size_t msg_len = (size_t)ntohl(net_msg_len);

        unsigned char *msg = malloc(msg_len > 0 ? msg_len : 1);
        if (!msg) { fprintf(stderr, "malloc failed\n"); exit(1); }
        if (msg_len > 0 && !ssl_read_all(s_ssl, msg, msg_len)) {
            fprintf(stderr, "[proxy] failed to read msg from server\n");
            free(msg);
            goto teardown;
        }

        uint32_t net_sig_len = 0;
        if (!ssl_read_all(s_ssl, (unsigned char *)&net_sig_len, sizeof(net_sig_len))) {
            fprintf(stderr, "[proxy] failed to read sig length from server\n");
            free(msg);
            goto teardown;
        }
        size_t sig_len = (size_t)ntohl(net_sig_len);

        unsigned char *sig = malloc(sig_len > 0 ? sig_len : 1);
        if (!sig) { fprintf(stderr, "malloc failed\n"); exit(1); }
        if (sig_len > 0 && !ssl_read_all(s_ssl, sig, sig_len)) {
            fprintf(stderr, "[proxy] failed to read sig from server\n");
            free(msg); free(sig);
            goto teardown;
        }

        /* now forward to client: length fields in network order are already
         * what we read, so just re-emit them. */
        if (!ssl_write_all(c_ssl, (unsigned char *)&net_msg_len, sizeof(net_msg_len)) ||
            (msg_len > 0 && !ssl_write_all(c_ssl, msg, msg_len)) ||
            !ssl_write_all(c_ssl, (unsigned char *)&net_sig_len, sizeof(net_sig_len)) ||
            (sig_len > 0 && !ssl_write_all(c_ssl, sig, sig_len))) {
            fprintf(stderr, "[proxy] failed to forward server reply to client\n");
        }

        free(msg);
        free(sig);

    teardown:
        SSL_shutdown(s_ssl);
        SSL_free(s_ssl);
        close(sfd);

        SSL_shutdown(c_ssl);
        SSL_free(c_ssl);
        close(cfd);
    }

    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    close(lfd);
    EVP_cleanup();
    return 0;
}
