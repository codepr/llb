/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2019, Andrea Giacomo Baldan All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <openssl/err.h>
#include "config.h"
#include "network.h"
#include "npt_internal.h"

/* Set non-blocking socket */
static inline int set_nonblocking(int fd) {
    int flags, result;
    flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
        goto err;

    result = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (result == -1)
        goto err;

    return NPT_SUCCESS;

err:

    perror("set_nonblocking");
    return NPT_FAILURE;
}

static inline int set_cloexec(int fd) {
    int flags, result;
    flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
        goto err;

    result = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    if (result == -1)
        goto err;

    return NPT_SUCCESS;

err:

    perror("set_cloexec");
    return NPT_FAILURE;
}

/*
 * Set TCP_NODELAY flag to true, disabling Nagle's algorithm, no more waiting
 * for incoming packets on the buffer
 */
static inline int set_tcpnodelay(int fd) {
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int) {1}, sizeof(int));
}

static int create_and_bind(const char *host, const char *port) {

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };

    struct addrinfo *result, *rp;
    int sfd;

    if (getaddrinfo(host, port, &hints, &result) != 0)
        goto err;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (sfd == -1) continue;

        /* set SO_REUSEADDR so the socket will be reusable after process kill */
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
                       &(int) { 1 }, sizeof(int)) < 0)
            perror("SO_REUSEADDR");

        if ((bind(sfd, rp->ai_addr, rp->ai_addrlen)) == 0) {
            /* Succesful bind */
            break;
        }
        (void) close(sfd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        goto err;

    return sfd;

err:

    perror("Unable to bind socket");
    return NPT_FAILURE;
}

/*
 * Create a non-blocking socket and make it listen on the specfied address and
 * port
 */
int make_listen(const char *host, const char *port) {

    int sfd;

    if ((sfd = create_and_bind(host, port)) == -1)
        abort();

    if ((set_nonblocking(sfd)) == -1)
        abort();

    (void) set_cloexec(sfd);

    // Set TCP_NODELAY only for TCP sockets
    (void) set_tcpnodelay(sfd);

    if ((listen(sfd, conf->tcp_backlog)) == -1) {
        perror("listen");
        abort();
    }

    return sfd;
}

/*
 * Create a socket and use it to connect to the specified host and port
 */
int make_connection(const char *host, int port) {

    struct sockaddr_in serveraddr;
    struct hostent *server;

    /* socket: create the socket */
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0)
        goto err;

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(host);
    if (server == NULL)
        goto err;

    /* build the server's address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *) server->h_addr,
          (char *) &serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(port);

    (void) set_nonblocking(sfd);
    (void) set_tcpnodelay(sfd);

    /* connect: create a connection with the server */
    if (connect(sfd, (const struct sockaddr *) &serveraddr,
                sizeof(serveraddr)) < 0)
        goto err;

    return sfd;

err:

    if (errno == EINPROGRESS)
        return sfd;

    perror("socket(2) opening socket failed");
    return NPT_FAILURE;
}

/*
 * Accept a connection and set it NON_BLOCKING and CLOEXEC, optionally also set
 * TCP_NODELAY disabling Nagle's algorithm
 */
static int accept_conn(int sfd, char *ip) {

    int clientsock;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    if ((clientsock = accept(sfd, (struct sockaddr *) &addr, &addrlen)) < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) perror("accept");
        return NPT_FAILURE;
    }

    if ((set_nonblocking(clientsock)) == -1)
        abort();

    (void) set_cloexec(clientsock);

    // Set TCP_NODELAY only for TCP sockets
    (void) set_tcpnodelay(clientsock);

    char ip_buff[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr.sin_addr, ip_buff, sizeof(ip_buff)) == NULL) {
        if (close(clientsock) < 0) perror("close");
        return NPT_FAILURE;
    }

    if (ip)
        snprintf(ip, INET_ADDRSTRLEN+6, "%s:%i", ip_buff, ntohs(addr.sin_port));

    return clientsock;
}

ssize_t stream_send(int fd, struct stream *stream) {
    size_t total = stream->size;
    ssize_t n = 0;

    while (stream->size > 0) {
        n = write(fd, stream->buf + n, stream->size);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }
        stream->size -= n;
    }

    return total - stream->size;

err:

    fprintf(stderr, "send(2) - error sending data: %s\n", strerror(errno));
    return NPT_FAILURE;
}

/*
 * Receive a given number of bytes on the descriptor fd, storing the stream of
 * data into a 2 Mb capped buffer
 */
ssize_t stream_recv(int fd, struct stream *stream) {

    ssize_t n = 0;

    do {
        n = read(fd, stream->buf + stream->size, stream->capacity-stream->size);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }

        //if (n == 0)
        //    return NPT_SUCCESS;

        stream->size += n;

        if (stream->size == stream->capacity) {
            stream->capacity *= 2;
            stream->buf = npt_realloc(stream->buf, stream->capacity);
        }
    } while (n > 0);

    return stream->size;

err:

    fprintf(stderr, "read(2) - error reading data: %s\n", strerror(errno));
    return NPT_FAILURE;
}

void openssl_init() {
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void openssl_cleanup() {
    EVP_cleanup();
}

SSL_CTX *create_ssl_context() {

    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

    if (!(conf->tls_protocols & NPT_TLSv1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    if (!(conf->tls_protocols & NPT_TLSv1_1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
#ifdef SSL_OP_NO_TLSv1_2
    if (!(conf->tls_protocols & NPT_TLSv1_2))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_3
    if (!(conf->tls_protocols & NPT_TLSv1_3))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

    return ctx;
}

static int client_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx) {

    (void) ctx;  // Unused

	/* Preverify should check expiry, revocation. */
	return preverify_ok;
}

void load_certificates(SSL_CTX *ctx, const char *ca,
                       const char *cert, const char *key) {

    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, client_certificate_verify);
    SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

SSL *ssl_accept(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    ERR_clear_error();
    if (SSL_accept(ssl) <= 0)
        ERR_print_errors_fp(stderr);
    return ssl;
}

ssize_t ssl_stream_send(SSL *ssl, struct stream *stream) {
    size_t total = stream->size;
    ssize_t n = 0;

    ERR_clear_error();

    while (stream->size > 0) {
        if ((n = SSL_write(ssl, stream->buf + n, stream->size)) <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || SSL_ERROR_NONE)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN
                || (err == SSL_ERROR_SYSCALL && !errno))
                return NPT_SUCCESS;  // Connection closed
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }
        stream->size -= n;
    }

    return total - stream->size;

err:

    fprintf(stderr, "SSL_write(2) - error sending data: %s\n", strerror(errno));
    return NPT_FAILURE;
}

ssize_t ssl_stream_recv(SSL *ssl, struct stream *stream) {

    ssize_t n = 0;

    ERR_clear_error();

    do {
        n = SSL_read(ssl, stream->buf + stream->size, stream->capacity - stream->size);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_NONE)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN
                || (err == SSL_ERROR_SYSCALL && !errno))
                return NPT_SUCCESS;  // Connection closed
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }

        if (n == 0)
            return NPT_SUCCESS;

        stream->size += n;

        if (stream->size == stream->capacity) {
            stream->capacity *= 2;
            stream->buf = npt_realloc(stream->buf, stream->capacity);
        }
    } while (n > 0);

    return stream->size;

err:

    fprintf(stderr, "SSL_read(2) - error reading data: %s\n", strerror(errno));
    return NPT_FAILURE;
}

/*
 * Main connection functions, meant to be set as function pointer to a struct
 * connection handle
 */
static int conn_accept(struct connection *c, int fd) {
    int ret = accept_conn(fd, c->ip);
    c->fd = ret;
    return ret;
}

static int conn_connect(struct connection *c, const char *host, int port) {
    c->fd = make_connection(host, port);
    return c->fd;
}

static ssize_t conn_send(struct connection *c, struct stream *stream) {
    return stream_send(c->fd, stream);
}

static ssize_t conn_recv(struct connection *c, struct stream * stream) {
    return stream_recv(c->fd, stream);
}

static void conn_close(struct connection *c) {
    close(c->fd);
}

// TLS version of the connection functions
// XXX Not so neat, improve later
static int conn_tls_accept(struct connection *c, int serverfd) {
    int fd = accept_conn(serverfd, c->ip);
    if (fd < 0)
        return fd;
    c->ssl = ssl_accept(c->ctx, fd);
    c->fd = fd;
    return fd;
}

static int conn_tls_connect(struct connection *c, const char *host, int port) {
    // TODO
    (void) c;
    (void) host;
    (void) port;
    return NPT_SUCCESS;
}

static ssize_t conn_tls_send(struct connection *c, struct stream *stream) {
    return ssl_stream_send(c->ssl, stream);
}

static ssize_t conn_tls_recv(struct connection *c, struct stream * stream) {
    return ssl_stream_recv(c->ssl, stream);
}

static void conn_tls_close(struct connection *c) {
    if (c->ssl)
        SSL_free(c->ssl);
    if (c->fd >= 0 && close(c->fd) < 0)
        perror("close");
}

void connection_init(struct connection *conn, const SSL_CTX *ssl_ctx) {
    conn->fd = -1;
    conn->ssl = NULL; // Will be filled in case of TLS connection on accept
    conn->ctx = (SSL_CTX *) ssl_ctx;
    if (ssl_ctx) {
        // We need a TLS connection
        conn->accept = conn_tls_accept;
        conn->connect = conn_tls_connect;
        conn->send = conn_tls_send;
        conn->recv = conn_tls_recv;
        conn->close = conn_tls_close;
    } else {
        conn->accept = conn_accept;
        conn->connect = conn_connect;
        conn->send = conn_send;
        conn->recv = conn_recv;
        conn->close = conn_close;
    }
}

/*
 * Simple abstraction over a socket connection, based on the connection type,
 * sets plain accept, read, write and close functions or the TLS version one.
 *
 * This structure allows to ignore some details at a higher level where we can
 * simply call accept, send, recv or close without actually worrying of the
 * type of the underlying communication.
 */
struct connection *connection_new(const SSL_CTX *ssl_ctx) {
    struct connection *conn = npt_malloc(sizeof(*conn));
    if (!conn)
        return NULL;
    connection_init(conn, ssl_ctx);
    return conn;
}

/*
 * 4 connection type agnostic functions to be used at a higher level, like the
 * server module. They accept a connection structure as the first parameter
 * in order to leverage the previously set underlying function.
 */
int accept_connection(struct connection *c, int fd) {
    return c->accept(c, fd);
}

int open_connection(struct connection *c, const char *host, int port) {
    return c->connect(c, host, port);
}

ssize_t send_data(struct connection *c, struct stream *stream) {
    return c->send(c, stream);
}

ssize_t recv_data(struct connection *c, struct stream *stream) {
    return c->recv(c, stream);
}

void close_connection(struct connection *c) {
    c->close(c);
}
