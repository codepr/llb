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

#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/timerfd.h>

struct stream {
    unsigned char *buf;
    size_t size;
    size_t capacity;
};

/*
 * Connection abstraction struct, provide a transparent interface for
 * connection handling, taking care of communication layer, being it encrypted
 * or plain, by setting the right callbacks to be used.
 *
 * The 4 main operations reflected by those callbacks are the ones that can be
 * performed on every FD:
 *
 * - accept
 * - read
 * - write
 * - close
 *
 * According to the type of connection we need, each one of these actions will
 * be set with the right function needed. Maintain even the address:port of the
 * connecting client.
 */
struct connection {
    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    char ip[INET_ADDRSTRLEN + 6];
    int (*accept) (struct connection *, int);
    ssize_t (*send) (struct connection *, struct stream *);
    ssize_t (*recv) (struct connection *, struct stream *);
    void (*close) (struct connection *);
};

void connection_init(struct connection *, const SSL_CTX *);

struct connection *connection_new(const SSL_CTX *);

int accept_connection(struct connection *, int);

ssize_t send_data(struct connection *, struct stream *);

ssize_t recv_data(struct connection *, struct stream *);

void close_connection(struct connection *);

/*
 * Create a non-blocking socket and make it listen on the specfied address and
 * port
 */
int make_listen(const char *, const char *);

/* I/O management functions */

/*
 * Send all data in a loop, avoiding interruption based on the kernel buffer
 * availability
 */
ssize_t stream_send(int, struct stream *);

/*
 * Receive (read) an arbitrary number of bytes from a file descriptor and
 * store them in a buffer
 */
ssize_t stream_recv(int, struct stream *);

// Init SSL context
SSL_CTX *create_ssl_context(void);

/* Init openssl library */
void openssl_init(void);

/* Release resources allocated by openssl library */
void openssl_cleanup(void);

/* Load cert.pem and key.pem certfiles from filesystem */
void load_certificates(SSL_CTX *, const char *, const char *, const char *);

/* Send data like sendall but adding encryption SSL */
ssize_t ssl_stream_send(SSL *, struct stream *);

/* Recv data like recvall but adding encryption SSL */
ssize_t ssl_stream_recv(SSL *, struct stream *);

SSL *ssl_accept(SSL_CTX *, int);

#endif
