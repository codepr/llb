/* BSD 2-Clause License
 *
 * Copyright (c) 2023, Andrea Giacomo Baldan All rights reserved.
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

#ifndef SERVER_H
#define SERVER_H

#include <stdatomic.h>
#include "network.h"

/*
 * Number of worker threads to be created. Each one will host his own ev_ctx
 * loop. This doesn't take into account the main thread, so to know the total
 * number of running loops +1 must be added to the THREADSNR value.
 */
#define THREADSNR 2

/*
 * Epoll default settings for concurrent events monitored
 */
#define EVENTLOOP_MAX_EVENTS    1024

/*
 * Initial memory allocation for HTTP transactions on server start-up, it
 * should be equal to roughly ~100 MB, read and write buffers are initialized
 * lazily
 */
#define MAX_ACTIVE_SESSIONS 1 << 19
#define MAX_STREAM_BUF_SIZE 1 << 12

#define HTTP_METHOD_MAX_LEN 256

/*
 * Error codes for packet reception, signaling respectively
 * - client disconnection
 * - error EAGAIN from a non-blocking read/write function
 * - error sending/receiving data on a connected socket
 */
#define ERRCLIENTDC         1
#define ERREAGAIN           2
#define ERRSOCKETERR        3

/*
 * Frontend endpoint, defines a pair host:port the server will listen on, to
 * which clients can connect to. There can be multiple different frontends.
 */
struct frontend {
    char host[0xFF];
    int port;
    int weight; // unused, ugly hack for config
};

/*
 * Backend endpoint, defines a pair host:port to which the traffic will be
 * load-balanced by the server, connecting clients through frontends will be
 * redirected to connected backends, according to the selected balancing
 * method.
 */
struct backend {
    char host[0xFF];
    int port;
    int weight;  // to be ignored in case of balancing != WEIGHTED_ROUND_ROBIN
    struct timeval start;
    volatile atomic_int active_connections;
    volatile atomic_size_t bytecount;
    volatile atomic_bool alive;
};

/*
 * Main structure, a global instance will be instantiated at start, tracking
 * the current backend for the round-robing algorithm to load-balance the
 * traffic between backends, accessed by the reference `backends`.
 *
 * A memory pool is used to initially allocate the HTTP transactions pool to
 * avoid malloc'ing every connection. Finally a SSL_CTX pointer is initialized
 * at the startup as well for the TLS communication between frontends and
 * clients.
 */
struct server {
    volatile atomic_uint current_backend;
    volatile atomic_int current_weight;
    volatile atomic_int gcd;
    struct memorypool *pool; /* A memory pool for clients allocation */
    struct backend *backends; /* A pointer to the backends registered */
    SSL_CTX *ssl_ctx; /* Application TLS context */
};

extern struct server server;

int start_server(const struct frontend *, int);
void daemonize(void);

#endif
