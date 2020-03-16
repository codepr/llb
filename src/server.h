/* BSD 2-Clause License
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

#ifndef SERVER_H
#define SERVER_H

#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <openssl/ssl.h>
#include "network.h"

/*
 * Number of worker threads to be created. Each one will host his own ev_ctx
 * loop. This doesn't take into account the main thread, so to know the total
 * number of running loops +1 must be added to the THREADSNR value.
 */
#define THREADSNR 2

/*
 * Epoll default settings for concurrent events monitored and timeout, -1
 * means no timeout at all, blocking undefinitely
 */
#define EVENTLOOP_MAX_EVENTS    1024
#define EVENTLOOP_TIMEOUT       -1

/*
 * Initial memory allocation for clients on server start-up, it should be
 * equal to ~40 MB, read and write buffers are initialized lazily
 */
#define BASE_CLIENTS_NUM  1024 * 128

/*
 * Error codes for packet reception, signaling respectively
 * - client disconnection
 * - error reading packet
 * - error packet sent exceeds size defined by configuration (generally default
 *   to 2MB)
 * - error EAGAIN from a non-blocking read/write function
 * - error sending/receiving data on a connected socket
 * - error OUT OF MEMORY
 */
#define ERRCLIENTDC         1
#define ERRPACKETERR        2
#define ERRMAXREQSIZE       3
#define ERREAGAIN           4
#define ERRSOCKETERR        5
#define ERRNOMEM            6

struct backend {
    char host[0xFF];
    int port;
    bool alive;
};

/*
 * Main structure, a global instance will be instantiated at start, tracking
 * topics, connected clients and registered closures.
 *
 * pending_msgs and pendings_acks are two arrays used to track remaining
 * messages to push out and acks respectively.
 */
struct server {
    volatile atomic_int current_backend;
    struct memorypool *pool; /* A memory pool for clients allocation */
    struct client *clients; /* Our clients map, it's a handle pointer for
                             * UTHASH APIs, must be set to NULL
                             */
    struct backend *backends;
    SSL_CTX *ssl_ctx; /* Application TLS context */
};

extern struct server server;

/*
 * The client actions can be summarized as a roughly simple state machine,
 * comprised by 2 states:
 * - WAITING_REQUEST   it's the step required to receive the full byte stream as
 *                     the encoded length describe. We wait for the effective
 *                     payload in this state.
 * - SENDING_DATA   the last status, a complete packet has been received and
 *                  has to be processed and reply back if needed.
 */
//enum client_status {
//    WAITING_REQUEST,
//    WAITING_RESPONSE,
//    SENDING_DATA
//};
//
///*
// * Wrapper structure around a connected client, each client can be a publisher
// * or a subscriber, it can be used to track sessions too.
// * As of now, no allocations will be fired, jsut a big pool of memory at the
// * start of the application will serve us a client pool, read and write buffers
// * are initialized lazily.
// *
// * It's an hashable struct which will be tracked during the execution of the
// * application, see https://troydhanson.github.io/uthash/userguide.html.
// */
//struct client {
//    struct ev_ctx *ctx; /* An event context refrence mostly used to fire write events */
//    int status; /* Current status of the client (state machine) */
//    struct stream stream;
//    struct connection conn; /* A connection structure, takes care of plain or
//                             * TLS encrypted communication by using callbacks
//                             */
//    struct connection backend;
//    time_t last_seen; /* The timestamp of the last action performed */
//    pthread_mutex_t mutex; /* Inner lock for the client, this avoid race-conditions on shared parts */
//    UT_hash_handle hh; /* UTHASH handle, needed to use UTHASH macros */
//};

int start_server(const char *, const char *);
void enqueue_event_write(const struct http_transaction *);
void daemonize(void);

#endif
