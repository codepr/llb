/* BSD 2-Clause License
 *
 * Copyright (c) 2020, Andrea Giacomo Baldan All rights reserved.
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

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "ev.h"
#include "log.h"
#include "config.h"
#include "server.h"
#include "network.h"
#include "memorypool.h"
#include "llb_internal.h"

#define HTTP_HEADER_CRLF "\r\n\r\n"

/*
 * To prevent weird bugs during init of transactions or allocation/freeing of
 * resources from the memorypool
 */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Auxiliary structure to be used as init argument for eventloop, fd is the
 * listening sockets array, the same number of the frontends number, we want to
 * share between multiple instances, cronjobs is just a flag to signal if we
 * want to register cronjobs on that particular instance or not (to not repeat
 * useless cron jobs on multiple threads)
 */
struct listen_payload {
    int *fds;
    int frontends_nr;
    bool cronjobs;
};

/*
 * Server global instance, contains the backends reference, the current
 * selected one, a memorypool for the transactions and the SSL context for the
 * TLS communication.
 */
struct server server;

/*
 * TCP server, based on I/O multiplexing abstraction called ev_ctx. Each thread
 * (if any) should have his own ev_ctx and thus being responsible of a subset
 * of clients.
 * At the init of the server, the ev_ctx will be instructed to run some
 * periodic tasks and to run a callback on accept on new connections. From now
 * on start a simple juggling of callbacks to be scheduled on the event loop,
 * typically after being accepted a connection his handle (fd) will be added to
 * the backend of the loop (this case we're using EPOLL as a backend but also
 * KQUEUE or SELECT/POLL should be easy to plug-in) and read_callback will be
 * run every time there's new data incoming. If a complete packet is received
 * and correctly parsed it will be processed by calling the right handler from
 * the handler module, based on the command it carries and a response will be
 * fired back.
 *
 *                              MAIN THREAD
 *                               [EV_CTX]
 *
 *    ACCEPT_CALLBACK          READ_CALLBACK          WRITE_CALLBACK
 *  -------------------     ------------------      ------------------
 *          |                        |                       |
 *        ACCEPT                     |                       |
 *          | ---------------------> |                       |
 *          |                  READ AND DECODE               |
 *          |                        |                       |
 *          |                        |                       |
 *          |                     PROCESS                    |
 *          |                        |                       |
 *          |                        |                       |
 *          |                        | --------------------> |
 *          |                        |                     WRITE
 *        ACCEPT                     |                       |
 *          | ---------------------> | <-------------------- |
 *          |                        |                       |
 *
 * The whole method could be easily distributed across a threadpool, by paying
 * attention to the shared critical parts on handler module.
 * The access to shared data strucures could be guarded by a mutex or a
 * spinlock, and being generally fast operations it shouldn't suffer high
 * contentions by the threads and thus being really fast.
 * The drawback of this approach is that the concurrency is not equally
 * distributed across all threads, each thread has it's own eventloop and thus
 * is responsible for a subset of connections, without any possibility of
 * cooperation from other threads. This should be mitigated by the fact that
 * this application mainly deals with short-lived connections so there's
 * frequent turnover of monitored FDs, increasing the number of connections
 * for each different thread.
 */

static void tcp_session_init(struct tcp_session *);

static void tcp_session_close(struct tcp_session *);

static void http_transaction_init(struct http_transaction *);

static void http_transaction_close(struct http_transaction *);

// CALLBACKS for the eventloop
static void accept_callback(struct ev_ctx *, void *);

static void tcp_read_callback(struct ev_ctx *, void *);

static void tcp_write_callback(struct ev_ctx *, void *);

static void http_read_callback(struct ev_ctx *, void *);

static void http_write_callback(struct ev_ctx *, void *);

static void enqueue_tcp_read(const struct tcp_session *);

static void enqueue_tcp_write(const struct tcp_session *);

static void enqueue_http_read(const struct http_transaction *);

static void enqueue_http_write(const struct http_transaction *);

/*
 * This function will be called in LLB_TCP_MODE after a new connection has been
 * accepted, just before start reading the data stream, select the backend
 * based on the balancing algorithm and connect to the resulting backend,
 * adding the new connection to the event loop
 */
static void route_tcp_to_backend(struct ev_ctx *, struct tcp_session *);

/*
 * Processing request function, will be applied on fully formed request
 * received on read_callback callback, requests are the one incoming from
 * connected clients toward backends
 */
static void process_http_request(struct ev_ctx *, struct http_transaction *);

/*
 * Processing response function, will be applied on fully formed received
 * responses on read_callback callback, responses are the one returned by
 * connected backends back to requesting clients
 */
static void process_http_response(struct ev_ctx *, struct http_transaction *);

/* Periodic routine to perform healthchecks on backends */
static void backends_healthcheck(struct ev_ctx *, void *);

/*
 * Utility functions to parse HTTP header infos like content-length and
 * transfer-encoding
 */

static inline void http_parse_header(struct http_transaction *);

static inline void http_parse_content_length(struct http_transaction *);

static inline int http_header_length(const struct http_transaction *);

#define CHUNKED_COMPLETE(tcp) \
    strcmp((char *) (tcp)->stream.buf + (tcp)->stream.size - 5, "0\r\n\r\n") == 0

#define PROCESS_HTTP_STREAM(http) do {                           \
    if ((http)->tcp_session.status == WAITING_REQUEST) {         \
        process_http_request((http)->tcp_session.ctx, (http));   \
    } else if ((http)->tcp_session.status == WAITING_RESPONSE) { \
        process_http_response((http)->tcp_session.ctx, (http));  \
    }                                                            \
} while (0);

/* Parse header length by scanning all chars till the double CRLF */
static inline int http_header_length(const struct http_transaction *http) {
    char *ptr = (char *) http->tcp_session.stream.buf;
    int count = 0;
    while (*ptr) {
        if (STREQ(ptr, HTTP_HEADER_CRLF, 4))
            return count + 4;
        ptr++;
        count++;
    }
    return LLB_FAILURE;
}

static inline void http_parse_content_length(struct http_transaction *http) {
    // XXX hack
    int header_length = http_header_length(http);
    const char *content_length =
        strstr((const char *) http->tcp_session.stream.buf, "Content-Length");
    char line[64];
    snprintf(line, 64, "%s", content_length);
    char *token = strtok(line, ":");
    if (token)
        http->tcp_session.stream.toread =
            atoi(token) + (http->tcp_session.stream.size - header_length);
}

// XXX Eyesore
static inline void http_parse_header(struct http_transaction *http) {
    const char *encoding =
        strstr((const char *) http->tcp_session.stream.buf, "Transfer-Encoding");
    if (encoding) {
        if (strstr((const char *) http->tcp_session.stream.buf, "chunked"))
            http->encoding = CHUNKED;
        else
            http->encoding = GENERIC;
    }
    // XXX
    if (http->encoding == GENERIC || http->encoding == UNSET)
        http_parse_content_length(http);
}

/* Simple error_code to string function, to be refined */
static const char *llberr(int rc) {
    switch (rc) {
        case -ERRCLIENTDC:
            return "Client disconnected";
        case -ERRSOCKETERR:
            return strerror(errno);
        case -ERREAGAIN:
            return "Socket FD EAGAIN";
        default:
            return "Unknown error";
    }
}

/*
 * ====================================================
 *  Cron tasks, to be repeated at fixed time intervals
 * ====================================================
 */

/*
 * Checks for health status of the backends, as of now it's pretty simple, if
 * a connection go well to the target backend, we flag it alive, otherwise it's
 * flagged dead
 */
static void backends_healthcheck(struct ev_ctx *ctx, void *data) {
    (void) data;
    int fd = 0;
    for (int i = 0; i < conf->backends_nr; ++i) {
#if THREADSNR > 0
        pthread_mutex_lock(&mutex);
#endif
        fd = make_connection(server.backends[i].host, server.backends[i].port);
#if THREADSNR > 0
        pthread_mutex_unlock(&mutex);
#endif
        if (fd < 0) {
            server.backends[i].alive = false;
        } else {
            server.backends[i].alive = true;
            close(fd);
        }
    }
}

/*
 * ======================================================
 *  Private functions and callbacks for server behaviour
 * ======================================================
 */

/*
 * All tcp sessions are pre-allocated at the start of the server, their content
 * have to be initialized at each connection only if not already initialized by
 * previous used connections, e.g. after a re-use of an already employed
 * connection
 */
static void tcp_session_init(struct tcp_session *tcp) {
    tcp->status = WAITING_REQUEST;
    tcp->stream.size = 0;
    tcp->stream.toread = 0;
    tcp->stream.capacity = MAX_HTTP_TRANSACTION_SIZE;
    if (!tcp->stream.buf)
        tcp->stream.buf =
            llb_calloc(MAX_HTTP_TRANSACTION_SIZE, sizeof(unsigned char));
}

/*
 * To promote tcp session re-usage and avoid to having re-allocate all buffers
 * each time a new client connects, we just "deactivate" the session and return
 * it to the server memory pool
 */
static void tcp_session_close(struct tcp_session *tcp) {
    tcp->stream.size = 0;
    tcp->stream.toread = 0;
    tcp->status = WAITING_REQUEST;
    ev_del_fd(tcp->ctx, tcp->pipe[CLIENT].fd);
    ev_del_fd(tcp->ctx, tcp->pipe[BACKEND].fd);
    close_connection(&tcp->pipe[CLIENT]);
    close_connection(&tcp->pipe[BACKEND]);
    memset(tcp->stream.buf, 0x00, tcp->stream.capacity);
    server.backends[tcp->backend_idx].active_connections--;
    if (conf->mode == LLB_TCP_MODE) {
#if THREADSNR > 0
        pthread_mutex_lock(&mutex);
#endif
        memorypool_free(server.pool, tcp);
#if THREADSNR > 0
        pthread_mutex_unlock(&mutex);
#endif
    }
}

/*
 * All transactions are pre-allocated at the start of the server, but their buffer
 * (read and write) is not, they're lazily allocated with this function, meant
 * to be called on the accept callback
 */
static void http_transaction_init(struct http_transaction *http) {
    http->encoding = UNSET;
    tcp_session_init(&http->tcp_session);
}

/*
 * As we really don't want to completely de-allocate an HTTP transaction in
 * favor of making it reusable by another connection we simply deactivate it
 * according to its state (e.g. if it's a clean_session connected client or
 * not) and we allow the http memory pool to reclaim it
 */
static void http_transaction_close(struct http_transaction *http) {
    http->encoding = UNSET;
    tcp_session_close(&http->tcp_session);
#if THREADSNR > 0
    pthread_mutex_lock(&mutex);
#endif
    memorypool_free(server.pool, http);
#if THREADSNR > 0
    pthread_mutex_unlock(&mutex);
#endif
}

/*
 * Read a stream of bytes into the stream of an http_transaction. Based on the
 * state of the transaction, be it a request from a client or a response from a
 * backend, it calls read on the right descriptor (or side of the pipe member).
 *
 * This function accept a socket fd, a buffer to read incoming streams of
 * bytes all in a pointer to an http_transaction structure.
 *
 * - http: A struct http_transaction pointer, contains the connection structure
 *         with the of the requesting client as well as his SSL context in case
 *         of TLS communication. Also it store the reading buffer to be used for
 *         incoming byte-streams.
 */
static inline int tcp_session_read(struct tcp_session *tcp) {

    ssize_t nread = 0;

    /*
     * Last status, we have access to the length of the packet and we know for
     * sure that it's not a PINGREQ/PINGRESP/DISCONNECT packet.
     */
    if (tcp->status == WAITING_REQUEST)
        nread = recv_data(&tcp->pipe[CLIENT], &tcp->stream);
    else if (tcp->status == WAITING_RESPONSE)
        nread = recv_data(&tcp->pipe[BACKEND], &tcp->stream);

    if (errno != EAGAIN && errno != EWOULDBLOCK && nread < 0)
        return -ERRSOCKETERR;
        //return nread == -1 ? -ERRSOCKETERR : -ERRCLIENTDC;

    if (conf->mode == LLB_TCP_MODE && nread == 0)
        return -ERRCLIENTDC;

    if (conf->mode == LLB_HTTP_MODE && (errno == EAGAIN || errno == EWOULDBLOCK))
        return -ERREAGAIN;

    return LLB_SUCCESS;
}

/*
 * Write stream of bytes to a client represented by a connection object, till
 * all bytes to be written is exhausted, tracked by towrite field or if an
 * EAGAIN (socket descriptor must be in non-blocking mode) error is raised,
 * meaning we cannot write anymore for the current cycle.
 */
static inline int tcp_session_write(struct tcp_session *tcp) {

    ssize_t wrote = 0;

    if (tcp->status == FORWARDING_REQUEST)
        wrote = send_data(&tcp->pipe[BACKEND], &tcp->stream);
    else if (tcp->status == FORWARDING_RESPONSE)
        wrote = send_data(&tcp->pipe[CLIENT], &tcp->stream);

    if (errno != EAGAIN && errno != EWOULDBLOCK && wrote < 0)
        goto clientdc;

    //if (errno == EAGAIN || errno == EWOULDBLOCK)
    //    return -ERREAGAIN;

    return LLB_SUCCESS;

clientdc:

    return -ERRSOCKETERR;
}

/*
 * ===========
 *  Callbacks
 * ===========
 */

static void tcp_write_callback(struct ev_ctx *ctx, void *arg) {
    struct tcp_session *tcp = arg;
    int err = tcp_session_write(tcp);
    switch (err) {
        case LLB_SUCCESS: // OK
            /*
             * Rearm descriptor making it ready to receive input,
             * read_callback will be the callback to be used; also reset the
             * read buffer status for the client.
             */
            // reset the pointer to the beginning of the buffer
            tcp->stream.size = 0;
            if (tcp->status == FORWARDING_REQUEST) {
                tcp->status = WAITING_RESPONSE;
            } else if (tcp->status == FORWARDING_RESPONSE) {
                tcp->status = WAITING_REQUEST;
            }
            enqueue_tcp_read(tcp);
            break;
        case -ERREAGAIN:
            enqueue_tcp_write(tcp);
            break;
        default:
            tcp_session_close(tcp);
            break;
    }
}

/*
 * Callback dedicated to client replies, try to send as much data as possible
 * epmtying the client buffer and rearming the socket descriptor for reading
 * after
 */
static void http_write_callback(struct ev_ctx *ctx, void *arg) {
    struct http_transaction *http = arg;
    int err = tcp_session_write(&http->tcp_session);
    switch (err) {
        case LLB_SUCCESS: // OK
            /*
             * Rearm descriptor making it ready to receive input,
             * read_callback will be the callback to be used; also reset the
             * read buffer status for the client.
             */
            if (http->tcp_session.status == FORWARDING_REQUEST) {
                http->tcp_session.status = WAITING_RESPONSE;
                // reset the pointer to the beginning of the buffer
                http->tcp_session.stream.size = 0;
                enqueue_http_read(http);
            } else if (http->tcp_session.status == FORWARDING_RESPONSE) {
                http_transaction_close(http);
            }
            break;
        case -ERREAGAIN:
            enqueue_http_write(http);
            break;
        default:
            http_transaction_close(http);
            break;
    }
}

/*
 * Handle incoming connections, create a a fresh new struct client structure
 * and link it to the fd, ready to be set in EV_READ event, then schedule a
 * call to the read_callback to handle incoming streams of bytes
 */
static void accept_callback(struct ev_ctx *ctx, void *data) {
    int serverfd = *((int *) data);
    while (1) {

        /*
         * Accept a new incoming connection assigning ip address
         * and socket descriptor to the connection structure
         * pointer passed as argument
         */
        struct connection conn;
        connection_init(&conn, conf->tls ? server.ssl_ctx : NULL);
        int fd = accept_connection(&conn, serverfd);
        if (fd == 0)
            continue;
        if (fd < 0) {
            close_connection(&conn);
            break;
        }

        /*
         * Create a connection structure to handle the client context of the
         * communication channel.
         */
        if (conf->mode == LLB_HTTP_MODE) {
#if THREADSNR > 0
            pthread_mutex_lock(&mutex);
#endif
            struct http_transaction *http = memorypool_alloc(server.pool);
#if THREADSNR > 0
            pthread_mutex_unlock(&mutex);
#endif
            http->tcp_session.pipe[CLIENT] = conn;
            http_transaction_init(http);
            http->tcp_session.ctx = ctx;

            /* Add it to the epoll loop */
            ev_register_event(ctx, fd, EV_READ, http_read_callback, http);
        } else  {
#if THREADSNR > 0
            pthread_mutex_lock(&mutex);
#endif
            struct tcp_session *tcp = memorypool_alloc(server.pool);
#if THREADSNR > 0
            pthread_mutex_unlock(&mutex);
#endif
            tcp->pipe[CLIENT] = conn;
            tcp_session_init(tcp);
            tcp->ctx = ctx;

            /* Connect to a backend and set to read events for incoming data */
            route_tcp_to_backend(ctx, tcp);
        }
    }
}

static void tcp_read_callback(struct ev_ctx *ctx, void *data) {
    struct tcp_session *tcp = data;
    /*
     * Received a bunch of data from a client,  we need to read the bytes and
     * encoding the content according to the protocol
     */
    int rc = tcp_session_read(tcp);
    switch (rc) {
        case LLB_SUCCESS:
            /*
             * All is ok, process the incoming request/response based on the
             * state of the transaction, in fact we need to forward the request
             * to a backend if in WAITING_RESPONSE state or we need to forward
             * the response back to the requesting client otherwise
             * (WAITING_RESPONSE state)
             */
            switch (tcp->status) {
                case WAITING_REQUEST:
                    tcp->status = FORWARDING_REQUEST;
                    break;
                case WAITING_RESPONSE:
                    tcp->status = FORWARDING_RESPONSE;
                    break;
            }
            enqueue_tcp_write(tcp);
            break;
        case -ERRCLIENTDC:
        case -ERRSOCKETERR:
            /*
             * We got an unexpected error or a disconnection from the
             * client side, close the connection and free the resources
             */
            log_error("Closing connection with %s -> %s: %s",
                      tcp->pipe[CLIENT].ip, tcp->pipe[BACKEND].ip, llberr(rc));
            tcp_session_close(tcp);
            break;
        case -ERREAGAIN:
            // TODO, check for content-length in case of non-chunked mode
            /*
             * We read all we could from the last read call, it's not certain
             * that all data is read, especially in chunked mode, so we proceed
             * processing the payload only when we're sure we finished reading
             * which happens in two cases:
             * - chunked response: the last chunk ends with a 0 length mini-header
             *   followed by 2 CRLF like "0\r\n\r\n"
             * - non-chunked response: a content-length header should be present
             *   stating the expected length of the transmission
             */
            enqueue_tcp_read(tcp);
            break;
    }
}

/*
 * Reading packet callback, it's the main function that will be called every
 * time a connected client has some data to be read, notified by the eventloop
 * context.
 */
static void http_read_callback(struct ev_ctx *ctx, void *data) {
    struct http_transaction *http = data;
    /*
     * Received a bunch of data from a client,  we need to read the bytes and
     * encoding the content according to the protocol
     */
    int rc = tcp_session_read(&http->tcp_session);
    switch (rc) {
        case LLB_SUCCESS:
            /*
             * All is ok, process the incoming request/response based on the
             * state of the transaction, in fact we need to forward the request
             * to a backend if in WAITING_RESPONSE state or we need to forward
             * the response back to the requesting client otherwise
             * (WAITING_RESPONSE state)
             */
            PROCESS_HTTP_STREAM(http);
            break;
        case -ERRCLIENTDC:
        case -ERRSOCKETERR:
            /*
             * We got an unexpected error or a disconnection from the
             * client side, close the connection and free the resources
             */
            log_error("Closing connection with %s -> %s: %s",
                      http->tcp_session.pipe[CLIENT].ip,
                      http->tcp_session.pipe[BACKEND].ip, llberr(rc));
            http_transaction_close(http);
            break;
        case -ERREAGAIN:
            // TODO, check for content-length in case of non-chunked mode
            /*
             * We read all we could from the last read call, it's not certain
             * that all data is read, especially in chunked mode, so we proceed
             * processing the payload only when we're sure we finished reading
             * which happens in two cases:
             * - chunked response: the last chunk ends with a 0 length mini-header
             *   followed by 2 CRLF like "0\r\n\r\n"
             * - non-chunked response: a content-length header should be present
             *   stating the expected length of the transmission
             */
            if (http->encoding == UNSET)
                http_parse_header(http);
            if (http->encoding != CHUNKED) {
                PROCESS_HTTP_STREAM(http);
            } else {
                if (CHUNKED_COMPLETE(&http->tcp_session))
                    PROCESS_HTTP_STREAM(http)
                else
                    enqueue_http_read(http);
            }
            break;
    }
}

/*
 * Select a backend to route the traffic towards, the selection occurs based on
 * the balancing algorithm available, currently llb supports the following
 * balancing algorithm:
 *
 * - Round robin
 * - Random
 * - Hash
 * - Leastconn
 * - Weighted round robin
 */
static int select_backend(struct backend **backend_ptr, const char *buf) {
    struct backend *backend = NULL;
    volatile atomic_int next = ATOMIC_VAR_INIT(0);
    char *ptr = NULL;
    switch (conf->load_balancing) {
        case ROUND_ROBIN:
            /*
             * 1. ROUND ROBIN balancing, just modulo the total number of backends to
             * obtain the index of the backend, iterate over and over in case of dead
             * endpoints
             */
            while (!backend || backend->alive == false) {
                next = server.current_backend++ % conf->backends_nr;
                backend = &server.backends[next];
            }
            break;
        case HASH_BALANCING:
            /*
             * 2. HASH BALANCING, uses a hash function to obtain a value from the
             * entire request and modulo the total number of the backends to select a
             * backend. Try hashing different parts of the request in case of dead
             * endpoints selected
             */
            ptr = (char *) buf;
            while (!backend || backend->alive == false) {
                // FIXME dumb heuristic
                next = djb_hash(ptr + next) % conf->backends_nr;
                backend = &server.backends[next];
            }
            break;
        case RANDOM_BALANCING:
            /*
             * 3. RANDOM BALANCING, just distribute the traffic in random manner
             * between all alive backends, it's the dumbest heuristic, can work as
             * well as the ROUND ROBIN one when all the backends servers have
             * similar specs
             */
            while (!backend || backend->alive == false) {
                next = RANDOM(0, conf->backends_nr);
                backend = &server.backends[next];
            }
            break;
        case LEASTCONN:
            /*
             * 4. LEASTCONN, iterate through all backends and choose the one
             * with lower active connections. Not very useful when the majority
             * of the traffic consists of short-lived connections, still makes
             * sense for future TCP improvements of the load-balancer
             */
            while (!backend || backend->alive == false) {
                int min = INT_MAX, curr_min = INT_MAX;
                /*
                 * We just iterate linearly through the entire backends array
                 * as the number of backends shouldn't grow that large to
                 * justify an efficient data-structure to sort out the backends
                 * based on active connections
                 */
                for (int i = 0; i < conf->backends_nr; ++i) {
                    if (min > curr_min) {
                        min = curr_min;
                        next = i;
                    }
                    if (curr_min > server.backends[i].active_connections)
                        curr_min = server.backends[i].active_connections;
                }
                backend = &server.backends[next];
            }
            break;
        case WEIGHTED_ROUND_ROBIN:
            /*
             * 5. WEIGHTED ROUND ROBIN, like the round robin selection but each
             * backend has a weight value that defines the priority in
             * receiving work (e.g. maybe some machines have better hw specs
             * and thus can handle heavier loads -> higher weight value)
             */
            while (!backend || backend->alive == false) {
                next = ATOMIC_VAR_INIT(server.current_backend);
                while (1) {
                    next = (next + 1) % conf->backends_nr;
                    server.current_backend = ATOMIC_VAR_INIT(next);
                    if (next == 0) {
                        server.current_weight -= server.gcd;
                        if (server.current_weight <= 0) {
                            // get the max weight
                            int max = 0;
                            for (int i = 0; i < conf->backends_nr; ++i) {
                                if (server.backends[i].weight > max)
                                    max = server.backends[i].weight;
                            }
                            server.current_weight = max;
                            if (server.current_weight == 0) {
                                backend = &server.backends[next];
                                break;
                            }
                        }
                    }
                    if (server.backends[next].weight >= server.current_weight) {
                        backend = &server.backends[next];
                        break;
                    }
                }
            }
            break;
        default:
            log_error("Unknown balancing algorithm");
            exit(EXIT_FAILURE);
    }
    *backend_ptr = backend;
    return next;
}

static void route_tcp_to_backend(struct ev_ctx *ctx, struct tcp_session *tcp) {
    struct backend *backend = NULL;
    volatile int next = select_backend(&backend, (const char *) tcp->stream.buf);
    /*
     * Create a connection structure to handle the client context of the
     * backend new communication channel.
     */
    connection_init(&tcp->pipe[BACKEND], conf->tls ? server.ssl_ctx : NULL);
#if THREADSNR > 0
    pthread_mutex_lock(&mutex);
#endif
    int fd = open_connection(&tcp->pipe[BACKEND], backend->host, backend->port);
#if THREADSNR > 0
    pthread_mutex_unlock(&mutex);
#endif
    if (fd == 0)
        return;
    if (fd < 0) {
        close_connection(&tcp->pipe[BACKEND]);
        return;
    }

    backend->active_connections++;
    tcp->status = WAITING_REQUEST;
    tcp->backend_idx = next;

    /* Add it to the epoll loop */
    ev_register_event(ctx, tcp->pipe[CLIENT].fd, EV_READ, tcp_read_callback, tcp);
    ev_register_event(ctx, fd, EV_READ, tcp_read_callback, tcp);
}

/*
 * This function is called only if the client has sent a full stream of bytes
 * consisting of a complete HTTP header and body.
 * According to the selected load-balancing algorithm specified in the
 * configuration, it chooses a backend to connect to and redirects the request
 * toward it by registering the newly connected descriptor to the event-loop
 * with the write callback.
 * Current algorithms supported are round-robin and hash-based routing.
 */
static void process_http_request(struct ev_ctx *ctx,
                                 struct http_transaction *http) {
    struct backend *backend = NULL;
    volatile int next =
        select_backend(&backend, (const char *) http->tcp_session.stream.buf);
    /*
     * Create a connection structure to handle the client context of the
     * backend new communication channel.
     */
    connection_init(&http->tcp_session.pipe[BACKEND],
                    conf->tls ? server.ssl_ctx : NULL);
#if THREADSNR > 0
        pthread_mutex_lock(&mutex);
#endif
    int fd = open_connection(&http->tcp_session.pipe[BACKEND],
                             backend->host, backend->port);
#if THREADSNR > 0
        pthread_mutex_unlock(&mutex);
#endif
    if (fd == 0)
        return;
    if (fd < 0) {
        close_connection(&http->tcp_session.pipe[BACKEND]);
        return;
    }

    backend->active_connections++;
    http->tcp_session.backend_idx = next;
    http->tcp_session.status = FORWARDING_REQUEST;

    /* Add it to the epoll loop */
    ev_register_event(ctx, fd, EV_WRITE, http_write_callback, http);
}

/*
 * The response received back from a backend, meant to be returned to the
 * requesting client, so just schedule a write back to the client
 */
static void process_http_response(struct ev_ctx *ctx,
                                  struct http_transaction *http) {
    http->tcp_session.status = FORWARDING_RESPONSE;
    enqueue_http_write(http);
}

/*
 * Eventloop stop callback, will be triggered by an EV_CLOSEFD event and stop
 * the running loop, unblocking the call.
 */
static void stop_handler(struct ev_ctx *ctx, void *arg) {
    (void) arg;
    ev_stop(ctx);
}

/*
 * Entry point function for the event loop, register all the frontends
 * descriptors for the ACCEPT callback, the event_fd member of the global
 * configuration to gracefull close each loop and only in *one thread* register
 * the healthcheck routine to be called once every second.
 */
static void eventloop_start(void *args) {
    struct listen_payload *loop_data = args;
    struct ev_ctx ctx;
    int *fds = loop_data->fds;
    ev_init(&ctx, EVENTLOOP_MAX_EVENTS);
    // Register stop event
#ifdef __linux__
    ev_register_event(&ctx, conf->run, EV_CLOSEFD|EV_READ, stop_handler, NULL);
#else
    ev_register_event(&ctx, conf->run[1], EV_CLOSEFD|EV_READ, stop_handler, NULL);
#endif
    // Register frontends listening FDs with accept callback
    for (int i = 0; i < loop_data->frontends_nr; ++i)
        ev_register_event(&ctx, fds[i], EV_READ, accept_callback, &fds[i]);
    // Register periodic tasks
    if (loop_data->cronjobs == true)
        ev_register_cron(&ctx, backends_healthcheck, NULL, 1, 0);
    // Start the loop, blocking call
    ev_run(&ctx);
    ev_destroy(&ctx);
}

/*
 * LLB_HTTP_MODE helper
 *
 * Fire a read callback to react accordingly to the descriptor ready to be read,
 * calling the HTTP read callback
 */
static void enqueue_http_read(const struct http_transaction *http) {
    if (http->tcp_session.status == WAITING_REQUEST)
        ev_fire_event(http->tcp_session.ctx, http->tcp_session.pipe[CLIENT].fd,
                      EV_READ, http_read_callback, (void *) http);
    else if (http->tcp_session.status == WAITING_RESPONSE)
        ev_fire_event(http->tcp_session.ctx, http->tcp_session.pipe[BACKEND].fd,
                      EV_READ, http_read_callback, (void *) http);
}

/*
 * LLB_HTTP_MODE helper
 *
 * Fire a write callback to reply after a client request, calling the HTTP write
 * callback
 */
static void enqueue_http_write(const struct http_transaction *http) {
    if (http->tcp_session.status == FORWARDING_REQUEST)
        ev_fire_event(http->tcp_session.ctx, http->tcp_session.pipe[BACKEND].fd,
                      EV_WRITE, http_write_callback, (void *) http);
    else if (http->tcp_session.status == FORWARDING_RESPONSE)
        ev_fire_event(http->tcp_session.ctx, http->tcp_session.pipe[CLIENT].fd,
                      EV_WRITE, http_write_callback, (void *) http);
}

/*
 * LLB_TCP_MODE helper
 *
 * Fire a read callback to react accordingly to the descriptor ready to be used,
 * calling the TCP read callback
 */
static void enqueue_tcp_read(const struct tcp_session *tcp) {
    if (tcp->status == WAITING_REQUEST)
        ev_fire_event(tcp->ctx, tcp->pipe[CLIENT].fd,
                      EV_READ, tcp_read_callback, (void *) tcp);
    else if (tcp->status == WAITING_RESPONSE)
        ev_fire_event(tcp->ctx, tcp->pipe[BACKEND].fd,
                      EV_READ, tcp_read_callback, (void *) tcp);
}

/*
 * LLB_TCP_MODE helper
 *
 * Fire a write callback to reply after a client request, calling the TCP write
 * callback
 */
static void enqueue_tcp_write(const struct tcp_session *tcp) {
    if (tcp->status == FORWARDING_REQUEST)
        ev_fire_event(tcp->ctx, tcp->pipe[BACKEND].fd,
                      EV_WRITE, tcp_write_callback, (void *) tcp);
    else if (tcp->status == FORWARDING_RESPONSE)
        ev_fire_event(tcp->ctx, tcp->pipe[CLIENT].fd,
                      EV_WRITE, tcp_write_callback, (void *) tcp);
}

/*
 * Helper for the WEIGHTED ROUND ROBIN algorithm, calculate the global maximum
 * divisor on an array of values (values are the weight of each backend)
 */

static inline int gcd(int a, int b) {
    if (a == 0)
        return b;
    return gcd(b % a, a);
}

static inline int GCD(int *arr, size_t size) {
    int result = arr[0];
    for (int i = 1; i < size; ++i) {
        result = gcd(arr[i], result);
        if (result == 1)
            return 1;
    }
    return result;
}

/*
 * ===================
 *  Main exposed APIs
 * ===================
 */

/*
 * Main entry point for the server, to be called with an array of frontend
 * structs and its length. Every frontend store an address and a port to start
 * listening on.
 */
int start_server(const struct frontend *frontends, int frontends_nr) {

    /* Initialize global llb instance */
    server.backends = conf->backends;
    for (int i = 0; i < conf->backends_nr; ++i)
        server.backends[i].alive = ATOMIC_VAR_INIT(true);
    server.current_backend =
        ATOMIC_VAR_INIT(conf->load_balancing == WEIGHTED_ROUND_ROBIN ? -1 : 0) ;
    server.current_weight = ATOMIC_VAR_INIT(0);
    if (conf->load_balancing == WEIGHTED_ROUND_ROBIN) {
        int weights[conf->backends_nr];
        for (int i = 0; i < conf->backends_nr; ++i)
            weights[i] = server.backends[i].weight;
        server.gcd = ATOMIC_VAR_INIT(GCD(weights, conf->backends_nr));
    }
    if (conf->mode == LLB_HTTP_MODE)
        server.pool = memorypool_new(MAX_HTTP_TRANSACTIONS,
                                     sizeof(struct http_transaction));
    else
        server.pool = memorypool_new(MAX_HTTP_TRANSACTIONS,
                                     sizeof(struct tcp_session));

    /* Setup SSL in case of flag true */
    if (conf->tls == true) {
        openssl_init();
        server.ssl_ctx = create_ssl_context();
        load_certificates(server.ssl_ctx, conf->cafile,
                          conf->certfile, conf->keyfile);
    }

    log_info("Server start");

    struct listen_payload loop_start = {
        .fds = llb_calloc(frontends_nr, sizeof(struct frontend)),
        .frontends_nr = frontends_nr,
        .cronjobs = false
    };

    /* Start frontend endpoints listening for new connections */
    for (int i = 0; i < frontends_nr; ++i)
        loop_start.fds[i] = make_listen(frontends[i].host, frontends[i].port);

#if THREADSNR > 0
    pthread_t thrs[THREADSNR];
    for (int i = 0; i < THREADSNR; ++i) {
        pthread_create(&thrs[i], NULL, (void * (*) (void *)) &eventloop_start, &loop_start);
        usleep(1500);
    }
#endif
    loop_start.cronjobs = true;
    // start eventloop, could be spread on multiple threads
    eventloop_start(&loop_start);

#if THREADSNR > 0
    for (int i = 0; i < THREADSNR; ++i)
        pthread_join(thrs[i], NULL);
#endif

    for (int i = 0; i < frontends_nr; ++i)
        close(loop_start.fds[i]);

    /* Destroy SSL context, if any present */
    if (conf->tls == true) {
        SSL_CTX_free(server.ssl_ctx);
        openssl_cleanup();
    }

    // release resources
    if (conf->mode == LLB_HTTP_MODE) {
        struct http_transaction *ptr;
        for (size_t i = 0; i < MAX_HTTP_TRANSACTIONS; ++i) {
            ptr = memorypool_advance_pointer(server.pool, i);
            if (ptr->tcp_session.stream.buf)
                llb_free(ptr->tcp_session.stream.buf);
        }
    } else {
        struct tcp_session *ptr;
        for (size_t i = 0; i < MAX_HTTP_TRANSACTIONS; ++i) {
            ptr = memorypool_advance_pointer(server.pool, i);
            if (ptr->stream.buf)
                llb_free(ptr->stream.buf);
        }
    }

    memorypool_destroy(server.pool);
    llb_free(loop_start.fds);

    log_info("llb v%s exiting", VERSION);

    return LLB_SUCCESS;
}

/*
 * Make the entire process a daemon
 */
void daemonize(void) {

    int fd;

    if (fork() != 0)
        exit(0);

    setsid();

    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}
