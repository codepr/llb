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
#include <unistd.h>
#include <string.h>
#include "ev.h"
#include "log.h"
#include "config.h"
#include "server.h"
#include "network.h"
#include "memorypool.h"
#include "llb_internal.h"

pthread_mutex_t mutex;

/*
 * Auxiliary structure to be used as init argument for eventloop, fd is the
 * listening sockets array, the same number of the frontends number, we want to
 * share between multiple instances, cronjobs is just a flag to signal if we
 * want to register cronjobs on that particular instance or not (to not repeat
 * useless cron jobs on multiple threads)
 */
struct listen_payload { int *fds; int frontends_nr; bool cronjobs; };

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
 * Right now we're using a single thread, but the whole method could be easily
 * distributed across a threadpool, by paying attention to the shared critical
 * parts on handler module.
 * The access to shared data strucures on the worker thread pool could be
 * guarded by a mutex or a spinlock, and being generally fast operations it
 * shouldn't suffer high contentions by the threads and thus being really fast.
 */

static void http_transaction_init(struct http_transaction *);

static void http_transaction_deactivate(struct http_transaction *);

// CALLBACKS for the eventloop
static void accept_callback(struct ev_ctx *, void *);

static void read_callback(struct ev_ctx *, void *);

static void write_callback(struct ev_ctx *, void *);

static void enqueue_event_read(const struct http_transaction *);

static void enqueue_event_write(const struct http_transaction *);

/*
 * Processing request function, will be applied on fully formed request
 * received on read_callback callback, requests are the one incoming from
 * connected clients toward backends
 */
static void process_request(struct ev_ctx *, struct http_transaction *);

/*
 * Processing response function, will be applied on fully formed received
 * responses on read_callback callback, responses are the one returned by
 * connected backends back to requesting clients
 */
static void process_response(struct ev_ctx *, struct http_transaction *);

/* Periodic routine to perform healthchecks on backends */
static void backends_healthcheck(struct ev_ctx *, void *);

static inline void http_parse_header(struct http_transaction *);

#define CHUNKED_COMPLETE(http) \
    strcmp((char *) (http)->stream.buf + (http)->stream.size - 5, "0\r\n\r\n") == 0

#define PROCESS_STREAM(http) do {                    \
    if ((http)->status == WAITING_REQUEST) {         \
        process_request((http)->ctx, (http));        \
    } else if ((http)->status == WAITING_RESPONSE) { \
        process_response((http)->ctx, (http));       \
    }                                                \
} while (0);

// XXX Eyesore
static inline void http_parse_header(struct http_transaction *http) {
    const char *encoding =
        strstr((const char *) http->stream.buf, "Transfer-Encoding");
    if (encoding) {
        if (strstr((const char *) http->stream.buf, "chunked"))
            http->encoding = CHUNKED;
        else
            http->encoding = GENERIC;
    }
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
        fd = make_connection(server.backends[i].host, server.backends[i].port);
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
 * All transactions are pre-allocated at the start of the server, but their buffers
 * (read and write) are not, they're lazily allocated with this function, meant
 * to be called on the accept callback
 */
static void http_transaction_init(struct http_transaction *http) {
    http->status = WAITING_REQUEST;
    http->encoding = UNSET;
    http->stream.size = 0;
    http->stream.capacity = MAX_HTTP_TRANSACTION_SIZE;
    if (!http->stream.buf)
        http->stream.buf =
            llb_calloc(MAX_HTTP_TRANSACTION_SIZE, sizeof(unsigned char));
}

/*
 * As we really don't want to completely de-allocate an HTTP transaction in
 * favor of making it reusable by another connection we simply deactivate it
 * according to its state (e.g. if it's a clean_session connected client or
 * not) and we allow the http memory pool to reclaim it
 */
static void http_transaction_deactivate(struct http_transaction *http) {
    http->stream.size = 0;
    http->encoding = UNSET;
    http->status = WAITING_REQUEST;
    ev_del_fd(http->ctx, http->pipe[CLIENT].fd);
    ev_del_fd(http->ctx, http->pipe[BACKEND].fd);
    close_connection(&http->pipe[CLIENT]);
    close_connection(&http->pipe[BACKEND]);
    memset(http->stream.buf, 0x00, http->stream.capacity);
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
static inline int http_transaction_read(struct http_transaction *http) {

    ssize_t nread = 0;

    /*
     * Last status, we have access to the length of the packet and we know for
     * sure that it's not a PINGREQ/PINGRESP/DISCONNECT packet.
     */
    if (http->status == WAITING_REQUEST)
        nread = recv_data(&http->pipe[CLIENT], &http->stream);
    else if (http->status == WAITING_RESPONSE)
        nread = recv_data(&http->pipe[BACKEND], &http->stream);

    if (errno != EAGAIN && errno != EWOULDBLOCK && nread < 0)
        return -ERRSOCKETERR;
        //return nread == -1 ? -ERRSOCKETERR : -ERRCLIENTDC;

    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return -ERREAGAIN;

    return LLB_SUCCESS;
}

/*
 * Write stream of bytes to a client represented by a connection object, till
 * all bytes to be written is exhausted, tracked by towrite field or if an
 * EAGAIN (socket descriptor must be in non-blocking mode) error is raised,
 * meaning we cannot write anymore for the current cycle.
 */
static inline int http_transaction_write(struct http_transaction *http) {

    ssize_t wrote = 0;

    if (http->status == FORWARDING_REQUEST)
        wrote = send_data(&http->pipe[BACKEND], &http->stream);
    else if (http->status == FORWARDING_RESPONSE)
        wrote = send_data(&http->pipe[CLIENT], &http->stream);

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

/*
 * Callback dedicated to client replies, try to send as much data as possible
 * epmtying the client buffer and rearming the socket descriptor for reading
 * after
 */
static void write_callback(struct ev_ctx *ctx, void *arg) {
    struct http_transaction *http = arg;
    int err = http_transaction_write(http);
    switch (err) {
        case LLB_SUCCESS: // OK
            /*
             * Rearm descriptor making it ready to receive input,
             * read_callback will be the callback to be used; also reset the
             * read buffer status for the client.
             */
            if (http->status == FORWARDING_REQUEST) {
                http->status = WAITING_RESPONSE;
                http->stream.size = 0;
                enqueue_event_read(http);
            } else if (http->status == FORWARDING_RESPONSE) {
                http_transaction_deactivate(http);
            }
            break;
        case -ERREAGAIN:
            enqueue_event_write(http);
            break;
        default:
            http_transaction_deactivate(http);
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
#if THREADSNR > 0
        pthread_mutex_lock(&mutex);
#endif
        struct http_transaction *http = memorypool_alloc(server.pool);
#if THREADSNR > 0
        pthread_mutex_unlock(&mutex);
#endif
        http->pipe[CLIENT] = conn;
        http_transaction_init(http);
        http->ctx = ctx;

        /* Add it to the epoll loop */
        ev_register_event(ctx, fd, EV_READ, read_callback, http);
    }
}

/*
 * Reading packet callback, it's the main function that will be called every
 * time a connected client has some data to be read, notified by the eventloop
 * context.
 */
static void read_callback(struct ev_ctx *ctx, void *data) {
    struct http_transaction *http = data;
    /*
     * Received a bunch of data from a client,  we need to read the bytes and
     * encoding the content according to the protocol
     */
    int rc = http_transaction_read(http);
    switch (rc) {
        case LLB_SUCCESS:
            /*
             * All is ok, process the incoming request/response based on the
             * state of the transaction, in fact we need to forward the request
             * to a backend if in WAITING_RESPONSE state or we need to forward
             * the response back to the requesting client otherwise
             * (WAITING_RESPONSE state)
             */
            PROCESS_STREAM(http);
            break;
        case -ERRCLIENTDC:
        case -ERRSOCKETERR:
            /*
             * We got an unexpected error or a disconnection from the
             * client side, close the connection and free the resources
             */
            log_error("Closing connection with %s -> %s: %s",
                      http->pipe[CLIENT].ip, http->pipe[BACKEND].ip, llberr(rc));
            http_transaction_deactivate(http);
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
                PROCESS_STREAM(http);
            } else {
                if (CHUNKED_COMPLETE(http))
                    PROCESS_STREAM(http)
                else
                    enqueue_event_read(http);
            }
            break;
    }
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
static void process_request(struct ev_ctx *ctx, struct http_transaction *http) {
    volatile atomic_int next = ATOMIC_VAR_INIT(0);
    struct backend *backend = NULL;
    if (conf->load_balancing == ROUND_ROBIN) {
        /*
         * 1. ROUND ROBIN balancing, just modulo the total number of backends to
         * obtain the index of the backend, iterate over and over in case of dead
         * endpoints
         */
        next = server.current_backend++ % conf->backends_nr;
        backend = &server.backends[next];
        while (backend->alive == false) {
            next = server.current_backend++ % conf->backends_nr;
            backend = &server.backends[next];
        }
    } else if (conf->load_balancing == HASH_BALANCING) {
        /*
         * 2. HASH BALANCING, uses a hash function to obtain a value from the
         * entire request and modulo the total number of the backends to select a
         * backend. Try hashing different parts of the request in case of dead
         * endpoints selected
         */
        size_t hash = djb_hash((const char *) http->stream.buf);
        next = hash % conf->backends_nr;
        backend = &server.backends[next];
        while (backend->alive == false) {
            // FIXME dumb heuristic
            next = djb_hash((const char *) http->stream.buf + next);
            backend = &server.backends[next];
        }
    }
    /*
     * Create a connection structure to handle the client context of the
     * backend new communication channel.
     */
    connection_init(&http->pipe[BACKEND], conf->tls ? server.ssl_ctx : NULL);
    int fd = open_connection(&http->pipe[BACKEND], backend->host, backend->port);
    if (fd == 0)
        return;
    if (fd < 0) {
        close_connection(&http->pipe[BACKEND]);
        return;
    }

    http->status = FORWARDING_REQUEST;

    /* Add it to the epoll loop */
    ev_register_event(ctx, fd, EV_WRITE, write_callback, http);
}

/*
 * The response received back from a backend, meant to be returned to the
 * requesting client, so just schedule a write back to the client
 */
static void process_response(struct ev_ctx *ctx, struct http_transaction *http) {
    http->status = FORWARDING_RESPONSE;
    enqueue_event_write(http);
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
    ev_register_event(&ctx, conf->run, EV_CLOSEFD|EV_READ, stop_handler, NULL);
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
 * ===================
 *  Main APIs exposed
 * ===================
 */

/* Fire a read callback to react accordingly to descriptor ready to be read */
static void enqueue_event_read(const struct http_transaction *http) {
    if (http->status == WAITING_REQUEST)
        ev_fire_event(http->ctx, http->pipe[CLIENT].fd,
                      EV_READ, read_callback, (void *) http);
    else if (http->status == WAITING_RESPONSE)
        ev_fire_event(http->ctx, http->pipe[BACKEND].fd,
                      EV_READ, read_callback, (void *) http);
}

/* Fire a write callback to reply after a client request */
static void enqueue_event_write(const struct http_transaction *http) {
    if (http->status == FORWARDING_REQUEST)
        ev_fire_event(http->ctx, http->pipe[BACKEND].fd,
                      EV_WRITE, write_callback, (void *) http);
    else if (http->status == FORWARDING_RESPONSE)
        ev_fire_event(http->ctx, http->pipe[CLIENT].fd,
                      EV_WRITE, write_callback, (void *) http);
}

/*
 * Main entry point for the server, to be called with an array of frontend
 * structs and its length. Every frontend store an address and a port to start
 * listening on.
 */
int start_server(const struct frontend *frontends, int frontends_nr) {

    /* Initialize global llb instance */
    server.current_backend = ATOMIC_VAR_INIT(0);
    server.pool =
        memorypool_new(MAX_HTTP_TRANSACTIONS, sizeof(struct http_transaction));
    server.backends = conf->backends;

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
