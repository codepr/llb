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
#include "npt_internal.h"

pthread_mutex_t mutex;

/*
 * Auxiliary structure to be used as init argument for eventloop, fd is the
 * listening socket we want to share between multiple instances, cronjobs is
 * just a flag to signal if we want to register cronjobs on that particular
 * instance or not (to not repeat useless cron jobs on multiple threads)
 */
struct listen_payload {
    int fd;
    bool cronjobs;
};

/* Broker global instance, contains the topic trie and the clients hashtable */
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
 *                             MAIN THREAD
 *                              [EV_CTX]
 *
 *    ACCEPT_CALLBACK         READ_CALLBACK         WRITE_CALLBACK
 *  -------------------    ------------------    --------------------
 *        |                        |                       |
 *      ACCEPT                     |                       |
 *        | ---------------------> |                       |
 *        |                  READ AND DECODE               |
 *        |                        |                       |
 *        |                        |                       |
 *        |                     PROCESS                    |
 *        |                        |                       |
 *        |                        |                       |
 *        |                        | --------------------> |
 *        |                        |                     WRITE
 *      ACCEPT                     |                       |
 *        | ---------------------> | <-------------------- |
 *        |                        |                       |
 *
 * Right now we're using a single thread, but the whole method could be easily
 * distributed across a threadpool, by paying attention to the shared critical
 * parts on handler module.
 * The access to shared data strucures on the worker thread pool could be
 * guarded by a spinlock, and being generally fast operations it shouldn't
 * suffer high contentions by the threads and thus being really fast.
 */

static void client_init(struct client *);

static void client_deactivate(struct client *);

// CALLBACKS for the eventloop
static void accept_callback(struct ev_ctx *, void *);

static void read_callback(struct ev_ctx *, void *);

static void write_callback(struct ev_ctx *, void *);

/*
 * Processing message function, will be applied on fully formed mqtt packet
 * received on read_callback callback
 */
static void process_message(struct ev_ctx *, struct client *);

/* Simple error_code to string function, to be refined */
//static const char *npterr(int rc) {
//    switch (rc) {
//        case -ERRCLIENTDC:
//            return "Client disconnected";
//        case -ERRSOCKETERR:
//            return strerror(errno);
//        case -ERRPACKETERR:
//            return "Error reading packet";
//        case -ERRMAXREQSIZE:
//            return "Packet sent exceeds max size accepted";
//        case -ERREAGAIN:
//            return "Socket FD EAGAIN";
//        default:
//            return "Unknown error";
//    }
//}

/*
 * ====================================================
 *  Cron tasks, to be repeated at fixed time intervals
 * ====================================================
 */

/*
 * ======================================================
 *  Private functions and callbacks for server behaviour
 * ======================================================
 */

/*
 * All clients are pre-allocated at the start of the server, but their buffers
 * (read and write) are not, they're lazily allocated with this function, meant
 * to be called on the accept callback
 */
static void client_init(struct client *client) {
    client->status = WAITING_DATA;
    client->stream.size = 0;
    client->stream.capacity = 2048;
    if (!client->stream.buf)
        client->stream.buf = npt_calloc(2048, sizeof(unsigned char));
    client->last_seen = time(NULL);
    pthread_mutex_init(&client->mutex, NULL);
}

/*
 * As we really don't want to completely de-allocate a client in favor of
 * making it reusable by another connection we simply deactivate it according
 * to its state (e.g. if it's a clean_session connected client or not) and we
 * allow the clients memory pool to reclaim it
 */
static void client_deactivate(struct client *client) {

#if THREADSNR > 0
    pthread_mutex_lock(&client->mutex);
#endif

    client->stream.size = 0;
    close_connection(&client->conn);
    HASH_DEL(server.clients, client);
    memorypool_free(server.pool, client);

#if THREADSNR > 0
    pthread_mutex_unlock(&client->mutex);
    pthread_mutex_destroy(&client->mutex);
#endif
}

/*
 * Parse packet header, it is required at least the Fixed Header of each
 * packed, which is contained in the first 2 bytes in order to read packet
 * type and total length that we need to recv to complete the packet.
 *
 * This function accept a socket fd, a buffer to read incoming streams of
 * bytes and a pointer to the decoded fixed header that will be set in the
 * final parsed packet.
 *
 * - c: A struct client pointer, contains the FD of the requesting client
 *      as well as his SSL context in case of TLS communication. Also it store
 *      the reading buffer to be used for incoming byte-streams, tracking
 *      read, to be read and reading position taking into account the bytes
 *      required to encode the packet length.
 */
static inline ssize_t client_read(struct client *c) {

    ssize_t nread = 0;

    /*
     * Last status, we have access to the length of the packet and we know for
     * sure that it's not a PINGREQ/PINGRESP/DISCONNECT packet.
     */
    nread = recv_data(&c->conn, &c->stream);

    if (errno != EAGAIN && errno != EWOULDBLOCK && nread <= 0)
        return nread == -1 ? -ERRSOCKETERR : -ERRCLIENTDC;

    //if (errno == EAGAIN && c->read < c->toread)
    //    return -ERREAGAIN;

//exit:

    return NPT_SUCCESS;
}

/*
 * Write stream of bytes to a client represented by a connection object, till
 * all bytes to be written is exhausted, tracked by towrite field or if an
 * EAGAIN (socket descriptor must be in non-blocking mode) error is raised,
 * meaning we cannot write anymore for the current cycle.
 */
static inline int client_write(struct client *c) {
#if THREADSNR > 0
    pthread_mutex_lock(&c->mutex);
#endif
    ssize_t wrote = send_data(&c->conn, &c->stream);
    if (errno != EAGAIN && errno != EWOULDBLOCK && wrote < 0)
        goto clientdc;
#if THREADSNR > 0
    pthread_mutex_unlock(&c->mutex);
#endif
    return NPT_SUCCESS;

clientdc:
#if THREADSNR > 0
    pthread_mutex_unlock(&c->mutex);
#endif
    return -ERRSOCKETERR;

//eagain:
#if THREADSNR > 0
    pthread_mutex_unlock(&c->mutex);
#endif
    return -ERREAGAIN;
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
    struct client *client = arg;
    int err = client_write(client);
    switch (err) {
        case NPT_SUCCESS: // OK
            /*
             * Rearm descriptor making it ready to receive input,
             * read_callback will be the callback to be used; also reset the
             * read buffer status for the client.
             */
            client->status = WAITING_DATA;
            ev_fire_event(ctx, client->conn.fd, EV_READ, read_callback, client);
            break;
        case -ERREAGAIN:
            enqueue_event_write(client);
            break;
        default:
            //log_info("Closing connection with %s: %s %i",
            //         client->conn.ip, npterr(client->rc), err);
            ev_del_fd(ctx, client->conn.fd);
            client_deactivate(client);
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
         * Create a client structure to handle his context
         * connection
         */
#if THREADSNR > 0
        pthread_mutex_lock(&mutex);
#endif
        struct client *c = memorypool_alloc(server.pool);
#if THREADSNR > 0
        pthread_mutex_unlock(&mutex);
#endif
        c->conn = conn;
        client_init(c);
        c->ctx = ctx;

        /* Add it to the epoll loop */
        ev_register_event(ctx, fd, EV_READ, read_callback, c);

        log_info("[%p] Connection from %s", (void *) pthread_self(), conn.ip);
    }
}

/*
 * Reading packet callback, it's the main function that will be called every
 * time a connected client has some data to be read, notified by the eventloop
 * context.
 */
static void read_callback(struct ev_ctx *ctx, void *data) {
    struct client *c = data;
    if (c->status == SENDING_DATA)
        return;
    /*
     * Received a bunch of data from a client, after the creation
     * of an IO event we need to read the bytes and encoding the
     * content according to the protocol
     */
    int rc = client_read(c);
    switch (rc) {
        case NPT_SUCCESS:
            /*
             * All is ok, raise an event to the worker poll EPOLL and
             * link it with the IO event containing the decode payload
             * ready to be processed
             */
            /* Record last action as of now */
            c->last_seen = time(NULL);
            c->status = SENDING_DATA;
            process_message(ctx, c);
            break;
        case -ERRCLIENTDC:
        case -ERRSOCKETERR:
        case -ERRPACKETERR:
        case -ERRMAXREQSIZE:
            /*
             * We got an unexpected error or a disconnection from the
             * client side, remove client from the global map and
             * free resources allocated such as io_event structure and
             * paired payload
             */
//            log_error("Closing connection with %s (%s): %s",
//                      c->client_id, c->conn.ip, npterr(rc));
#if THREADSNR > 0
            pthread_mutex_lock(&mutex);
#endif
            // Clean resources
            ev_del_fd(ctx, c->conn.fd);

#if THREADSNR > 0
            pthread_mutex_unlock(&mutex);
#endif
            client_deactivate(c);
            break;
        case -ERREAGAIN:
            ev_fire_event(ctx, c->conn.fd, EV_READ, read_callback, c);
            break;
    }
}

/*
 * This function is called only if the client has sent a full stream of bytes
 * consisting of a complete packet as expected by the MQTT protocol and by the
 * declared length of the packet.
 * It uses eventloop APIs to react accordingly to the packet type received,
 * validating it before proceed to call handlers. Depending on the handler
 * called and its outcome, it'll enqueue an event to write a reply or just
 * reset the client state to allow reading some more packets.
 */
static void process_message(struct ev_ctx *ctx, struct client *c) {
    log_debug("Processing");
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
 * IO worker function, wait for events on a dedicated epoll descriptor which
 * is shared among multiple threads for input and output only, following the
 * normal EPOLL semantic, EPOLLIN for incoming bytes to be unpacked and
 * processed by a worker thread, EPOLLOUT for bytes incoming from a worker
 * thread, ready to be delivered out.
 */
static void eventloop_start(void *args) {
    struct listen_payload *loop_data = args;
    struct ev_ctx ctx;
    int sfd = loop_data->fd;
    ev_init(&ctx, EVENTLOOP_MAX_EVENTS);
    // Register stop event
    ev_register_event(&ctx, conf->run, EV_CLOSEFD|EV_READ, stop_handler, NULL);
    // Register listening FD with accept callback
    ev_register_event(&ctx, sfd, EV_READ, accept_callback, &sfd);
    // Register periodic tasks
    //if (loop_data->cronjobs == true) {
    //    ev_register_cron(&ctx, publish_stats, NULL, conf->stats_pub_interval, 0);
    //    ev_register_cron(&ctx, inflight_msg_check, NULL, 1, 0);
    //    ev_register_cron(&ctx, persist_session, NULL, 1, 0);
    //}
    // Start the loop, blocking call
    ev_run(&ctx);
    ev_destroy(&ctx);
}

/*
 * ===================
 *  Main APIs exposed
 * ===================
 */

/* Fire a write callback to reply after a client request */
void enqueue_event_write(const struct client *c) {
    ev_fire_event(c->ctx, c->conn.fd, EV_WRITE, write_callback, (void *) c);
}

/*
 * Main entry point for the server, to be called with an address and a port
 * to start listening
 */
int start_server(const char *addr, const char *port) {

    /* Initialize global Npt instance */
    server.pool = memorypool_new(BASE_CLIENTS_NUM, sizeof(struct client));
    server.clients = NULL;
    pthread_mutex_init(&mutex, NULL);

    /* Start listening for new connections */
    int sfd = make_listen(addr, port);

    /* Setup SSL in case of flag true */
    if (conf->tls == true) {
        openssl_init();
        server.ssl_ctx = create_ssl_context();
        load_certificates(server.ssl_ctx, conf->cafile,
                          conf->certfile, conf->keyfile);
    }

    log_info("Server start");

    struct listen_payload loop_start = { sfd, false };

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

    close(sfd);

    /* Destroy SSL context, if any present */
    if (conf->tls == true) {
        SSL_CTX_free(server.ssl_ctx);
        openssl_cleanup();
    }
    pthread_mutex_destroy(&mutex);

    log_info("Npt v%s exiting", VERSION);

    return NPT_SUCCESS;
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
