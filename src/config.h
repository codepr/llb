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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdbool.h>
#include "uthash.h"

// Eventloop backend check
#ifdef __linux__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 44)
#define EPOLL 1
#define EVENTLOOP_BACKEND "epoll"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 1, 23)
#define POLL 1
#define EVENTLOOP_BACKEND "poll"
#else
#define SELECT 1
#define EVENTLOOP_BACKEND "select"
#endif
/*
#elif (defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)) \
    || defined(__FreeBSD__) || defined(__OpenBSD__) || defined (__NetBSD__)
#define KQUEUE 1
#define EVENTLOOP_BACKEND "kqueue"
*/
#endif // __linux__

// TLS versions

#define NPT_TLSv1       0x01
#define NPT_TLSv1_1     0x02
#define NPT_TLSv1_2     0x04
#define NPT_TLSv1_3     0x08

// Default parameters

#define VERSION                     "0.17.0"
#define DEFAULT_LOG_LEVEL           DEBUG
#define DEFAULT_CONF_PATH           "/etc/npt/npt.conf"
#define DEFAULT_HOSTNAME            "127.0.0.1"
#define DEFAULT_PORT                "8789"
#define DEFAULT_MAX_MEMORY          "2GB"
#define DEFAULT_MAX_REQUEST_SIZE    "512KB"
#define DEFAULT_STATS_INTERVAL      "10s"
#define DEFAULT_KEEPALIVE           "60s"
#ifdef TLS1_3_VERSION
#define DEFAULT_TLS_PROTOCOLS       (NPT_TLSv1_2 | NPT_TLSv1_3)
#else
#define DEFAULT_TLS_PROTOCOLS       NPT_TLSv1_2
#endif

#define STREQ(s1, s2, len) strncasecmp(s1, s2, len) == 0 ? true : false

struct config {
    /* NPT version <MAJOR.MINOR.PATCH> */
    const char *version;
    /* Eventfd to break the epoll_wait loop in case of signals */
    int run;
    /* Logging level, to be set by reading configuration */
    int loglevel;
    /* Log file path */
    char logpath[0xFFF];
    /* Hostname to listen on */
    char hostname[0xFF];
    /* Port to open while listening, only if socket_family is INET,
     * otherwise it's ignored */
    char port[0xFF];
    /* TCP backlog size */
    int tcp_backlog;
    /* TLS flag */
    bool tls;
    /* TLS protocol version */
    int tls_protocols;
    /* Certificate authority file path */
    char cafile[0xFFF];
    /* SSL - Cert file location on filesystem */
    char certfile[0xFFF];
    /* SSL - Key file location on filesystem */
    char keyfile[0xFFF];
};

extern struct config *conf;

int parse_int(const char *);
void config_set_default(void);
void config_print(void);
int config_load(const char *);

#endif
