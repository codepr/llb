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

#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include "log.h"
#include "config.h"
#include "server.h"
#include "network.h"
#include "npt_internal.h"

/* The main configuration structure */
static struct config config;
struct config *conf;

struct llevel {
    const char *lname;
    int loglevel;
};

static const struct llevel lmap[5] = {
    {"DEBUG", DEBUG},
    {"WARNING", WARNING},
    {"ERROR", ERROR},
    {"INFO", INFORMATION},
    {"INFORMATION", INFORMATION}
};

static inline void strip_spaces(char **str) {
    if (!*str) return;
    while (isspace(**str) && **str) ++(*str);
}

/* Parse the integer part of a string, by effectively iterate through it and
   converting the numbers found */
int parse_int(const char *string) {
    int n = 0;

    while (*string && isdigit(*string)) {
        n = (n * 10) + (*string - '0');
        string++;
    }
    return n;
}

#define PARSE_CONFIG_COMMAS(token, target, type) do {           \
    type *t = (type *) (target);                                \
    char *end_token;                                            \
    size_t toklen = strlen((token));                            \
    char tmp[toklen + 1];                                       \
    snprintf(tmp, toklen + 1, "%s", (token));                   \
    char *host = strtok_r(tmp, ":", &end_token);                \
    char *port = strtok_r(NULL, ":", &end_token);               \
    snprintf(t->host, strlen(host) + 1, "%s", host);            \
    t->port = atoi(port);                                       \
} while (0);

static int parse_config_tls_protocols(char *token) {
    int protocols = 0;
    if (STREQ(token, "tlsv1_1", 7) == true)
        protocols |= NPT_TLSv1_1;
    else if (STREQ(token, "tlsv1_2", 7) == true)
        protocols |= NPT_TLSv1_2;
    else if (STREQ(token, "tlsv1_3", 7) == true)
        protocols |= NPT_TLSv1_3;
    else if (STREQ(token, "tlsv1", 5) == true)
        protocols |= NPT_TLSv1;
    return protocols;
}

/* Set configuration values based on what is read from the persistent
   configuration on disk */
static void add_config_value(const char *key, const char *value) {

    size_t klen = strlen(key);
    size_t vlen = strlen(value);

    if (STREQ("log_level", key, klen) == true) {
        for (int i = 0; i < 3; i++) {
            if (STREQ(lmap[i].lname, value, vlen) == true)
                config.loglevel = lmap[i].loglevel;
        }
    } else if (STREQ("log_path", key, klen) == true) {
        strcpy(config.logpath, value);
    } else if (STREQ("frontends", key, klen) == true) {
        if (vlen == 0) return;
        char *end_str;
        char *token = strtok_r((char *) value, ",", &end_str);
        if (!token) {
            PARSE_CONFIG_COMMAS((char *) value,
                                &config.frontends[config.frontends_nr],
                                struct frontend);
        } else {
            do {
                if (config.frontends_nr >= config.max_frontends_nr) {
                    config.max_frontends_nr *= 2;
                    config.frontends =
                        npt_realloc(config.frontends,
                                    config.max_frontends_nr * sizeof(struct frontend));
                }
                PARSE_CONFIG_COMMAS(token, &config.frontends[config.frontends_nr++],
                                    struct frontend);
            } while ((token = strtok_r(NULL, ",", &end_str)));
        }
    } else if (STREQ("backends", key, klen) == true) {
        if (vlen == 0) return;
        char *end_str;
        char *token = strtok_r((char *) value, ",", &end_str);
        if (!token) {
            PARSE_CONFIG_COMMAS((char *) value,
                                &config.backends[config.backends_nr],
                                struct backend);
        } else {
            do {
                if (config.backends_nr >= config.max_backends_nr) {
                    config.max_backends_nr *= 2;
                    config.backends =
                        npt_realloc(config.backends,
                                    config.max_backends_nr * sizeof(struct backend));
                }
                PARSE_CONFIG_COMMAS(token, &config.backends[config.backends_nr++],
                                    struct backend);
            } while ((token = strtok_r(NULL, ",", &end_str)));
        }
    } else if (STREQ("tcp_backlog", key, klen) == true) {
        int tcp_backlog = parse_int(value);
        config.tcp_backlog = tcp_backlog <= SOMAXCONN ? tcp_backlog : SOMAXCONN;
    } else if (STREQ("cafile", key, klen) == true) {
        config.tls = true;
        strcpy(config.cafile, value);
    } else if (STREQ("certfile", key, klen) == true) {
        strcpy(config.certfile, value);
    } else if (STREQ("keyfile", key, klen) == true) {
        strcpy(config.keyfile, value);
    } else if (STREQ("tls_protocols", key, klen) == true) {
        if (vlen == 0) return;
        config.tls_protocols = 0;
        char *token = strtok((char *) value, ",");
        if (!token) {
            config.tls_protocols = parse_config_tls_protocols((char *) value);
        } else {
            while (token) {
                config.tls_protocols |= parse_config_tls_protocols(token);
                token = strtok(NULL, ",");
            }
        }
    }
}

static inline void unpack_bytes(char **str, char *dest) {

    if (!str || !dest) return;

    while (!isspace(**str) && **str) *dest++ = *(*str)++;
}

/*
 * Return the 'length' of a positive number, as the number of chars it would
 * take in a string
 */
static inline int number_len(size_t number) {
    int len = 1;
    while (number) {
        len++;
        number /= 10;
    }
    return len;
}

/* Format a memory in bytes to a more human-readable form, e.g. 64b or 18Kb
 * instead of huge numbers like 130230234 bytes */
char *memory_to_string(size_t memory) {

    int numlen = 0;
    int translated_memory = 0;

    char *mstring = NULL;

    if (memory < 1024) {
        translated_memory = memory;
        numlen = number_len(translated_memory);
        // +1 for 'b' +1 for nul terminating
        mstring = npt_malloc(numlen + 1);
        snprintf(mstring, numlen + 1, "%db", translated_memory);
    } else if (memory < 1048576) {
        translated_memory = memory / 1024;
        numlen = number_len(translated_memory);
        // +2 for 'Kb' +1 for nul terminating
        mstring = npt_malloc(numlen + 2);
        snprintf(mstring, numlen + 2, "%dKb", translated_memory);
    } else if (memory < 1073741824) {
        translated_memory = memory / (1024 * 1024);
        numlen = number_len(translated_memory);
        // +2 for 'Mb' +1 for nul terminating
        mstring = npt_malloc(numlen + 2);
        snprintf(mstring, numlen + 2, "%dMb", translated_memory);
    } else {
        translated_memory = memory / (1024 * 1024 * 1024);
        numlen = number_len(translated_memory);
        // +2 for 'Gb' +1 for nul terminating
        mstring = npt_malloc(numlen + 2);
        snprintf(mstring, numlen + 2, "%dGb", translated_memory);
    }

    return mstring;
}

int config_load(const char *configpath) {

    assert(configpath);

    FILE *fh = fopen(configpath, "r");

    if (!fh) {
        log_warning("WARNING: Unable to open conf file %s", configpath);
        log_warning("To specify a config file run npt -c /path/to/conf");
        return false;
    }

    char line[0xFFF], key[0xFF], value[0xFFF];
    int linenr = 0;
    char *pline, *pkey, *pval;

    while (fgets(line, 0xFFF, fh) != NULL) {

        memset(key, 0x00, 0xFF);
        memset(value, 0x00, 0xFFF);

        linenr++;

        // Skip comments or empty lines
        if (line[0] == '#') continue;

        // Remove whitespaces if any before the key
        pline = line;
        strip_spaces(&pline);

        if (*pline == '\0') continue;

        // Read key
        pkey = key;
        unpack_bytes(&pline, pkey);

        // Remove whitespaces if any after the key and before the value
        strip_spaces(&pline);

        // Ignore eventually incomplete configuration, but notify it
        if (line[0] == '\0') {
            log_warning("WARNING: Incomplete configuration '%s' at line %d. "
                        "Fallback to default.", key, linenr);
            continue;
        }

        // Read value
        pval = value;
        unpack_bytes(&pline, pval);

        // At this point we have key -> value ready to be ingested on the
        // global configuration object
        add_config_value(key, value);
    }

    return true;
}

void config_set_default(void) {

    // Set the global pointer
    conf = &config;

    // Set default values
    config.version = VERSION;
    config.loglevel = DEFAULT_LOG_LEVEL;
    memset(config.logpath, 0x00, 0xFFF);
    config.frontends_nr = 0;
    config.max_frontends_nr = 2;
    config.backends_nr = 0;
    config.max_backends_nr = 2;
    config.frontends = npt_calloc(config.max_frontends_nr, sizeof(struct frontend));
    config.backends = npt_calloc(config.max_backends_nr, sizeof(struct backend));
    strcpy(config.frontends[0].host, DEFAULT_HOSTNAME);
    config.frontends[0].port = DEFAULT_PORT;
    config.run = eventfd(0, EFD_NONBLOCK);
    config.tcp_backlog = SOMAXCONN;
    config.tls = false;
    config.tls_protocols = DEFAULT_TLS_PROTOCOLS;
}

void config_print_tls_versions(void) {
    char protocols[64] = {0};
    int pos = 0;
    if (config.tls_protocols & NPT_TLSv1) {
        strncpy(protocols, "TLSv1, ", 64);
        pos += 7;
    }
    if (config.tls_protocols & NPT_TLSv1_1) {
        strncpy(protocols + pos, "TLSv1_1, ", 64 - pos);
        pos += 9;
    }
    if (config.tls_protocols & NPT_TLSv1_2) {
        strncpy(protocols + pos, "TLSv1_2, ", 64 - pos);
        pos += 9;
    }
    if (config.tls_protocols & NPT_TLSv1_3) {
        strncpy(protocols + pos, "TLSv1_3, ", 64 - pos);
        pos += 9;
    }
    protocols[pos - 2] = '\0';
    log_info("\tTLS: %s", protocols);
}

void config_print(void) {
    const char *llevel = NULL;
    for (int i = 0; i < 4; i++) {
        if (lmap[i].loglevel == config.loglevel)
            llevel = lmap[i].lname;
    }
    log_info("Npt v%s is starting", VERSION);
    log_info("Network settings:");
    log_info("\tFrontends:");
    for (int i = 0; i < config.frontends_nr; ++i) {
        log_info("\tAddress: %s", config.frontends[i].host);
        log_info("\tPort: %i", config.frontends[i].port);
    }
    log_info("\tTcp backlog: %d", config.tcp_backlog);
    if (config.tls == true) config_print_tls_versions();
    log_info("Logging:");
    log_info("\tlevel: %s", llevel);
    if (config.logpath[0])
        log_info("\tlogpath: %s", config.logpath);
    log_info("Event loop backend: %s", EVENTLOOP_BACKEND);
}

void config_unload(void) {
    npt_free(config.backends);
    npt_free(config.frontends);
}
