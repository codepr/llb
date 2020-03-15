#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include "log.h"
#include "config.h"

static FILE *fh = NULL;

void npt_log_init(const char *file) {
    if (!file) return;
    fh = fopen(file, "a+");
    if (!fh)
        printf("%lu WARNING: Unable to open file %s\n",
               (unsigned long) time(NULL), file);
}

void npt_log_close(void) {
    if (fh) {
        fflush(fh);
        fclose(fh);
    }
}

void npt_log(int level, const char *fmt, ...) {

    if (level < conf->loglevel)
        return;

    assert(fmt);

    va_list ap;
    char msg[MAX_LOG_SIZE + 4];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Truncate message too long and copy 3 bytes to make space for 3 dots */
    memcpy(msg + MAX_LOG_SIZE, "...", 3);
    msg[MAX_LOG_SIZE + 3] = '\0';

    // Open two handler, one for standard output and a second for the
    // persistent log file
    FILE *fp = stdout;

    if (!fp)
        return;

    fprintf(fp, "%lu %s\n", (unsigned long) time(NULL), msg);
    if (fh)
        fprintf(fh, "%lu %s\n", (unsigned long) time(NULL), msg);
}

