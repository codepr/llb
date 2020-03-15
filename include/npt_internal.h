#ifndef NPT_INTERNAL
#define NPT_INTERNAL

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#define NPT_SUCCESS  0
#define NPT_FAILURE -1

static inline void *npt_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "[%s:%ul] Out of memory (%lu bytes)\n",
                __FILE__, __LINE__, size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static inline void *npt_calloc(size_t n, size_t size) {
    void *ptr = calloc(n, size);
    if (!ptr) {
        fprintf(stderr, "[%s:%ul] Out of memory (%lu bytes)\n",
                __FILE__, __LINE__, size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static inline void *npt_realloc(void *ptr, size_t size) {
    assert(ptr && size > 0);
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "[%s:%ul] Out of memory (%lu bytes)\n",
                __FILE__, __LINE__, size);
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

static inline void npt_free(void *ptr) {
    free(ptr);
}

#endif
