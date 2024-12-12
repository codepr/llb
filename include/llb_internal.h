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

#ifndef LLB_INTERNAL
#define LLB_INTERNAL

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define RANDOM(A, B)         A + rand() / (RAND_MAX / (B - A))

/* Load-balancing mode */
#define LLB_TCP_MODE         0
#define LLB_HTTP_MODE        1

#define LLB_SUCCESS          0
#define LLB_FAILURE          -1

/* Load-balancing algorithms */
#define ROUND_ROBIN          0
#define HASH_BALANCING       1
#define RANDOM_BALANCING     2
#define LEASTCONN            3
#define LEASTTRAFFIC         4
#define WEIGHTED_ROUND_ROBIN 5

static inline void *llb_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr && size != 0) {
        fprintf(stderr, "[%s:%ul] Out of memory (%lu bytes)\n", __FILE__,
                __LINE__, size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static inline void *llb_calloc(size_t n, size_t size)
{
    void *ptr = calloc(n, size);
    if (!ptr && size != 0 && n != 0) {
        fprintf(stderr, "[%s:%ul] Out of memory (%lu bytes)\n", __FILE__,
                __LINE__, size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static inline void *llb_realloc(void *ptr, size_t size)
{
    assert(ptr && size > 0);
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size != 0) {
        fprintf(stderr, "[%s:%ul] Out of memory (%lu bytes)\n", __FILE__,
                __LINE__, size);
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

static inline void llb_free(void *ptr) { free(ptr); }

/* D. J. Bernstein hash function */
static inline size_t djb_hash(const char *str)
{
    size_t hash = 5381;
    while (*str)
        hash = 33 * hash ^ (unsigned char)*str++;
    return hash;
}

#endif
