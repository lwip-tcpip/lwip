/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 */

#include "fuzz_mem.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/debug.h"

#include <stdlib.h>
#include <string.h>

#if defined(__SANITIZE_ADDRESS__)
#define FUZZ_HAVE_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FUZZ_HAVE_ASAN 1
#endif
#endif

#ifdef FUZZ_HAVE_ASAN
#include <sanitizer/asan_interface.h>
#define FUZZ_ASAN_POISON(p, s)   ASAN_POISON_MEMORY_REGION((p), (s))
#define FUZZ_ASAN_UNPOISON(p, s) ASAN_UNPOISON_MEMORY_REGION((p), (s))
#else
#define FUZZ_ASAN_POISON(p, s)   do { (void)(p); (void)(s); } while (0)
#define FUZZ_ASAN_UNPOISON(p, s) do { (void)(p); (void)(s); } while (0)
#endif

struct fuzz_init_alloc {
  void *ptr;
  void *snapshot;
  size_t size;
  int freed;
};

static struct fuzz_init_alloc init_allocs[128];
static size_t init_alloc_count;
static void *iter_allocs[4096];
static size_t iter_alloc_count;
static int fuzz_in_iter;

void *
fuzz_malloc(size_t size)
{
  void *p;

  if (fuzz_in_iter && (iter_alloc_count >= LWIP_ARRAYSIZE(iter_allocs))) {
    return NULL;
  }

  p = malloc(size);
  if (p == NULL) {
    return NULL;
  }

  if (!fuzz_in_iter) {
    LWIP_ASSERT("too many init allocs", init_alloc_count < LWIP_ARRAYSIZE(init_allocs));
    init_allocs[init_alloc_count].ptr = p;
    init_allocs[init_alloc_count].snapshot = NULL;
    init_allocs[init_alloc_count].size = size;
    init_allocs[init_alloc_count].freed = 0;
    init_alloc_count++;
  } else {
    iter_allocs[iter_alloc_count++] = p;
  }

  return p;
}

void *
fuzz_calloc(size_t count, size_t size)
{
  size_t total;
  void *p;

  if ((count != 0) && (size > ((size_t)-1) / count)) {
    return NULL;
  }
  total = count * size;
  p = fuzz_malloc(total);
  if (p != NULL) {
    memset(p, 0, total);
  }
  return p;
}

void
fuzz_free(void *ptr)
{
  size_t i;

  if (ptr == NULL) {
    return;
  }

  if (!fuzz_in_iter) {
    for (i = 0; i < init_alloc_count; i++) {
      if (init_allocs[i].ptr == ptr) {
        init_allocs[i] = init_allocs[--init_alloc_count];
        break;
      }
    }
    free(ptr);
    return;
  }

  for (i = 0; i < iter_alloc_count; i++) {
    if (iter_allocs[i] == ptr) {
      iter_allocs[i] = iter_allocs[--iter_alloc_count];
      free(ptr);
      return;
    }
  }

  for (i = 0; i < init_alloc_count; i++) {
    if (init_allocs[i].ptr == ptr) {
      LWIP_ASSERT("double free of init alloc", !init_allocs[i].freed);
      /* Defer free and poison so UAF within this iteration still traps,
       * while snapshot restore keeps init-time pointers valid. */
      init_allocs[i].freed = 1;
      FUZZ_ASAN_POISON(ptr, init_allocs[i].size);
      return;
    }
  }

  /* Unknown pointer or double-free: let libc/ASan report it. */
  free(ptr);
}

void
fuzz_mem_snapshot(void)
{
  size_t i;

  for (i = 0; i < init_alloc_count; i++) {
    init_allocs[i].snapshot = malloc(init_allocs[i].size);
    LWIP_ASSERT("init snapshot alloc failed", init_allocs[i].snapshot != NULL);
    memcpy(init_allocs[i].snapshot, init_allocs[i].ptr, init_allocs[i].size);
  }
  fuzz_in_iter = 1;
}

void
fuzz_mem_reset(void)
{
  size_t i;

  for (i = 0; i < iter_alloc_count; i++) {
    free(iter_allocs[i]);
  }
  iter_alloc_count = 0;

  for (i = 0; i < init_alloc_count; i++) {
    if (init_allocs[i].freed) {
      FUZZ_ASAN_UNPOISON(init_allocs[i].ptr, init_allocs[i].size);
      init_allocs[i].freed = 0;
    }
    memcpy(init_allocs[i].ptr, init_allocs[i].snapshot, init_allocs[i].size);
  }
}

void
fuzz_mem_cleanup(void)
{
  size_t i;

  fuzz_mem_reset();
  for (i = 0; i < init_alloc_count; i++) {
    free(init_allocs[i].snapshot);
    init_allocs[i].snapshot = NULL;
  }
  fuzz_in_iter = 0;
}
