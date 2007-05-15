/** @file
 *
 * Dynamic memory manager
 *
 */

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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include <string.h>

#include "lwip/arch.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"

#include "lwip/sys.h"

#include "lwip/stats.h"

#if (MEM_LIBC_MALLOC == 0)
/* lwIP replacement for your libc malloc() */

/* This does not have to be aligned since for getting its size,
 * we only use the macro SIZEOF_STRUCT_MEM, which automatically alignes.
 */
struct mem {
  mem_size_t next;
  mem_size_t prev;
  u8_t used;
};

/* All allocated blocks will be MIN_SIZE bytes big, at least! */
#ifndef MIN_SIZE
#define MIN_SIZE             12
#endif /* MIN_SIZE */
#define MIN_SIZE_ALIGNED     MEM_ALIGN_SIZE(MIN_SIZE)
#define SIZEOF_STRUCT_MEM    MEM_ALIGN_SIZE(sizeof(struct mem))
#define MEM_SIZE_ALIGNED     MEM_ALIGN_SIZE(MEM_SIZE)

static struct mem *ram_end;
/* the heap. we need one struct mem at the end and some room for alignment */
static u8_t ram_heap[MEM_SIZE_ALIGNED + (2*SIZEOF_STRUCT_MEM) + MEM_ALIGNMENT];
static u8_t *ram; /* for alignment, ram is now a pointer instead of an array */
static struct mem *lfree; /* pointer to the lowest free block */
static sys_sem_t mem_sem; /* concurrent access protection */

/*
 * "Plug holes" by combining adjacent empty struct mems.
 * After this function is through, there should not exist
 * one empty struct mem pointing to another empty struct mem.
 *
 * @param mem this points to a struct mem which just has been freed
 * @internal this function is only called by mem_free() and mem_realloc()
 *
 * This assumes access to the heap is protected by the calling function
 * already.
 */
static void
plug_holes(struct mem *mem)
{
  struct mem *nmem;
  struct mem *pmem;

  LWIP_ASSERT("plug_holes: mem >= ram", (u8_t *)mem >= ram);
  LWIP_ASSERT("plug_holes: mem < ram_end", (u8_t *)mem < (u8_t *)ram_end);
  LWIP_ASSERT("plug_holes: mem->used == 0", mem->used == 0);

  /* plug hole forward */
  LWIP_ASSERT("plug_holes: mem->next <= MEM_SIZE_ALIGNED", mem->next <= MEM_SIZE_ALIGNED);

  nmem = (struct mem *)&ram[mem->next];
  if (mem != nmem && nmem->used == 0 && (u8_t *)nmem != (u8_t *)ram_end) {
  	/* if mem->next is unused and not end of ram, combine mem and mem->next */
    if (lfree == nmem) {
      lfree = mem;
    }
    mem->next = nmem->next;
    ((struct mem *)&ram[nmem->next])->prev = (u8_t *)mem - ram;
  }

  /* plug hole backward */
  pmem = (struct mem *)&ram[mem->prev];
  if (pmem != mem && pmem->used == 0) {
  	/* if mem->prev is unused, combine mem and mem->prev */
    if (lfree == mem) {
      lfree = pmem;
    }
    pmem->next = mem->next;
    ((struct mem *)&ram[mem->next])->prev = (u8_t *)pmem - ram;
  }
}

/*
 * Zero the heap and initialize start, end and lowest-free
 */
void
mem_init(void)
{
  struct mem *mem;

  LWIP_ASSERT("Sanity check alignment",
    (SIZEOF_STRUCT_MEM & (MEM_ALIGNMENT-1)) == 0);

  /* align the heap */
  memset(ram_heap, 0, sizeof(ram_heap));
  ram = MEM_ALIGN(ram_heap);
  /* initialize the start of the heap */
  mem = (struct mem *)ram;
  mem->next = MEM_SIZE_ALIGNED;
  mem->prev = 0;
  mem->used = 0;
  /* initialize the end of the heap */
  ram_end = (struct mem *)&ram[MEM_SIZE_ALIGNED];
  ram_end->used = 1;
  ram_end->next = MEM_SIZE_ALIGNED;
  ram_end->prev = MEM_SIZE_ALIGNED;

  mem_sem = sys_sem_new(1);

  /* initialize the lowest-free pointer to the start of the heap */
  lfree = (struct mem *)ram;

#if MEM_STATS
  lwip_stats.mem.avail = MEM_SIZE_ALIGNED;
#endif /* MEM_STATS */
}

/* Put a struct mem back on the heap
 * @param rmem is the data portion of a struct mem as returned by a previous
 *             call to mem_malloc()
 */
void
mem_free(void *rmem)
{
  struct mem *mem;

  if (rmem == NULL) {
    LWIP_DEBUGF(MEM_DEBUG | LWIP_DBG_TRACE | 2, ("mem_free(p == NULL) was called.\n"));
    return;
  }
  LWIP_ASSERT("mem_free: sanity check alignment", (((mem_ptr_t)rmem) & (MEM_ALIGNMENT-1)) == 0);

  /* protect the heap from concurrent access */
  sys_sem_wait(mem_sem);

  LWIP_ASSERT("mem_free: legal memory", (u8_t *)rmem >= (u8_t *)ram &&
    (u8_t *)rmem < (u8_t *)ram_end);

  if ((u8_t *)rmem < (u8_t *)ram || (u8_t *)rmem >= (u8_t *)ram_end) {
    LWIP_DEBUGF(MEM_DEBUG | 3, ("mem_free: illegal memory\n"));
#if MEM_STATS
    ++lwip_stats.mem.err;
#endif /* MEM_STATS */
    sys_sem_signal(mem_sem);
    return;
  }
  /* Get the corresponding struct mem ... */
  mem = (struct mem *)((u8_t *)rmem - SIZEOF_STRUCT_MEM);
  /* ... which has to be in a used state ... */
  LWIP_ASSERT("mem_free: mem->used", mem->used);
  /* ... and is now unused. */
  mem->used = 0;

  if (mem < lfree) {
    /* the newly freed struct is now the lowest */
    lfree = mem;
  }

#if MEM_STATS
  lwip_stats.mem.used -= mem->next - ((u8_t *)mem - ram);
#endif /* MEM_STATS */

  /* finally, see if prev or next are free also */
  plug_holes(mem);
  sys_sem_signal(mem_sem);
}

/* In contrast to its name, mem_realloc can only shrink memory, not expand it.
 * Since the only use (for now) is in pbuf_realloc (which also can only shrink),
 * this shouldn't be a problem!
 */
void *
mem_realloc(void *rmem, mem_size_t newsize)
{
  mem_size_t size;
  mem_size_t ptr, ptr2;
  struct mem *mem, *mem2;

  /* Expand the size of the allocated memory region so that we can
     adjust for alignment. */
  newsize = MEM_ALIGN_SIZE(newsize);

  if (newsize > MEM_SIZE_ALIGNED) {
    return NULL;
  }

  if(newsize < MIN_SIZE_ALIGNED) {
    /* every data block must be at least MIN_SIZE_ALIGNED long */
    newsize = MIN_SIZE_ALIGNED;
  }

  LWIP_ASSERT("mem_realloc: legal memory", (u8_t *)rmem >= (u8_t *)ram &&
   (u8_t *)rmem < (u8_t *)ram_end);

  if ((u8_t *)rmem < (u8_t *)ram || (u8_t *)rmem >= (u8_t *)ram_end) {
    LWIP_DEBUGF(MEM_DEBUG | 3, ("mem_realloc: illegal memory\n"));
    return rmem;
  }
  /* Get the corresponding struct mem ... */
  mem = (struct mem *)((u8_t *)rmem - SIZEOF_STRUCT_MEM);
  /* ... and its offset pointer */
  ptr = (u8_t *)mem - ram;

  size = mem->next - ptr - SIZEOF_STRUCT_MEM;
  LWIP_ASSERT("mem_realloc can only shrink memory", newsize <= size);
  if (newsize > size) {
    /* not supported */
    return NULL;
  }
  if (newsize == size) {
    /* No change in size, simply return */
    return rmem;
  }

  /* protect the heap from concurrent access */
  sys_sem_wait(mem_sem);

#if MEM_STATS
  lwip_stats.mem.used -= (size - newsize);
#endif /* MEM_STATS */

  mem2 = (struct mem *)&ram[mem->next];
  if(mem2->used == 0) {
    /* The next struct is unused, we can simply move it at little */
    mem_size_t next;
    /* remember the old next pointer */
    next = mem2->next;
    ptr2 = ptr + SIZEOF_STRUCT_MEM + newsize;
    mem2 = (struct mem *)&ram[ptr2];
    mem2->used = 0;
    mem2->next = next;
    mem2->prev = ptr;
    mem->next = ptr2;
    if (mem2->next != MEM_SIZE_ALIGNED) {
      ((struct mem *)&ram[mem2->next])->prev = ptr2;
    }
  } else if (newsize + SIZEOF_STRUCT_MEM + MIN_SIZE_ALIGNED < size) {
    /* There's room for another struct mem with at least MIN_SIZE_ALIGNED of data. */
    ptr2 = ptr + SIZEOF_STRUCT_MEM + newsize;
    mem2 = (struct mem *)&ram[ptr2];
    mem2->used = 0;
    mem2->next = mem->next;
    mem2->prev = ptr;
    mem->next = ptr2;
    if (mem2->next != MEM_SIZE_ALIGNED) {
      ((struct mem *)&ram[mem2->next])->prev = ptr2;
    }
    /* mem->next is used, so no need to plug holes! */
  }
  /* else {
    the remaining space stays unused since it is too small
  } */
  sys_sem_signal(mem_sem);
  return rmem;
}

#if 0
/**
 * Adam's mem_malloc(), suffers from bug #17922
 * Set if to 0 for alternative mem_malloc().
 */
void *
mem_malloc(mem_size_t size)
{
  mem_size_t ptr, ptr2;
  struct mem *mem, *mem2;

  if (size == 0) {
    return NULL;
  }

  /* Expand the size of the allocated memory region so that we can
     adjust for alignment. */
  if ((size % MEM_ALIGNMENT) != 0) {
    size += MEM_ALIGNMENT - ((size + SIZEOF_STRUCT_MEM) % MEM_ALIGNMENT);
  }

  if (size > MEM_SIZE_ALIGNED) {
    return NULL;
  }

  sys_sem_wait(mem_sem);

  for (ptr = (u8_t *)lfree - ram; ptr < MEM_SIZE_ALIGNED; ptr = ((struct mem *)&ram[ptr])->next) {
    mem = (struct mem *)&ram[ptr];
    if (!mem->used &&
       mem->next - (ptr + SIZEOF_STRUCT_MEM) >= size + SIZEOF_STRUCT_MEM) {
      ptr2 = ptr + SIZEOF_STRUCT_MEM + size;
      mem2 = (struct mem *)&ram[ptr2];

      mem2->prev = ptr;
      mem2->next = mem->next;
      mem->next = ptr2;
      if (mem2->next != MEM_SIZE_ALIGNED) {
        ((struct mem *)&ram[mem2->next])->prev = ptr2;
      }

      mem2->used = 0;
      mem->used = 1;
#if MEM_STATS
      lwip_stats.mem.used += (size + SIZEOF_STRUCT_MEM);
      /*      if (lwip_stats.mem.max < lwip_stats.mem.used) {
        lwip_stats.mem.max = lwip_stats.mem.used;
        } */
      if (lwip_stats.mem.max < ptr2) {
        lwip_stats.mem.max = ptr2;
      }
#endif /* MEM_STATS */

      if (mem == lfree) {
        /* Find next free block after mem */
        while (lfree->used && lfree != ram_end) {
          lfree = (struct mem *)&ram[lfree->next];
        }
        LWIP_ASSERT("mem_malloc: !lfree->used", !lfree->used);
      }
      sys_sem_signal(mem_sem);
      LWIP_ASSERT("mem_malloc: allocated memory not above ram_end.",
       (mem_ptr_t)mem + SIZEOF_STRUCT_MEM + size <= (mem_ptr_t)ram_end);
      LWIP_ASSERT("mem_malloc: allocated memory properly aligned.",
       (unsigned long)((u8_t *)mem + SIZEOF_STRUCT_MEM) % MEM_ALIGNMENT == 0);
      return (u8_t *)mem + SIZEOF_STRUCT_MEM;
    }
  }
  LWIP_DEBUGF(MEM_DEBUG | 2, ("mem_malloc: could not allocate %"S16_F" bytes\n", (s16_t)size));
#if MEM_STATS
  ++lwip_stats.mem.err;
#endif /* MEM_STATS */
  sys_sem_signal(mem_sem);
  return NULL;
}
#else
/**
 * Adam's mem_malloc() plus solution for bug #17922
 *
 * Allocate a block of memory with a minimum of 'size' bytes.
 * @param size is the minimum size of the requested block in bytes.
 *
 * Note that the returned value will always be aligned.
 */
void *
mem_malloc(mem_size_t size)
{
  mem_size_t ptr, ptr2;
  struct mem *mem, *mem2;

  if (size == 0) {
    return NULL;
  }

  /* Expand the size of the allocated memory region so that we can
     adjust for alignment. */
  size = MEM_ALIGN_SIZE(size);

  if(size < MIN_SIZE_ALIGNED) {
    /* every data block must be at least MIN_SIZE_ALIGNED long */
    size = MIN_SIZE_ALIGNED;
  }

  if (size > MEM_SIZE_ALIGNED) {
    return NULL;
  }

  /* protect the heap from concurrent access */
  sys_sem_wait(mem_sem);

  /* Scan through the heap searching for a free block that is big enough,
   * beginning with the lowest free block.
   */
  for (ptr = (u8_t *)lfree - ram; ptr < MEM_SIZE_ALIGNED - size;
       ptr = ((struct mem *)&ram[ptr])->next) {
    mem = (struct mem *)&ram[ptr];

    if ((!mem->used) &&
        (mem->next - (ptr + SIZEOF_STRUCT_MEM)) >= size) {
      /* mem is not used and at least perfect fit is possible */

      if (mem->next - (ptr + (2*SIZEOF_STRUCT_MEM) + MIN_SIZE_ALIGNED) >= size) {
        /* split large block, create empty remainder,
           remainder must be large enough to contain MIN_SIZE_ALIGNED data: if
           mem->next - (ptr + (2*SIZEOF_STRUCT_MEM)) == size,
           struct mem would fit in but no data between mem2 and mem2->next
         */
        ptr2 = ptr + SIZEOF_STRUCT_MEM + size;
        /* create mem2 struct */
        mem2 = (struct mem *)&ram[ptr2];
        mem2->used = 0;
        mem2->next = mem->next;
        mem2->prev = ptr;
        /* and insert it between mem and mem->next */
        mem->next = ptr2;
        mem->used = 1;

        if (mem2->next != MEM_SIZE_ALIGNED) {
          ((struct mem *)&ram[mem2->next])->prev = ptr2;
        }
      } else {
        /* near fit or excact fit: do not split, no mem2 creation
         * also can't move mem->next directly behind mem, since mem->next
         * will always be used at this point!
         */
        mem->used = 1;
      }

#if MEM_STATS
      lwip_stats.mem.used += (size + SIZEOF_STRUCT_MEM);
      if (lwip_stats.mem.max < lwip_stats.mem.used) {
        lwip_stats.mem.max = lwip_stats.mem.used;
      }
#endif /* MEM_STATS */
      if (mem == lfree) {
        /* Find next free block after mem and update lowest free pointer */
        while (lfree->used && lfree != ram_end) {
          lfree = (struct mem *)&ram[lfree->next];
        }
        LWIP_ASSERT("mem_malloc: !lfree->used", ((lfree == ram_end) || (!lfree->used)));
      }
      sys_sem_signal(mem_sem);
      LWIP_ASSERT("mem_malloc: allocated memory not above ram_end.",
       (mem_ptr_t)mem + SIZEOF_STRUCT_MEM + size <= (mem_ptr_t)ram_end);
      LWIP_ASSERT("mem_malloc: allocated memory properly aligned.",
       (unsigned long)((u8_t *)mem + SIZEOF_STRUCT_MEM) % MEM_ALIGNMENT == 0);
      LWIP_ASSERT("mem_malloc: sanity check alignment",
        (((mem_ptr_t)mem) & (MEM_ALIGNMENT-1)) == 0);

      return (u8_t *)mem + SIZEOF_STRUCT_MEM;
    }
  }
  LWIP_DEBUGF(MEM_DEBUG | 2, ("mem_malloc: could not allocate %"S16_F" bytes\n", (s16_t)size));
#if MEM_STATS
  ++lwip_stats.mem.err;
#endif /* MEM_STATS */
  sys_sem_signal(mem_sem);
  return NULL;
}
#endif

#endif /* MEM_LIBC_MALLOC == 0 */

