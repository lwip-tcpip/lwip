/**
 * @file
 * Packet buffers/chains management module
 */

/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
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

#include "lwip/opt.h"

#include "lwip/stats.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/pbuf.h"

#include "lwip/sys.h"

#include "arch/perf.h"

static u8_t pbuf_pool_memory[(PBUF_POOL_SIZE * MEM_ALIGN_SIZE(PBUF_POOL_BUFSIZE + sizeof(struct pbuf)))];

#if !SYS_LIGHTWEIGHT_PROT
static volatile u8_t pbuf_pool_free_lock, pbuf_pool_alloc_lock;
static sys_sem_t pbuf_pool_free_sem;
#endif

static struct pbuf *pbuf_pool = NULL;
static struct pbuf *pbuf_pool_alloc_cache = NULL;
static struct pbuf *pbuf_pool_free_cache = NULL;

/**
 *
 * Initializes the pbuf module.
 *
 * A large part of memory is allocated for holding the pool of pbufs.
 * The size of the individual pbufs in the pool is given by the size
 * parameter, and the number of pbufs in the pool by the num parameter.
 *
 * After the memory has been allocated, the pbufs are set up. The
 * ->next pointer in each pbuf is set up to point to the next pbuf in
 * the pool.
 *
 */
void
pbuf_init(void)
{
  struct pbuf *p, *q = NULL;
  u16_t i;

  pbuf_pool = (struct pbuf *)&pbuf_pool_memory[0];
  LWIP_ASSERT("pbuf_init: pool aligned", (long)pbuf_pool % MEM_ALIGNMENT == 0);
   
#ifdef PBUF_STATS
  lwip_stats.pbuf.avail = PBUF_POOL_SIZE;
#endif /* PBUF_STATS */
  
  /* Set up ->next pointers to link the pbufs of the pool together */
  p = pbuf_pool;
  
  for(i = 0; i < PBUF_POOL_SIZE; ++i) {
    p->next = (struct pbuf *)((u8_t *)p + PBUF_POOL_BUFSIZE + sizeof(struct pbuf));
    p->len = p->tot_len = PBUF_POOL_BUFSIZE;
    p->payload = MEM_ALIGN((void *)((u8_t *)p + sizeof(struct pbuf)));
    q = p;
    p = p->next;
  }
  
  /* The ->next pointer of last pbuf is NULL to indicate that there
     are no more pbufs in the pool */
  q->next = NULL;

#if !SYS_LIGHTWEIGHT_PROT  
  pbuf_pool_alloc_lock = 0;
  pbuf_pool_free_lock = 0;
  pbuf_pool_free_sem = sys_sem_new(1);
#endif  
}

/**
 * @internal only called from pbuf_alloc()
 */
static struct pbuf *
pbuf_pool_alloc(void)
{
  struct pbuf *p = NULL;

  SYS_ARCH_DECL_PROTECT(old_level);
  SYS_ARCH_PROTECT(old_level);
  /* First, see if there are pbufs in the cache. */
  if(pbuf_pool_alloc_cache) {
    p = pbuf_pool_alloc_cache;
    if(p) {
      pbuf_pool_alloc_cache = p->next; 
    }
  } else {
#if !SYS_LIGHTWEIGHT_PROT      
    /* Next, check the actual pbuf pool, but if the pool is locked, we
       pretend to be out of buffers and return NULL. */
    if(pbuf_pool_free_lock) {
#ifdef PBUF_STATS
      ++lwip_stats.pbuf.alloc_locked;
#endif /* PBUF_STATS */
      return NULL;
    }
    pbuf_pool_alloc_lock = 1;
    if(!pbuf_pool_free_lock) {
#endif /* SYS_LIGHTWEIGHT_PROT */        
      p = pbuf_pool;
      if(p) {
	pbuf_pool = p->next; 
      }
#if !SYS_LIGHTWEIGHT_PROT      
#ifdef PBUF_STATS
    } else {
      ++lwip_stats.pbuf.alloc_locked;
#endif /* PBUF_STATS */
    }
    pbuf_pool_alloc_lock = 0;
#endif /* SYS_LIGHTWEIGHT_PROT */    
  }
  
#ifdef PBUF_STATS
  if(p != NULL) {    
    ++lwip_stats.pbuf.used;
    if(lwip_stats.pbuf.used > lwip_stats.pbuf.max) {
      lwip_stats.pbuf.max = lwip_stats.pbuf.used;
    }
  }
#endif /* PBUF_STATS */

  SYS_ARCH_UNPROTECT(old_level);
  return p;   
}

/**
 * @internal only called from pbuf_alloc()
 */
static void
pbuf_pool_free(struct pbuf *p)
{
  struct pbuf *q;
  SYS_ARCH_DECL_PROTECT(old_level);
  SYS_ARCH_PROTECT(old_level); 

#ifdef PBUF_STATS
    for(q = p; q != NULL; q = q->next) {
      --lwip_stats.pbuf.used;
    }
#endif /* PBUF_STATS */

  if(pbuf_pool_alloc_cache == NULL) {
    pbuf_pool_alloc_cache = p;
  } else {  
    for(q = pbuf_pool_alloc_cache; q->next != NULL; q = q->next);
    q->next = p;    
  }
  SYS_ARCH_UNPROTECT(old_level);
}

/**
 *
 * Allocates a pbuf at protocol layer l.
 * The actual memory allocated for the pbuf is determined by the
 * layer at which the pbuf is allocated and the requested size
 * (from the size parameter). The flag parameter decides how and
 * where the pbuf should be allocated as follows:
 * 
 * - PBUF_RAM: buffer memory for pbuf is allocated as one large
 *             chunk. This includes protocol headers as well. 
 * - PBUF_ROM: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. Additional headers must be prepended
 *             by allocating another pbuf and chain in to the front of
 *             the ROM pbuf. It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 * - PBUF_POOL: the pbuf is allocated as a pbuf chain, with pbufs from
 *              the pbuf pool that is allocated during pbuf_init().
 */
struct pbuf *
pbuf_alloc(pbuf_layer l, u16_t size, pbuf_flag flag)
{
  struct pbuf *p, *q, *r;
  u16_t offset;
  s32_t rem_len;

  /* determine header offset */
  offset = 0;
  switch (l) {
  case PBUF_TRANSPORT:
    offset += PBUF_TRANSPORT_HLEN;
    /* FALLTHROUGH */
  case PBUF_IP:
    offset += PBUF_IP_HLEN;
    /* FALLTHROUGH */
  case PBUF_LINK:
    offset += PBUF_LINK_HLEN;
    break;
  case PBUF_RAW:
    break;
  default:
    LWIP_ASSERT("pbuf_alloc: bad pbuf layer", 0);
    return NULL;
  }

  switch (flag) {
  case PBUF_POOL:
    /* allocate head of pbuf chain into p */
    p = pbuf_pool_alloc();
    if (p == NULL) {
#ifdef PBUF_STATS
      ++lwip_stats.pbuf.err;
#endif /* PBUF_STATS */
      return NULL;
    }
    p->next = NULL;
    
    /* make the payload pointer points offset bytes into pbuf data memory */
    p->payload = MEM_ALIGN((void *)((u8_t *)p + (sizeof(struct pbuf) + offset)));
    /* the total length of the pbuf is the requested size */
    p->tot_len = size;
    /* set the length of the first pbuf is the chain */
    p->len = size > PBUF_POOL_BUFSIZE - offset? PBUF_POOL_BUFSIZE - offset: size;
    p->flags = PBUF_FLAG_POOL;
    
    /* allocate the tail of the pbuf chain. */
    r = p;
    rem_len = size - p->len;
    while(rem_len > 0) {      
      q = pbuf_pool_alloc();
      if (q == NULL) {
	DEBUGF(PBUF_DEBUG | 2, ("pbuf_alloc: Out of pbufs in pool.\n"));
#ifdef PBUF_STATS
        ++lwip_stats.pbuf.err;
#endif /* PBUF_STATS */
        /* bail out unsuccesfully */
        pbuf_pool_free(p);
        return NULL;
      }
      q->next = NULL;
      r->next = q;
      q->len = rem_len > PBUF_POOL_BUFSIZE? PBUF_POOL_BUFSIZE: rem_len;
      q->flags = PBUF_FLAG_POOL;
      q->payload = (void *)((u8_t *)q + sizeof(struct pbuf));
      r = q;
      q->ref = 1;
      rem_len -= PBUF_POOL_BUFSIZE;
    }
    /* end of chain */
    r->next = NULL;

    LWIP_ASSERT("pbuf_alloc: pbuf->payload properly aligned",
	   ((u32_t)p->payload % MEM_ALIGNMENT) == 0);
    break;
  case PBUF_RAM:
    /* If pbuf is to be allocated in RAM, allocate memory for it. */
    p = mem_malloc(MEM_ALIGN_SIZE(sizeof(struct pbuf) + size + offset));
    if (p == NULL) {
      return NULL;
    }
    /* Set up internal structure of the pbuf. */
    p->payload = MEM_ALIGN((void *)((u8_t *)p + sizeof(struct pbuf) + offset));
    p->len = p->tot_len = size;
    p->next = NULL;
    p->flags = PBUF_FLAG_RAM;

    LWIP_ASSERT("pbuf_alloc: pbuf->payload properly aligned",
	   ((u32_t)p->payload % MEM_ALIGNMENT) == 0);
    break;
  /* pbuf references existing (static constant) ROM payload? */
  case PBUF_ROM:
  /* pbuf references existing (externally allocated) RAM payload? */
  case PBUF_REF:
    /* only allocate memory for the pbuf structure */
    p = memp_mallocp(MEMP_PBUF);
    if (p == NULL) {
      DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_alloc: Could not allocate MEMP_PBUF for PBUF_REF.\n"));
      return NULL;
    }
    /* caller must set this field properly, afterwards */
    p->payload = NULL;
    p->len = p->tot_len = size;
    p->next = NULL;
    p->flags = (flag == PBUF_ROM? PBUF_FLAG_ROM: PBUF_FLAG_REF);
    break;
  default:
    LWIP_ASSERT("pbuf_alloc: erroneous flag", 0);
    return NULL;
  }
  p->ref = 1;
  return p;
}

/**
 *
 * Moves free buffers from the pbuf_pool_free_cache to the pbuf_pool
 * list (if possible).
 *
 */
void
pbuf_refresh(void)
{
  struct pbuf *p;
  SYS_ARCH_DECL_PROTECT(old_level);
  SYS_ARCH_PROTECT(old_level);
 
#if !SYS_LIGHTWEIGHT_PROT
  sys_sem_wait(pbuf_pool_free_sem);
#endif /* else SYS_LIGHTWEIGHT_PROT */
  
  if(pbuf_pool_free_cache != NULL) {
#if !SYS_LIGHTWEIGHT_PROT      
    pbuf_pool_free_lock = 1;
    if(!pbuf_pool_alloc_lock) {
#endif /* SYS_LIGHTWEIGHT_PROT */
      if(pbuf_pool == NULL) {
	pbuf_pool = pbuf_pool_free_cache;	
      } else {  
	for(p = pbuf_pool; p->next != NULL; p = p->next);
	p->next = pbuf_pool_free_cache;   
      }
      pbuf_pool_free_cache = NULL;
#if !SYS_LIGHTWEIGHT_PROT      
#ifdef PBUF_STATS
    } else {
      ++lwip_stats.pbuf.refresh_locked;
#endif /* PBUF_STATS */
    }
    
    pbuf_pool_free_lock = 0;
#endif /* SYS_LIGHTWEIGHT_PROT */    
  }
  SYS_ARCH_UNPROTECT(old_level);
#if !SYS_LIGHTWEIGHT_PROT      
  sys_sem_signal(pbuf_pool_free_sem);
#endif /* SYS_LIGHTWEIGHT_PROT */  
}

#ifdef PBUF_STATS
#define DEC_PBUF_STATS do { --lwip_stats.pbuf.used; } while (0)
#else /* PBUF_STATS */
#define DEC_PBUF_STATS
#endif /* PBUF_STATS */

#define PBUF_POOL_FAST_FREE(p)  do {                                    \
                                  p->next = pbuf_pool_free_cache;       \
                                  pbuf_pool_free_cache = p;             \
                                  DEC_PBUF_STATS;                       \
                                } while (0)

#if SYS_LIGHTWEIGHT_PROT
#define PBUF_POOL_FREE(p)  do {                                         \
                                SYS_ARCH_DECL_PROTECT(old_level);       \
                                SYS_ARCH_PROTECT(old_level);            \
                                PBUF_POOL_FAST_FREE(p);                 \
                                SYS_ARCH_UNPROTECT(old_level);          \
                               } while(0)
#else /* SYS_LIGHTWEIGHT_PROT */
#define PBUF_POOL_FREE(p)  do {                                         \
                             sys_sem_wait(pbuf_pool_free_sem);          \
                             PBUF_POOL_FAST_FREE(p);                    \
                             sys_sem_signal(pbuf_pool_free_sem);        \
                           } while(0)
#endif /* SYS_LIGHTWEIGHT_PROT */

/**
 * Shrink a pbuf chain to a desired length.
 *
 * @param p pbuf to shrink.
 * @param new_len desired new length of pbuf chain
 *
 * Depending on the desired length, the first few pbufs in a chain might
 * be skipped and left unchanged. The new last pbuf in the chain will be
 * resized, and any remaining pbufs will be freed.
 * 
 * @note If the pbuf is ROM/REF, only the ->tot_len and ->len fields are adjusted.
 *
 * @bug Cannot grow the size of a pbuf (chain) (yet).
 */
void
pbuf_realloc(struct pbuf *p, u16_t new_len)
{
  struct pbuf *q, *r;
  u16_t rem_len; /* remaining length */
  s16_t grow;

  LWIP_ASSERT("pbuf_realloc: sane p->flags", p->flags == PBUF_FLAG_POOL ||
              p->flags == PBUF_FLAG_ROM ||
              p->flags == PBUF_FLAG_RAM ||
              p->flags == PBUF_FLAG_REF);

  /* desired length larger than current length? */
  if (new_len >= p->tot_len) {
    /* enlarging not yet supported */
    return;
  }
  
  /* the pbuf chain grows by (new_len - p->tot_len) bytes
   * (which may be negative in case of shrinking) */
  grow = new_len - p->tot_len;
  
  /* first, step over any pbufs that should remain in the chain */
  rem_len = new_len;
  q = p;  
  /* this pbuf should be kept? */
  while (rem_len > q->len) {
    /* decrease remaining length by pbuf length */
    rem_len -= q->len;
    /* decrease total length indicator */
    q->tot_len += grow;
    /* proceed to next pbuf in chain */
    q = q->next;
  }
  /* we have now reached the new last pbuf (in q) */
  /* rem_len == desired length for pbuf q */  

  /* shrink allocated memory for PBUF_RAM */
  /* (other types merely adjust their length fields */
  if ((q->flags == PBUF_FLAG_RAM) && (rem_len != q->len)) {
    /* reallocate and adjust the length of the pbuf that will be split */
    mem_realloc(q, (u8_t *)q->payload - (u8_t *)q + rem_len);
  }
  /* adjust length fields for new last pbuf */
  q->len = rem_len;
  q->tot_len = q->len;

  /* any remaining pbufs in chain? */
  if (q->next != NULL) {
    /* free remaining pbufs in chain */
    pbuf_free(q->next);
  }
  /* q is last packet in chain */
  q->next = NULL;

  pbuf_refresh();
}

/**
 * Tries to decrease the payload pointer by the given header size.
 * 
 * Adjusts the ->payload pointer so that space for a header appears in
 * the pbuf. Also, the ->tot_len and ->len fields are adjusted.
 *
 * @param hdr_decrement Number of bytes to decrement header size.
 * (Using a negative value increases the header size.)
 *
 * @return 1 on failure, 0 on succes.
 */
u8_t
pbuf_header(struct pbuf *p, s16_t header_size)
{
  void *payload;
  /* referencing pbufs cannot be realloc()ed */
  /* TODO: WHY NOT? just adjust payload, tot_len and len? */
  if (p->flags == PBUF_FLAG_ROM ||
      p->flags == PBUF_FLAG_REF) {
    /* failure */
    return 1;
  }
  
  payload = p->payload;
  p->payload = (u8_t *)p->payload - header_size;

  DEBUGF(PBUF_DEBUG, ("pbuf_header: old %p new %p (%d)\n", payload, p->payload, header_size));
  
  /* */
  if((u8_t *)p->payload < (u8_t *)p + sizeof(struct pbuf)) {
    DEBUGF(PBUF_DEBUG | 2, ("pbuf_header: failed as %p < %p\n",
			(u8_t *)p->payload,
			(u8_t *)p + sizeof(struct pbuf)));\
    /* restore old payload pointer */
    p->payload = payload;
    return 1;
  }
  p->len += header_size;
  p->tot_len += header_size;
  
  return 0;
}

/**
 * Free a pbuf (chain) from its user, de-allocate if zero users.
 *
 * Decrements the pbuf reference count. If it reaches
 * zero, the pbuf is deallocated.
 *
 * This is repeated for each pbuf in the chain, until a non-zero
 * reference count is encountered, or the end of the chain is reached. 
 *
 * @param pbuf pbuf (chain) to be freed from its user.
 *
 * @return the number of unreferenced pbufs that were de-allocated 
 * from the head of the chain.
 *
 * @note the reference counter of a pbuf equals the number of pointers
 * that refer to the pbuf (or into the pbuf).
 *
 * @internal examples:
 *
 * 1->2->3 becomes ...1->3
 * 3->3->3 becomes 2->3->3
 * 1->1->2 becomes ....->1
 * 2->1->1 becomes 1->1->1
 * 1->1->1 becomes .......
 * 
 */ 
u8_t
pbuf_free(struct pbuf *p)
{
  struct pbuf *q;
  u8_t count;
  SYS_ARCH_DECL_PROTECT(old_level);

  if (p == NULL) {
    DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_free(p==NULL) was called.\n"));
    return 0;
  }

  PERF_START;

  LWIP_ASSERT("pbuf_free: sane flags", p->flags == PBUF_FLAG_POOL ||
    p->flags == PBUF_FLAG_ROM ||
    p->flags == PBUF_FLAG_RAM ||
    p->flags == PBUF_FLAG_REF );

  q = p;
  count = 0;
  /* Since decrementing ref cannot be guaranteed to be a single machine operation
   * we must protect it. Also, the later test of ref must be protected.
   */
  SYS_ARCH_PROTECT(old_level);
  /* de-allocate all consecutive pbufs from the head of the chain that
   * obtain a zero reference count */
  while (p != NULL) {
    /* all pbufs in a chain are referenced at least once */
    LWIP_ASSERT("pbuf_free: q->ref > 0", q->ref > 0);
    p->ref--;
    /* this pbuf is no longer referenced to? */
    if (p->ref == 0)
    {
      /* remember next pbuf in chain for next iteration */
      q = p->next;
  
      /* is this a pbuf from the pool? */
      if (p->flags == PBUF_FLAG_POOL) {
        p->len = p->tot_len = PBUF_POOL_BUFSIZE;
        p->payload = (void *)((u8_t *)p + sizeof(struct pbuf));
        PBUF_POOL_FREE(p);
      /* a RAM/ROM referencing pbuf */
      } else if (p->flags == PBUF_FLAG_ROM || p->flags == PBUF_FLAG_REF) {
        memp_freep(MEMP_PBUF, p);
      /* pbuf with data */
      } else {
        mem_free(p);
      }
      count++;
      /* proceed to next pbuf */
      p = q;
    /* p->ref > 0, this pbuf is still referenced to */
    /* (so the remaining pbufs in chain as well)    */
    } else {
      /* stop walking through chain */
      p = NULL;
    }
  }
  SYS_ARCH_UNPROTECT(old_level);
  pbuf_refresh();
  PERF_STOP("pbuf_free");
  /* return number of de-allocated pbufs */
  return count;
}

/**
 * Count number of pbufs in a chain
 *
 * @param p first pbuf of chain
 * @return the number of pbufs in a chain
 */

u8_t
pbuf_clen(struct pbuf *p)
{
  u8_t len;

  len = 0;  
  while (p != NULL) {
    ++len;
    p = p->next;
  }
  return len;
}
/**
 *
 * Increment the reference count of the pbuf.
 *
 * @param p pbuf to increase reference counter of
 *
 */
void
pbuf_ref(struct pbuf *p)
{
  SYS_ARCH_DECL_PROTECT(old_level);
  /* pbuf given? */  
  if(p != NULL) {
    SYS_ARCH_PROTECT(old_level);
    ++(p->ref);
    SYS_ARCH_UNPROTECT(old_level);
  }
}

/**
 *
 * Increment the reference count of all pbufs in a chain.
 *
 * @param p first pbuf of chain
 *
 */
void
pbuf_ref_chain(struct pbuf *p)
{
  SYS_ARCH_DECL_PROTECT(old_level);
  SYS_ARCH_PROTECT(old_level);
    
  while (p != NULL) {
    ++p->ref;
    p = p->next;
  }
  SYS_ARCH_UNPROTECT(old_level);
}


/**
 *
 * Link two pbuf (chains) together.
 * 
 * The ->tot_len field of the first pbuf (h) is adjusted.
 */
void
pbuf_chain(struct pbuf *h, struct pbuf *t)
{
  struct pbuf *p;

  LWIP_ASSERT("h != NULL", h != NULL);
  LWIP_ASSERT("t != NULL", t != NULL);
  
  /* proceed to last pbuf of chain */
  for (p = h; p->next != NULL; p = p->next) {
    /* add length of second chain to totals of first chain */
    p->tot_len += t->tot_len;
  }
  /* chain last pbuf of h chain (p) with first of tail (t) */
  p->next = t;
  /* t is now referenced to one more time */
  pbuf_ref(t);
  DEBUGF(PBUF_DEBUG | DBG_FRESH | 2, ("pbuf_chain: referencing tail %p\n", (void *) t));
}

/**
 * Dechains the first pbuf from its succeeding pbufs in the chain.
 *
 * Makes p->tot_len field equal to p->len.
 * @param p pbuf to dechain
 * @return remainder of the pbuf chain, or NULL if it was de-allocated.
 */
struct pbuf *
pbuf_dechain(struct pbuf *p)
{
  struct pbuf *q;
  /* tail */  
  q = p->next;
  /* pbuf has successor in chain? */
  if (q != NULL) {
    /* tot_len invariant: (p->tot_len == p->len + p->next->tot_len) */
    LWIP_ASSERT("p->tot_len = p->len + q->tot_len", p->tot_len = p->len + q->tot_len);
    /* enforce invariant if assertion is disabled */
    q->tot_len = p->tot_len - p->len;
  }
  /* decouple pbuf from remainder */
  p->tot_len = p->len;
  p->next = NULL;
#if PBUF_CHAIN_DOES_REFER /** TODO (WORK IN PROGRESS) */
  /* q is no longer referenced by p */
  deallocated = pbuf_free(q);
  DEBUGF(PBUF_DEBUG | DBG_FRESH | 2, ("pbuf_dechain: unreferencing %p\n", (void *) q));
#endif
  /* return remaining tail or NULL if deallocated */
  return (deallocated? NULL: q);
}

/**
 *
 * Create PBUF_POOL (or PBUF_RAM) copies of PBUF_REF pbufs.
 *
 * Go through a pbuf chain and replace any PBUF_REF buffers
 * with PBUF_POOL (or PBUF_RAM) pbufs, each taking a copy of
 * the referenced data.
 *
 * @note The pbuf you give as argument, may have been replaced
 * by calling pbuf_take(p). You must therefore explicitly use
 * p = pbuf_take(p);
 * @note Any replaced pbufs will be freed through pbuf_free().
 *
 * Used to queue packets on behalf of the lwIP stack, such as
 * ARP based queueing.
 *
 * @param f Head of pbuf chain to process
 *
 * @return Pointer to new head of pbuf chain (which may have been
 * replaced itself). 
 */
struct pbuf *
pbuf_take(struct pbuf *f)
{
  struct pbuf *p, *prev, *top;
  LWIP_ASSERT("pbuf_take: f != NULL", f != NULL);
  DEBUGF(PBUF_DEBUG | DBG_TRACE | 3, ("pbuf_take(%p)", (void*)f));

  prev = NULL;
  p = f;
  top = f;
  /* iterate through pbuf chain */
  do
  {
    /* pbuf is of type PBUF_REF? */
    if (p->flags == PBUF_FLAG_REF)
    {
      /* the replacement pbuf */
      struct pbuf *q;
      DEBUGF(PBUF_DEBUG | DBG_TRACE, ("pbuf_take: encountered PBUF_REF %p", (void *)p));
      /* allocate a pbuf (w/ payload) fully in RAM */
      /* PBUF_POOL buffers are faster if we can use them */
      if (p->len <= PBUF_POOL_BUFSIZE) {
        q = pbuf_alloc(PBUF_RAW, p->len, PBUF_POOL);
        if (q == NULL) DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_take: Could not allocate PBUF_POOL"));
      } else {
      	/* no replacement pbuf yet */
        q = NULL;
        DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_take: PBUF_POOL too small to replace PBUF_REF"));
      }
      /* no (large enough) PBUF_POOL was available? retry with PBUF_RAM */
      if (q == NULL) {
        q = pbuf_alloc(PBUF_RAW, p->len, PBUF_RAM);
        if (q == NULL) DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_take: Could not allocate PBUF_RAM"));
      }
      /* replacement pbuf could be allocated? */
      if (q != NULL)
      {  
        /* copy successor */
        q->next = p->next;
        /* remove linkage from original pbuf */
        p->next = NULL;
        /* remove linkage to original pbuf */
        if (prev != NULL)
          /* prev->next == p at this point */
          /* break chain and insert new pbuf instead */
          prev->next = q;
          /* p is no longer pointed to by prev or by our caller, 
           * as the caller must do p = pbuf_take(p); so free it
           * from our usage.
           * note that we have set p->next to NULL already so that
           * we will not free the rest of the chain by accident.
           */
          pbuf_free(p);
        /* prev == NULL, so we replaced the top pbuf of the chain */
        else
          top = q;
        /* copy pbuf payload */
        memcpy(q->payload, p->payload, p->len);
        q->tot_len = p->tot_len;
        q->len = p->len;
        /* do not copy ref, since someone else might be using the old buffer */
        /* pbuf is not freed, as this is the responsibility of the application */
        DEBUGF(PBUF_DEBUG, ("pbuf_take: replaced PBUF_REF %p with %p\n", (void *)p, (void *)q));
        p = q;
      }
      else
      {
        /* deallocate chain */
        pbuf_free(top);
        DEBUGF(PBUF_DEBUG | 2, ("pbuf_take: failed to allocate replacement pbuf for %p\n", (void *)p));
        return NULL;
      }
    }
    else {
      DEBUGF(PBUF_DEBUG | DBG_TRACE | 1, ("pbuf_take: not PBUF_REF"));
    }

    prev = p;
    p = p->next;
  } while (p);
  DEBUGF(PBUF_DEBUG | DBG_TRACE | 1, ("pbuf_take: end of chain reached."));
  
  return top;
}

