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

#define NEW_PBUF_REALLOC 1 /* enabling this should fix bug #1903 */
#define PBUF_CHAIN_DOES_REFER 1 /** enabling this fixes bug #2968 */

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

/*-----------------------------------------------------------------------------------*/
/* pbuf_init():
 *
 * Initializes the pbuf module. A large part of memory is allocated
 * for holding the pool of pbufs. The size of the individual pbufs in
 * the pool is given by the size parameter, and the number of pbufs in
 * the pool by the num parameter.
 *
 * After the memory has been allocated, the pbufs are set up. The
 * ->next pointer in each pbuf is set up to point to the next pbuf in
 * the pool.
 */
/*-----------------------------------------------------------------------------------*/
void
pbuf_init(void)
{
  struct pbuf *p, *q = 0;
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
/*-----------------------------------------------------------------------------------*/
/* The following two functions are only called from pbuf_alloc(). */
/*-----------------------------------------------------------------------------------*/
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
/*-----------------------------------------------------------------------------------*/
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
/*-----------------------------------------------------------------------------------*/
/* pbuf_alloc():
 *
 * Allocates a pbuf at protocol layer l. The actual memory allocated
 * for the pbuf is determined by the layer at which the pbuf is
 * allocated and the requested size (from the size parameter). The
 * flag parameter decides how and where the pbuf should be allocated
 * as follows:
 * 
 * * PBUF_RAM: buffer memory for pbuf is allocated as one large
 *             chunk. This includes protocol headers as well. 
 * * PBUF_ROM: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. Additional headers must be prepended
 *             by allocating another pbuf and chain in to the front of
 *             the ROM pbuf. It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * * PBUF_REF: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 * * PBUF_POOL: the pbuf is allocated as a pbuf chain, with pbufs from
 *              the pbuf pool that is allocated during pbuf_init().
 */
/*-----------------------------------------------------------------------------------*/
struct pbuf *
pbuf_alloc(pbuf_layer l, u16_t size, pbuf_flag flag)
{
  struct pbuf *p, *q, *r;
  u16_t offset;
  s32_t rsize;

  /* determine header offset */
  offset = 0;
  switch(l) {
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

  switch(flag) {
  case PBUF_POOL:
    /* allocate head of pbuf chain into p */
    p = pbuf_pool_alloc();
    if(p == NULL) {
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
    rsize = size - p->len;
    while(rsize > 0) {      
      q = pbuf_pool_alloc();
      if (q == NULL) {
	DEBUGF(PBUF_DEBUG | 2, ("pbuf_alloc: Out of pbufs in pool.\n"));
#ifdef PBUF_STATS
        ++lwip_stats.pbuf.err;
#endif /* PBUF_STATS */
        pbuf_pool_free(p);
        return NULL;
      }
      q->next = NULL;
      r->next = q;
      q->len = rsize > PBUF_POOL_BUFSIZE? PBUF_POOL_BUFSIZE: rsize;
      q->flags = PBUF_FLAG_POOL;
      q->payload = (void *)((u8_t *)q + sizeof(struct pbuf));
      r = q;
      q->ref = 1;
      rsize -= PBUF_POOL_BUFSIZE;
    }
    /* end of chain */
    r->next = NULL;

    LWIP_ASSERT("pbuf_alloc: pbuf->payload properly aligned",
	   ((u32_t)p->payload % MEM_ALIGNMENT) == 0);
    break;
  case PBUF_RAM:
    /* If pbuf is to be allocated in RAM, allocate memory for it. */
    p = mem_malloc(MEM_ALIGN_SIZE(sizeof(struct pbuf) + size + offset));
    if(p == NULL) {
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
    if(p == NULL) {
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
/*-----------------------------------------------------------------------------------*/
/* pbuf_refresh():
 *
 * Moves free buffers from the pbuf_pool_free_cache to the pbuf_pool
 * list (if possible).
 *
 */
/*-----------------------------------------------------------------------------------*/
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
 * Shrink a pbuf chain to a certain size.
 *
 * @param p pbuf to shrink.
 * @param size new size
 *
 * Depending on the desired size, the first few pbufs in a chain might
 * be skipped.
 * @note If the pbuf is ROM/REF, only the ->tot_len and ->len fields are adjusted.
 * If the chain
 * a pbuf chain, as it might be with both pbufs in dynamically
 * allocated RAM and for pbufs from the pbuf pool, we have to step
 * through the chain until we find the new endpoint in the pbuf chain.
 * Then the pbuf that is right on the endpoint is resized and any
 * further pbufs on the chain are deallocated.
 * @bug Cannot grow the size of a pbuf (chain).
 */
/*-----------------------------------------------------------------------------------*/
#if NEW_PBUF_REALLOC
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

  if (new_len >= p->tot_len) {
    /** enlarging not yet supported */
    return;
  }
  
  /* { the pbuf chains grows by (new_len - p->tot_len) bytes } */
  grow = new_len - p->tot_len;
  
  /* first, step over any pbufs that should remain in the chain */
  rem_len = new_len;
  q = p;  
  /* this pbuf should be kept? */
  while (rem_len > q->len) {
    /* decrease remaining length by pbuf length */
    rem_len -= q->len;
    q->tot_len += grow;
    q = q->next;
  }
  /* { we have now reached the new last pbuf } */
  /* { rem_len == desired length for pbuf q } */  

  /* shrink allocated memory for PBUF_RAM */
  /* (other types merely adjust their length fields */
  if ((q->flags == PBUF_FLAG_RAM) && (rem_len != q->len )) {
    /* reallocate and adjust the length of the pbuf that will be split */
    mem_realloc(q, (u8_t *)q->payload - (u8_t *)q + rem_len);
  }
  /* adjust length fields */
  q->len = rem_len;
  q->tot_len = q->len;

  /* deallocate any left over pbufs */
  /* remember next pbuf in chain */
  r = q->next;
  /* q is last packet in chain */
  q->next = NULL;
  /* first pbuf to be dealloced */
  q = r;
  /* any pbuf left? */
  while(q != NULL) {
    /* remember next pbuf in chain */
    r = q->next;
    /* deallocate pbuf */
    if (q->flags == PBUF_FLAG_POOL) {
      PBUF_POOL_FREE(q);
    } else {
      pbuf_free(q);
    }
    q = r;
  }

  pbuf_refresh();
}
#else /* pbuf_realloc() of CVS version 1.23 */
void
pbuf_realloc(struct pbuf *p, u16_t size)
{
  struct pbuf *q, *r;
  u16_t rsize;

  LWIP_ASSERT("pbuf_realloc: sane p->flags", p->flags == PBUF_FLAG_POOL ||
              p->flags == PBUF_FLAG_ROM ||
              p->flags == PBUF_FLAG_RAM ||
              p->flags == PBUF_FLAG_REF);

  if(p->tot_len <= size) {
    return;
  }
  
  switch(p->flags) {
  case PBUF_FLAG_POOL:
    /* First, step over any pbufs that should still be in the chain. */
    rsize = size;
    q = p;  
    while(rsize > q->len) {
      rsize -= q->len;      
      q = q->next;
    }
    /* Adjust the length of the pbuf that will be halved. */
    q->len = rsize;

    /* And deallocate any left over pbufs. */
    r = q->next;
    q->next = NULL;
    q = r;
    while(q != NULL) {
      r = q->next;
      PBUF_POOL_FREE(q);
      q = r;
    }
    break;
  case PBUF_FLAG_ROM:
  case PBUF_FLAG_REF:
    p->len = size;
    break;
  case PBUF_FLAG_RAM:
    /* First, step over the pbufs that should still be in the chain. */
    rsize = size;
    q = p;
    while(rsize > q->len) {
      rsize -= q->len;
      q = q->next;
    }
    if(q->flags == PBUF_FLAG_RAM) {
    /* Reallocate and adjust the length of the pbuf that will be halved. */
      mem_realloc(q, (u8_t *)q->payload - (u8_t *)q + rsize);
    }
    
    q->len = rsize;
    
    /* And deallocate any left over pbufs. */
    r = q->next;
    q->next = NULL;
    q = r;
    while(q != NULL) {
      r = q->next;
      pbuf_free(q);
      q = r;
    }
    break;
  }
  p->tot_len = size;

  pbuf_refresh();
}
#endif

/**
 * Decreases the header size by the given amount.
 * 
 * Adjusts the ->payload pointer so that space for a header appears in
 * the pbuf. Also, the ->tot_len and ->len fields are adjusted.
 *
 * @param hdr_decrement Number of bytes to decrement header size.
 * (Using a negative value increases the header size.)
 *
 * @return 1 on failure, 0 on succes.
 */
/*-----------------------------------------------------------------------------------*/
u8_t
pbuf_header(struct pbuf *p, s16_t header_size)
{
  void *payload;
  /* referencing pbufs cannot be realloc()ed */
  if (p->flags == PBUF_FLAG_ROM ||
      p->flags == PBUF_FLAG_REF) {
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
 * For a single pbuf, decrement its reference count. If it reaches
 * zero, de-allocate the associated memory.
 *
 * For chained pbufs, all reference counts of the pbufs in the chain
 * are decremented. Only if the first pbuf reference count reaches
 * zero, all pbufs are de-allocated.
 *
 * @param pbuf pbuf (chain) to be freed from its user.
 *
 * @note The reference count should not decrease when inspecting the
 * pbuf chain from head to tail.
 *
 * @note Chained pbufs with different reference counts should really
 * not occur. Something that references to the first pbuf, has access
 * to the complete chain, so all references
 */ 
/*-----------------------------------------------------------------------------------*/
u8_t
pbuf_free(struct pbuf *p)
{
  struct pbuf *q;
  u8_t count = 0;
  u16_t last_ref_count;
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

  LWIP_ASSERT("pbuf_free: p->ref > 0", p->ref > 0);
  p->ref--;

  /* Since decrementing ref cannot be guarranteed to be a single machine operation
   * we must protect it. Also, the later test of ref must be protected.
   */
  SYS_ARCH_PROTECT(old_level);
  /* decrement individual reference count for each pbuf in chain */
  for (q = p->next; q != NULL; q = q->next) {
    /* reference counts can be 0, as 2nd and further pbufs will
       only be freed if the head of the chain is freed */
    LWIP_ASSERT("pbuf_free: q->ref >= 0", q->ref >= 0);
    /* decrease reference count, but do not wrap! */
    if (q->ref > 0)
      q->ref--;
  }

  /* first pbuf now no longer needed? */
  if (p->ref == 0) {
    SYS_ARCH_UNPROTECT(old_level);

    while (p != NULL) {
      /* remember next in chain */
      q = p->next;
      /* this is a pbuf from the pool? */
      if (p->flags == PBUF_FLAG_POOL) {
        p->len = p->tot_len = PBUF_POOL_BUFSIZE;
        p->payload = (void *)((u8_t *)p + sizeof(struct pbuf));
        PBUF_POOL_FREE(p);
      /* RAM/ROM referencing pbuf */
      } else if (p->flags == PBUF_FLAG_ROM || p->flags == PBUF_FLAG_REF) {
        memp_freep(MEMP_PBUF, p);
      /* pbuf with data */
      } else {
        mem_free(p);
      }
      /* next in chain */
      p = q;
      /* Only free the next one in a chain if it's reference count is 0.
      This allows buffer chains to have multiple headers pointing to them. */
      if (p != NULL)
      {
        p->ref--;
        if (p->ref > 0)
          break;
      }

      ++count;
    }
    pbuf_refresh();
  } else
    SYS_ARCH_UNPROTECT(old_level);
  PERF_STOP("pbuf_free");

  return count;
}
/*-----------------------------------------------------------------------------------*/
/* pbuf_clen():
 *
 * Returns the length of the pbuf chain.
 */
/*-----------------------------------------------------------------------------------*/
u8_t
pbuf_clen(struct pbuf *p)
{
  u8_t len;

  if(p == NULL) {
    return 0;
  }
  
  for(len = 0; p != NULL; p = p->next) {
    ++len;
  }
  return len;
}
/*-----------------------------------------------------------------------------------*/
/* pbuf_ref():
 *
 * Increments the reference count of the pbuf.
 */
/*-----------------------------------------------------------------------------------*/
void
pbuf_ref(struct pbuf *p)
{
    SYS_ARCH_DECL_PROTECT(old_level);
    
  if(p == NULL) {
    return;
  }

  SYS_ARCH_PROTECT(old_level);
  ++(p->ref);
  SYS_ARCH_UNPROTECT(old_level);
}

/*------------------------------------------------------------------------------*/
/* pbuf_ref_chain():
 *
 * Increments the reference count of all pbufs in a chain.
 */
void
pbuf_ref_chain(struct pbuf *p)
{
    SYS_ARCH_DECL_PROTECT(old_level);
    SYS_ARCH_PROTECT(old_level);
    
    while (p != NULL) {
        p->ref++;
        p=p->next;
    }

    SYS_ARCH_UNPROTECT(old_level);
}


/**
 *
 * Link two pbuf (chains) together.
 * 
 * The ->tot_len field of the first pbuf (h) is adjusted.
 */
/*-----------------------------------------------------------------------------------*/
void
pbuf_chain(struct pbuf *h, struct pbuf *t)
{
  struct pbuf *p;

  LWIP_ASSERT("h != NULL", h != NULL);
  LWIP_ASSERT("t != NULL", t != NULL);
  
  /* proceed to last pbuf of chain */
  for(p = h; p->next != NULL; p = p->next) {
    /* add length of second chain to totals of first chain */
    p->tot_len += t->tot_len;
  }
  /* chain */
  p->next = t;
#if PBUF_CHAIN_DOES_REFER /** TODO (WORK IN PROGRESS) */
  /* t is now referenced to one more time */
  pbuf_ref(t);
  DEBUGF(DEBUG_PBUF | DBG_FRESH | 2, ("pbuf_chain: referencing %p\n", q));
#endif
}

/**
 * Dechains the first pbuf from its succeeding pbufs in the chain.
 *
 * Makes p->tot_len field equal to p->len.
 * @param p pbuf to dechain
 * @return remainder (if any) of the pbuf chain.
 */
struct pbuf *
pbuf_dechain(struct pbuf *p)
{
  struct pbuf *q;
  
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
  pbuf_free(q);
  DEBUGF(DEBUG_PBUF | DBG_FRESH | 2, ("pbuf_dechain: unreferencing %p\n", q));
#endif
  return q;
}

/**
 *
 * Create PBUF_POOL (or PBUF_RAM) copies of PBUF_REF pbufs.
 *
 * Go through a pbuf chain and replace any PBUF_REF buffers
 * with PBUF_POOL (or PBUF_RAM) pbufs, each taking a copy of
 * the referenced data.
 *
 * Used to queue packets on behalf of the lwIP stack, such as ARP based
 * queueing.
 *
 * @param f Head of pbuf chain to process
 *
 * @return Pointer to new head of pbuf chain.
 */
struct pbuf *
pbuf_take(struct pbuf *f)
{
  struct pbuf *p, *prev, *top;
  LWIP_ASSERT("pbuf_take: f != NULL", f != NULL);
  DEBUGF(PBUF_DEBUG | DBG_TRACE | 3, ("pbuf_take(%p)\n", (void*)f));

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
      q = NULL;
      DEBUGF(PBUF_DEBUG | DBG_TRACE, ("pbuf_take: encountered PBUF_REF %p\n", (void *)p));
      /* allocate a pbuf (w/ payload) fully in RAM */
      /* PBUF_POOL buffers are faster if we can use them */
      if (p->len <= PBUF_POOL_BUFSIZE) {
        q = pbuf_alloc(PBUF_RAW, p->len, PBUF_POOL);
        if (q == NULL) DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_take: Could not allocate PBUF_RAW\n"));
      }
      /* no (large enough) PBUF_POOL was available? retry with PBUF_RAM */
      if (q == NULL) {
        q = pbuf_alloc(PBUF_RAW, p->len, PBUF_RAM);
        if (q == NULL) DEBUGF(PBUF_DEBUG | DBG_TRACE | 2, ("pbuf_take: Could not allocate PBUF_POOL\n"));
      }
      if (q != NULL)
      {  
        /* copy successor */
        q->next = p->next;
        if (prev != NULL)
          /* Break chain and insert new pbuf instead */
          prev->next = q;
        else
          top = q;
        p->next = NULL;
        /* copy pbuf payload */
        memcpy(q->payload, p->payload, p->len);
        q->tot_len = p->tot_len;
        q->len = p->len;
        /* do not copy ref, since someone else might be using the old buffer */
        /* pbuf is not freed, as this is the responsibility of the application */
        DEBUGF(PBUF_DEBUG, ("pbuf_take: replaced PBUF_REF %p with %q\n", (void *)p, (void *)q));
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

