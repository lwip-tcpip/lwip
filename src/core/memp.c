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

#include "lwip/opt.h"

#include "lwip/memp.h"

#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/raw.h"
#include "lwip/tcp.h"
#include "lwip/api.h"
#include "lwip/api_msg.h"
#include "lwip/tcpip.h"

#include "lwip/sys.h"
#include "lwip/stats.h"

#if ARP_QUEUEING
#include "netif/etharp.h"
#endif

struct memp {
  struct memp *next;
#if MEMP_OVERFLOW_CHECK
  const char *file;
  int line;
#endif /* MEMP_OVERFLOW_CHECK */
};

static struct memp *memp_tab[MEMP_MAX];

#if MEMP_OVERFLOW_CHECK
/* if MEMP_OVERFLOW_CHECK is turned on, we reserve some bytes at the beginning
 * and at the end of each element, initialize them as 0xcd and check
 * them later. */
/* If MEMP_OVERFLOW_CHECK is >= 2, on every call to memp_malloc or memp_free,
 * every single element in each pool is checked!
 * This is VERY SLOW but also very helpful. */
#ifndef MEMP_SANITY_REGION_BEFORE
#define MEMP_SANITY_REGION_BEFORE  MEM_ALIGN_SIZE(16)
#endif /* MEMP_SANITY_REGION_BEFORE*/
#ifndef MEMP_SANITY_REGION_AFTER
#define MEMP_SANITY_REGION_AFTER   MEM_ALIGN_SIZE(16)
#endif /* MEMP_SANITY_REGION_AFTER*/

/* MEMP_SIZE: save space for struct memp and for sanity check */
#define MEMP_SIZE          (MEM_ALIGN_SIZE(sizeof(struct memp)) + MEMP_SANITY_REGION_BEFORE)
#define MEMP_ALIGN_SIZE(x) (MEM_ALIGN_SIZE(x) + MEMP_SANITY_REGION_AFTER)

#else /* MEMP_OVERFLOW_CHECK */

/* No sanity checks
 * We don't need to preserve the struct memp while not allocated, so we
 * can save a little space and set MEMP_SIZE to 0.
 */
#define MEMP_SIZE           0
#define MEMP_ALIGN_SIZE(x) (MEM_ALIGN_SIZE(x))

#endif /* MEMP_OVERFLOW_CHECK */

static const u16_t memp_sizes[MEMP_MAX] = {
  MEMP_ALIGN_SIZE(sizeof(struct pbuf)),
  MEMP_ALIGN_SIZE(sizeof(struct raw_pcb)),
  MEMP_ALIGN_SIZE(sizeof(struct udp_pcb)),
  MEMP_ALIGN_SIZE(sizeof(struct tcp_pcb)),
  MEMP_ALIGN_SIZE(sizeof(struct tcp_pcb_listen)),
  MEMP_ALIGN_SIZE(sizeof(struct tcp_seg)),
  MEMP_ALIGN_SIZE(sizeof(struct netbuf)),
  MEMP_ALIGN_SIZE(sizeof(struct netconn)),
  MEMP_ALIGN_SIZE(sizeof(struct tcpip_msg)),
#if ARP_QUEUEING
  MEMP_ALIGN_SIZE(sizeof(struct etharp_q_entry)),
#endif
  MEMP_ALIGN_SIZE(sizeof(struct pbuf)) + MEMP_ALIGN_SIZE(PBUF_POOL_BUFSIZE),
  MEMP_ALIGN_SIZE(sizeof(struct sys_timeo))
};

static const u16_t memp_num[MEMP_MAX] = {
  MEMP_NUM_PBUF,
  MEMP_NUM_RAW_PCB,
  MEMP_NUM_UDP_PCB,
  MEMP_NUM_TCP_PCB,
  MEMP_NUM_TCP_PCB_LISTEN,
  MEMP_NUM_TCP_SEG,
  MEMP_NUM_NETBUF,
  MEMP_NUM_NETCONN,
  MEMP_NUM_TCPIP_MSG,
#if ARP_QUEUEING
  MEMP_NUM_ARP_QUEUE,
#endif
  PBUF_POOL_SIZE,
  MEMP_NUM_SYS_TIMEOUT
};

#define MEMP_TYPE_SIZE(qty, type) \
  ((qty) * (MEMP_SIZE + MEMP_ALIGN_SIZE(sizeof(type))))

static u8_t memp_memory[MEM_ALIGNMENT - 1 + 
  MEMP_TYPE_SIZE(MEMP_NUM_PBUF, struct pbuf) +
  MEMP_TYPE_SIZE(MEMP_NUM_RAW_PCB, struct raw_pcb) +
  MEMP_TYPE_SIZE(MEMP_NUM_UDP_PCB, struct udp_pcb) +
  MEMP_TYPE_SIZE(MEMP_NUM_TCP_PCB, struct tcp_pcb) +
  MEMP_TYPE_SIZE(MEMP_NUM_TCP_PCB_LISTEN, struct tcp_pcb_listen) +
  MEMP_TYPE_SIZE(MEMP_NUM_TCP_SEG, struct tcp_seg) +
  MEMP_TYPE_SIZE(MEMP_NUM_NETBUF, struct netbuf) +
  MEMP_TYPE_SIZE(MEMP_NUM_NETCONN, struct netconn) +
  MEMP_TYPE_SIZE(MEMP_NUM_TCPIP_MSG, struct tcpip_msg) +
#if ARP_QUEUEING
  MEMP_TYPE_SIZE(MEMP_NUM_ARP_QUEUE, struct etharp_q_entry) +
#endif
  MEMP_TYPE_SIZE(PBUF_POOL_SIZE, struct pbuf) +
                 PBUF_POOL_SIZE * MEMP_ALIGN_SIZE(PBUF_POOL_BUFSIZE) +
  MEMP_TYPE_SIZE(MEMP_NUM_SYS_TIMEOUT, struct sys_timeo)];

#if MEMP_SANITY_CHECK
static int
memp_sanity(void)
{
  s16_t i, c;
  struct memp *m, *n;

  for (i = 0; i < MEMP_MAX; i++) {
    for (m = memp_tab[i]; m != NULL; m = m->next) {
      c = 1;
      for (n = memp_tab[i]; n != NULL; n = n->next) {
        if (n == m && --c < 0) {
          return 0;
        }
      }
    }
  }
  return 1;
}
#endif /* MEMP_SANITY_CHECK*/
#if MEMP_OVERFLOW_CHECK
static void
memp_overflow_check_single(struct memp *p, u16_t memp_size)
{
  u16_t k;
  u8_t *m;
#if MEMP_SANITY_REGION_BEFORE > 0
  m = (u8_t*)p + MEMP_SIZE - MEMP_SANITY_REGION_BEFORE;
  for (k = 0; k < MEMP_SANITY_REGION_BEFORE; k++) {
    if (m[k] != 0xcd) {
      LWIP_ASSERT("detected memp underflow!", 0);
    }
  }
#endif
#if MEMP_SANITY_REGION_AFTER > 0
  m = (u8_t*)p + MEMP_SIZE + memp_size - MEMP_SANITY_REGION_AFTER;
  for (k = 0; k < MEMP_SANITY_REGION_AFTER; k++) {
    if (m[k] != 0xcd) {
      LWIP_ASSERT("detected memp overflow!", 0);
    }
  }
#endif
}
static void
memp_overflow_check(void)
{
  u16_t i, j;
  struct memp *p;

  p = MEM_ALIGN(memp_memory);
  for (i = 0; i < MEMP_MAX; ++i) {
    p = p;
    for (j = 0; j < memp_num[i]; ++j) {
      memp_overflow_check_single(p, memp_sizes[i]);
      p = (struct memp*)((u8_t*)p + MEMP_SIZE + memp_sizes[i]);
    }
  }
}
static void
memp_overflow_init(void)
{
  u16_t i, j;
  struct memp *p;
  u8_t *m;

  p = MEM_ALIGN(memp_memory);
  for (i = 0; i < MEMP_MAX; ++i) {
    p = p;
    for (j = 0; j < memp_num[i]; ++j) {
#if MEMP_SANITY_REGION_BEFORE > 0
      m = (u8_t*)p + MEMP_SIZE - MEMP_SANITY_REGION_BEFORE;
      memset(m, 0xcd, MEMP_SANITY_REGION_BEFORE);
#endif
#if MEMP_SANITY_REGION_AFTER > 0
      m = (u8_t*)p + MEMP_SIZE + memp_sizes[i] - MEMP_SANITY_REGION_AFTER;
      memset(m, 0xcd, MEMP_SANITY_REGION_AFTER);
#endif
      p = (struct memp*)((u8_t*)p + MEMP_SIZE + memp_sizes[i]);
    }
  }
}
#endif /* MEMP_OVERFLOW_CHECK */

void
memp_init(void)
{
  struct memp *memp;
  u16_t i, j;

#if MEMP_STATS
  for (i = 0; i < MEMP_MAX; ++i) {
    lwip_stats.memp[i].used = lwip_stats.memp[i].max =
      lwip_stats.memp[i].err = 0;
    lwip_stats.memp[i].avail = memp_num[i];
  }
#endif /* MEMP_STATS */

  memp = MEM_ALIGN(memp_memory);
  for (i = 0; i < MEMP_MAX; ++i) {
    memp_tab[i] = NULL;
    for (j = 0; j < memp_num[i]; ++j) {
      memp->next = memp_tab[i];
      memp_tab[i] = memp;
      memp = (struct memp *)((u8_t *)memp + MEMP_SIZE + memp_sizes[i]);
    }
  }
#if MEMP_OVERFLOW_CHECK
  memp_overflow_init();
  /* check everything a first time to see if it worked */
  memp_overflow_check();
#endif /* MEMP_OVERFLOW_CHECK */
}

void *
#if MEMP_OVERFLOW_CHECK
memp_malloc_fn(memp_t type, const char* file, const int line)
#else
memp_malloc(memp_t type)
#endif
{
  struct memp *memp;
  SYS_ARCH_DECL_PROTECT(old_level);
 
  LWIP_ASSERT("memp_malloc: type < MEMP_MAX", type < MEMP_MAX);

  SYS_ARCH_PROTECT(old_level);
#if MEMP_OVERFLOW_CHECK >= 2
  memp_overflow_check();
#endif /* MEMP_OVERFLOW_CHECK >= 2 */

  memp = memp_tab[type];
  
  if (memp != NULL) {    
    memp_tab[type] = memp->next;    
    memp->next = NULL;
#if MEMP_OVERFLOW_CHECK
    memp->file = file;
    memp->line = line;
#endif /* MEMP_OVERFLOW_CHECK */
#if MEMP_STATS
    ++lwip_stats.memp[type].used;
    if (lwip_stats.memp[type].used > lwip_stats.memp[type].max) {
      lwip_stats.memp[type].max = lwip_stats.memp[type].used;
    }
#endif /* MEMP_STATS */
    LWIP_ASSERT("memp_malloc: memp properly aligned",
                ((mem_ptr_t)memp % MEM_ALIGNMENT) == 0);
  } else {
    LWIP_DEBUGF(MEMP_DEBUG | 2, ("memp_malloc: out of memory in pool %"S16_F"\n", type));
#if MEMP_STATS
    ++lwip_stats.memp[type].err;
#endif /* MEMP_STATS */
  }

  SYS_ARCH_UNPROTECT(old_level);

  return (void*)((u8_t*)memp + MEMP_SIZE);
}

void
memp_free(memp_t type, void *mem)
{
  struct memp *memp;
  SYS_ARCH_DECL_PROTECT(old_level);

  if (mem == NULL) {
    return;
  }
  LWIP_ASSERT("memp_free: mem properly aligned",
                ((mem_ptr_t)mem % MEM_ALIGNMENT) == 0);

  memp = (struct memp *)((u8_t*)mem - MEMP_SIZE);

  SYS_ARCH_PROTECT(old_level);
#if MEMP_OVERFLOW_CHECK
#if MEMP_OVERFLOW_CHECK >= 2
  memp_overflow_check();
#else
  memp_overflow_check_single(memp, memp_sizes[type]);
#endif /* MEMP_OVERFLOW_CHECK >= 2 */
#endif /* MEMP_OVERFLOW_CHECK */

#if MEMP_STATS
  lwip_stats.memp[type].used--; 
#endif /* MEMP_STATS */
  
  memp->next = memp_tab[type]; 
  memp_tab[type] = memp;

#if MEMP_SANITY_CHECK
  LWIP_ASSERT("memp sanity", memp_sanity());
#endif /* MEMP_SANITY_CHECK */

  SYS_ARCH_UNPROTECT(old_level);
}
