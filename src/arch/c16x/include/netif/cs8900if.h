/*
 * Copyright (c) 2001-2003 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2001-2003 Axon Digital Design B.V., The Netherlands.
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
 * Author: Leon Woestenberg <leon.woestenberg@axon.tv>
 *
 * This is a device driver for the Crystal Semiconductor CS8900
 * chip in combination with the lwIP stack.
 *
 * This is work under development. Please coordinate changes
 * and requests with Leon Woestenberg <leon.woestenberg@axon.tv>
 *
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code under any conditions they seem fit.
 *
 */
#ifndef __NETIF_CS8900IF_H__
#define __NETIF_CS8900IF_H__

#include "lwip/netif.h"

/* interface statistics gathering
 * such as collisions, dropped packets, missed packets
 * 0 = no statistics, minimal memory requirements, no overhead 
 * 1 = statistics on, but some have large granularity (0x200), very low overhead
 * 2 = statistics on, updated on every call to cs8900_service(), low overhead
 */
#define CS8900_STATS 2

struct cs8900if
{
  //struct eth_addr *ethaddr;
  u8_t needs_service;
  u8_t use_polling;
#if (CS8900_STATS > 0)
  u32_t interrupts; // #interrupt requests of cs8900
  u32_t missed; // #packets on medium that could not enter cs8900a chip due to buffer shortage
  u32_t dropped; // #packets dropped after they have been received in chip buffer
  u32_t collisions; // #collisions on medium when transmitting packets 
  u32_t sentpackets; // #number of sent packets
  u32_t sentbytes; // #number of sent bytes
#endif
  /* Add whatever per-interface state that is needed here. */
};

void cs8900if_init(struct netif *);
void cs8900if_service(struct netif *);
void cs8900if_input(struct netif *netif);
err_t cs8900if_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr);

void cs8900_send_debug(unsigned char *p, unsigned int len);

#endif /* __NETIF_CS8900IF_H__ */
