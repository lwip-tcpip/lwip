/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Swedish Institute
 *      of Computer Science and its contributors.
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 *
 */

#ifndef __NETIF_ETHARP_H__
#define __NETIF_ETHARP_H__

#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"

#include "arch/bpstruct.h"
PACK_STRUCT_BEGIN
struct eth_addr {
  PACK_STRUCT_FIELD(u8_t addr[6]);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#include "arch/epstruct.h"

#include "arch/bpstruct.h"
PACK_STRUCT_BEGIN
struct eth_hdr {
  PACK_STRUCT_FIELD(struct eth_addr dest);
  PACK_STRUCT_FIELD(struct eth_addr src);
  PACK_STRUCT_FIELD(u16_t type);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#include "arch/epstruct.h"

#define ARP_TMR_INTERVAL 10000

#define ETHTYPE_ARP 0x0806
#define ETHTYPE_IP  0x0800

void etharp_init(void);
void etharp_tmr(void);
struct pbuf *etharp_ip_input(struct netif *netif, struct pbuf *p);
struct pbuf *etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr,
			   struct pbuf *p);
struct pbuf *etharp_output(struct netif *netif, struct ip_addr *ipaddr,
			   struct pbuf *q);
struct pbuf *etharp_output_sent(struct pbuf *p);
struct pbuf *etharp_query(struct netif *netif, struct ip_addr *ipaddr);


#endif /* __NETIF_ARP_H__ */
