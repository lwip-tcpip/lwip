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

PACK_STRUCT_BEGIN
struct eth_addr {
  PACK_STRUCT_FIELD(u8_t addr[6]);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

PACK_STRUCT_BEGIN
struct eth_hdr {
  PACK_STRUCT_FIELD(struct eth_addr dest);
  PACK_STRUCT_FIELD(struct eth_addr src);
  PACK_STRUCT_FIELD(u16_t type);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

#define ARP_TMR_INTERVAL 10000

#define ETHTYPE_ARP 0x0806
#define ETHTYPE_IP  0x0800

/* Initializes ARP. */
void etharp_init(void);

/* The etharp_tmr() function should be called every ETHARP_TMR_INTERVAL
   microseconds (10 seconds). This function is responsible for
   expiring old entries in the ARP table. */
void etharp_tmr(void);

/* Should be called for all incoming packets of IP kind. The function
   does not alter the packet in any way, it just updates the ARP
   table. After this function has been called, the normal TCP/IP stack
   input function should be called.

   The function may return a pbuf containing a packet that had
   previously been queued for transmission. The device driver must
   transmit this packet onto the network, and call pbuf_free() for the
   pbuf.
*/
struct pbuf *etharp_ip_input(struct netif *netif, struct pbuf *p);

/* Should be called for incoming ARP packets. The pbuf in the argument
   is freed by this function. If the function returns a pbuf (i.e.,
   returns non-NULL), that pbuf constitutes an ARP reply and should be
   sent out on the Ethernet.

   The driver must call pbuf_free() for the returned pbuf when the
   packet has been sent. 
*/
struct pbuf *etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr,
			   struct pbuf *p);


/* The etharp_output() function should be called for all outgoing
   packets. The pbuf returned by the function should be sent out on
   the Ethernet.

   The function prepares the packet for transmission over the Ethernet
   by adding an Ethernet header. If there is no IP -> MAC address
   mapping, the function will queue the outgoing packet and return an
   ARP request.
*/
struct pbuf *etharp_output(struct netif *netif, struct ip_addr *ipaddr,
			   struct pbuf *q);


#endif /* __NETIF_ARP_H__ */
