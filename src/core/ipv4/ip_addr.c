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

#include "lwip/ip_addr.h"
#include "lwip/inet.h"

/* used by IP_ADDR_ANY and IP_ADDR_BROADCAST in ip_addr.h */
const struct ip_addr ip_addr_any = { 0x00000000UL };
const struct ip_addr ip_addr_broadcast = { 0xffffffffUL };

/* work in progress - meant to replace ip_addr.h macro
 * as it does not support non-broadcast interfaces.
 * lwip-devel 18-2-2004
 */
#if 0
#include "lwip/netif.h"

bool ip_addr_isbroadcast(ip_addr *addr1, struct netif *netif)

bool ip_addr_isbroadcast(addr1, netif)
{
  /* all ones (broadcast) or all zeroes (old skool broadcast) */
  if (addr1->addr == ip_addr_broadcast.ip_addr) ||
      addr1->addr == ip_addr_any.ip_addr))
    return 1;
  /* no broadcast support on this network interface
   * we cannot proceed matching against broadcast addresses */
  else if (netif->flags &= NETIF_FLAG_BROADCAST == 0)
    return 0;
  /* address matches network interface address exactly? */
  else if (netif->ip_addr.addr == addr1->addr)
    return 0;
  /* host identifier bits are all ones? => broadcast address */
  else if (~netif->netmask.addr & addr1->addr ==
           ~netif->netmask.addr & ip_addr_broadcast.ip_addr)
    return 1;
  else
    return 0;
}
#endif