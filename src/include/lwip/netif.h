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
#ifndef __LWIP_NETIF_H__
#define __LWIP_NETIF_H__

#include "lwip/opt.h"

#include "lwip/err.h"

#include "lwip/ip_addr.h"

#include "lwip/inet.h"
#include "lwip/pbuf.h"

/** must be the maximum of all used hardware address lengths */
#define NETIF_HWADDR_LEN 6

struct netif {
  struct netif *next;
  u8_t num;
  u16_t mtu;
  struct ip_addr ip_addr;
  struct ip_addr netmask;  /* netmask in network byte order */
  struct ip_addr gw;
  unsigned char hwaddr[NETIF_HWADDR_LEN];

  /* This function is called by the network device driver
     when it wants to pass a packet to the TCP/IP stack. */
  err_t (* input)(struct pbuf *p, struct netif *inp);

  /* The following two fields should be filled in by the
     initialization function for the device driver. */

  char name[2];
  /* This function is called by the IP module when it wants
     to send a packet on the interface. This function typically
     first resolves the hardware address, then sends the packet. */
  err_t (* output)(struct netif *netif, struct pbuf *p,
		   struct ip_addr *ipaddr);
  /* This function is called by the ARP module when it wants
     to send a packet on the interface. This function outputs
     the pbuf on the link medium. */
  err_t (* linkoutput)(struct netif *netif, struct pbuf *p);

  /* This field can be set by the device driver and could point
     to state information for the device. */
  void *state;
};

/** The list of network interfaces. */
extern struct netif *netif_list;
/** The default network interface. */
extern struct netif *netif_default;

/* netif_init() must be called first. */
void netif_init(void);

struct netif *netif_add(struct ip_addr *ipaddr, struct ip_addr *netmask,
			struct ip_addr *gw,
			void (* init)(struct netif *netif),
			err_t (* input)(struct pbuf *p, struct netif *netif));

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
struct netif *netif_find(char *name);

void netif_set_default(struct netif *netif);

void netif_set_ipaddr(struct netif *netif, struct ip_addr *ipaddr);
void netif_set_netmask(struct netif *netif, struct ip_addr *netmast);
void netif_set_gw(struct netif *netif, struct ip_addr *gw);

#endif /* __LWIP_NETIF_H__ */
