/**
 * @file
 * Raw Access module
 *
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

/*-----------------------------------------------------------------------------------*/
/* raw.c
 *
 * The code for the Raw Access to the IP
 *
 */
/*-----------------------------------------------------------------------------------*/
#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/raw.h"

#include "lwip/stats.h"

#include "arch/perf.h"
#include "lwip/snmp.h"

#if LWIP_RAW
/* The list of RAW PCBs */

static struct raw_pcb *raw_pcbs = NULL;

/*-----------------------------------------------------------------------------------*/
void
raw_init(void)
{
  raw_pcbs = NULL;
}

/**
 * Determine if in incoming IP packet is covered by a RAW pcb and
 * and process it if possible
 *
 * Given an incoming UDP datagram (as a chain of pbufs) this function
 * finds a corresponding UDP PCB and
 *
 * @param pbuf pbuf to be demultiplexed to a UDP PCB.
 * @param netif network interface on which the datagram was received.
 * @return 0 if packet cannot be handled (pbuf needs to be freed then)
 *         or 1 if the packet has been processed
 *
 */
int
raw_input(struct pbuf *p, struct netif *inp)
{
  struct raw_pcb *pcb;
  struct ip_hdr *iphdr;
  int proto;
  int rc = 0;

  iphdr = p->payload;
  proto = IPH_PROTO(iphdr);

  for(pcb = raw_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->protocol == proto) {
      if (pcb->recv) {
        pcb->recv(pcb->recv_arg, pcb, p, &(iphdr->src));
      }
      pbuf_free(p);
      rc = 1;
      break;
    }
  }
  return rc;
}

/**
 * Bind a RAW PCB.
 *
 * @param pcb RAW PCB to be bound with a local address ipaddr.
 * @param ipaddr local IP address to bind with. Use IP_ADDR_ANY to
 * bind to all local interfaces.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_USE. The specified ipaddr is already bound to by
 * another RAW PCB.
 *
 * @see raw_disconnect()
 */
err_t
raw_bind(struct raw_pcb *pcb, struct ip_addr *ipaddr)
{
  ip_addr_set(&pcb->local_ip, ipaddr);
  return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/
void
raw_recv(struct raw_pcb *pcb,
   void (* recv)(void *arg, struct raw_pcb *upcb, struct pbuf *p,
           struct ip_addr *addr),
   void *recv_arg)
{
  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}

/**
 * Send the raw IP packet to the given address. Note that actually you cannot
 * modify the IP headers (this is inconsitent with the receive callback where
 * you actually get the IP headers), you can only specifiy the ip payload here.
 * It requires some more changes in LWIP. (there will be a raw_send() function
 * then)
 *
 * @param pcb the raw pcb which to send
 * @param p the ip payload to send
 * @param ipaddr the destination address of the whole IP packet
 *
 */
err_t
raw_send_payload(struct raw_pcb *pcb, struct pbuf *p, struct ip_addr *ipaddr)
{
  err_t err;
  struct netif *netif;
  struct ip_addr *src_ip;

  LWIP_DEBUGF(UDP_DEBUG | DBG_TRACE | 3, ("raw_send_payload\n"));

  if ((netif = ip_route(ipaddr)) == NULL) {
    LWIP_DEBUGF(UDP_DEBUG | 1, ("raw_send_payload: No route to 0x%lx\n", ipaddr));
#ifdef RAW_STATS
/*    ++lwip_stats.raw.rterr;*/
#endif /* UDP_STATS */
    return ERR_RTE;
  }

  if (ip_addr_isany(&pcb->local_ip)) {
    /* use outgoing network interface IP address as source address */
    src_ip = &(netif->ip_addr);
  } else {
    /* use UDP PCB local IP address as source address */
    src_ip = &(pcb->local_ip);
  }

  err = ip_output_if (p, src_ip, ipaddr, 64, pcb->tos, pcb->protocol, netif);

  return ERR_OK;
}

/**
 * Remove an RAW PCB.
 *
 * @param pcb RAW PCB to be removed. The PCB is removed from the list of
 * RAW PCB's and the data structure is freed from memory.
 *
 * @see raw_new()
 */
void
raw_remove(struct raw_pcb *pcb)
{
  struct raw_pcb *pcb2;
  /* pcb to be removed is first in list? */
  if (raw_pcbs == pcb) {
    /* make list start at 2nd pcb */
    raw_pcbs = raw_pcbs->next;
  /* pcb not 1st in list */
  } else for(pcb2 = raw_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
    /* find pcb in udp_pcbs list */
    if (pcb2->next != NULL && pcb2->next == pcb) {
      /* remove pcb from list */
      pcb2->next = pcb->next;
    }
  }
  memp_free(MEMP_RAW_PCB, pcb);
}

/**
 * Create a RAW PCB.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param proto the protocol number of the IPs payload (e.g. IP_PROTO_ICMP)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_new(u16_t proto) {
  struct raw_pcb *pcb;

  LWIP_DEBUGF(RAW_DEBUG | DBG_TRACE | 3, ("raw_new\n"));

  pcb = memp_malloc(MEMP_RAW_PCB);
  /* could allocate RAW PCB? */
  if (pcb != NULL) {
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct raw_pcb));
    pcb->protocol = proto;
    pcb->next = raw_pcbs;
    raw_pcbs = pcb;
  }

  return pcb;
}

#endif /* LWIP_RAW */
