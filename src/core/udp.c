/*
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
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
 * $Id: udp.c,v 1.3 2002/11/21 10:32:19 likewise Exp $
 */

/*-----------------------------------------------------------------------------------*/
/* udp.c
 *
 * The code for the User Datagram Protocol UDP.
 *
 */
/*-----------------------------------------------------------------------------------*/
#include "lwip/debug.h"

#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/icmp.h"

#include "lwip/stats.h"

#include "arch/perf.h"
#if LWIP_SNMP > 0
#  include "snmp.h"
#endif

/*-----------------------------------------------------------------------------------*/

/* The list of UDP PCBs. */
#if LWIP_UDP
static struct udp_pcb *udp_pcbs = NULL;

static struct udp_pcb *pcb_cache = NULL;
#endif /* LWIP_UDP */

#if UDP_DEBUG
int udp_debug_print(struct udp_hdr *udphdr);
#endif /* UDP_DEBUG */
	  
/*-----------------------------------------------------------------------------------*/
void
udp_init(void)
{
#if LWIP_UDP
  udp_pcbs = pcb_cache = NULL;
#endif /* LWIP_UDP */
}

#if LWIP_UDP
/*-----------------------------------------------------------------------------------*/
/* udp_lookup:
 *
 * An experimental feature that will be changed in future versions. Do
 * not depend on it yet...
 */
/*-----------------------------------------------------------------------------------*/
#ifdef LWIP_DEBUG
u8_t
udp_lookup(struct ip_hdr *iphdr, struct netif *inp)
{
  struct udp_pcb *pcb;
  struct udp_hdr *udphdr;
  u16_t src, dest;
  
  PERF_START;
  
  udphdr = (struct udp_hdr *)(u8_t *)iphdr + IPH_HL(iphdr) * 4/sizeof(u8_t);

  src = NTOHS(udphdr->src);
  dest = NTOHS(udphdr->dest);
  
  pcb = pcb_cache;
  if(pcb != NULL &&
     pcb->remote_port == src &&
     pcb->local_port == dest &&
     (ip_addr_isany(&pcb->remote_ip) ||
      ip_addr_cmp(&(pcb->remote_ip), &(iphdr->src))) &&
     (ip_addr_isany(&pcb->local_ip) ||
      ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
    return 1;
  } else {  
    for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      if(pcb->remote_port == src &&
	 pcb->local_port == dest &&
	 (ip_addr_isany(&pcb->remote_ip) ||
	  ip_addr_cmp(&(pcb->remote_ip), &(iphdr->src))) &&
	 (ip_addr_isany(&pcb->local_ip) ||
	  ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
	pcb_cache = pcb;
	break;
      }
    }

    if(pcb == NULL) {
      for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
	if(pcb->remote_port == 0 &&
	   pcb->local_port == dest &&
	   (ip_addr_isany(&pcb->remote_ip) ||
	    ip_addr_cmp(&(pcb->remote_ip), &(iphdr->src))) &&
	   (ip_addr_isany(&pcb->local_ip) ||
	    ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
	  break;
	}
      }
    }
  }

  PERF_STOP("udp_lookup");
  
  if(pcb != NULL) {
    return 1;
  } else {  
    return 1;
  }
}
#endif /* LWIP_DEBUG */
/*-----------------------------------------------------------------------------------*/
void
udp_input(struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;  
  struct udp_pcb *pcb;
  struct ip_hdr *iphdr;
  u16_t src, dest;
  
  PERF_START;
  
#ifdef UDP_STATS
  ++stats.udp.recv;
#endif /* UDP_STATS */

  iphdr = p->payload;

  pbuf_header(p, -(UDP_HLEN + IPH_HL(iphdr) * 4));

  udphdr = (struct udp_hdr *)((u8_t *)p->payload - UDP_HLEN);
  
  DEBUGF(UDP_DEBUG, ("udp_input: received datagram of length %d\n", p->tot_len));
	
  src = NTOHS(udphdr->src);
  dest = NTOHS(udphdr->dest);

#if UDP_DEBUG
  udp_debug_print(udphdr);
#endif /* UDP_DEBUG */
  
  /* Demultiplex packet. First, go for a perfect match. */
  for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    DEBUGF(UDP_DEBUG, ("udp_input: pcb local port %d (dgram %d)\n",
		       pcb->local_port, ntohs(udphdr->dest)));
    if(pcb->remote_port == src &&
       pcb->local_port == dest &&
       (ip_addr_isany(&pcb->remote_ip) ||
	ip_addr_cmp(&(pcb->remote_ip), &(iphdr->src))) &&
       (ip_addr_isany(&pcb->local_ip) ||
	ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
      break;
    }
  }

  if(pcb == NULL) {
    for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      DEBUGF(UDP_DEBUG, ("udp_input: pcb local port %d (dgram %d)\n",
			 pcb->local_port, dest));
      if(pcb->local_port == dest &&
	 (ip_addr_isany(&pcb->remote_ip) ||
	  ip_addr_cmp(&(pcb->remote_ip), &(iphdr->src))) &&
	 (ip_addr_isany(&pcb->local_ip) ||
	  ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
	break;
      }      
    }
  }


  /* Check checksum if this is a match or if it was directed at us. */
  /*  if(pcb != NULL ||
      ip_addr_cmp(&inp->ip_addr, &iphdr->dest)) {*/
  if(pcb != NULL) {
    DEBUGF(UDP_DEBUG, ("udp_input: calculating checksum\n"));
    pbuf_header(p, UDP_HLEN);    
#ifdef IPv6
    if(iphdr->nexthdr == IP_PROTO_UDPLITE) {    
#else
    if(IPH_PROTO(iphdr) == IP_PROTO_UDPLITE) {    
#endif /* IPv4 */
      /* Do the UDP Lite checksum */
      if(inet_chksum_pseudo(p, (struct ip_addr *)&(iphdr->src),
			    (struct ip_addr *)&(iphdr->dest),
			    IP_PROTO_UDPLITE, ntohs(udphdr->len)) != 0) {
	DEBUGF(UDP_DEBUG, ("udp_input: UDP Lite datagram discarded due to failing checksum\n"));
#ifdef UDP_STATS
	++stats.udp.chkerr;
	++stats.udp.drop;
#endif /* UDP_STATS */
#if LWIP_SNMP > 0
    snmp_inc_udpinerrors();
#endif
	pbuf_free(p);
	goto end;
      }
    } else {
      if(udphdr->chksum != 0) {
	if(inet_chksum_pseudo(p, (struct ip_addr *)&(iphdr->src),
			      (struct ip_addr *)&(iphdr->dest),
			      IP_PROTO_UDP, p->tot_len) != 0) {
	  DEBUGF(UDP_DEBUG, ("udp_input: UDP datagram discarded due to failing checksum\n"));
	  
#ifdef UDP_STATS
	  ++stats.udp.chkerr;
	  ++stats.udp.drop;
#endif /* UDP_STATS */
#if LWIP_SNMP > 0
    snmp_inc_udpinerrors();
#endif
	  pbuf_free(p);
	  goto end;
	}
      }
    }
    pbuf_header(p, -UDP_HLEN);    
    if(pcb != NULL) {
#if LWIP_SNMP > 0
      snmp_inc_udpindatagrams();
#endif
      pcb->recv(pcb->recv_arg, pcb, p, &(iphdr->src), src);
    } else {
      DEBUGF(UDP_DEBUG, ("udp_input: not for us.\n"));
      
      /* No match was found, send ICMP destination port unreachable unless
	 destination address was broadcast/multicast. */
      
      if(!ip_addr_isbroadcast(&iphdr->dest, &inp->netmask) &&
	 !ip_addr_ismulticast(&iphdr->dest)) {
	
	/* deconvert from host to network byte order */
	udphdr->src = htons(udphdr->src);
	udphdr->dest = htons(udphdr->dest); 
	
	/* adjust pbuf pointer */
	p->payload = iphdr;
	icmp_dest_unreach(p, ICMP_DUR_PORT);
      }
#ifdef UDP_STATS
      ++stats.udp.proterr;
      ++stats.udp.drop;
#endif /* UDP_STATS */
#if LWIP_SNMP > 0
    snmp_inc_udpnoports();
#endif
      pbuf_free(p);
    }
  } else {
    pbuf_free(p);
  }
  end:
    
  PERF_STOP("udp_input");
}
/*-----------------------------------------------------------------------------------*/
err_t
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
  struct udp_hdr *udphdr;
  struct netif *netif;
  struct ip_addr *src_ip;
  err_t err;
  struct pbuf *hdr;


  DEBUGF(UDP_DEBUG, ("udp_send"));
  /* hdr will point to the UDP header pbuf if an extra header pbuf has
     to be allocated. */
  hdr = NULL;
  
  if(pbuf_header(p, UDP_HLEN)) {
    hdr = pbuf_alloc(PBUF_IP, UDP_HLEN, PBUF_RAM);
    if(hdr == NULL) {
      return ERR_MEM;
    }
    pbuf_chain(hdr, p);
    p = hdr;
  }
  DEBUGF(UDP_DEBUG, ("udp_send: got pbuf"));

  udphdr = p->payload;
  udphdr->src = htons(pcb->local_port);
  udphdr->dest = htons(pcb->remote_port);
  udphdr->chksum = 0x0000;

  if((netif = ip_route(&(pcb->remote_ip))) == NULL) {
    DEBUGF(UDP_DEBUG, ("udp_send: No route to 0x%lx\n", pcb->remote_ip.addr));
#ifdef UDP_STATS
    ++stats.udp.rterr;
#endif /* UDP_STATS */
    return ERR_RTE;
  }

  if(ip_addr_isany(&pcb->local_ip)) {
    src_ip = &(netif->ip_addr);
  } else {
    src_ip = &(pcb->local_ip);
  }
  
  DEBUGF(UDP_DEBUG, ("udp_send: sending datagram of length %d\n", p->tot_len));
  
  if(pcb->flags & UDP_FLAGS_UDPLITE) {
    DEBUGF(UDP_DEBUG, ("udp_send: UDP LITE packet length %u", p->tot_len));
    udphdr->len = htons(pcb->chksum_len);
    /* calculate checksum */
    udphdr->chksum = inet_chksum_pseudo(p, src_ip, &(pcb->remote_ip),
					IP_PROTO_UDP, pcb->chksum_len);
    if(udphdr->chksum == 0x0000) {
      udphdr->chksum = 0xffff;
    }
    err = ip_output_if(p, src_ip, &pcb->remote_ip, UDP_TTL, IP_PROTO_UDPLITE, netif);    
#if LWIP_SNMP > 0
    snmp_inc_udpoutdatagrams();
#endif
  } else {
    DEBUGF(UDP_DEBUG, ("udp_send: UDP packet length %u", p->tot_len));
    udphdr->len = htons(p->tot_len);
    /* calculate checksum */
    if((pcb->flags & UDP_FLAGS_NOCHKSUM) == 0) {
      udphdr->chksum = inet_chksum_pseudo(p, src_ip, &pcb->remote_ip,
					  IP_PROTO_UDP, p->tot_len);
      if(udphdr->chksum == 0x0000) {
	udphdr->chksum = 0xffff;
      }
    }
    DEBUGF(UDP_DEBUG, ("udp_send: UDP checksum %x", udphdr->chksum));
#if LWIP_SNMP > 0
    snmp_inc_udpoutdatagrams();
#endif
    DEBUGF(UDP_DEBUG, ("udp_send: ip_output_if(,,,,IP_PROTO_UDP,)"));
    err = ip_output_if(p, src_ip, &pcb->remote_ip, UDP_TTL, IP_PROTO_UDP, netif);    
  }

  if(hdr != NULL) {
    pbuf_dechain(hdr);
    pbuf_free(hdr);
  }
  
#ifdef UDP_STATS
  ++stats.udp.xmit;
#endif /* UDP_STATS */
  return err;
}
/*-----------------------------------------------------------------------------------*/
err_t
udp_bind(struct udp_pcb *pcb, struct ip_addr *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  ip_addr_set(&pcb->local_ip, ipaddr);
  pcb->local_port = port;

  /* Insert UDP PCB into the list of active UDP PCBs. */
  for(ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    if(pcb == ipcb) {
      /* Already on the list, just return. */
      return ERR_OK;
    }
  }
  /* We need to place the PCB on the list. */
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;

  DEBUGF(UDP_DEBUG, ("udp_bind: bound to port %d\n", port));
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
err_t
udp_connect(struct udp_pcb *pcb, struct ip_addr *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  ip_addr_set(&pcb->remote_ip, ipaddr);
  pcb->remote_port = port;

  /* Insert UDP PCB into the list of active UDP PCBs. */
  for(ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    if(pcb == ipcb) {
      /* Already on the list, just return. */
      return ERR_OK;
    }
  }
  /* We need to place the PCB on the list. */
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
void
udp_recv(struct udp_pcb *pcb,
	 void (* recv)(void *arg, struct udp_pcb *upcb, struct pbuf *p,
		       struct ip_addr *addr, u16_t port),
	 void *recv_arg)
{
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}
/*-----------------------------------------------------------------------------------*/
void
udp_remove(struct udp_pcb *pcb)
{
  struct udp_pcb *pcb2;
  
  if(udp_pcbs == pcb) {
    udp_pcbs = udp_pcbs->next;
  } else for(pcb2 = udp_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
    if(pcb2->next != NULL && pcb2->next == pcb) {
      pcb2->next = pcb->next;
    }
  }

  memp_free(MEMP_UDP_PCB, pcb);  
}
/*-----------------------------------------------------------------------------------*/
struct udp_pcb *
udp_new(void) {
  struct udp_pcb *pcb;
  pcb = memp_malloc(MEMP_UDP_PCB);
  if(pcb != NULL) {
    bzero(pcb, sizeof(struct udp_pcb));
    return pcb;
  }
  return NULL;

}
/*-----------------------------------------------------------------------------------*/
#if UDP_DEBUG
int
udp_debug_print(struct udp_hdr *udphdr)
{
  DEBUGF(UDP_DEBUG, ("UDP header:\n"));
  DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(UDP_DEBUG, ("|     %5d     |     %5d     | (src port, dest port)\n",
		     ntohs(udphdr->src), ntohs(udphdr->dest)));
  DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(UDP_DEBUG, ("|     %5d     |     0x%04x    | (len, chksum)\n",
		     ntohs(udphdr->len), ntohs(udphdr->chksum)));
  DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  return 0;
}
#endif /* UDP_DEBUG */
/*-----------------------------------------------------------------------------------*/
#endif /* LWIP_UDP */









