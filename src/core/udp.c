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
#include "lwip/snmp.h"

/*-----------------------------------------------------------------------------------*/

/* The list of UDP PCBs. */
#if LWIP_UDP
/*static*/ struct udp_pcb *udp_pcbs = NULL;

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
  (void)inp;

    udphdr = (struct udp_hdr *)(u8_t *)iphdr + IPH_HL(iphdr) * 4;

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
  }
  else {  
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
  }
  else {  
    return 1;
  }
}
#endif /* LWIP_DEBUG */
/**
 * Process an incoming UDP datagram.
 *
 * Given an incoming UDP datagram (as a chain of pbufs) this function
 * finds a corresponding UDP PCB and
 *
 * @param pbuf pbuf to be demultiplexed to a UDP PCB.
 * @param netif network interface on which the datagram was received.
 *
 * @see udp_disconnect()
 */
void
udp_input(struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;  
  struct udp_pcb *pcb;
  struct ip_hdr *iphdr;
  u16_t src, dest;
  
  PERF_START;
  
#ifdef UDP_STATS
  ++lwip_stats.udp.recv;
#endif /* UDP_STATS */

  iphdr = p->payload;

  pbuf_header(p, -(UDP_HLEN + IPH_HL(iphdr) * 4));

  udphdr = (struct udp_hdr *)((u8_t *)p->payload - UDP_HLEN);
  
  DEBUGF(UDP_DEBUG, ("udp_input: received datagram of length %u\n", p->tot_len));
	
  src = NTOHS(udphdr->src);
  dest = NTOHS(udphdr->dest);

#if UDP_DEBUG
  udp_debug_print(udphdr);
#endif /* UDP_DEBUG */

  /* print the UDP source and destination */
  DEBUGF(UDP_DEBUG, ("udp (%u.%u.%u.%u, %u) <-- (%u.%u.%u.%u, %u)\n",
    ip4_addr1(&iphdr->dest), ip4_addr2(&iphdr->dest),
    ip4_addr3(&iphdr->dest), ip4_addr4(&iphdr->dest), ntohs(udphdr->dest),
    ip4_addr1(&iphdr->src), ip4_addr2(&iphdr->src),
    ip4_addr3(&iphdr->src), ip4_addr4(&iphdr->src), ntohs(udphdr->src)));
  /* Iterate through the UDP pcb list for a fully matching pcb */
  for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    /* print the PCB local and remote address */
    DEBUGF(UDP_DEBUG, ("pcb (%u.%u.%u.%u, %u) --- (%u.%u.%u.%u, %u)\n",
      ip4_addr1(&pcb->local_ip), ip4_addr2(&pcb->local_ip),
      ip4_addr3(&pcb->local_ip), ip4_addr4(&pcb->local_ip), pcb->local_port,
      ip4_addr1(&pcb->remote_ip), ip4_addr2(&pcb->remote_ip),
      ip4_addr3(&pcb->remote_ip), ip4_addr4(&pcb->remote_ip), pcb->remote_port));

       /* PCB remote port matches UDP source port? */
    if((pcb->remote_port == src) &&
       /* PCB local port matches UDP destination port? */
       (pcb->local_port == dest) &&
       /* accepting from any remote (source) IP address? or... */
       (ip_addr_isany(&pcb->remote_ip) ||
       /* PCB remote IP address matches UDP source IP address? */
      	ip_addr_cmp(&(pcb->remote_ip), &(iphdr->src))) &&
       /* accepting on any local (netif) IP address? or... */
       (ip_addr_isany(&pcb->local_ip) ||
       /* PCB local IP address matches UDP destination IP address? */
      	ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
      break;
    }
  }
  /* no fully matching pcb found? then look for an unconnected pcb */
  if (pcb == NULL) {
    /* Iterate through the UDP PCB list for a pcb that matches
       the local address. */
    for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      DEBUGF(UDP_DEBUG, ("pcb (%u.%u.%u.%u, %u) --- (%u.%u.%u.%u, %u)\n",
        ip4_addr1(&pcb->local_ip), ip4_addr2(&pcb->local_ip),
        ip4_addr3(&pcb->local_ip), ip4_addr4(&pcb->local_ip), pcb->local_port,
        ip4_addr1(&pcb->remote_ip), ip4_addr2(&pcb->remote_ip),
        ip4_addr3(&pcb->remote_ip), ip4_addr4(&pcb->remote_ip), pcb->remote_port));
      /* unconnected? */
      if(((pcb->flags & UDP_FLAGS_CONNECTED) == 0) &&
     	  /* destination port matches? */
	      (pcb->local_port == dest) &&
	      /* not bound to a specific (local) interface address? or... */
	      (ip_addr_isany(&pcb->local_ip) ||
	      /* ...matching interface address? */
	      ip_addr_cmp(&(pcb->local_ip), &(iphdr->dest)))) {
	       break;
      }      
    }
  }

  /* Check checksum if this is a match or if it was directed at us. */
  if(pcb != NULL  || ip_addr_cmp(&inp->ip_addr, &iphdr->dest)) 
    {
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
	++lwip_stats.udp.chkerr;
	++lwip_stats.udp.drop;
#endif /* UDP_STATS */
  snmp_inc_udpinerrors();
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
	  ++lwip_stats.udp.chkerr;
	  ++lwip_stats.udp.drop;
#endif /* UDP_STATS */
    snmp_inc_udpinerrors();
	  pbuf_free(p);
	  goto end;
	}
      }
    }
    pbuf_header(p, -UDP_HLEN);    
    if(pcb != NULL) {
      snmp_inc_udpindatagrams();
      pcb->recv(pcb->recv_arg, pcb, p, &(iphdr->src), src);
    } else {
      DEBUGF(UDP_DEBUG, ("udp_input: not for us.\n"));
      
      /* No match was found, send ICMP destination port unreachable unless
	 destination address was broadcast/multicast. */
      
      if(!ip_addr_isbroadcast(&iphdr->dest, &inp->netmask) &&
	 !ip_addr_ismulticast(&iphdr->dest)) {
	
	/* adjust pbuf pointer */
	p->payload = iphdr;
	icmp_dest_unreach(p, ICMP_DUR_PORT);
      }
#ifdef UDP_STATS
      ++lwip_stats.udp.proterr;
      ++lwip_stats.udp.drop;
#endif /* UDP_STATS */
    snmp_inc_udpnoports();
      pbuf_free(p);
    }
  } else {
    pbuf_free(p);
  }
  end:
    
  PERF_STOP("udp_input");
}
/**
 * Send data using UDP. 
 *
 * @param pcb UDP PCB used to send the data.
 * @param pbuf chain of pbuf's to be sent.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_MEM. Out of memory.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB.
 * 
 * @see udp_disconnect()
 */
err_t
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
  struct udp_hdr *udphdr;
  struct netif *netif;
  struct ip_addr *src_ip;
  err_t err;
  struct pbuf *hdr;

  DEBUGF(UDP_DEBUG, ("udp_send\n"));

  if(pcb->local_port == 0) {
    err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if(err != ERR_OK)
      return err;
  }

  /* hdr will point to the UDP header pbuf if an extra header pbuf has
     to be allocated. */
  hdr = NULL;
  
  /* succeeding in adding an UDP header to first given pbuf in chain? */
  if(pbuf_header(p, UDP_HLEN)) {
    /* allocate header in new pbuf */
    hdr = pbuf_alloc(PBUF_IP, UDP_HLEN, PBUF_RAM);
    /* new header pbuf could not be allocated? */
    if(hdr == NULL) {
      return ERR_MEM;
    }
    /* chain header in front of given pbuf */
    pbuf_chain(hdr, p);
    /* have p point to header pbuf */
    p = hdr;
  }
  DEBUGF(UDP_DEBUG, ("udp_send: got pbuf\n"));

  udphdr = p->payload;
  udphdr->src = htons(pcb->local_port);
  udphdr->dest = htons(pcb->remote_port);
  udphdr->chksum = 0x0000;

  if((netif = ip_route(&(pcb->remote_ip))) == NULL) {
    DEBUGF(UDP_DEBUG, ("udp_send: No route to 0x%lx\n", pcb->remote_ip.addr));
#ifdef UDP_STATS
    ++lwip_stats.udp.rterr;
#endif /* UDP_STATS */
    return ERR_RTE;
  }
  /* using IP_ANY_ADDR? */
  if(ip_addr_isany(&pcb->local_ip)) {
    /* use network interface IP address as source address */
    src_ip = &(netif->ip_addr);
  } else {
    /* use UDP PCB local IP address as source address */
    src_ip = &(pcb->local_ip);
  }
  
  DEBUGF(UDP_DEBUG, ("udp_send: sending datagram of length %u\n", p->tot_len));
  
  /* UDP Lite protocol? */
  if(pcb->flags & UDP_FLAGS_UDPLITE) {
    DEBUGF(UDP_DEBUG, ("udp_send: UDP LITE packet length %u\n", p->tot_len));
    /* set UDP message length in UDP header */
    udphdr->len = htons(pcb->chksum_len);
    /* calculate checksum */
    udphdr->chksum = inet_chksum_pseudo(p, src_ip, &(pcb->remote_ip),
					IP_PROTO_UDP, pcb->chksum_len);
    /* chksum zero must become 0xffff, as zero means 'no checksum' */
    if(udphdr->chksum == 0x0000) udphdr->chksum = 0xffff;
    /* output to IP */
    err = ip_output_if(p, src_ip, &pcb->remote_ip, UDP_TTL, IP_PROTO_UDPLITE, netif);    
    snmp_inc_udpoutdatagrams();
  } else {
    DEBUGF(UDP_DEBUG, ("udp_send: UDP packet length %u\n", p->tot_len));
    udphdr->len = htons(p->tot_len);
    /* calculate checksum */
    if((pcb->flags & UDP_FLAGS_NOCHKSUM) == 0) {
      udphdr->chksum = inet_chksum_pseudo(p, src_ip, &pcb->remote_ip, IP_PROTO_UDP, p->tot_len);
      /* chksum zero must become 0xffff, as zero means 'no checksum' */
      if(udphdr->chksum == 0x0000) udphdr->chksum = 0xffff;
    }
    DEBUGF(UDP_DEBUG, ("udp_send: UDP checksum %x\n", udphdr->chksum));
    snmp_inc_udpoutdatagrams();
    DEBUGF(UDP_DEBUG, ("udp_send: ip_output_if(,,,,IP_PROTO_UDP,)\n"));
    /* output to IP */
    err = ip_output_if(p, src_ip, &pcb->remote_ip, UDP_TTL, IP_PROTO_UDP, netif);    
  }
  /* dechain and free the header pbuf */
  if(hdr != NULL) {
    pbuf_dechain(hdr);
    pbuf_free(hdr);
  }
  
#ifdef UDP_STATS
  ++lwip_stats.udp.xmit;
#endif /* UDP_STATS */
  return err;
}
/**
 * Bind an UDP PCB.
 *
 * @param pcb UDP PCB to be bound with a local address ipaddr and port.
 * @param ipaddr local IP address to bind with. Use IP_ADDR_ANY to
 * bind to all local interfaces.
 * @param port local UDP port to bind with.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB.
 * 
 * @see udp_disconnect()
 */
err_t
udp_bind(struct udp_pcb *pcb, struct ip_addr *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  u8_t rebind;

  rebind = 0;
  /* Check for double bind and rebind of the same pcb */
  for(ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    /* is this UDP PCB already on active list? */ 
    if (pcb == ipcb) {
      /* TODO: add assert that rebind is 0 here (pcb may
         occur at most once in list) */
	    rebind = 1;
    }
/* this code does not allow upper layer to share a UDP port for
   listening to broadcast or multicast traffic (See SO_REUSE_ADDR and
   SO_REUSE_PORT under *BSD). TODO: See where it fits instead, OR
   combine with implementation of UDP PCB flags. Leon Woestenberg. */
#if 0 
    /* port matches that of PCB in list? */
    else if ((ipcb->local_port == port) &&
       /* IP address matches, or one is IP_ADDR_ANY? */
       (ip_addr_isany(&(ipcb->local_ip)) ||
	     ip_addr_isany(ipaddr) ||
	     ip_addr_cmp(&(ipcb->local_ip), ipaddr))) {
      /* other PCB already binds to this local IP and port */
      DEBUGF(UDP_DEBUG, ("udp_bind: local port %u already bound by another pcb\n", port));
      return ERR_USE;	   
    }
#endif
  }
  /* bind local address */
  ip_addr_set(&pcb->local_ip, ipaddr);
  if (port == 0) {
#ifndef UDP_LOCAL_PORT_RANGE_START
#define UDP_LOCAL_PORT_RANGE_START 4096
#define UDP_LOCAL_PORT_RANGE_END   0x7fff
#endif
  	port = UDP_LOCAL_PORT_RANGE_START;
  	ipcb = udp_pcbs;
  	while((ipcb != NULL) && (port != UDP_LOCAL_PORT_RANGE_END)) {
  		if(ipcb->local_port == port) {
  			port++;
  			ipcb = udp_pcbs;
  		} else
  			ipcb = ipcb->next;
  	}
  	if(ipcb) /* no more ports available in local range */
      DEBUGF(UDP_DEBUG, ("udp_bind: out of free UDP ports\n"));
  		return ERR_USE;
  }
  pcb->local_port = port;
  /* We need to place the PCB on the list if not already there. */
  if (rebind == 0) {
    pcb->next = udp_pcbs;
    udp_pcbs = pcb;
  }  
  DEBUGF(UDP_DEBUG, ("udp_bind: bound to port %u\n", port));
  return ERR_OK;
}
/**
 * Connect an UDP PCB.
 *
 * This will associate the UDP PCB with the remote address.
 *
 * @param pcb UDP PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 * @param port remote UDP port to connect with.
 *
 * @return lwIP error code
 * 
 * @see udp_disconnect()
 */
err_t
udp_connect(struct udp_pcb *pcb, struct ip_addr *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;

  if(pcb->local_port == 0) {
    err_t err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if(err != ERR_OK)
      return err;
  }

  ip_addr_set(&pcb->remote_ip, ipaddr);
  pcb->remote_port = port;
/** TODO: this functionality belongs in upper layers */
#if 0

  pcb->flags |= UDP_FLAGS_CONNECTED;
  /* Nail down local IP for netconn_addr()/getsockname() */
  if(ip_addr_isany(&pcb->local_ip) && !ip_addr_isany(&pcb->remote_ip)) { 
    struct netif *netif;

    if((netif = ip_route(&(pcb->remote_ip))) == NULL) {
    	DEBUGF(UDP_DEBUG, ("udp_connect: No route to 0x%lx\n", pcb->remote_ip.addr));
#ifdef UDP_STATS
        ++lwip_stats.udp.rterr;
#endif /* UDP_STATS */
    	return ERR_RTE;
    }
    /** TODO: this will bind the udp pcb locally, to the interface which
        is used to route output packets to the remote address. However, we
        might want to accept incoming packets on any interface! */
    pcb->local_ip = netif->ip_addr;
  } else if(ip_addr_isany(&pcb->remote_ip)) { 
    pcb->local_ip.addr = 0;
  }
#endif
  /* Insert UDP PCB into the list of active UDP PCBs. */
  for(ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    if(pcb == ipcb) {
      /* already on the list, just return */
      return ERR_OK;
    }
  }
  /* PCB not yet on the list, add PCB now */
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;
  return ERR_OK;
}

void
udp_disconnect(struct udp_pcb *pcb)
{
	pcb->flags &= ~UDP_FLAGS_CONNECTED;
}
/*-----------------------------------------------------------------------------------*/
void
udp_recv(struct udp_pcb *pcb,
	 void (* recv)(void *arg, struct udp_pcb *upcb, struct pbuf *p,
		       struct ip_addr *addr, u16_t port),
	 void *recv_arg)
{
  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}
/**
 * Remove an UDP PCB.
 *
 * @param pcb UDP PCB to be removed. The PCB is removed from the list of
 * UDP PCB's and the data structure is freed from memory.
 * 
 * @see udp_new()
 */
void
udp_remove(struct udp_pcb *pcb)
{
  struct udp_pcb *pcb2;
  /* pcb to be removed is first in list? */
  if (udp_pcbs == pcb) {
    /* make list start at 2nd pcb */
    udp_pcbs = udp_pcbs->next;
  /* pcb not 1st in list */
  } else for(pcb2 = udp_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
    /* find pcb in udp_pcbs list */
    if(pcb2->next != NULL && pcb2->next == pcb) {
      /* remove pcb from list */
      pcb2->next = pcb->next;
    }
  }
  memp_free(MEMP_UDP_PCB, pcb);  
}
/**
 * Create a UDP PCB.
 *
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 * 
 * @see udp_remove()
 */
struct udp_pcb *
udp_new(void) {
  struct udp_pcb *pcb;
  pcb = memp_malloc(MEMP_UDP_PCB);
  /* could allocate UDP PCB? */
  if(pcb != NULL) {
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct udp_pcb));
  }
  return pcb;
}
/*-----------------------------------------------------------------------------------*/
#if UDP_DEBUG
int
udp_debug_print(struct udp_hdr *udphdr)
{
  DEBUGF(UDP_DEBUG, ("UDP header:\n"));
  DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(UDP_DEBUG, ("|     %5u     |     %5u     | (src port, dest port)\n",
		     ntohs(udphdr->src), ntohs(udphdr->dest)));
  DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(UDP_DEBUG, ("|     %5u     |     0x%04x    | (len, chksum)\n",
		     ntohs(udphdr->len), ntohs(udphdr->chksum)));
  DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  return 0;
}
#endif /* UDP_DEBUG */
/*-----------------------------------------------------------------------------------*/
#endif /* LWIP_UDP */









