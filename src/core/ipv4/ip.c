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
/* ip.c
 *
 * This is the code for the IP layer.
 *
 */   
/*-----------------------------------------------------------------------------------*/

#include "lwip/debug.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/stats.h"

#include "arch/perf.h"

#include "lwip/snmp.h"
#if LWIP_DHCP
#  include "lwip/dhcp.h"
#endif /* LWIP_DHCP */

/*-----------------------------------------------------------------------------------*/
/* ip_init:
 *
 * Initializes the IP layer.
 */
/*-----------------------------------------------------------------------------------*/
void
ip_init(void)
{
}
/*-----------------------------------------------------------------------------------*/
/* ip_lookup:
 *
 * An experimental feature that will be changed in future versions. Do
 * not depend on it yet...
 */
/*-----------------------------------------------------------------------------------*/
#ifdef LWIP_DEBUG
u8_t
ip_lookup(void *header, struct netif *inp)
{
  struct ip_hdr *iphdr;

  iphdr = header;

  /* not IP v4? */
  if(IPH_V(iphdr) != 4) {
    return 0;
  }

  /* Immediately accept/decline packets that are fragments or has
     options. */
#if IP_REASSEMBLY == 0
  /*  if((IPH_OFFSET(iphdr) & htons(IP_OFFMASK | IP_MF)) != 0) {
    return 0;
    }*/
#endif /* IP_REASSEMBLY == 0 */

#if IP_OPTIONS == 0
  if(IPH_HL(iphdr) != 5) {
    return 0;
  }
#endif /* IP_OPTIONS == 0 */
  
  switch(IPH_PROTO(iphdr)) {
#if LWIP_UDP > 0
  case IP_PROTO_UDP:
    return udp_lookup(iphdr, inp);
#endif /* LWIP_UDP */
#if LWIP_TCP > 0    
  case IP_PROTO_TCP:
    return 1;
#endif /* LWIP_TCP */
  case IP_PROTO_ICMP:
    return 1;
  default:
    return 0;
  }
}
#endif /* LWIP_DEBUG */
/*-----------------------------------------------------------------------------------*/
/* ip_route:
 *
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 */
/*-----------------------------------------------------------------------------------*/
struct netif *
ip_route(struct ip_addr *dest)
{
  struct netif *netif;

  /* iterate through netifs */  
  for(netif = netif_list; netif != NULL; netif = netif->next) {
    /* network mask matches? */
    if(ip_addr_maskcmp(dest, &(netif->ip_addr), &(netif->netmask))) {
      /* return netif on which to forward IP packet */
      return netif;
    }
  }
  /* no matching netif found, use default netif */
  return netif_default;
}
#if IP_FORWARD
/*-----------------------------------------------------------------------------------*/
/* ip_forward:
 *
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 */
/*-----------------------------------------------------------------------------------*/
static void
ip_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
  struct netif *netif;
  
  PERF_START;
  /* Find network interface where to forward this IP packet to. */
  netif = ip_route((struct ip_addr *)&(iphdr->dest));
  if(netif == NULL) {
    DEBUGF(IP_DEBUG, ("ip_forward: no forwarding route for 0x%lx found\n",
                      iphdr->dest.addr));
    snmp_inc_ipnoroutes();
    return;
  }
  /* Do not forward packets onto the same network interface on which
     they arrived. */
  if(netif == inp) {
    DEBUGF(IP_DEBUG, ("ip_forward: not bouncing packets back on incoming interface.\n"));
    snmp_inc_ipnoroutes();
    return;
  }
  
  /* decrement TTL */
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);
  /* send ICMP if TTL == 0 */
  if(IPH_TTL(iphdr) == 0) {
    /* Don't send ICMP messages in response to ICMP messages */
    if(IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
      icmp_time_exceeded(p, ICMP_TE_TTL);
      snmp_inc_icmpouttimeexcds();
    }
    return;       
  }
  
  /* Incrementally update the IP checksum. */
  if(IPH_CHKSUM(iphdr) >= htons(0xffff - 0x100)) {
    IPH_CHKSUM_SET(iphdr, IPH_CHKSUM(iphdr) + htons(0x100) + 1);
  } else {
    IPH_CHKSUM_SET(iphdr, IPH_CHKSUM(iphdr) + htons(0x100));
  }

  DEBUGF(IP_DEBUG, ("ip_forward: forwarding packet to 0x%lx\n",
                    iphdr->dest.addr));

#ifdef IP_STATS
  ++lwip_stats.ip.fw;
  ++lwip_stats.ip.xmit;
#endif /* IP_STATS */
    snmp_inc_ipforwdatagrams();

  PERF_STOP("ip_forward");
  /* transmit pbuf on chosen interface */
  netif->output(netif, p, (struct ip_addr *)&(iphdr->dest));
}
#endif /* IP_FORWARD */
/*-----------------------------------------------------------------------------------*/
/* ip_input:
 *
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 */
/*-----------------------------------------------------------------------------------*/
err_t
ip_input(struct pbuf *p, struct netif *inp) {
  static struct ip_hdr *iphdr;
  static struct netif *netif;
  static u16_t iphdrlen;
  
#ifdef IP_STATS
  ++lwip_stats.ip.recv;
#endif /* IP_STATS */
  snmp_inc_ipinreceives();

  /* identify the IP header */
  iphdr = p->payload;
  if(IPH_V(iphdr) != 4) {
    DEBUGF(IP_DEBUG, ("IP packet dropped due to bad version number %d\n", IPH_V(iphdr)));
#if IP_DEBUG
    ip_debug_print(p);
#endif /* IP_DEBUG */
    pbuf_free(p);
#ifdef IP_STATS
    ++lwip_stats.ip.err;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    snmp_inc_ipunknownprotos();
    return ERR_OK;
  }
  /* obtain IP header length in number of 32-bit words */
  iphdrlen = IPH_HL(iphdr);
  /* calculate IP header length in bytes */
  iphdrlen *= 4;

  /* header length exceeds first pbuf length? */  
  if(iphdrlen > p->len) {
    DEBUGF(IP_DEBUG, ("IP header (len %u) does not fit in first pbuf (len %u), IP packet droppped.\n",
      iphdrlen, p->len));
    /* free (drop) packet pbufs */
    pbuf_free(p);
#ifdef IP_STATS
    ++lwip_stats.ip.lenerr;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    snmp_inc_ipindiscards();
    return ERR_OK;
  }

  /* verify checksum */
  if(inet_chksum(iphdr, iphdrlen) != 0) {

    DEBUGF(IP_DEBUG, ("Checksum (0x%x) failed, IP packet dropped.\n", inet_chksum(iphdr, iphdrlen)));
#if IP_DEBUG
    ip_debug_print(p);
#endif /* IP_DEBUG */
    pbuf_free(p);
#ifdef IP_STATS
    ++lwip_stats.ip.chkerr;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    snmp_inc_ipindiscards();
    return ERR_OK;
  }
  
  /* Trim pbuf. This should have been done at the netif layer,
     but we'll do it anyway just to be sure that its done. */
  pbuf_realloc(p, ntohs(IPH_LEN(iphdr)));

  /* is this packet for us? */
  for(netif = netif_list; netif != NULL; netif = netif->next) {

    DEBUGF(IP_DEBUG, ("ip_input: iphdr->dest 0x%lx netif->ip_addr 0x%lx (0x%lx, 0x%lx, 0x%lx)\n",
                      iphdr->dest.addr, netif->ip_addr.addr,
                      iphdr->dest.addr & netif->netmask.addr,
                      netif->ip_addr.addr & netif->netmask.addr,
                      iphdr->dest.addr & ~(netif->netmask.addr)));

    /* interface configured? */
    if(!ip_addr_isany(&(netif->ip_addr)))
    {
      /* unicast to this interface address? */
      if(ip_addr_cmp(&(iphdr->dest), &(netif->ip_addr)) ||
        /* or broadcast matching this interface network address? */
        (ip_addr_isbroadcast(&(iphdr->dest), &(netif->netmask)) &&
         ip_addr_maskcmp(&(iphdr->dest), &(netif->ip_addr), &(netif->netmask))) ||
         /* or restricted broadcast? */
         ip_addr_cmp(&(iphdr->dest), IP_ADDR_BROADCAST)) {
         DEBUGF(IP_DEBUG, ("ip_input: packet accepted on interface %c%c\n",
                       netif->name[0], netif->name[1]));
         /* break out of for loop */
         break;
      }
    }
  }
#if LWIP_DHCP
  /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
     using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
     According to RFC 1542 section 3.1.1, referred by RFC 2131). */
  if(netif == NULL) {
    /* remote port is DHCP server? */
    if(IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      DEBUGF(IP_DEBUG, ("ip_input: UDP packet to DHCP client port %u\n",
       ntohs(((struct udp_hdr *)((u8_t *)iphdr + iphdrlen))->dest)));
      if (ntohs(((struct udp_hdr *)((u8_t *)iphdr + iphdrlen))->dest) == DHCP_CLIENT_PORT) {
        DEBUGF(IP_DEBUG, ("ip_input: DHCP packet accepted.\n"));
        netif = inp;
      }
    }
  }
#endif /* LWIP_DHCP */
        /* packet not for us? */  
  if(netif == NULL) {
    /* packet not for us, route or discard */
    DEBUGF(IP_DEBUG, ("ip_input: packet not for us.\n"));
#if IP_FORWARD
    /* non-broadcast packet? */
    if(!ip_addr_isbroadcast(&(iphdr->dest), &(inp->netmask))) {
      /* try to forward IP packet on (other) interfaces */
      ip_forward(p, iphdr, inp);
    }
    else
#endif /* IP_FORWARD */
    {
      snmp_inc_ipindiscards();
    }
    pbuf_free(p);
    return ERR_OK;
  }

#if IP_REASSEMBLY
  if((IPH_OFFSET(iphdr) & htons(IP_OFFMASK | IP_MF)) != 0) {
    DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04x tot_len=%u len=%u MF=%u offset=%u), calling ip_reass()\n", ntohs(IPH_ID(iphdr)), p->tot_len, ntohs(IPH_LEN(iphdr)), !!(IPH_OFFSET(iphdr) & htons(IP_MF)), (ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK)*8));
    p = ip_reass(p);
    if(p == NULL) {
      return ERR_OK;
    }
    iphdr = p->payload;
  }
#else /* IP_REASSEMBLY */
  if((IPH_OFFSET(iphdr) & htons(IP_OFFMASK | IP_MF)) != 0) {
    pbuf_free(p);
    DEBUGF(IP_DEBUG, ("IP packet dropped since it was fragmented (0x%x) (while IP_REASSEMBLY == 0).\n",
                  ntohs(IPH_OFFSET(iphdr))));
#ifdef IP_STATS
    ++lwip_stats.ip.opterr;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    snmp_inc_ipunknownprotos();
    return ERR_OK;
  }
#endif /* IP_REASSEMBLY */
  
#if IP_OPTIONS == 0
  if(iphdrlen > IP_HLEN) {
    DEBUGF(IP_DEBUG, ("IP packet dropped since there were IP options (while IP_OPTIONS == 0).\n"));
    pbuf_free(p);    
#ifdef IP_STATS
    ++lwip_stats.ip.opterr;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    snmp_inc_ipunknownprotos();
    return ERR_OK;
  }  
#endif /* IP_OPTIONS == 0 */

  /* send to upper layers */
#if IP_DEBUG
  DEBUGF(IP_DEBUG, ("ip_input: \n"));
  ip_debug_print(p);
  DEBUGF(IP_DEBUG, ("ip_input: p->len %d p->tot_len %d\n", p->len, p->tot_len));
#endif /* IP_DEBUG */   

  switch(IPH_PROTO(iphdr)) {
#if LWIP_UDP > 0    
  case IP_PROTO_UDP:
    snmp_inc_ipindelivers();
    udp_input(p, inp);
    break;
#endif /* LWIP_UDP */
#if LWIP_TCP > 0    
  case IP_PROTO_TCP:
    snmp_inc_ipindelivers();
    tcp_input(p, inp);
    break;
#endif /* LWIP_TCP */
  case IP_PROTO_ICMP:
    snmp_inc_ipindelivers();
    icmp_input(p, inp);
    break;
  default:
    /* send ICMP destination protocol unreachable unless is was a broadcast */
    if(!ip_addr_isbroadcast(&(iphdr->dest), &(inp->netmask)) &&
       !ip_addr_ismulticast(&(iphdr->dest))) {
      p->payload = iphdr;
      icmp_dest_unreach(p, ICMP_DUR_PROTO);
    }
    pbuf_free(p);

    DEBUGF(IP_DEBUG, ("Unsupported transportation protocol %d\n", IPH_PROTO(iphdr)));

#ifdef IP_STATS
    ++lwip_stats.ip.proterr;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    snmp_inc_ipunknownprotos();

  }
  return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/
/* ip_output_if:
 *
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 */
/*-----------------------------------------------------------------------------------*/
err_t
ip_output_if(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
             u8_t ttl,
             u8_t proto, struct netif *netif)
{
  static struct ip_hdr *iphdr;
  static u16_t ip_id = 0;

  snmp_inc_ipoutrequests();
  
  if(dest != IP_HDRINCL) {
    if(pbuf_header(p, IP_HLEN)) {
      DEBUGF(IP_DEBUG, ("ip_output: not enough room for IP header in pbuf\n"));
      
#ifdef IP_STATS
      ++lwip_stats.ip.err;
#endif /* IP_STATS */
      snmp_inc_ipoutdiscards();
      return ERR_BUF;
    }
    
    iphdr = p->payload;
    
    IPH_TTL_SET(iphdr, ttl);
    IPH_PROTO_SET(iphdr, proto);
    
    ip_addr_set(&(iphdr->dest), dest);

    IPH_VHLTOS_SET(iphdr, 4, IP_HLEN / 4, 0);
    IPH_LEN_SET(iphdr, htons(p->tot_len));
    IPH_OFFSET_SET(iphdr, htons(IP_DF));
    IPH_ID_SET(iphdr, htons(ip_id));
    ++ip_id;

    if(ip_addr_isany(src)) {
      ip_addr_set(&(iphdr->src), &(netif->ip_addr));
    } else {
      ip_addr_set(&(iphdr->src), src);
    }

    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));
  } else {
    iphdr = p->payload;
    dest = &(iphdr->dest);
  }

#if IP_FRAG     
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu))
    return ip_frag(p,netif,dest);
#endif
  
#ifdef IP_STATS
  lwip_stats.ip.xmit++;
#endif /* IP_STATS */
  DEBUGF(IP_DEBUG, ("ip_output_if: %c%c ", netif->name[0], netif->name[1]));
#if IP_DEBUG
  ip_debug_print(p);
#endif /* IP_DEBUG */

  DEBUGF(IP_DEBUG, ("netif->output()"));

  return netif->output(netif, p, dest);  
}
/*-----------------------------------------------------------------------------------*/
/* ip_output:
 *
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 */
/*-----------------------------------------------------------------------------------*/
err_t
ip_output(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
          u8_t ttl, u8_t proto)
{
  struct netif *netif;
  
  if((netif = ip_route(dest)) == NULL) {
    DEBUGF(IP_DEBUG, ("ip_output: No route to 0x%lx\n", dest->addr));

#ifdef IP_STATS
    ++lwip_stats.ip.rterr;
#endif /* IP_STATS */
    snmp_inc_ipoutdiscards();
    return ERR_RTE;
  }

  return ip_output_if(p, src, dest, ttl, proto, netif);
}
/*-----------------------------------------------------------------------------------*/
#if IP_DEBUG
void
ip_debug_print(struct pbuf *p)
{
  struct ip_hdr *iphdr = p->payload;
  u8_t *payload;

  payload = (u8_t *)iphdr + IP_HLEN;
  
  DEBUGF(IP_DEBUG, ("IP header:\n"));
  DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(IP_DEBUG, ("|%2d |%2d |   %2u  |      %4u     | (v, hl, tos, len)\n",
                    IPH_V(iphdr),
                    IPH_HL(iphdr),
                    IPH_TOS(iphdr),
                    ntohs(IPH_LEN(iphdr))));
  DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(IP_DEBUG, ("|    %5u      |%u%u%u|    %4u   | (id, flags, offset)\n",
                    ntohs(IPH_ID(iphdr)),
                    ntohs(IPH_OFFSET(iphdr)) >> 15 & 1,
                    ntohs(IPH_OFFSET(iphdr)) >> 14 & 1,
                    ntohs(IPH_OFFSET(iphdr)) >> 13 & 1,
                    ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK));
  DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(IP_DEBUG, ("|   %2u  |   %2u  |    0x%04x     | (ttl, proto, chksum)\n",
                    IPH_TTL(iphdr),
                    IPH_PROTO(iphdr),
                    ntohs(IPH_CHKSUM(iphdr))));
  DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(IP_DEBUG, ("|  %3ld  |  %3ld  |  %3ld  |  %3ld  | (src)\n",
                    ntohl(iphdr->src.addr) >> 24 & 0xff,
                    ntohl(iphdr->src.addr) >> 16 & 0xff,
                    ntohl(iphdr->src.addr) >> 8 & 0xff,
                    ntohl(iphdr->src.addr) & 0xff));
  DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  DEBUGF(IP_DEBUG, ("|  %3ld  |  %3ld  |  %3ld  |  %3ld  | (dest)\n",
                    ntohl(iphdr->dest.addr) >> 24 & 0xff,
                    ntohl(iphdr->dest.addr) >> 16 & 0xff,
                    ntohl(iphdr->dest.addr) >> 8 & 0xff,
                    ntohl(iphdr->dest.addr) & 0xff));
  DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* IP_DEBUG */
/*-----------------------------------------------------------------------------------*/





