/**
 * @file
 * Address Resolution Protocol module for IP over Ethernet
 *
 * $Log: etharp.c,v $
 * Revision 1.3  2002/11/06 11:43:21  likewise
 * find_arp_entry() returned 0 instead of ARP_TABLE_SIZE if full pending cache (bug #1625).
 *
 * Revision 1.2  2002/11/04 14:56:40  likewise
 * Fixed NULL pointer bug (#1493). Fix for memory leak bug (#1601), etharp_output_sent(). Added etharp_query for DHCP.
 *
 */

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
 */

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/inet.h"
#include "netif/etharp.h"
#include "lwip/ip.h"
#include "lwip/stats.h"

#if LWIP_DHCP
#  include "lwip/dhcp.h"
#endif


#define ARP_MAXAGE 120  /* 120 * 10 seconds = 20 minutes. */
#define ARP_MAXPENDING 2 /* 2 * 10 seconds = 20 seconds. */

#define HWTYPE_ETHERNET 1

#define ARP_REQUEST 1
#define ARP_REPLY 2

/* MUST be compiled with "pack structs" or equivalent! */
PACK_STRUCT_BEGIN
struct etharp_hdr {
  PACK_STRUCT_FIELD(struct eth_hdr ethhdr);
  PACK_STRUCT_FIELD(u16_t hwtype);
  PACK_STRUCT_FIELD(u16_t proto);
  PACK_STRUCT_FIELD(u16_t _hwlen_protolen);
  PACK_STRUCT_FIELD(u16_t opcode);
  PACK_STRUCT_FIELD(struct eth_addr shwaddr);
  PACK_STRUCT_FIELD(struct ip_addr sipaddr);
  PACK_STRUCT_FIELD(struct eth_addr dhwaddr);
  PACK_STRUCT_FIELD(struct ip_addr dipaddr);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

#define ARPH_HWLEN(hdr) (NTOHS((hdr)->_hwlen_protolen) >> 8)
#define ARPH_PROTOLEN(hdr) (NTOHS((hdr)->_hwlen_protolen) & 0xff)


#define ARPH_HWLEN_SET(hdr, len) (hdr)->_hwlen_protolen = HTONS(ARPH_PROTOLEN(hdr) | ((len) << 8))
#define ARPH_PROTOLEN_SET(hdr, len) (hdr)->_hwlen_protolen = HTONS((len) | (ARPH_HWLEN(hdr) << 8))

PACK_STRUCT_BEGIN
struct ethip_hdr {
  PACK_STRUCT_FIELD(struct eth_hdr eth);
  PACK_STRUCT_FIELD(struct ip_hdr ip);
};
PACK_STRUCT_END

enum etharp_state {
  ETHARP_STATE_EMPTY,
  ETHARP_STATE_PENDING,
  ETHARP_STATE_STABLE
};

struct etharp_entry {
  struct ip_addr ipaddr;
  struct eth_addr ethaddr;
  enum etharp_state state;
  struct pbuf *p;
  void *payload;
  u16_t len, tot_len;
  u8_t ctime;
};

static const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}};
static struct etharp_entry arp_table[ARP_TABLE_SIZE];
static u8_t ctime;

/**
 * Initializes ARP module.
 */
void
etharp_init(void)
{
  u8_t i;
  /* clear ARP entries */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    arp_table[i].state = ETHARP_STATE_EMPTY;
  }
}

/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ETHARP_TMR_INTERVAL microseconds (10 seconds),
 * in order to expire entries in the ARP table.
 */
void
etharp_tmr(void)
{
  u8_t i;
  
  ++ctime;
  /* remove expired entries from the ARP table */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    if(arp_table[i].state == ETHARP_STATE_STABLE &&       
       ctime - arp_table[i].ctime >= ARP_MAXAGE) {
      DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired stable entry %d.\n", i));
      arp_table[i].state = ETHARP_STATE_EMPTY;
    } else if(arp_table[i].state == ETHARP_STATE_PENDING &&
	      ctime - arp_table[i].ctime >= ARP_MAXPENDING) {
      DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired pending entry %d - dequeueing %p.\n", i, arp_table[i].p));
      arp_table[i].state = ETHARP_STATE_EMPTY;
      pbuf_free(arp_table[i].p);      
      arp_table[i].p = NULL;
    }
  }  
}

/**
 * Return an empty ARP entry or, if the table is full, ARP_TABLE_SIZE if all
 * entries are pending, otherwise the oldest entry.
 *
 * @return The ARP entry index that is available, ARP_TABLE_SIZE if no usable
 * entry is found.
 */
static u8_t
find_arp_entry(void)
{
  u8_t i, j, maxtime;
  
  /* Try to find an unused entry in the ARP table. */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    if(arp_table[i].state == ETHARP_STATE_EMPTY) {
      break;
    }
  }
  
  /* If no unused entry is found, we try to find the oldest entry and
     throw it away. */
  if(i == ARP_TABLE_SIZE) {
    maxtime = 0;
    j = ARP_TABLE_SIZE;
    for(i = 0; i < ARP_TABLE_SIZE; ++i) {
      if(arp_table[i].state == ETHARP_STATE_STABLE &&
	 ctime - arp_table[i].ctime > maxtime) {
	maxtime = ctime - arp_table[i].ctime;
	j = i;
      }
    }
    i = j;
  }
  return i;
}

static struct pbuf *
update_arp_entry(struct ip_addr *ipaddr, struct eth_addr *ethaddr)
{
  u8_t i, k;
  struct pbuf *p;
  struct eth_hdr *ethhdr;
  
  /* Walk through the ARP mapping table and try to find an entry to
     update. If none is found, the IP -> MAC address mapping is
     inserted in the ARP table. */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    /* Check if the source IP address of the incoming packet matches
       the IP address in this ARP table entry. */
    if(ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
      
      /* First, check those entries that are already in use. */
      if(arp_table[i].state == ETHARP_STATE_STABLE) {
	/* An old entry found, update this and return. */
	for(k = 0; k < 6; ++k) {
	  arp_table[i].ethaddr.addr[k] = ethaddr->addr[k];
	}
	arp_table[i].ctime = ctime;
	return NULL;
      }
      if(arp_table[i].state == ETHARP_STATE_PENDING) {
	/* A pending entry was found, so we fill this in and return
	   the queued packet (if any). */
	for(k = 0; k < 6; ++k) {
	  arp_table[i].ethaddr.addr[k] = ethaddr->addr[k];
	}
	arp_table[i].ctime = ctime;
	arp_table[i].state = ETHARP_STATE_STABLE;
	p = arp_table[i].p;
	if(p != NULL) {	
	  p->payload = arp_table[i].payload;	
	  p->len = arp_table[i].len;
	  p->tot_len = arp_table[i].tot_len;      
	  arp_table[i].p = NULL;	
	  
	  ethhdr = p->payload;
	  
	  for(k = 0; k < 6; ++k) {
	    ethhdr->dest.addr[k] = ethaddr->addr[k];
	  }
	  
	  ethhdr->type = htons(ETHTYPE_IP);	  	 	  
	}
	return p;
      }
    }
  }
  /* We get here if no ARP entry was found. If so, we create one. */
  i = find_arp_entry();
  if(i == ARP_TABLE_SIZE) {
    return NULL;
  }

  ip_addr_set(&arp_table[i].ipaddr, ipaddr);
  for(k = 0; k < 6; ++k) {
    arp_table[i].ethaddr.addr[k] = ethaddr->addr[k];
  }
  arp_table[i].ctime = ctime;
  arp_table[i].state = ETHARP_STATE_STABLE;
  arp_table[i].p = NULL;
  
  return NULL;
}

/**
 * Updates the ARP table and may return any queued packet to be sent
 *
 * Should be called for all incoming packets of IP kind. The function
 * does not alter the packet in any way, it just updates the ARP
 * table. After this function has been called, the normal TCP/IP stack
 * input function should be called.
 *
 * The function may return a pbuf containing a packet that had
 * previously been queued for transmission. The device driver must
 * transmit this packet onto the network, and call pbuf_free() for the
 * pbuf.
 */
struct pbuf *
etharp_ip_input(struct netif *netif, struct pbuf *p)
{
  struct ethip_hdr *hdr;
  
  hdr = p->payload;
  
  /* Only insert/update an entry if the source IP address of the
     incoming IP packet comes from a host on the local network. */
  if(!ip_addr_maskcmp(&(hdr->ip.src), &(netif->ip_addr), &(netif->netmask))) {
    return NULL;
  }
  DEBUGF(ETHARP_DEBUG, ("etharp_ip_input: updating ETHARP table.\n"));
  return update_arp_entry(&(hdr->ip.src), &(hdr->eth.src));
}


/**
 * Updates the ARP table and may return any queued packet to be sent
 * 
 * Should be called for incoming ARP packets. The pbuf in the argument
 * is freed by this function. If the function returns a pbuf (i.e.,
 * returns non-NULL), that pbuf constitutes an ARP reply and should be
 * sent out on the Ethernet.
 *
 * @note The driver must call pbuf_free() for the returned pbuf when the
 * packet has been sent. 
 */
struct pbuf *
etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
{
  struct etharp_hdr *hdr;
  u8_t i;
  
  if(p->tot_len < sizeof(struct etharp_hdr)) {
    DEBUGF(ETHARP_DEBUG, ("etharp_etharp_input: packet too short (%d/%d)\n", p->tot_len, sizeof(struct etharp_hdr)));
    pbuf_free(p);
    return NULL;
  }

  hdr = p->payload;
  
  switch(htons(hdr->opcode)) {
  case ARP_REQUEST:
    /* ARP request. If it asked for our address, we send out a
       reply. */
    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: ARP request\n"));
    if(ip_addr_cmp(&(hdr->dipaddr), &(netif->ip_addr))) {
      hdr->opcode = htons(ARP_REPLY);

      ip_addr_set(&(hdr->dipaddr), &(hdr->sipaddr));
      ip_addr_set(&(hdr->sipaddr), &(netif->ip_addr));

      for(i = 0; i < 6; ++i) {
	hdr->dhwaddr.addr[i] = hdr->shwaddr.addr[i];
	hdr->shwaddr.addr[i] = ethaddr->addr[i];
	hdr->ethhdr.dest.addr[i] = hdr->dhwaddr.addr[i];
	hdr->ethhdr.src.addr[i] = ethaddr->addr[i];
      }

      hdr->hwtype = htons(HWTYPE_ETHERNET);
      ARPH_HWLEN_SET(hdr, 6);
      
      hdr->proto = htons(ETHTYPE_IP);
      ARPH_PROTOLEN_SET(hdr, sizeof(struct ip_addr));      
      
      hdr->ethhdr.type = htons(ETHTYPE_ARP);      
      return p;
    }
    break;
  case ARP_REPLY:    
    /* ARP reply. We insert or update the ARP table. */
    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: ARP reply\n"));
    if(ip_addr_cmp(&(hdr->dipaddr), &(netif->ip_addr))) {     
      struct pbuf *q;
#if (LWIP_DHCP && DHCP_DOES_ARP_CHECK)
      dhcp_arp_reply(&hdr->sipaddr);
#endif
      /* update_arp_entry() will return a pbuf that has previously been
	 queued waiting for an ARP reply. */
      q = update_arp_entry(&(hdr->sipaddr), &(hdr->shwaddr));
      pbuf_free(p);
      p = NULL;
      return q;
    }
    break;
  default:
    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: unknown type %d\n", htons(hdr->opcode)));
    break;
  }

  pbuf_free(p);
  return NULL;
}

/** 
 * Resolve Ethernet address and append header to the outgoing packet.
 *
 * The etharp_output() function should be called for all outgoing
 * packets. The pbuf returned by the function should be sent out on
 * the Ethernet. This pbuf must then be passed to etharp_output_sent().
 *
 * The function prepares the packet for transmission over the Ethernet
 * by adding an Ethernet header. If there is no IP -> MAC address
 * mapping, the function will queue the outgoing packet and return an
 * ARP request packet instead.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param ipaddr The IP address of the packet destination.
 * @param pbuf The pbuf(s) containing the IP packet.
 * 
 * @return The packet which should be sent on the network and must be freed by
 * the caller.
 *
 * @see etharp_output_sent()
 */
struct pbuf *
etharp_output(struct netif *netif, struct ip_addr *ipaddr, struct pbuf *q)
{
  struct eth_addr *dest, *srcaddr, mcastaddr;
  struct eth_hdr *ethhdr;
  struct etharp_hdr *hdr;
  struct pbuf *p;
  u8_t i;

  /* obtain source Ethernet address of the given interface */
  srcaddr = (struct eth_addr *)netif->hwaddr;

  /* Make room for Ethernet header. */
  if(pbuf_header(q, sizeof(struct eth_hdr)) != 0) {    
    /* The pbuf_header() call shouldn't fail, and we'll just bail
       out if it does.. */
    DEBUGF(ETHARP_DEBUG, ("etharp_output: could not allocate room for header.\n"));
#ifdef LINK_STATS
    ++stats.link.lenerr;
#endif /* LINK_STATS */
    return NULL;
  }

  /* assume unresolved Ethernet address */
  dest = NULL;
  /* Construct Ethernet header. Start with looking up deciding which
     MAC address to use as a destination address. Broadcasts and
     multicasts are special, all other addresses are looked up in the
     ARP table. */
  /* destination IP address is an IP broadcast address? */
  if(ip_addr_isany(ipaddr) ||
     ip_addr_isbroadcast(ipaddr, &(netif->netmask))) {
    /* broadcast on Ethernet also */ 
    dest = (struct eth_addr *)&ethbroadcast;
  } else if(ip_addr_ismulticast(ipaddr)) {
    /* Hash IP multicast address to MAC address. */
    mcastaddr.addr[0] = 0x01;
    mcastaddr.addr[1] = 0x0;
    mcastaddr.addr[2] = 0x5e;
    mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
    mcastaddr.addr[4] = ip4_addr3(ipaddr);
    mcastaddr.addr[5] = ip4_addr4(ipaddr);
    /* destination Ethernet address is multicast */
    dest = &mcastaddr;
  /* destination IP unicast address */
  } else {
    /* the destination IP network address does not match the interface's
       network address */
    if(!ip_addr_maskcmp(ipaddr, &(netif->ip_addr), &(netif->netmask))) {
      /* Use the IP address of the default gateway if the destination
         is not on the same subnet as we are. */      
      ipaddr = &(netif->gw);
    }

    /* Try to find a stable IP-to-Ethernet address mapping for this IP
       destination address */
    for(i = 0; i < ARP_TABLE_SIZE; ++i) {    
      if(arp_table[i].state == ETHARP_STATE_STABLE &&
	 ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
	dest = &arp_table[i].ethaddr;
	break;
      }
    }
  }
  
  /* could not find a destination Ethernet address? */ 
  if(dest == NULL) {
    /* No destination address has been found, so we'll have to send
       out an ARP request for the IP address. The outgoing packet is
       queued unless the queue is full. */
       
    /* TODO: The host requirements RFC states that ARP should save at least one
       packet, and this should be the _latest_ packet. */
    
    /* We check if we are already querying for this address. If so,
       we'll bail out. */
    for(i = 0; i < ARP_TABLE_SIZE; ++i) {
      if(arp_table[i].state == ETHARP_STATE_PENDING &&
	 ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
	DEBUGF(ETHARP_DEBUG, ("etharp_output: already queued\n"));
	return NULL;
      }
    }

    /* find a usable ARP entry */
    i = find_arp_entry();
    
    /* If all table entries were in pending state, we won't send out any
       more ARP requests. We'll just give up. */
    if(i == ARP_TABLE_SIZE) {
      return NULL;
    }
    
    /* Now, i is the ARP table entry which we will fill with the new
       information. */
    ip_addr_set(&arp_table[i].ipaddr, ipaddr);
    arp_table[i].ctime = ctime;
    arp_table[i].state = ETHARP_STATE_PENDING;
#if 1
    arp_table[i].p = q;
    arp_table[i].payload = q->payload;
    arp_table[i].len = q->len;
    arp_table[i].tot_len = q->tot_len;
    
    /* Because the pbuf will be queued, we'll increase the reference
       count. */
    DEBUGF(ETHARP_DEBUG, ("etharp_output: queueing %p\n", q));
    pbuf_ref(q);
#else
    arp_table[i].p = NULL;
#endif /* 0 */

    
    /* We allocate a pbuf for the outgoing ARP request packet. */
    p = pbuf_alloc(PBUF_LINK, sizeof(struct etharp_hdr), PBUF_RAM);
    if(p == NULL) {
      /* No ARP request packet could be allocated, so we forget about
	 the ARP table entry. */
      if(i != ARP_TABLE_SIZE) {
	arp_table[i].state = ETHARP_STATE_EMPTY;
	/* We decrease the reference count of the queued pbuf (which now
	   is dequeued). */
	DEBUGF(ETHARP_DEBUG, ("etharp_output: couldn't alloc pbuf for query, dequeueing %p\n", q));
	pbuf_free(q);
      }      
      return NULL;
    }
    
    hdr = p->payload;
    
    hdr->opcode = htons(ARP_REQUEST);
    
    for(i = 0; i < 6; ++i) {
      hdr->dhwaddr.addr[i] = 0x00;
      hdr->shwaddr.addr[i] = srcaddr->addr[i];
    }
    
    ip_addr_set(&(hdr->dipaddr), ipaddr);
    ip_addr_set(&(hdr->sipaddr), &(netif->ip_addr));
    
    hdr->hwtype = htons(HWTYPE_ETHERNET);
    ARPH_HWLEN_SET(hdr, 6);
    
    hdr->proto = htons(ETHTYPE_IP);
    ARPH_PROTOLEN_SET(hdr, sizeof(struct ip_addr));
    
    for(i = 0; i < 6; ++i) {
      hdr->ethhdr.dest.addr[i] = 0xff;
      hdr->ethhdr.src.addr[i] = srcaddr->addr[i];
    }
    
    hdr->ethhdr.type = htons(ETHTYPE_ARP);      
    return p;
  } else {
    /* A valid IP->MAC address mapping was found, so we construct the
       Ethernet header for the outgoing packet. */

    ethhdr = q->payload;
    
    for(i = 0; i < 6; i++) {
      ethhdr->dest.addr[i] = dest->addr[i];
      ethhdr->src.addr[i] = srcaddr->addr[i];
    }
    
    ethhdr->type = htons(ETHTYPE_IP);
  
    return q;
  }
}

/**
 * Clean up the ARP request that was allocated by ARP.
 *
 * This must be called after you have sent the packet
 * returned by etharp_output(). It frees any pbuf 
 * allocated for an ARP request.
 */
struct pbuf *
etharp_output_sent(struct pbuf *p)
{
  struct etharp_hdr *hdr;
  hdr=p->payload;
  if (hdr->opcode == htons(ARP_REQUEST)) {
    pbuf_free(p); p=NULL;
  };
  return p;
}

/**
 * Initiate an ARP query for the given IP address.
 *
 * Used by the DHCP module to support "gratuitous" ARP,
 * i.e. send ARP requests for one's own IP address, to
 * see if others have the IP address in use.
 *
 * Might be used in the future by manual IP configuration
 * as well.
 *
 */

struct pbuf *etharp_query(struct netif *netif, struct ip_addr *ipaddr)
{
  struct eth_addr *srcaddr;
  struct etharp_hdr *hdr;
  struct pbuf *p;
  u8_t i, j;
  u8_t maxtime;

  srcaddr = (struct eth_addr *)netif->hwaddr;
  /* We check if we are already querying for this address. If so,
  we'll bail out. */
  for(i = 0; i < ARP_TABLE_SIZE; ++i)
  {
    if(arp_table[i].state == ETHARP_STATE_PENDING && ip_addr_cmp(ipaddr, &arp_table[i].ipaddr))
    {
      DEBUGF(ETHARP_DEBUG, ("etharp_output: already queued\n"));
      return NULL;
    }
  }
  /* We now try to find an unused entry in the ARP table that we
  will setup and queue the outgoing packet. */
  for(i = 0; i < ARP_TABLE_SIZE; ++i)
  {
    if(arp_table[i].state == ETHARP_STATE_EMPTY)
    {
      break;
    }
  }

  /* If no unused entry is found, we try to find the oldest entry and
  throw it away. */
  if(i == ARP_TABLE_SIZE)
  {
    maxtime = 0;
    j = 0;
    for(i = 0; i < ARP_TABLE_SIZE; ++i)
    {
      if(arp_table[i].state == ETHARP_STATE_STABLE && ctime - arp_table[i].ctime > maxtime)
      {
        maxtime = ctime - arp_table[i].ctime;
        j = i;
      }
    }
    i = j;
  }

  /* If all table entries were in pending state, we won't send out any
  more ARP requests. We'll just give up. */
  if(i == ARP_TABLE_SIZE)
  {
    DEBUGF(ETHARP_DEBUG, ("etharp_output: no more ARP table entries available.\n"));
    return NULL;
  }

  /* Now, i is the ARP table entry which we will fill with the new
  information. */
  ip_addr_set(&arp_table[i].ipaddr, ipaddr);
  /*    for(k = 0; k < 6; ++k) {
  arp_table[i].ethaddr.addr[k] = dest->addr[k];
  }*/
  arp_table[i].ctime = ctime;
  arp_table[i].state = ETHARP_STATE_PENDING;
  arp_table[i].p = NULL;

  /* We allocate a pbuf for the outgoing ARP request packet. */
  p = pbuf_alloc(PBUF_LINK, sizeof(struct etharp_hdr), PBUF_RAM);
  if(p == NULL)
  {
    /* No ARP request packet could be allocated, so we forget about
    the ARP table entry. */
    if(i != ARP_TABLE_SIZE)
    {
      arp_table[i].state = ETHARP_STATE_EMPTY;
    }      
    return NULL;
  }

  hdr = p->payload;

  hdr->opcode = htons(ARP_REQUEST);

  for(i = 0; i < 6; ++i)
  {
    hdr->dhwaddr.addr[i] = 0x00;
    hdr->shwaddr.addr[i] = srcaddr->addr[i];
  }

  ip_addr_set(&(hdr->dipaddr), ipaddr);
  ip_addr_set(&(hdr->sipaddr), &(netif->ip_addr));

  hdr->hwtype = htons(HWTYPE_ETHERNET);
  ARPH_HWLEN_SET(hdr, 6);

  hdr->proto = htons(ETHTYPE_IP);
  ARPH_PROTOLEN_SET(hdr, sizeof(struct ip_addr));

  for(i = 0; i < 6; ++i)
  {
    hdr->ethhdr.dest.addr[i] = 0xff;
    hdr->ethhdr.src.addr[i] = srcaddr->addr[i];
  }

  hdr->ethhdr.type = htons(ETHTYPE_ARP);      
  return p;
}
