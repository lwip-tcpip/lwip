/**
 * @file
 * Address Resolution Protocol module for IP over Ethernet
 *
 * $Log: etharp.c,v $
 * Revision 1.18  2003/01/08 09:24:50  likewise
 * Removed etharp_output_sent() as etharp.c no longer returns ARP packets to the driver.
 *
 * Revision 1.17  2002/12/18 12:49:02  jani
 * renamed (hopefully everywhere) stats to lwip_stats.closes bug #1901
 *
 * Revision 1.16  2002/12/17 09:41:16  jani
 * Use C style comments.In debug stataments cast various struct pointers to void* to
 * avoid printf warnings.misc warnings in etharp.
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
 
/*
 * TODO:
 *
RFC 3220 4.6          IP Mobility Support for IPv4          January 2002 

      -  A Gratuitous ARP [45] is an ARP packet sent by a node in order 
         to spontaneously cause other nodes to update an entry in their 
         ARP cache.  A gratuitous ARP MAY use either an ARP Request or 
         an ARP Reply packet.  In either case, the ARP Sender Protocol 
         Address and ARP Target Protocol Address are both set to the IP 
         address of the cache entry to be updated, and the ARP Sender 
         Hardware Address is set to the link-layer address to which this 
         cache entry should be updated.  When using an ARP Reply packet, 
         the Target Hardware Address is also set to the link-layer 
         address to which this cache entry should be updated (this field 
         is not used in an ARP Request packet). 

         In either case, for a gratuitous ARP, the ARP packet MUST be 
         transmitted as a local broadcast packet on the local link.  As 
         specified in [36], any node receiving any ARP packet (Request 
         or Reply) MUST update its local ARP cache with the Sender 
         Protocol and Hardware Addresses in the ARP packet, if the 
         receiving node has an entry for that IP address already in its 
         ARP cache.  This requirement in the ARP protocol applies even 
         for ARP Request packets, and for ARP Reply packets that do not 
         match any ARP Request transmitted by the receiving node [36]. 
*
  My suggestion would be to send a ARP request for our newly obtained
  address upon configuration of an Ethernet interface.

*/

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/inet.h"
#include "netif/etharp.h"
#include "lwip/ip.h"
#include "lwip/stats.h"
#include "lwipopts.h"

/* ARP needs to inform DHCP of any ARP replies? */
#if (LWIP_DHCP && DHCP_DOES_ARP_CHECK)
#  include "lwip/dhcp.h"
#endif

/** the time an ARP entry stays valid after its last update, (120 * 10) seconds = 20 minutes. */
#define ARP_MAXAGE 120  
/** the time an ARP entry stays pending after first request, (2 * 10) seconds = 20 seconds. */
#define ARP_MAXPENDING 2 

/**
 * 
 * - If enabled, cache entries are generated for every kind of ARP/IP traffic.
 * This enhances behaviour for sending to a dynamic set of hosts, for example
 * if acting as a gateway.
 * - If disabled, cache entries are generated only for IP destination addresses
 * in use by lwIP or applications. This enhances performance if sending to a small,
 * reasonably static number of hosts. Typically for embedded devices.
 */
#ifndef ETHARP_ALWAYS_INSERT
#  define ETHARP_ALWAYS_INSERT 1
#endif

#define HWTYPE_ETHERNET 1

/** ARP message types */
#define ARP_REQUEST 1
#define ARP_REPLY 2

#define ARPH_HWLEN(hdr) (NTOHS((hdr)->_hwlen_protolen) >> 8)
#define ARPH_PROTOLEN(hdr) (NTOHS((hdr)->_hwlen_protolen) & 0xff)

#define ARPH_HWLEN_SET(hdr, len) (hdr)->_hwlen_protolen = HTONS(ARPH_PROTOLEN(hdr) | ((len) << 8))
#define ARPH_PROTOLEN_SET(hdr, len) (hdr)->_hwlen_protolen = HTONS((len) | (ARPH_HWLEN(hdr) << 8))

enum etharp_state {
  ETHARP_STATE_EMPTY,
  ETHARP_STATE_PENDING,
  ETHARP_STATE_STABLE
};

struct etharp_entry {
  struct ip_addr ipaddr;
  struct eth_addr ethaddr;
  enum etharp_state state;
#if ARP_QUEUEING
  struct pbuf *p;
#endif
  u8_t ctime;
};

static const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}};
static struct etharp_entry arp_table[ARP_TABLE_SIZE];
static u8_t ctime;

static struct pbuf *update_arp_entry(struct netif *netif, struct ip_addr *ipaddr, struct eth_addr *ethaddr, u8_t flags);
#define ARP_INSERT_FLAG 1

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
#if ARP_QUEUEING
    arp_table[i].p = NULL;
#endif
  }
  /* reset ARP current time */
  ctime = 0;
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
  DEBUGF(ETHARP_DEBUG, ("etharp_timer\n"));
  /* remove expired entries from the ARP table */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    if((arp_table[i].state == ETHARP_STATE_STABLE) &&       
       (ctime - arp_table[i].ctime >= ARP_MAXAGE)) {
      DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired stable entry %u.\n", i));
      arp_table[i].state = ETHARP_STATE_EMPTY;
#if ARP_QUEUEING
      /* remove any queued packet */
      pbuf_free(arp_table[i].p);      
      arp_table[i].p = NULL;
#endif
    } else if((arp_table[i].state == ETHARP_STATE_PENDING) &&
	      (ctime - arp_table[i].ctime >= ARP_MAXPENDING)) {
      arp_table[i].state = ETHARP_STATE_EMPTY;
#if ARP_QUEUEING
      DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired pending entry %u - dequeueing %p.\n", i, (void *)(arp_table[i].p)));
      /* remove any queued packet */
      pbuf_free(arp_table[i].p);      
      arp_table[i].p = NULL;
#else
      DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired pending entry %u.\n", i));
#endif
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
      DEBUGF(ETHARP_DEBUG, ("find_arp_entry: found empty entry %u\n", i));
      break;
    }
  }
  
  /* If no unused entry is found, we try to find the oldest entry and
     throw it away. */
  if(i == ARP_TABLE_SIZE) {
    maxtime = 0;
    j = ARP_TABLE_SIZE;
    for(i = 0; i < ARP_TABLE_SIZE; ++i) {
      /* remember entry with oldest stable entry in j*/
      if((arp_table[i].state == ETHARP_STATE_STABLE) &&
      (ctime - arp_table[i].ctime > maxtime)) {
        maxtime = ctime - arp_table[i].ctime;
	      j = i;
      }
    }
    DEBUGF(ETHARP_DEBUG, ("find_arp_entry: found oldest stable entry %u\n", j));
    i = j;
  }
  DEBUGF(ETHARP_DEBUG, ("find_arp_entry: returning %u, state %u\n", i, arp_table[i].state));
  return i;
}

/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * @param ipaddr IP address of the inserted ARP entry.
 * @param ethaddr Ethernet address of the inserted ARP entry.
 * @param flags Defines behaviour:
 * - ARP_INSERT_FLAG Allows ARP to insert this as a new item. If not specified,
 * only existing ARP entries will be updated.
 *
 * @return pbuf If non-NULL, a packet that was queued on a pending entry.
 * You should sent it and must call pbuf_free() afterwards.
 *
 * @see pbuf_free()
 */
static struct pbuf *
update_arp_entry(struct netif *netif, struct ip_addr *ipaddr, struct eth_addr *ethaddr, u8_t flags)
{
  u8_t i, k;
#if ARP_QUEUEING
  struct eth_hdr *ethhdr;
#endif
  DEBUGF(ETHARP_DEBUG, ("update_arp_entry()"));
  DEBUGF(ETHARP_DEBUG, ("update_arp_entry: %u.%u.%u.%u - %02x:%02x:%02x:%02x:%02x:%02x\n", ip4_addr1(ipaddr), ip4_addr2(ipaddr), ip4_addr3(ipaddr), ip4_addr4(ipaddr),
  ethaddr->addr[0], ethaddr->addr[1], ethaddr->addr[2], ethaddr->addr[3], ethaddr->addr[4], ethaddr->addr[5]));
  /* do not update for 0.0.0.0 addresses */
  if (ipaddr->addr == 0) {
    DEBUGF(ETHARP_DEBUG, ("update_arp_entry: will not add 0.0.0.0 to ARP cache\n"));
    return NULL;
  }
  /* Walk through the ARP mapping table and try to find an entry to
  update. If none is found, the IP -> MAC address mapping is
  inserted in the ARP table. */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    /* Check if the source IP address of the incoming packet matches
    the IP address in this ARP table entry. */
    if(ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
      /* pending entry? */
      if(arp_table[i].state == ETHARP_STATE_PENDING) {
        DEBUGF(ETHARP_DEBUG, ("update_arp_entry: pending entry %u goes stable\n", i));
        /* A pending entry was found, mark it stable */
        arp_table[i].state = ETHARP_STATE_STABLE;
        /* fall-through to next if */
      }
      /* stable entry? (possible just marked to become stable) */
      if(arp_table[i].state == ETHARP_STATE_STABLE) {
        DEBUGF(ETHARP_DEBUG, ("update_arp_entry: updating stable entry %u\n", i));
        /* An old entry found, update this and return. */
        for(k = 0; k < 6; ++k) {
          arp_table[i].ethaddr.addr[k] = ethaddr->addr[k];
        }
        /* time stamp */
        arp_table[i].ctime = ctime;
#if ARP_QUEUEING
        /* queued packet present? */
        if(arp_table[i].p != NULL) {	

          /* fill-in Ethernet header */
          ethhdr = arp_table[i].p->payload;
          for(k = 0; k < 6; ++k) {
            ethhdr->dest.addr[k] = ethaddr->addr[k];
          }
          ethhdr->type = htons(ETHTYPE_IP);	  	 	  
          DEBUGF(ETHARP_DEBUG, ("update_arp_entry: sending queued IP packet.\n"));
          /* send the queued IP packet */
          netif->linkoutput(netif, arp_table[i].p);
          /* free the queued IP packet */
          pbuf_free(arp_table[i].p);
          /* remove queued packet from ARP entry (must be freed by the caller) */
          arp_table[i].p = NULL;	
        }
#endif
        return NULL;
      }
    } /* if */
  } /* for */

  /* no matching ARP entry was found */
  ASSERT("update_arp_entry: i == ARP_TABLE_SIZE", i == ARP_TABLE_SIZE);

  DEBUGF(ETHARP_DEBUG, ("update_arp_entry: IP address not yet in table\n"));
  /* allowed to insert an entry? */
  if ((ETHARP_ALWAYS_INSERT) || (flags & ARP_INSERT_FLAG))
  {
    DEBUGF(ETHARP_DEBUG, ("update_arp_entry: adding entry to table\n"));
    /* find an empty or old entry. */
    i = find_arp_entry();
    if(i == ARP_TABLE_SIZE) {
      DEBUGF(ETHARP_DEBUG, ("update_arp_entry: no available entry found\n"));
      return NULL;
    }
    /* see if find_arp_entry() gave us an old stable, or empty entry to re-use */
    if (arp_table[i].state == ETHARP_STATE_STABLE) {
      DEBUGF(ETHARP_DEBUG, ("update_arp_entry: overwriting old stable entry %u\n", i));
      /* stable entries should have no queued packets (TODO: allow later) */
      ASSERT("update_arp_entry: arp_table[i].p == NULL", arp_table[i].p == NULL);
    } else {
      DEBUGF(ETHARP_DEBUG, ("update_arp_entry: filling empty entry %u with state %u\n", i, arp_table[i].state));
      ASSERT("update_arp_entry: arp_table[i].state == ETHARP_STATE_EMPTY", arp_table[i].state == ETHARP_STATE_EMPTY);
    }
    /* set IP address */  
    ip_addr_set(&arp_table[i].ipaddr, ipaddr);
    /* set Ethernet hardware address */  
    for(k = 0; k < 6; ++k) {
      arp_table[i].ethaddr.addr[k] = ethaddr->addr[k];
    }
    /* time-stamp */  
    arp_table[i].ctime = ctime;
    /* mark as stable */  
    arp_table[i].state = ETHARP_STATE_STABLE;
    /* no queued packet */  
#if ARP_QUEUEING
    arp_table[i].p = NULL;
#endif
  }
  else
  {
    DEBUGF(ETHARP_DEBUG, ("update_arp_entry: no matching stable entry to update\n"));
  }
  return NULL;
}

/**
 * Updates the ARP table using the given packet.
 *
 * Uses the incoming IP packet's source address to update the
 * ARP cache for the local network. The function does not alter
 * or free the packet. This function must be called before the
 * packet p is passed to the IP layer.
 *
 * @param netif The lwIP network interface on which the IP packet pbuf arrived.
 * @param pbuf The IP packet that arrived on netif.
 * 
 * @return NULL
 *
 * @see pbuf_free()
 */
struct pbuf *
etharp_ip_input(struct netif *netif, struct pbuf *p)
{
  struct ethip_hdr *hdr;
  
  /* Only insert an entry if the source IP address of the
     incoming IP packet comes from a host on the local network. */
  hdr = p->payload;
  /* source is on local network? */
  if(!ip_addr_maskcmp(&(hdr->ip.src), &(netif->ip_addr), &(netif->netmask))) {
    /* do nothing */
    return NULL;
  }
  
  DEBUGF(ETHARP_DEBUG, ("etharp_ip_input: updating ETHARP table.\n"));
  /* update ARP table, ask to insert entry */
  update_arp_entry(netif, &(hdr->ip.src), &(hdr->eth.src), ARP_INSERT_FLAG);
  return NULL;
}


/**
 * Responds to ARP requests, updates ARP entries and sends queued IP packets.
 * 
 * Should be called for incoming ARP packets. The pbuf in the argument
 * is freed by this function.
 *
 * @param netif The lwIP network interface on which the ARP packet pbuf arrived.
 * @param pbuf The ARP packet that arrived on netif. Is freed by this function.
 * @param ethaddr Ethernet address of netif.
 *
 * @return NULL
 *
 * @see pbuf_free()
 */
struct pbuf *
etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
{
  struct etharp_hdr *hdr;
  u8_t i;

  /* drop short ARP packets */
  if(p->tot_len < sizeof(struct etharp_hdr)) {
    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: packet too short (%d/%d)\n", p->tot_len, sizeof(struct etharp_hdr)));
    pbuf_free(p);
    return NULL;
  }

  hdr = p->payload;

  switch(htons(hdr->opcode)) {
  /* ARP request? */
  case ARP_REQUEST:
    /* ARP request. If it asked for our address, we send out a
    reply. In any case, we time-stamp any existing ARP entry,
    and possiby send out an IP packet that was queued on it. */

    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: incoming ARP request\n"));
    /* we are not configured? */
    if(netif->ip_addr.addr == 0) {
      DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: we are unconfigured, ARP request ignored.\n"));
      pbuf_free(p);
      return NULL;
    }
    /* update the ARP cache */
    update_arp_entry(netif, &(hdr->sipaddr), &(hdr->shwaddr), 0);
    /* ARP request for our address? */
    if(ip_addr_cmp(&(hdr->dipaddr), &(netif->ip_addr))) {

      DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: replying to ARP request for our IP address\n"));
      /* re-use pbuf to send ARP reply */
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
      /* return ARP reply */
      netif->linkoutput(netif, p);
    } else {
      DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: incoming ARP request was not for us.\n"));
    }
    break;
  case ARP_REPLY:    
    /* ARP reply. We insert or update the ARP table. */
    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: incoming ARP reply\n"));
#if (LWIP_DHCP && DHCP_DOES_ARP_CHECK)
    /* DHCP needs to know about ARP replies */
    dhcp_arp_reply(&hdr->sipaddr);
#endif
    /* ARP reply directed to us? */
    if(ip_addr_cmp(&(hdr->dipaddr), &(netif->ip_addr))) {
      DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: incoming ARP reply is for us\n"));
      /* update_the ARP cache, ask to insert */
      update_arp_entry(netif, &(hdr->sipaddr), &(hdr->shwaddr), ARP_INSERT_FLAG);
    /* ARP reply not directed to us */
    } else {
      DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: incoming ARP reply is not for us\n"));
      /* update the destination address pair */
      update_arp_entry(netif, &(hdr->sipaddr), &(hdr->shwaddr), 0);
      /* update the destination address pair */
      update_arp_entry(netif, &(hdr->dipaddr), &(hdr->dhwaddr), 0);
    }
    break;
  default:
    DEBUGF(ETHARP_DEBUG, ("etharp_arp_input: ARP unknown opcode type %d\n", htons(hdr->opcode)));
    break;
  }
  /* free ARP packet */
  pbuf_free(p);
  p = NULL;
  /* nothing to send, we did it! */
  return NULL;
}

/** 
 * Resolve and fill-in Ethernet address header for outgoing packet.
 *
 * If ARP has the Ethernet address in cache, the given packet is
 * returned, ready to be sent.
 *
 * If ARP does not have the Ethernet address in cache the packet is
 * queued and a ARP request is sent (on a best-effort basis). This
 * ARP request is returned as a pbuf, which should be sent by the
 * caller.
 *
 * If ARP failed to allocate resources, NULL is returned.
 *
 * A returned non-NULL packet should be sent by the caller and
 * etharp_output_sent() must be called afterwards to free any ARP
 * request.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param ipaddr The IP address of the packet destination.
 * @param pbuf The pbuf(s) containing the IP packet to be sent.
 * 
 * @return If non-NULL, a packet ready to be sent. 
 * @see etharp_output_sent()
 */
struct pbuf *
etharp_output(struct netif *netif, struct ip_addr *ipaddr, struct pbuf *q)
{
  struct eth_addr *dest, *srcaddr, mcastaddr;
  struct eth_hdr *ethhdr;
  u8_t i;

  /* Make room for Ethernet header. */
  if(pbuf_header(q, sizeof(struct eth_hdr)) != 0) {    
    /* The pbuf_header() call shouldn't fail, and we'll just bail
    out if it does.. */
    DEBUGF(ETHARP_DEBUG, ("etharp_output: could not allocate room for header.\n"));
#ifdef LINK_STATS
    ++lwip_stats.link.lenerr;
#endif /* LINK_STATS */
    return NULL;
  }

  /* obtain source Ethernet address of the given interface */
  srcaddr = (struct eth_addr *)netif->hwaddr;

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
  }
  /* destination IP address is an IP multicast address? */
  else if(ip_addr_ismulticast(ipaddr)) {
    /* Hash IP multicast address to MAC address. */
    mcastaddr.addr[0] = 0x01;
    mcastaddr.addr[1] = 0x0;
    mcastaddr.addr[2] = 0x5e;
    mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
    mcastaddr.addr[4] = ip4_addr3(ipaddr);
    mcastaddr.addr[5] = ip4_addr4(ipaddr);
    /* destination Ethernet address is multicast */
    dest = &mcastaddr;
  }
  /* destination IP address is an IP unicast address */
  else {
    /* destination IP network address not on local network? */
    /* this occurs if the packet is routed to the default gateway on this interface */
    if(!ip_addr_maskcmp(ipaddr, &(netif->ip_addr), &(netif->netmask))) {
      /* gateway available? */
      if (netif->gw.addr != 0)
      {
        /* use the gateway IP address */
        ipaddr = &(netif->gw);
      }
      /* no gateway available? */
      else
      {
        /* IP destination address outside local network, but no gateway available */
        return NULL;
      }
    }

    /* Ethernet address for IP destination address is in ARP cache? */
    for(i = 0; i < ARP_TABLE_SIZE; ++i) {
      /* match found? */    
      if(arp_table[i].state == ETHARP_STATE_STABLE &&
        ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
        dest = &arp_table[i].ethaddr;
        break;
      }
    }
    /* could not find the destination Ethernet address in ARP cache? */
    if (dest == NULL) {
      /* ARP query for the IP address, submit this IP packet for queueing */
      etharp_query(netif, ipaddr, q);
      /* return nothing */
      return NULL;
    }
    /* destination Ethernet address resolved from ARP cache */
    else
    {
      /* fallthrough */
    }
  }

  /* destination Ethernet address known */
  if (dest != NULL) {
    /* A valid IP->MAC address mapping was found, so we construct the
    Ethernet header for the outgoing packet. */
    ethhdr = q->payload;

    for(i = 0; i < 6; i++) {
      ethhdr->dest.addr[i] = dest->addr[i];
      ethhdr->src.addr[i] = srcaddr->addr[i];
    }

    ethhdr->type = htons(ETHTYPE_IP);
    /* return the outgoing packet */
    return q;
  }
  /* never reached; here for safety */ 
  return NULL;
}

/**
 * Send an ARP request for the given IP address.
 *
 * Sends an ARP request for the given IP address, unless
 * a request for this address is already pending. Optionally
 * queues an outgoing packet on the resulting ARP entry.
 *
 * @param netif The lwIP network interface where ipaddr
 * must be queried for.
 * @param ipaddr The IP address to be resolved.
 * @param q If non-NULL, a pbuf that must be queued on the
 * ARP entry for the ipaddr IP address.
 *
 * @return NULL.
 *
 * @note Might be used in the future by manual IP configuration
 * as well.
 *
 * TODO: enqueue q here if possible (BEWARE: possible other packet already
 * queued.
 * TODO: The host requirements RFC states that ARP should save at least one
 * packet, and this should be the _latest_ packet.
 * TODO: use the ctime field to see how long ago an ARP request was sent,
 * possibly retry.
 */
struct pbuf *etharp_query(struct netif *netif, struct ip_addr *ipaddr, struct pbuf *q)
{
  struct eth_addr *srcaddr;
  struct etharp_hdr *hdr;
  struct pbuf *p;
  u8_t i;

  srcaddr = (struct eth_addr *)netif->hwaddr;
  /* bail out if this IP address is pending */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    if(ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
      if (arp_table[i].state == ETHARP_STATE_PENDING) {
        DEBUGF(ETHARP_DEBUG, ("etharp_query: requested IP already pending\n"));
        /* break out of for-loop */
        break;
      }
      else if (arp_table[i].state == ETHARP_STATE_STABLE) {
        DEBUGF(ETHARP_DEBUG, ("etharp_query: requested IP already stable\n"));
        return NULL;
      }
    }
  }
  /* queried address not yet pending in ARP table? */
  if (i == ARP_TABLE_SIZE)
  {
    DEBUGF(ETHARP_DEBUG, ("etharp_query: IP address non-pending\n"));
    /* find an available entry */
    i = find_arp_entry();
    /* bail out if no ARP entries are available */
    if(i == ARP_TABLE_SIZE)
    {
      DEBUGF(ETHARP_DEBUG, ("etharp_query: no more ARP table entries available.\n"));
      return NULL;
    }
    DEBUGF(ETHARP_DEBUG, ("etharp_query: created ARP table entry.\n"));
    /* i is available, create ARP entry */
    ip_addr_set(&arp_table[i].ipaddr, ipaddr);
    arp_table[i].ctime = ctime;
    arp_table[i].state = ETHARP_STATE_PENDING;
#if ARP_QUEUEING
    arp_table[i].p = NULL;
#endif
  }
  /* allocate a pbuf for the outgoing ARP request packet */
  p = pbuf_alloc(PBUF_LINK, sizeof(struct etharp_hdr), PBUF_RAM);
  /* could allocate pbuf? */
  if (p != NULL) {
    DEBUGF(ETHARP_DEBUG, ("etharp_query: sending ARP request.\n"));
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
    /* send ARP query */
    netif->linkoutput(netif, p);
    /* free ARP query packet */
    pbuf_free(p);
    p = NULL;
  } else {
    DEBUGF(ETHARP_DEBUG, ("etharp_query: could not allocate pbuf for ARP request.\n"));
  }
#if ARP_QUEUEING
  /* any pbuf to queue and queue is empty? */
  if ((q != NULL) && (arp_table[i].p == NULL)) {
    /* copy PBUF_REF referenced payloads to PBUF_RAM */
    q = pbuf_unref(q);
    /* pbufs are queued, increase the reference count */
    pbuf_ref_chain(q);
    /* remember pbuf to queue, if any */
    arp_table[i].p = q;
    DEBUGF(ETHARP_DEBUG, ("etharp_query: queued packet on ARP entry.\n"));
  }
#endif
  return NULL;
}
