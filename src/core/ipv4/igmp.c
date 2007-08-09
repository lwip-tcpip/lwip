/**
 * @file
 *
 * IGMP - Internet Group Management Protocol
 */

/*
 * Copyright (c) 2002 CITEL Technologies Ltd.
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
 * 3. Neither the name of CITEL Technologies Ltd nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY CITEL TECHNOLOGIES AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL CITEL TECHNOLOGIES OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 * This file is a contribution to the lwIP TCP/IP stack.
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code.
*/

/************************************************************
In the spirit of LW (I hope)
-------------------------------------------------------------
note 1)
Although the rfc requires V1 AND V2 capability
we will only support v2 since now V1 is 5 years old
V1 can be added if required

a debug print and statistic have been implemented to
show this up.
-------------------------------------------------------------
-------------------------------------------------------------
note 2)

A query for a specific group address (as opposed to ALLHOSTS)
has now been implemented as I am unsure if it is required

a debug print and statistic have been implemented to
show this up.
-------------------------------------------------------------
-------------------------------------------------------------
note 3)
The router alert rfc 2113 is implemented in outgoing packets
but not checked rigorously incoming
-------------------------------------------------------------
Steve Reynolds
------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 * RFC 988  - Host extensions for IP multicasting                         - V0
 * RFC 1054 - Host extensions for IP multicasting                         -
 * RFC 1112 - Host extensions for IP multicasting                         - V1
 * RFC 2236 - Internet Group Management Protocol, Version 2               - V2  <- this code is based on this RFC (it's the "de facto" standard)
 * RFC 3376 - Internet Group Management Protocol, Version 3               - V3
 * RFC 4604 - Using Internet Group Management Protocol Version 3...       - V3+
 * RFC 2113 - IP Router Alert Option                                      - 
 *----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 * Includes
 *----------------------------------------------------------------------------*/

#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/stats.h"
#include "lwip/igmp.h"

#include "arch/perf.h"

#include "string.h"

/* IGMP support available? */
#if defined(LWIP_IGMP) && (LWIP_IGMP > 0)

/*-----------------------------------------------------------------------------
 * Globales
 *----------------------------------------------------------------------------*/

static struct igmp_group* igmp_group_list;
static struct igmp_stats  igmpstats; /** @todo: Should we have stats per netif? */

static struct ip_addr     allsystems;
static struct ip_addr     allrouters;

/**
 * Initialize this module
 *
 * Only network interfaces registered when this function is called
 * are igmp-enabled.
 *
 * This will enable igmp on all interface. In the current implementation it
 * is not possible to have igmp on one interface but not the other.
 */
void
igmp_init(void)
{
  struct igmp_group* group;
  struct netif*      netif;

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_init: initializing\n"));

  IP4_ADDR(&allsystems, 224, 0, 0, 1);
  IP4_ADDR(&allrouters, 224, 0, 0, 2);

  igmp_group_list = NULL;

  /* Clear stats*/
  memset(&igmpstats, 0, sizeof(igmpstats));

  for (netif = netif_list; netif != NULL; netif = netif->next) {
    group = igmp_lookup_group(netif, &allsystems);
      
    if (group != NULL) {
      group->group_state = IDLE_MEMBER;

      /* Allow the igmp messages at the MAC level */
      if (netif->igmp_mac_filter != NULL) {
        netif->igmp_mac_filter(netif, &allsystems, IGMP_ADD_MAC_FILTER);
      }
    }
  }
}

/**
 * Search for a group in the global igmp_group_list
 *
 * @param ifp the network interface for which to look
 * @param addr the group ip address to search for
 * @return a struct igmp_group* if the group has been found,
 *         NULL if the group wasn't found.
 */
struct igmp_group *
igmp_lookfor_group(struct netif *ifp, struct ip_addr *addr)
{
  struct igmp_group *group = igmp_group_list;

  while (group) {
    if ((group->interface == ifp) && (ip_addr_cmp(&(group->group_address), addr))) {
      return group;
    }
    group = group->next;
  }

  /* to be clearer, we return NULL here instead of
   * 'group' (which is also NULL at this point).
   */
  return NULL;
}

/**
 * Search for a specific igmp group and create a new one if not found-
 *
 * @param ifp the network interfacefor which to look
 * @param addr the group ip address to search
 * @return a struct igmp_group*,
 *         NULL on memory error.
 */
struct igmp_group *
igmp_lookup_group(struct netif *ifp, struct ip_addr *addr)
{
  struct igmp_group *group = igmp_group_list;
  
  /* Search if the group already exists */
  group = igmp_lookfor_group(ifp, addr);
  if (group != NULL) {
    /* Group already exists. */
    return group;
  }

  /* Group doesn't exist yet, create a new one. */
  group = mem_malloc(sizeof(struct igmp_group));
  if (group != NULL) {
    group->interface          = ifp;
    ip_addr_set(&(group->group_address), addr);
    group->timer              = 0; /* Not running */
    group->group_state        = NON_MEMBER;
    group->last_reporter_flag = 0;
    group->next               = igmp_group_list;

    igmp_group_list = group;
     
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_lookup_group: allocated a new group with address %x on if %x \n", (int) addr, (int) ifp));
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_lookup_group: impossible to allocated a new group with address %x on if %x \n", (int) addr, (int) ifp));
  }

  return group;
}

/**
 * Called from ip_input() if a new IGMP packet is received.
 *
 * @param p received igmp packet, p->payload pointing to the ip header
 * @param inp network interface on which the packet was received
 * @param dest destination ip address of the igmp packet
 */
void
igmp_input(struct pbuf *p, struct netif *inp, struct ip_addr *dest)
{
  struct ip_hdr *    iphdr;
  struct igmpmsg*    igmp;
  struct igmp_group* group;
  struct igmp_group* groupref;

  /* Note that the length CAN be greater than 8 but only 8 are used - All are included in the checksum */    
  iphdr = p->payload;
  if (pbuf_header(p, -(IPH_HL(iphdr) * 4)) || (p->len < IGMP_MINLEN)) {
    pbuf_free(p);
    igmpstats.igmp_length_err++;
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: length error\n"));
    return;
  }

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: message to address %l \n", (long)dest->addr));

  /* Now calculate and check the checksum */
  igmp = (struct igmpmsg *)p->payload;
  if (inet_chksum(igmp, p->len)) {
    pbuf_free(p);
    igmpstats.igmp_checksum_err++;
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: checksum error\n"));
    return;
  }

  /* Packet is ok so find an existing group */
  group = igmp_lookfor_group(inp, dest); /* use the incoming IP address! */
  
  /* If group can be found or create... */
  if (!group) {
    pbuf_free(p);
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: IGMP frame not for us\n"));
    return;
  }

  /* NOW ACT ON THE INCOMING MESSAGE TYPE... */

  /* The membership query message goes to the all groups address */
  /* and it control block does not have state */
  if ((igmp->igmp_msgtype == IGMP_MEMB_QUERY) && (ip_addr_cmp(dest, &allsystems)) &&
      (igmp->igmp_group_address.addr == 0)) {
    /* THIS IS THE GENERAL QUERY */
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: General IGMP_MEMB_QUERY on ALL SYSTEMS ADDRESS 224.0.0.1\n"));

    if (0 ==igmp->igmp_maxresp) {
      igmpstats.igmp_v1_rxed++;
      igmp->igmp_maxresp = 10;
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: got an all hosts query with time== 0 - this is V1 and not implemented - treat as v2\n"));
    }

    igmpstats.igmp_group_query_rxed++;
    groupref = igmp_group_list;
    while (groupref) {
      if ((groupref->interface == inp) &&
          (!(ip_addr_cmp(&(groupref->group_address), &allsystems)))) {
        /* Do not send messages on the all systems group address! */
        if ((groupref->group_state == IDLE_MEMBER) ||
            ((groupref->group_state == DELAYING_MEMBER) &&
             (igmp->igmp_maxresp > groupref->timer))) {
          igmp_start_timer(groupref, (igmp->igmp_maxresp)/2);
          groupref->group_state = DELAYING_MEMBER;
        }
      }
      groupref = groupref->next;
    }
  } else {
    if ((igmp->igmp_msgtype == IGMP_MEMB_QUERY) && ip_addr_cmp (dest, &allsystems) &&
        (group->group_address.addr != 0)) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: got a  query to a specific group using the allsystems address \n"));

      /* we first need to re-lookup the group since we used dest last time */
      group = igmp_lookfor_group(inp, &igmp->igmp_group_address); /* use the incoming IP address! */
      if (group != NULL) {
        igmpstats.igmp_unicast_query++;

        if ((group->group_state == IDLE_MEMBER) || ((group->group_state == DELAYING_MEMBER) &&
            (igmp->igmp_maxresp > group->timer))) {
          igmp_start_timer(group, (igmp->igmp_maxresp)/2);
          group->group_state = DELAYING_MEMBER;
        }
      }
    } else {
      if ((igmp->igmp_msgtype == IGMP_MEMB_QUERY) && !(ip_addr_cmp (dest, &allsystems)) &&
          (group->group_address.addr != 0)) {
        LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: got a  query to a specific group with the group address as destination \n"));

        igmpstats.igmp_unicast_query++; /* This is the unicast query */
        if ((group->group_state == IDLE_MEMBER) || ((group->group_state == DELAYING_MEMBER) &&
            (igmp->igmp_maxresp > group->timer))) {
          igmp_start_timer(group, (igmp->igmp_maxresp)/2);
          group->group_state = DELAYING_MEMBER;
        }
      } else {
        if (igmp->igmp_msgtype == IGMP_V2_MEMB_REPORT) {
          LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: got an IGMP_V2_MEMB_REPORT \n"));

          igmpstats.report_rxed++;
          if (group->group_state == DELAYING_MEMBER) {
            /* This is on a specific group we have already looked up */
            group->timer = 0; /* stopped */
            group->group_state = IDLE_MEMBER;
            group->last_reporter_flag = 0;
          }
        } else {
          LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: unexpected msg %x in state %x on group %x  at interface %x\n", (int) igmp->igmp_msgtype, (int) group->group_state, (int) &group, (int) group->interface));
        }
      }
    }
  }
  pbuf_free(p);
  return;
}

/**
 * Join a group on one network interface.
 *
 * @param ifp the network interface which should join a new group
 * @param groupaddr the ip address of the group which to join
 * @return ERR_OK if group was joined, an err_t otherwise
 */
err_t
igmp_joingroup(struct netif *ifp, struct ip_addr *groupaddr)
{
  struct igmp_group *group;

  /* make sure it is multicast address */
  if (!ip_addr_ismulticast(groupaddr)) {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup: attempt to join non-multicast address\n"));
    return ERR_VAL;
  }

  /* find group or create a new one if not found */
  group = igmp_lookup_group(ifp, groupaddr);

  if (group != NULL) {
    /* This should create a new group, check the state to make sure */
    if (group->group_state != NON_MEMBER) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup: join to group not in state NON_MEMBER\n"));
      return ERR_OK;
    }

    /* OK - it was new group */
    igmpstats.igmp_joins++;

    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup: join to new group: "));
    ip_addr_debug_print(IGMP_DEBUG, groupaddr);
    LWIP_DEBUGF(IGMP_DEBUG, ("\n"));

    if (ifp->igmp_mac_filter != NULL) {
      ifp->igmp_mac_filter(ifp, groupaddr, IGMP_ADD_MAC_FILTER);
    }

    igmp_send(group, IGMP_V2_MEMB_REPORT);

    igmp_start_timer(group, 5);

    /* Need to work out where this timer comes from */
    group->group_state = DELAYING_MEMBER;

    return ERR_OK;
  }

  return ERR_MEM;
}

/**
 * Leave a group on one network interface.
 *
 * @param ifp the network interface which should leave a group
 * @param groupaddr the ip address of the group which to leave
 * @return ERR_OK if group was left, an err_t otherwise
 */
err_t
igmp_leavegroup(struct netif *ifp, struct ip_addr *groupaddr)
{
  struct igmp_group *group;

  group = igmp_lookfor_group(ifp, groupaddr);

  if (group != NULL) {
    /* Only send a leave if the flag is set according to the state diagram */
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup: Leaving group: "));
    ip_addr_debug_print(IGMP_DEBUG, groupaddr);
    LWIP_DEBUGF(IGMP_DEBUG, ("\n"));

    if (group->last_reporter_flag) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup: sending leaving group"));
      igmpstats.igmp_leave_sent++;
      igmp_send(group, IGMP_LEAVE_GROUP);
    }

    /* The block is not deleted since the group still exists and we may rejoin */
    group->last_reporter_flag = 0;
    group->group_state        = NON_MEMBER;
    group->timer              = 0;

    if (ifp->igmp_mac_filter != NULL) {
      ifp->igmp_mac_filter(ifp, groupaddr, IGMP_DEL_MAC_FILTER);
    }

    return ERR_OK;
  }

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup: not member of group"));

  return ERR_VAL;
}

/**
 * The igmp timer function (both for NO_SYS=1 and =0)
 * Should be called every IGMP_TMR_INTERVAL milliseconds (100 ms is default).
 */
void
igmp_tmr(void)
{
  struct igmp_group *group = igmp_group_list;

  while (group != NULL) {
    if (group->timer != 0) {
      group->timer -= 1;
      if (group->timer == 0) {
        igmp_timeout(group);
      }
    }
    group = group->next;
  }
}

/**
 * Called if a timeout for one group is reached.
 * Sends a report for this group.
 *
 * @param group an igmp_group for which a timeout is reached
 */
void
igmp_timeout(struct igmp_group *group)
{
  /* If the state is DELAYING_MEMBER then we send a report for this group */
  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_timeout: got a timeout\n"));

  if (group->group_state == DELAYING_MEMBER) {
    igmp_send(group, IGMP_V2_MEMB_REPORT);
  }
}

/**
 * Start a timer for an igmp group
 *
 * @param group the igmp_group for which to start a timer
 * @param max_time the time in multiples of IGMP_TMR_INTERVAL (decrease with
 *        every call to igmp_tmr())
 */
void
igmp_start_timer(struct igmp_group *group, u8_t max_time)
{
  /* Important !! this should be random 0 -> max_time
   * find out how to do this
   */
  group->timer = max_time;
}

/**
 * Stop a timer for an igmp_group
 *
 * @param group the igmp_group for which to stop the timer
 */
void
igmp_stop_timer(struct igmp_group *group)
{
  group->timer = 0;
}

/**
 * Sends an IP packet on a network interface. This function constructs the IP header
 * and calculates the IP header checksum. If the source IP address is NULL,
 * the IP address of the outgoing network interface is filled in as source address.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 */
err_t
igmp_ip_output_if(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
                  u8_t ttl, u8_t proto, struct netif *netif)
{
  static struct ip_hdr * iphdr = NULL;
  static u16_t           ip_id = 0;
  u16_t *                ra    = NULL;

  /* First write in the "router alert" */
  if (pbuf_header(p, ROUTER_ALERTLEN)) {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_ip_output_if: not enough room for IP header in pbuf\n"));
    return ERR_BUF;
  }

  /* This is the "router alert" option */
  ra    = p->payload;
  ra[0] = htons (0x9404);
  ra[1] = 0x0000;

  /* now the normal ip header */
  if (pbuf_header(p, IP_HLEN)) {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_ip_output_if: not enough room for IP header in pbuf\n"));
    return ERR_BUF;
  }

  iphdr = p->payload;
  if (dest != IP_HDRINCL) {
    iphdr->_ttl_proto = (proto<<8);
    iphdr->_ttl_proto |= ttl;

    /*  iphdr->dest = dest->addr; */
    ip_addr_set(&(iphdr->dest), dest);
#ifdef HAVE_BITFIELDS
    iphdr->_v_hl_tos |= ((IP_HLEN+ ROUTER_ALERTLEN)/4)<<16;
    iphdr->_v_hl_tos |= 4<<24;
#else
    iphdr->_v_hl_tos = (4 << 4) | ((IP_HLEN + ROUTER_ALERTLEN)/ 4 & 0xf);
#endif /* HAVE_BITFIELDS */

    iphdr->_v_hl_tos |= 0;
    iphdr->_len       = htons(p->tot_len);
    iphdr->_offset    = htons(0);
    iphdr->_id        = htons(ip_id++);

    if (ip_addr_isany(src)) {
      ip_addr_set(&(iphdr->src), &(netif->ip_addr));
    } else {
      ip_addr_set(&(iphdr->src), src);
    }

    iphdr->_chksum = 0;
    iphdr->_chksum = inet_chksum(iphdr, IP_HLEN + ROUTER_ALERTLEN);
  } else {
    dest = &(iphdr->dest);
  }

#if IP_DEBUG
  ip_debug_print(p);
#endif

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_ip_output_if: sending to netif %x \n", (int) netif));

  return netif->output(netif, p, dest);
}

/**
 * Send an igmp packet to a specific group.
 *
 * @param the group to which to send the packet
 * @param type the type of igmp packet to send
 */
void
igmp_send(struct igmp_group *group, u8_t type)
{
  struct pbuf*    p    = NULL;
  struct igmpmsg* igmp = NULL;
  struct ip_addr  src  = {0};
  struct ip_addr* dest = NULL;

  /* IP header + IGMP header */
  p = pbuf_alloc(PBUF_TRANSPORT, IGMP_MINLEN, PBUF_RAM);
  
  if (p) {
    igmp = p->payload;
    LWIP_ASSERT("igmp_send: check that first pbuf can hold struct igmpmsg",
               (p->len >= sizeof(struct igmpmsg)));
    ip_addr_set(&src, &((group->interface)->ip_addr));
     
    if (type == IGMP_V2_MEMB_REPORT) {
      dest = &(group->group_address);
      igmpstats.report_sent++;
      ip_addr_set(&(igmp->igmp_group_address), &(group->group_address));
      group->last_reporter_flag = 1; /* Remember we were the last to report */
    } else {
      if (type == IGMP_LEAVE_GROUP) {
        dest = &allrouters;
        ip_addr_set(&(igmp->igmp_group_address), &(group->group_address));
      }
    }

   if ((type == IGMP_V2_MEMB_REPORT) || (type == IGMP_LEAVE_GROUP)) {
     igmp->igmp_msgtype  = type;
     igmp->igmp_maxresp  = 0;
     igmp->igmp_checksum = 0;
     igmp->igmp_checksum = inet_chksum( igmp, IGMP_MINLEN);

     igmp_ip_output_if( p, &src, dest, IGMP_TTL, IP_PROTO_IGMP, group->interface);
   }
    
   pbuf_free (p);
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_send: not enough memory for igmp_send\n"));
  }
}

#endif /* LWIP_IGMP */
