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
static struct igmp_stats  igmpstats;

static struct ip_addr     allsystems;
static struct ip_addr     allrouters;

/**
 * Initialize this module
 *
 * Only network interfaces registered when this function is called
 * are igmp-enabled.
 */
void
igmp_init(void)
{
  struct igmp_group* group;
  struct netif*      netif;

  LWIP_DEBUGF(IGMP_DEBUG, ("IGMP Initialising\n"));

  IP4_ADDR(&allsystems, 224, 0, 0, 1);
  IP4_ADDR(&allrouters, 224, 0, 0, 2);

  igmp_group_list = NULL;
  memset(&igmpstats, 0, sizeof(igmpstats));

  for (netif = netif_list; netif != NULL; netif = netif->next) {
    group = lookup_group(netif, &allsystems);
      
    if (group) {
      group->group_state = IDLE_MEMBER;

      /* Allow the igmp messages at the MAC level */
      if (netif->igmp_mac_filter != NULL) {
        netif->igmp_mac_filter(netif, &allsystems, IGMP_ADD_MAC_FILTER);
        netif->igmp_mac_filter(netif, &allrouters, IGMP_ADD_MAC_FILTER);
      }
    }
  }
}

/**
 * Search for a group in the global igmp_group_list
 *
 * @param ifp the network interfacefor which to look
 * @param addr the group ip address to search
 * @return a struct igmp_group* if the group has been found,
 *         NULL if the group wasn't found.
 */
struct igmp_group *
lookfor_group(struct netif *ifp, struct ip_addr *addr)
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
lookup_group(struct netif *ifp, struct ip_addr *addr)
{
  struct igmp_group *group = igmp_group_list;
  
  /* Search if the group already exists */
  group = lookfor_group(ifp, addr);
  if (group != NULL) {
    /* Group already exists. */
    return group;
  }

  /* Group doesn't exist yet, create a new one. */
  group = mem_malloc(sizeof(struct igmp_group));
  if (group) {
    group->interface          = ifp;
    ip_addr_set(&(group->group_address), addr);
    group->timer              = 0; /* Not running */
    group->group_state        = NON_MEMBER;
    group->last_reporter_flag = 0;
    group->next               = igmp_group_list;

    igmp_group_list = group;
     
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %d  allocated a new group with address %x on if %x \n", __LINE__, (int) addr, (int) ifp));
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %d  impossible to allocated a new group with address %x on if %x \n", __LINE__, (int) addr, (int) ifp));
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
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %x igmp length error\n", __LINE__));
    return;
  }

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp message to address %l \n", (long)dest->addr));

  /* Now calculate and check the checksum */
  igmp = (struct igmpmsg *)p->payload;
  if (inet_chksum(igmp, p->len)) {
    pbuf_free(p);
    igmpstats.igmp_checksum_err++;
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %d igmp checksum error\n", __LINE__));
    return;
  }

  /* Packet is ok so find the group (or create a new one) */
  group = lookup_group(inp, dest); /* use the incoming IP address! */
  
  /* If group can be found or create... */
  if (!group) {
    pbuf_free(p);
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %d igmp allocation error\n", __LINE__));
    return;
  }

  /* NOW ACT ON THE INCOMING MESSAGE TYPE... */

  /* The membership query message goes to the all groups address */
  /* and it control block does not have state */
  if ((IGMP_MEMB_QUERY == igmp->igmp_msgtype) && (ip_addr_cmp(dest, &allsystems)) &&
      (igmp->igmp_group_address.addr == 0)) {
    /* THIS IS THE GENERAL QUERY */
    LWIP_DEBUGF(IGMP_DEBUG, ("General IGMP_MEMB_QUERY on ALL SYSTEMS ADDRESS 224.0.0.1\n"));

    if (0 ==igmp->igmp_maxresp) {
      igmpstats.igmp_v1_rxed++;
      igmp->igmp_maxresp = 10;
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %d got an all hosts query with time== 0 - this is V1 and not implemented - treat as v2\n", __LINE__));
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
    if ((IGMP_MEMB_QUERY == igmp->igmp_msgtype) && ip_addr_cmp (dest, &allsystems) &&
        (group->group_address.addr != 0)) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %x got a  query to a specific group using the allsystems address \n", __LINE__));

      /* we first need to re-lookup the group since we used dest last time */
      group = lookup_group(inp, &igmp->igmp_group_address); /* use the incoming IP address! */
      igmpstats.igmp_unicast_query++;

      if ((IDLE_MEMBER == group->group_state ) || ((DELAYING_MEMBER == group->group_state) &&
          (igmp->igmp_maxresp > group->timer))) {
        igmp_start_timer(group, (igmp->igmp_maxresp)/2);
        group->group_state = DELAYING_MEMBER;
      }
    } else {
      if ((IGMP_MEMB_QUERY == igmp->igmp_msgtype) && !(ip_addr_cmp (dest, &allsystems)) &&
          (group->group_address.addr != 0)) {
        LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %x got a  query to a specific group with the group address as destination \n", __LINE__));

        igmpstats.igmp_unicast_query++; /* This is the unicast query */
        if ((IDLE_MEMBER == group->group_state) || ((DELAYING_MEMBER == group->group_state) &&
            (igmp->igmp_maxresp > group->timer))) {
          igmp_start_timer(group, (igmp->igmp_maxresp)/2);
          group->group_state = DELAYING_MEMBER;
        }
      } else {
        if (IGMP_V2_MEMB_REPORT == igmp->igmp_msgtype) {
          LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c,Line %x got an IGMP_V2_MEMB_REPORT \n", __LINE__));

          igmpstats.report_rxed++;
          if (DELAYING_MEMBER == group->group_state) {
            /* This is on a specific group we have already looked up */
            group->timer = 0; /* stopped */
            group->group_state = IDLE_MEMBER;
            group->last_reporter_flag = 0;
          }
        } else {
          LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input, Line %x unexpected msg %x in state %x on group %x  at interface %x\n", __LINE__, (int) igmp->igmp_msgtype, (int) group->group_state, (int) &group, (int) group->interface));
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

  group = lookup_group(ifp, groupaddr);

  if (group) {
    /* This should create a new group, check the state to make sure */
    if (group->group_state != NON_MEMBER) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c Line %x join to group not in state NON_MEMBER\n", __LINE__));
      return ERR_OK;
    }

    /* OK - it was new group */
    igmpstats.igmp_joins++;

    LWIP_DEBUGF(IGMP_DEBUG, ("igmp join to new group\n"));

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

  group = lookup_group(ifp, groupaddr);

  if (group) {
    /* Only send a leave if the flag is set according to the state diagram */
    if (group->last_reporter_flag) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c Line %x Leaving group\n", __LINE__));
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

  return ERR_MEM;
}

/**
 * The igmp timer function (both for NO_SYS=1 and =0)
 * Should be called every IGMP_TMR_INTERVAL milliseconds (100 ms is default).
 */
void
igmp_tmr()
{
  struct igmp_group *group = igmp_group_list;

  while (group) {
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
  LWIP_DEBUGF(IGMP_DEBUG, ("igmp.c, got a timeout\n"));

  if (DELAYING_MEMBER == group->group_state) {
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

  LWIP_DEBUGF(IGMP_DEBUG, ("IGMP sending to netif %x \n", (int) netif));

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
    LWIP_ASSERT("check that first pbuf can hold struct igmpmsg",
               (p->len >= sizeof(struct igmpmsg)));
    ip_addr_set(&src, &((group->interface)->ip_addr));
     
    if (IGMP_V2_MEMB_REPORT == type) {
      dest = &(group->group_address);
      igmpstats.report_sent++;
      ip_addr_set(&(igmp->igmp_group_address), &(group->group_address));
      group->last_reporter_flag = 1; /* Remember we were the last to report */
    } else {
      if (IGMP_LEAVE_GROUP == type) {
        dest = &allrouters;
        ip_addr_set(&(igmp->igmp_group_address), &(group->group_address));
      }
    }

   if ((IGMP_V2_MEMB_REPORT == type) || (IGMP_LEAVE_GROUP == type)) {
     igmp->igmp_msgtype  = type;
     igmp->igmp_maxresp  = 0;
     igmp->igmp_checksum = 0;
     igmp->igmp_checksum = inet_chksum( igmp, IGMP_MINLEN);

     igmp_ip_output_if( p, &src, dest, IGMP_TTL, IP_PROTO_IGMP, group->interface);
   }
    
   pbuf_free (p);
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("IGMP, not enough memory for igmp_send\n"));
  }
}

#endif /* LWIP_IGMP */
