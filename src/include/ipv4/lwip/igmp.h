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

#ifndef IGMPH
#define IGMPH

#include "lwip/opt.h"

/* IGMP support available? */
#if defined(LWIP_IGMP) && (LWIP_IGMP > 0)

#ifdef __cplusplus
extern "C" {
#endif

/* Some routers are not happy with ROUTER ALERT make it defineable, 1 to enable */
#define USE_ROUTER_ALERT 0

/*
 * IGMP packet format.
 */
struct igmpmsg {
 u8_t  igmp_msgtype;
 u8_t  igmp_maxresp;
 u16_t igmp_checksum;
 struct ip_addr igmp_group_address;
};

#define MCAST224            224
#define ALLROUTERS_GROUP    224,0,0,2

#define IGMP_MINLEN         8

/*
 * Message types, including version number.
 */
#define IGMP_MEMB_QUERY     0x11 /* Membership query         */
#define IGMP_V1_MEMB_REPORT 0x12 /* Ver. 1 membership report */
#define IGMP_V2_MEMB_REPORT 0x16 /* Ver. 2 membership report */
#define IGMP_LEAVE_GROUP    0x17 /* Leave-group message      */

/* Timer */
#define IGMP_TMR_INTERVAL   100 /* Milliseconds */

/* MAC Filter Actions */
#define IGMP_DEL_MAC_FILTER 0
#define IGMP_ADD_MAC_FILTER 1

/* Group  membership states */
#define NON_MEMBER          0
#define DELAYING_MEMBER     1
#define IDLE_MEMBER         2 

/* Put this is another place when integrated */
#define IP_PROTO_IGMP       2
#define IGMP_TTL            1
#define ROUTER_ALERTLEN     4

/* 
 * now a group structure - there is
 * a list of groups for each interface
 * these should really be linked from the interface, but
 * if we keep them separate we will not affect the lwip original code
 * too much
 * 
 * There will be a group for the all systems group address but this 
 * will not run the state machine as it is used to kick off reports
 * from all the other groups
 */

struct igmp_group {
  struct igmp_group *next;
  struct netif *interface;
  struct ip_addr group_address;
  u8_t last_reporter_flag; /* signifies we were the last person to report */
  u8_t group_state;
  u16_t timer;
};



struct igmp_stats{

  u32_t igmp_length_err;
  u32_t igmp_checksum_err;
  u32_t igmp_v1_rxed;
  u32_t igmp_joins;
  u32_t igmp_leave_sent;
  u32_t igmp_unicast_query;
  u32_t report_sent;
  u32_t igmp_group_query_rxed;
  u32_t report_rxed;
};


/*  Prototypes */
void   igmp_init(void);

struct igmp_group *lookfor_group(struct netif *ifp, struct ip_addr *addr);

struct igmp_group *lookup_group(struct netif *ifp, struct ip_addr *addr);

void   igmp_input( struct pbuf *p, struct netif *inp, struct ip_addr *dest);

err_t  igmp_joingroup( struct netif* ifp, struct ip_addr *groupaddr);

err_t  igmp_leavegroup( struct netif* ifp, struct ip_addr *groupaddr);

void   igmp_tmr();

void   igmp_timeout( struct igmp_group *group);

void   igmp_start_timer( struct igmp_group *group,u8_t max_time);

void   igmp_stop_timer( struct igmp_group *group);

err_t  igmp_ip_output_if( struct pbuf *p, struct ip_addr *src, struct ip_addr *dest, u8_t ttl, u8_t proto, struct netif *netif);

void   igmp_send( struct igmp_group *group, u8_t type);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IGMP */

#endif /* IGMPH */
