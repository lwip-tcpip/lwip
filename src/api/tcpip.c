/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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

#include "lwip/sys.h"

#include "lwip/memp.h"
#include "lwip/pbuf.h"

#include "netif/etharp.h"

#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/tcpip.h"
#include "lwip/igmp.h"

static void (* tcpip_init_done)(void *arg) = NULL;
static void *tcpip_init_done_arg           = NULL;
static sys_mbox_t mbox                     = SYS_MBOX_NULL;

#if LWIP_TCP
static int tcpip_tcp_timer_active = 0;

static void
tcpip_tcp_timer(void *arg)
{
  (void)arg;

  /* call TCP timer handler */
  tcp_tmr();
  /* timer still needed? */
  if (tcp_active_pcbs || tcp_tw_pcbs) {
    /* restart timer */
    sys_timeout( TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
  } else {
    /* disable timer */
    tcpip_tcp_timer_active = 0;
  }
}

#if !NO_SYS
void
tcp_timer_needed(void)
{
  /* timer is off but needed again? */
  if (!tcpip_tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
    /* enable and start timer */
    tcpip_tcp_timer_active = 1;
    sys_timeout( TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
  }
}
#endif /* !NO_SYS */
#endif /* LWIP_TCP */

#if IP_REASSEMBLY
static void
ip_timer(void *data)
{
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: ip_reass_tmr()\n"));
  ip_reass_tmr();
  sys_timeout( IP_TMR_INTERVAL, ip_timer, NULL);
}
#endif /* IP_REASSEMBLY */

#if LWIP_ARP
static void
arp_timer(void *arg)
{
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: etharp_tmr()\n"));
  etharp_tmr();
  sys_timeout( ARP_TMR_INTERVAL, arp_timer, NULL);
}
#endif /* LWIP_ARP */

#if LWIP_DHCP
static void
dhcp_timer_coarse(void *arg)
{
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: dhcp_coarse_tmr()\n"));
  dhcp_coarse_tmr();
  sys_timeout(DHCP_COARSE_TIMER_SECS*1000, dhcp_timer_coarse, NULL);
}

static void
dhcp_timer_fine(void *arg)
{
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: dhcp_fine_tmr()\n"));
  dhcp_fine_tmr();
  sys_timeout(DHCP_FINE_TIMER_MSECS, dhcp_timer_fine, NULL);
}
#endif /* LWIP_DHCP */

#if ETHARP_TCPIP_ETHINPUT
static void
ethernet_input(struct pbuf *p, struct netif *netif)
{
  struct eth_hdr* ethhdr;

  /* points to packet payload, which starts with an Ethernet header */
  ethhdr = p->payload;
  
  switch (htons(ethhdr->type)) {
    /* IP packet? */
    case ETHTYPE_IP:
      #if ETHARP_TRUST_IP_MAC
      /* update ARP table */
      etharp_ip_input( netif, p);
      #endif
      /* skip Ethernet header */
      if(pbuf_header(p, -(s16_t)sizeof(struct eth_hdr))) {
        LWIP_ASSERT("Can't move over header in packet", 0);
        pbuf_free(p);
        p = NULL;
      }
      else
        /* pass to IP layer */
        ip_input(p, netif);
      break;
      
    case ETHTYPE_ARP:
      /* pass p to ARP module  */
      etharp_arp_input(netif, (struct eth_addr*)(netif->hwaddr), p);
      break;

    default:
      pbuf_free(p);
      p = NULL;
      break;
  }
}
#endif /* ETHARP_TCPIP_ETHINPUT */

static void
tcpip_thread(void *arg)
{
  struct tcpip_msg *msg;

#if IP_REASSEMBLY
  sys_timeout( IP_TMR_INTERVAL, ip_timer, NULL);
#endif /* IP_REASSEMBLY */
#if LWIP_ARP
  sys_timeout( ARP_TMR_INTERVAL, arp_timer, NULL);
#endif /* LWIP_ARP */
#if LWIP_DHCP
  sys_timeout(DHCP_COARSE_TIMER_SECS*1000, dhcp_timer_coarse, NULL);
  sys_timeout(DHCP_FINE_TIMER_MSECS, dhcp_timer_fine, NULL);
#endif /* LWIP_DHCP */
#if LWIP_IGMP
  igmp_init();
#endif /* LWIP_IGMP */

  if (tcpip_init_done != NULL) {
    tcpip_init_done(tcpip_init_done_arg);
  }

  while (1) {                          /* MAIN Loop */
    sys_mbox_fetch(mbox, (void *)&msg);
    switch (msg->type) {
    case TCPIP_MSG_API:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: API message %p\n", (void *)msg));
      api_msg_input(msg->msg.apimsg);
      break;

#if ETHARP_TCPIP_INPUT      
    case TCPIP_MSG_INPUT:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: IP packet %p\n", (void *)msg));
      ip_input(msg->msg.inp.p, msg->msg.inp.netif);
      break;
#endif /* ETHARP_TCPIP_INPUT */

#if ETHARP_TCPIP_ETHINPUT
    case TCPIP_MSG_ETHINPUT:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: Ethernet packet %p\n", (void *)msg));
      ethernet_input(msg->msg.inp.p, msg->msg.inp.netif);
      break;
#endif /* ETHARP_TCPIP_ETHINPUT */

    case TCPIP_MSG_CALLBACK:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: CALLBACK %p\n", (void *)msg));
      msg->msg.cb.f(msg->msg.cb.ctx);
      break;
    default:
      break;
    }
    
    if (msg->type!=TCPIP_MSG_API) {
      memp_free(MEMP_TCPIP_MSG, msg);
    }
  }
}

#if ETHARP_TCPIP_INPUT
err_t
tcpip_input(struct pbuf *p, struct netif *inp)
{
  struct tcpip_msg *msg;

  if (mbox != SYS_MBOX_NULL) {
    msg = memp_malloc(MEMP_TCPIP_MSG);
    if (msg == NULL) {
      pbuf_free(p);
      return ERR_MEM;
    }

    msg->type = TCPIP_MSG_INPUT;
    msg->msg.inp.p = p;
    msg->msg.inp.netif = inp;
    sys_mbox_post(mbox, msg);
    return ERR_OK;
  }
  return ERR_VAL;
}
#endif /* ETHARP_TCPIP_INPUT */

#if ETHARP_TCPIP_ETHINPUT
err_t
tcpip_ethinput(struct pbuf *p, struct netif *inp)
{
  struct tcpip_msg *msg;

  if (mbox != SYS_MBOX_NULL) {
    msg = memp_malloc(MEMP_TCPIP_MSG);
    if (msg == NULL) {
      pbuf_free(p);    
      return ERR_MEM;  
    }
    
    msg->type = TCPIP_MSG_ETHINPUT;
    msg->msg.inp.p = p;
    msg->msg.inp.netif = inp;
    sys_mbox_post(mbox, msg);
    return ERR_OK;
  }
  return ERR_VAL;
}
#endif /* ETHARP_TCPIP_ETHINPUT */

err_t
tcpip_callback(void (*f)(void *ctx), void *ctx)
{
  struct tcpip_msg *msg;

  if (mbox != SYS_MBOX_NULL) {
    msg = memp_malloc(MEMP_TCPIP_MSG);
    if (msg == NULL) {
      return ERR_MEM;
    }

    msg->type = TCPIP_MSG_CALLBACK;
    msg->msg.cb.f = f;
    msg->msg.cb.ctx = ctx;
    sys_mbox_post(mbox, msg);
    return ERR_OK;
  }
  return ERR_VAL;
}

err_t
tcpip_apimsg(struct api_msg *apimsg)
{
  struct tcpip_msg msg;
  
  if (mbox != SYS_MBOX_NULL) {
    msg.type = TCPIP_MSG_API;
    msg.msg.apimsg = apimsg;
    sys_mbox_post(mbox, &msg);
    sys_mbox_fetch(apimsg->msg.conn->mbox, NULL);
    return ERR_OK;
  }
  return ERR_VAL;
}

void
tcpip_init(void (* initfunc)(void *), void *arg)
{
#if LWIP_ARP
  etharp_init();
#endif /*LWIP_ARP */
  ip_init();
#if LWIP_UDP
  udp_init();
#endif /* LWIP_UDP */
#if LWIP_TCP
  tcp_init();
#endif /* LWIP_TCP */

  tcpip_init_done = initfunc;
  tcpip_init_done_arg = arg;
  mbox = sys_mbox_new();
  sys_thread_new(tcpip_thread, NULL, TCPIP_THREAD_PRIO);
}

