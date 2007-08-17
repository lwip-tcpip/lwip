/**
 * @file
 * Sequential API Main thread module
 *
 */

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
#include "netif/ppp_oe.h"

#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/tcpip.h"
#include "lwip/igmp.h"

#if !NO_SYS

/* global variables */
static void (* tcpip_init_done)(void *arg) = NULL;
static void *tcpip_init_done_arg           = NULL;
static sys_mbox_t mbox                     = SYS_MBOX_NULL;

#if LWIP_TCPIP_CORE_LOCKING
/** The global semaphore to lock the stack. */
sys_sem_t lock_tcpip_core = 0;
#endif /* LWIP_TCPIP_CORE_LOCKING */

#if LWIP_TCP
/* global variable that shows if the tcp timer is currently scheduled or not */
static int tcpip_tcp_timer_active = 0;

/**
 * Timer callback function that calls tcp_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
tcpip_tcp_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);

  /* call TCP timer handler */
  tcp_tmr();
  /* timer still needed? */
  if (tcp_active_pcbs || tcp_tw_pcbs) {
    /* restart timer */
    sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
  } else {
    /* disable timer */
    tcpip_tcp_timer_active = 0;
  }
}

#if !NO_SYS
/**
 * Called from TCP_REG when registering a new PCB:
 * the reason is to have the TCP timer only running when
 * there are active (or time-wait) PCBs.
 */
void
tcp_timer_needed(void)
{
  /* timer is off but needed again? */
  if (!tcpip_tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
    /* enable and start timer */
    tcpip_tcp_timer_active = 1;
    sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
  }
}
#endif /* !NO_SYS */
#endif /* LWIP_TCP */

#if IP_REASSEMBLY
/**
 * Timer callback function that calls ip_reass_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
ip_reass_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: ip_reass_tmr()\n"));
  ip_reass_tmr();
  sys_timeout(IP_TMR_INTERVAL, ip_reass_timer, NULL);
}
#endif /* IP_REASSEMBLY */

#if LWIP_ARP
/**
 * Timer callback function that calls etharp_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
arp_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: etharp_tmr()\n"));
  etharp_tmr();
  sys_timeout(ARP_TMR_INTERVAL, arp_timer, NULL);
}
#endif /* LWIP_ARP */

#if LWIP_DHCP
/**
 * Timer callback function that calls dhcp_coarse_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
dhcp_timer_coarse(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: dhcp_coarse_tmr()\n"));
  dhcp_coarse_tmr();
  sys_timeout(DHCP_COARSE_TIMER_SECS*1000, dhcp_timer_coarse, NULL);
}

/**
 * Timer callback function that calls dhcp_fine_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
dhcp_timer_fine(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: dhcp_fine_tmr()\n"));
  dhcp_fine_tmr();
  sys_timeout(DHCP_FINE_TIMER_MSECS, dhcp_timer_fine, NULL);
}
#endif /* LWIP_DHCP */

#if LWIP_AUTOIP
/**
 * Timer callback function that calls autoip_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
autoip_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: autoip_tmr()\n"));
  autoip_tmr();
  sys_timeout(AUTOIP_TMR_INTERVAL, autoip_timer, NULL);
}
#endif /* LWIP_AUTOIP */

#if LWIP_IGMP
/**
 * Timer callback function that calls igmp_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
igmp_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: igmp_tmr()\n"));
  igmp_tmr();
  sys_timeout(IGMP_TMR_INTERVAL, igmp_timer, NULL);
}
#endif /* LWIP_IGMP */

#if ETHARP_TCPIP_ETHINPUT
/**
 * Process received ethernet frames. Using this function instead of directly
 * calling ip_input and passing ARP frames through etharp in ethernetif_input,
 * the ARP cache is protected from concurrent access.
 *
 * @param p the recevied packet, p->payload pointing to the ethernet header
 * @param netif the network interface on which the packet was received
 */
static err_t
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

#if PPPOE_SUPPORT
    case ETHTYPE_PPPOEDISC: /* PPP Over Ethernet Discovery Stage */
      pppoe_disc_input(netif, p);
      break;
    case ETHTYPE_PPPOE: /* PPP Over Ethernet Session Stage */
      pppoe_data_input(netif, p);
      break;
#endif /* PPPOE_SUPPORT */

    default:
      pbuf_free(p);
      p = NULL;
      break;
  }

  return ERR_OK; /* return value ignored */
}
#endif /* ETHARP_TCPIP_ETHINPUT */

/**
 * The main lwIP thread. This thread has exclusive access to lwIP core functions
 * (unless access to them is not locked). Other threads communicate with this
 * thread using message boxes.
 *
 * It also starts all the timers to make sure they are running in the right
 * thread context.
 *
 * @param arg unused argument
 */
static void
tcpip_thread(void *arg)
{
  struct tcpip_msg *msg;
  LWIP_UNUSED_ARG(arg);

#if IP_REASSEMBLY
  sys_timeout(IP_TMR_INTERVAL, ip_reass_timer, NULL);
#endif /* IP_REASSEMBLY */
#if LWIP_ARP
  sys_timeout(ARP_TMR_INTERVAL, arp_timer, NULL);
#endif /* LWIP_ARP */
#if LWIP_DHCP
  sys_timeout(DHCP_COARSE_TIMER_SECS*1000, dhcp_timer_coarse, NULL);
  sys_timeout(DHCP_FINE_TIMER_MSECS, dhcp_timer_fine, NULL);
#endif /* LWIP_DHCP */
#if LWIP_AUTOIP
  sys_timeout(AUTOIP_TMR_INTERVAL, autoip_timer, NULL);
#endif /* LWIP_AUTOIP */

  if (tcpip_init_done != NULL) {
    tcpip_init_done(tcpip_init_done_arg);
  }

#if LWIP_IGMP
  igmp_init();
  sys_timeout(IGMP_TMR_INTERVAL, igmp_timer, NULL);
#endif /* LWIP_IGMP */

  LOCK_TCPIP_CORE();
  while (1) {                          /* MAIN Loop */
    sys_mbox_fetch(mbox, (void *)&msg);
    switch (msg->type) {
    case TCPIP_MSG_API:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: API message %p\n", (void *)msg));
      msg->msg.apimsg->function(&(msg->msg.apimsg->msg));
      break;

#if ETHARP_TCPIP_INPUT || ETHARP_TCPIP_ETHINPUT
    case TCPIP_MSG_INPKT:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: PACKET %p\n", (void *)msg));
      msg->msg.inp.f(msg->msg.inp.p, msg->msg.inp.netif);
      memp_free(MEMP_TCPIP_MSG_INPKT, msg);
      break;
#endif /* ETHARP_TCPIP_INPUT || ETHARP_TCPIP_ETHINPUT */

#if LWIP_NETIF_API
    case TCPIP_MSG_NETIFAPI:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: Netif API message %p\n", (void *)msg));
      msg->msg.netifapimsg->function(&(msg->msg.netifapimsg->msg));
      break;
#endif /* LWIP_NETIF_API */

    case TCPIP_MSG_CALLBACK:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: CALLBACK %p\n", (void *)msg));
      msg->msg.cb.f(msg->msg.cb.ctx);
      memp_free(MEMP_TCPIP_MSG_API, msg);
      break;
    case TCPIP_MSG_TIMEOUT:
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: TIMEOUT %p\n", (void *)msg));

      if(msg->msg.tmo.msecs != 0xffffffff)
        sys_timeout (msg->msg.tmo.msecs, msg->msg.tmo.h, msg->msg.tmo.arg);
      else
        sys_untimeout (msg->msg.tmo.h, msg->msg.tmo.arg);
      memp_free(MEMP_TCPIP_MSG_API, msg);
      break;
    default:
      break;
    }
  }
}

#if ETHARP_TCPIP_INPUT
/**
 * Pass a received IP packet to tcpip_thread for input processing
 *
 * @param p the recevied packet, p->payload pointing to the IP header
 * @param netif the network interface on which the packet was received
 */
err_t
tcpip_input(struct pbuf *p, struct netif *inp)
{
  struct tcpip_msg *msg;

  if (mbox != SYS_MBOX_NULL) {
    msg = memp_malloc(MEMP_TCPIP_MSG_INPKT);
    if (msg == NULL) {
      return ERR_MEM;
    }

    msg->type = TCPIP_MSG_INPKT;
    msg->msg.inp.f = ip_input;
    msg->msg.inp.p = p;
    msg->msg.inp.netif = inp;
    sys_mbox_post(mbox, msg);
    return ERR_OK;
  }
  return ERR_VAL;
}

err_t
tcpip_input_callback(struct pbuf *p, struct netif *inp, err_t (*f)(struct pbuf *, struct netif *))
{
  struct tcpip_msg *msg;

  if (mbox != SYS_MBOX_NULL) {
    msg = memp_malloc(MEMP_TCPIP_MSG_INPKT);
    if (msg == NULL) {
      return ERR_MEM;  
    }

    msg->type = TCPIP_MSG_INPKT;
    msg->msg.inp.f = f;
    msg->msg.inp.p = p;
    msg->msg.inp.netif = inp;
    sys_mbox_post(mbox, msg);
    return ERR_OK;
  }
  return ERR_VAL;
}
#endif /* ETHARP_TCPIP_INPUT */

#if ETHARP_TCPIP_ETHINPUT
/**
 * Pass a received IP packet to tcpip_thread for input processing
 *
 * @param p the recevied packet, p->payload pointing to the ethernet header
 * @param netif the network interface on which the packet was received
 */
err_t
tcpip_ethinput(struct pbuf *p, struct netif *inp)
{
  return tcpip_input_callback(p, inp, ethernet_input);
}
#endif /* ETHARP_TCPIP_ETHINPUT */

/**
 * Call a specific function in the thread context of
 * tcpip_thread for easy access synchronization.
 * A function called in that way may access lwIP core code
 * without fearing concurrent access.
 *
 * @param f the function to call
 * @param ctx parameter passed to f
 * @return ERR_OK if the function was called, another err_t if not
 */
err_t
tcpip_callback(void (*f)(void *ctx), void *ctx)
{
  struct tcpip_msg *msg;

  if (mbox != SYS_MBOX_NULL) {
    msg = memp_malloc(MEMP_TCPIP_MSG_API);
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
tcpip_timeout(u32_t msecs, sys_timeout_handler h, void *arg)
{
  struct tcpip_msg *msg;
   
  if (mbox != SYS_MBOX_NULL) {
	msg = memp_malloc(MEMP_TCPIP_MSG_API);
	if (msg == NULL) {
		return ERR_MEM;  
	}      

	msg->type = TCPIP_MSG_TIMEOUT;
	msg->msg.tmo.msecs = msecs;
	msg->msg.tmo.h = h;
	msg->msg.tmo.arg = arg;
	sys_mbox_post(mbox, msg);
	return ERR_OK;
  }
  return ERR_VAL;
}

/**
 * Call the lower part of a netconn_* function
 * This function is then running in the thread context
 * of tcpip_thread and has exclusive access to lwIP core code.
 *
 * @param apimsg a struct containing the function to call and its parameters
 * @return ERR_OK if the function was called, another err_t if not
 */
err_t
tcpip_apimsg(struct api_msg *apimsg)
{
  struct tcpip_msg msg;
  
  if (mbox != SYS_MBOX_NULL) {
    msg.type = TCPIP_MSG_API;
    msg.msg.apimsg = apimsg;
    sys_mbox_post(mbox, &msg);
    sys_arch_mbox_fetch(apimsg->msg.conn->mbox, NULL, 0);
    return ERR_OK;
  }
  return ERR_VAL;
}

#if LWIP_TCPIP_CORE_LOCKING
/**
 * Call the lower part of a netconn_* function
 * This function has exclusive access to lwIP core code by locking it
 * before the function is called.
 *
 * @param apimsg a struct containing the function to call and its parameters
 * @return ERR_OK (only for compatibility fo tcpip_apimsg())
 */
err_t
tcpip_apimsg_lock(struct api_msg *apimsg)
{
  LOCK_TCPIP_CORE();
  apimsg->function(&(apimsg->msg));
  UNLOCK_TCPIP_CORE();
  return ERR_OK;

}
#endif /* LWIP_TCPIP_CORE_LOCKING */

#if LWIP_NETIF_API
#if !LWIP_TCPIP_CORE_LOCKING
/**
 * Much like tcpip_apimsg, but calls the lower part of a netifapi_*
 * function.
 *
 * @param netifapimsg a struct containing the function to call and its parameters
 * @return error code given back by the function that was called
 */
err_t
tcpip_netifapi(struct netifapi_msg* netifapimsg)
{
  struct tcpip_msg msg;
  
  if (mbox != SYS_MBOX_NULL) {
    netifapimsg->msg.sem = sys_sem_new(0);
    if (netifapimsg->msg.sem == SYS_SEM_NULL) {
      netifapimsg->msg.err = ERR_MEM;
      return netifapimsg->msg.err;
    }
    
    msg.type = TCPIP_MSG_NETIFAPI;
    msg.msg.netifapimsg = netifapimsg;
    sys_mbox_post(mbox, &msg);
    sys_sem_wait(netifapimsg->msg.sem);
    sys_sem_free(netifapimsg->msg.sem);
    return netifapimsg->msg.err;
  }
  return ERR_VAL;
}
#else /* !LWIP_TCPIP_CORE_LOCKING */
/**
 * Call the lower part of a netifapi_* function
 * This function has exclusive access to lwIP core code by locking it
 * before the function is called.
 *
 * @param netifapimsg a struct containing the function to call and its parameters
 * @return ERR_OK (only for compatibility fo tcpip_netifapi())
 */
err_t
tcpip_netifapi_lock(struct netifapi_msg* netifapimsg)
{
  LOCK_TCPIP_CORE();  
  netifapimsg->function(&(netifapimsg->msg));
  UNLOCK_TCPIP_CORE();
  return netifapimsg->msg.err;
}
#endif /* !LWIP_TCPIP_CORE_LOCKING */
#endif /* LWIP_NETIF_API */

/**
 * Initialize this module:
 * - initialize ARP, IP, UDP and TCP
 * - start the tcpip_thread
 *
 * @param initfunc a function to call when tcpip_thread is running and
 *        finished initializing
 * @param arg argument to pass to initfunc
 */
void
tcpip_init(void (* initfunc)(void *), void *arg)
{
#if LWIP_ARP
  etharp_init();
#endif /* LWIP_ARP */
  ip_init();
#if LWIP_RAW
  raw_init();
#endif /* LWIP_RAW */
#if LWIP_UDP
  udp_init();
#endif /* LWIP_UDP */
#if LWIP_TCP
  tcp_init();
#endif /* LWIP_TCP */
#if LWIP_AUTOIP
  autoip_init();
#endif /* LWIP_AUTOIP */

  tcpip_init_done = initfunc;
  tcpip_init_done_arg = arg;
  mbox = sys_mbox_new();
#if LWIP_TCPIP_CORE_LOCKING
  lock_tcpip_core = sys_sem_new(1);
#endif /* LWIP_TCPIP_CORE_LOCKING */

  sys_thread_new(tcpip_thread, NULL, TCPIP_THREAD_PRIO);
}

#endif /* !NO_SYS */
