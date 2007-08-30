/**
 * @file
 * Modules initialization
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

#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "netif/etharp.h"
#include "lwip/ip.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/igmp.h"
#include "lwip/autoip.h"


#ifdef LWIP_DEBUG
void
lwip_sanity_check()
{
  /* Warnings */
  if (MEMP_NUM_NETBUF > (PBUF_POOL_SIZE+MEMP_NUM_PBUF))
    LWIP_PLATFORM_DIAG(("lwip_sanity_check: WARNING: MEMP_NUM_NETBUF should be less than the sum of PBUF_POOL_SIZE and MEMP_NUM_PBUF\n"));
#if LWIP_NETCONN
  if (MEMP_NUM_NETCONN > (MEMP_NUM_TCP_PCB+MEMP_NUM_TCP_PCB_LISTEN+MEMP_NUM_UDP_PCB+MEMP_NUM_RAW_PCB))
    LWIP_PLATFORM_DIAG(("lwip_sanity_check: WARNING: MEMP_NUM_NETCONN should be less than the sum of MEMP_NUM_{TCP,RAW,UDP}_PCB+MEMP_NUM_TCP_PCB_LISTEN\n"));
#endif /* LWIP_NETCONN */
  if (TCP_SND_QUEUELEN < (2 * (TCP_SND_BUF/TCP_MSS)))
    LWIP_PLATFORM_DIAG(("lwip_sanity_check: WARNING: TCP_SND_QUEUELEN must be at least as much as (2 * TCP_SND_BUF/TCP_MSS) for things to work\n"));
  if (TCP_SNDLOWAT > TCP_SND_BUF)
    LWIP_PLATFORM_DIAG(("lwip_sanity_check: WARNING: TCP_SNDLOWAT must be less than or equal to TCP_SND_BUF.\n"));

  /* Errors */
  #if (!LWIP_ARP && ARP_QUEUEING)
    #error "If you want to use ARP Queueing, you have to define LWIP_ARP=1 in your lwipopts.h"
  #endif
  #if (!LWIP_UDP && LWIP_UDPLITE)
    #error "If you want to use UDP Lite, you have to define LWIP_UDP=1 in your lwipopts.h"
  #endif
  #if (!LWIP_UDP && LWIP_SNMP)
    #error "If you want to use SNMP, you have to define LWIP_UDP=1 in your lwipopts.h"
  #endif
  #if (!LWIP_UDP && LWIP_DHCP)
    #error "If you want to use DHCP, you have to define LWIP_UDP=1 in your lwipopts.h"
  #endif
  #if (!LWIP_UDP && LWIP_IGMP)
    #error "If you want to use IGMP, you have to define LWIP_UDP=1 in your lwipopts.h"
  #endif
  #if (LWIP_UDP && (MEMP_NUM_UDP_PCB<=0))
    #error "If you want to use UDP, you have to define MEMP_NUM_UDP_PCB>=1 in your lwipopts.h"
  #endif
  #if (LWIP_TCP && (MEMP_NUM_TCP_PCB<=0))
    #error "If you want to use TCP, you have to define MEMP_NUM_TCP_PCB>=1 in your lwipopts.h"
  #endif
  #if ((LWIP_SOCKET || LWIP_NETCONN) && (NO_SYS==1))
    #error "If you want to use Sequential API, you have to define NO_SYS=0 in your lwipopts.h"
  #endif
  #if ((LWIP_NETCONN || LWIP_SOCKET) && (MEMP_NUM_TCPIP_MSG_API<=0))
    #error "If you want to use Sequential API, you have to define MEMP_NUM_TCPIP_MSG_API>=1 in your lwipopts.h"
  #endif
  #if (!LWIP_NETCONN && LWIP_SOCKET)
    #error "If you want to use Socket API, you have to define LWIP_NETCONN=1 in your lwipopts.h"
  #endif
  #if (((!LWIP_DHCP) || (!LWIP_AUTOIP)) && DHCP_AUTOIP_COOP)
   #error "If you want to use DHCP/AUTOIP cooperation mode, you have to define LWIP_DHCP=1 and LWIP_AUTOIP=1 in your lwipopts.h"
  #endif
  #if (((!LWIP_DHCP) || (!LWIP_ARP)) && DHCP_DOES_ARP_CHECK)
   #error "If you want to use DHCP ARP checking, you have to define LWIP_DHCP=1 and LWIP_ARP=1 in your lwipopts.h"
  #endif

/** @todo integrate these checks (from task #7142 : Sanity check user-configurable values) :
  if (MEMP_NUM_TCP_SEG < TCP_SND_QUEUELEN)
    LWIP_PLATFORM_DIAG(("MEMP_NUM_TCP_SEG should be at least as big as TCP_SND_QUEUELEN\n"));
- Ditto MEMP_NUM_ARP_QUEUE can be compared to the number of pbufs.
- Ditto IP_FRAG_USES_STATIC_BUF
- Ditto TCP_SND_QUEUELEN
- TCP_WND versus PBUF_POOL_SIZE*PBUF_POOL_BUFSIZE
- TCP_MSS <= TCP_WND
- We could consider ensuring that the number of pbufs exceed MEMP_NUM_NETBUF+MEMP_NUM_ARP_QUEUE+TCP_SND_QUEUELEN
- Perhaps do range checking on some values? */
}
#else  /* LWIP_DEBUG */
#define lwip_sanity_check()
#endif /* LWIP_DEBUG */

/**
 * Perform Sanity check of user-configurable values, and initialize all modules.
 */
void
lwip_init(void)
{
  /* Sanity check user-configurable values */
  lwip_sanity_check();

  /* Modules initialization */
  stats_init();
  sys_init();
  mem_init();
  memp_init();
  pbuf_init();
  netif_init();
#if LWIP_SOCKET
  lwip_socket_init();
#endif /* LWIP_SOCKET */
  ip_init();
#if LWIP_ARP
  etharp_init();
#endif /* LWIP_ARP */
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
#if LWIP_IGMP
  igmp_init();
#endif /* LWIP_IGMP */
}
