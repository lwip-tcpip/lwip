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

void
lwip_init(void)
{
  /**@todo Add here runtime Sanity checks from "task #7142 : Sanity check user-configurable values" */

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
