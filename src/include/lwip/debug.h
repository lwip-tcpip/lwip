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
#ifndef __LWIP_DEBUG_H__
#define __LWIP_DEBUG_H__

#include "lwipopts.h"

#ifdef LWIP_DEBUG

#define LWIP_ASSERT(x,y) do { if(!(y)) LWIP_PLATFORM_ASSERT(x); } while(0)
#define DEBUGF(debug, x) do { if(debug) LWIP_PLATFORM_DIAG(x); } while(0)
#define LWIP_ERROR(x)	 do { LWIP_PLATFORM_DIAG(x); } while(0)	

/* These defines control the amount of debugging output: */
#define MEM_TRACKING

#ifndef DEMO_DEBUG
#define DEMO_DEBUG       0
#endif

#ifndef ETHARP_DEBUG
#define ETHARP_DEBUG     0
#endif

#ifndef NETIF_DEBUG
#define NETIF_DEBUG      0
#endif

#ifndef PBUF_DEBUG
#define PBUF_DEBUG       0
#endif

#ifndef DELIF_DEBUG
#define DELIF_DEBUG      0
#endif

#ifndef DROPIF_DEBUG
#define DROPIF_DEBUG     0
#endif

#ifndef TUNIF_DEBUG
#define TUNIF_DEBUG      0
#endif

#ifndef UNIXIF_DEBUG
#define UNIXIF_DEBUG     0
#endif

#ifndef TAPIF_DEBUG
#define TAPIF_DEBUG      0
#endif

#ifndef SIO_FIFO_DEBUG
#define SIO_FIFO_DEBUG   0
#endif

#ifndef SLIP_DEBUG
#define SLIP_DEBUG        0
#endif

#ifndef PPP_DEBUG
#define PPP_DEBUG        0
#endif

#ifndef API_LIB_DEBUG
#define API_LIB_DEBUG    0
#endif

#ifndef API_MSG_DEBUG
#define API_MSG_DEBUG    0
#endif

#ifndef SOCKETS_DEBUG
#define SOCKETS_DEBUG    0
#endif

#ifndef ICMP_DEBUG
#define ICMP_DEBUG       0
#endif

#ifndef INET_DEBUG
#define INET_DEBUG       0
#endif

#ifndef IP_DEBUG
#define IP_DEBUG         0
#endif

#ifndef IP_REASS_DEBUG
#define IP_REASS_DEBUG   0
#endif

#ifndef MEM_DEBUG
#define MEM_DEBUG        0
#endif

#ifndef MEMP_DEBUG
#define MEMP_DEBUG       0
#endif

#ifndef SYS_DEBUG
#define SYS_DEBUG        0
#endif

#ifndef TCP_DEBUG
#define TCP_DEBUG        0
#endif

#ifndef TCP_INPUT_DEBUG
#define TCP_INPUT_DEBUG  0
#endif

#ifndef TCP_FR_DEBUG
#define TCP_FR_DEBUG     0
#endif

#ifndef TCP_RTO_DEBUG
#define TCP_RTO_DEBUG    0
#endif

#ifndef TCP_REXMIT_DEBUG
#define TCP_REXMIT_DEBUG 0
#endif

#ifndef TCP_CWND_DEBUG
#define TCP_CWND_DEBUG   0
#endif

#ifndef TCP_WND_DEBUG
#define TCP_WND_DEBUG    0
#endif

#ifndef TCP_OUTPUT_DEBUG
#define TCP_OUTPUT_DEBUG 0
#endif

#ifndef TCP_RST_DEBUG
#define TCP_RST_DEBUG    0
#endif

#ifndef TCP_QLEN_DEBUG
#define TCP_QLEN_DEBUG   0
#endif

#ifndef UDP_DEBUG
#define UDP_DEBUG        0
#endif

#ifndef TCPIP_DEBUG
#define TCPIP_DEBUG      0
#endif

#ifndef TCPDUMP_DEBUG
#define TCPDUMP_DEBUG    0
#endif

#ifndef DHCP_DEBUG
#define DHCP_DEBUG       0
#endif



#else /* LWIP_DEBUG */

/* DEBUG is not defined, so we define null macros for LWIP_ASSERT , DEBUGF and LWIP_ERROR */

#define LWIP_ASSERT(x,y)
#define DEBUGF(debug, x)
#define LWIP_ERROR(x)

/* And we define those to be zero: */

#define DEMO_DEBUG       0
#define ETHARP_DEBUG     0
#define NETIF_DEBUG      0
#define PBUF_DEBUG       0
#define DELIF_DEBUG      0
#define DROPIF_DEBUG     0
#define TUNIF_DEBUG      0
#define UNIXIF_DEBUG     0
#define TAPIF_DEBUG      0
#define SIO_FIFO_DEBUG   0
#define PPP_DEBUG        0
#define API_LIB_DEBUG    0
#define API_MSG_DEBUG    0
#define SOCKETS_DEBUG    0
#define ICMP_DEBUG       0
#define INET_DEBUG       0
#define IP_DEBUG         0
#define IP_REASS_DEBUG   0
#define MEM_DEBUG        0
#define MEMP_DEBUG       0
#define SYS_DEBUG        0
#define TCP_DEBUG        0
#define TCP_INPUT_DEBUG  0
#define TCP_FR_DEBUG     0
#define TCP_RTO_DEBUG    0
#define TCP_REXMIT_DEBUG 0
#define TCP_CWND_DEBUG   0
#define TCP_WND_DEBUG    0
#define TCP_OUTPUT_DEBUG 0
#define TCP_RST_DEBUG    0
#define TCP_QLEN_DEBUG   0
#define UDP_DEBUG        0
#define TCPIP_DEBUG      0
#define TCPDUMP_DEBUG    0
#define DHCP_DEBUG       0

#endif /* LWIP_DEBUG */


#endif /* __LWIP_DEBUG_H__ */






