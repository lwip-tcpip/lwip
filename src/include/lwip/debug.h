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

#include "arch/cc.h"

/** lower two bits indicate debug level
 * - 0 off
 * - 1 warning
 * - 2 serious
 * - 3 severe
 */
#define DBG_MASK_LEVEL 3

/** print only debug messages with this level or higher */
#define DBG_MIN_LEVEL 0

/** flag for DEBUGF to enable the debug message */
#define DBG_ON  0x80U
/** flag for DEBUGF to disable the debug message */
#define DBG_OFF 0x00U

/** flag for DEBUGF to indicate it is a tracing message (to follow program flow) */
#define DBG_TRACE   0x40
/** flag for DEBUGF to indicate it is a state debug message (to follow states) */
#define DBG_STATE   0x20
/** flag for DEBUGF that indicates newly added code, not thoroughly tested yet */
#define DBG_FRESH   0x10
/** flag for DEBUGF to halt after printing this debug message */
#define DBG_HALT    0x08

#define LWIP_ASSERT(x,y) do { if(!(y)) LWIP_PLATFORM_ASSERT(x); } while(0)
/** print debug message only if debug message is enabled AND is of correct type
  * AND is at least DBG_LEVEL */
#define DEBUGF(debug, x) do { if ((debug & DBG_ON) && (debug & DBG_TYPES_ON) && ((debug & DBG_MASK_LEVEL) >= DBG_MIN_LEVEL)) { LWIP_PLATFORM_DIAG(x); if (debug & DBG_HALT) while(1); } } while(0)
#define LWIP_ERROR(x)	 do { LWIP_PLATFORM_DIAG(x); } while(0)	

#ifndef LWIP_DEBUG

#define LWIP_ASSERT(x,y) 
#define DEBUGF(debug, x) 
#define LWIP_ERROR(x)	


#define DBG_TYPES_ON 0U

 /**
 * Disable all debug messages
 */
#define DEMO_DEBUG       DBG_OFF
#define ETHARP_DEBUG     DBG_OFF
#define NETIF_DEBUG      DBG_OFF
#define PBUF_DEBUG       DBG_OFF
#define DELIF_DEBUG      DBG_OFF
#define DROPIF_DEBUG     DBG_OFF
#define TUNIF_DEBUG      DBG_OFF
#define UNIXIF_DEBUG     DBG_OFF
#define TAPIF_DEBUG      DBG_OFF
#define SIO_FIFO_DEBUG   DBG_OFF
#define PPP_DEBUG        DBG_OFF
#define API_LIB_DEBUG    DBG_OFF
#define API_MSG_DEBUG    DBG_OFF
#define SOCKETS_DEBUG    DBG_OFF
#define ICMP_DEBUG       DBG_OFF
#define INET_DEBUG       DBG_OFF
#define IP_DEBUG         DBG_OFF
#define IP_REASS_DEBUG   DBG_OFF
#define MEM_DEBUG        DBG_OFF
#define MEMP_DEBUG       DBG_OFF
#define SYS_DEBUG        DBG_OFF
#define TCP_DEBUG        DBG_OFF
#define TCP_INPUT_DEBUG  DBG_OFF
#define TCP_FR_DEBUG     DBG_OFF
#define TCP_RTO_DEBUG    DBG_OFF
#define TCP_REXMIT_DEBUG DBG_OFF
#define TCP_CWND_DEBUG   DBG_OFF
#define TCP_WND_DEBUG    DBG_OFF
#define TCP_OUTPUT_DEBUG DBG_OFF
#define TCP_RST_DEBUG    DBG_OFF
#define TCP_QLEN_DEBUG   DBG_OFF
#define UDP_DEBUG        DBG_OFF
#define TCPIP_DEBUG      DBG_OFF
#define TCPDUMP_DEBUG    DBG_OFF
#define DHCP_DEBUG       DBG_OFF

#endif /* LWIP_DEBUG */


#endif /* __LWIP_DEBUG_H__ */






