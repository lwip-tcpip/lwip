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
#ifndef __LWIP_OPT_H__
#define __LWIP_OPT_H__

#include "lwipopts.h"

/* Define some handy default values for configuration parameters. */

#ifndef ICMP_TTL
#define ICMP_TTL                255
#endif

#ifndef UDP_TTL
#define UDP_TTL                 255
#endif

#ifndef TCP_TTL
#define TCP_TTL                 255
#endif

#ifndef TCP_MSS
#define TCP_MSS                 128 /* A *very* conservative default. */
#endif

#ifndef TCP_WND
#define TCP_WND                 2048
#endif 

#ifndef TCP_MAXRTX
#define TCP_MAXRTX              12
#endif

#ifndef TCP_SYNMAXRTX
#define TCP_SYNMAXRTX           6
#endif

#ifndef MEM_ALIGNMENT
#define MEM_ALIGNMENT           1
#endif

#ifndef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE          16
#endif

#ifndef PBUF_POOL_BUFSIZE
#define PBUF_POOL_BUFSIZE       128
#endif

#ifndef PBUF_LINK_HLEN
#define PBUF_LINK_HLEN          0
#endif

#ifndef LWIP_UDP
#define LWIP_UDP                1
#endif

#ifndef LWIP_TCP
#define LWIP_TCP                1
#endif

#ifndef LWIP_EVENT_API
#define LWIP_EVENT_API    0
#define LWIP_CALLBACK_API 1
#else 
#define LWIP_EVENT_API    1
#define LWIP_CALLBACK_API 0
#endif /* LWIP_CALLBACK_API */

#endif /* __LWIP_OPT_H__ */



