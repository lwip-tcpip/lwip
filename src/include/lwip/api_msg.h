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
#ifndef __LWIP_API_MSG_H__
#define __LWIP_API_MSG_H__

#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

#include "lwip/ip.h"

#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IP addresses and port numbers are expected to be in
 * the same byte order as in the corresponding pcb.
 */
struct api_msg_msg {
  struct netconn *conn;
  union {
    struct netbuf *b; /* do_send */
    struct {
      u8_t proto;
    } n; /* do_newconn */
    struct {
      struct ip_addr *ipaddr;
      u16_t port;
    } bc; /* do_bind, do_connect */
    struct {
      const void *dataptr;
      u16_t len;
      u8_t copy;
    } w; /* do_write */
    struct {
      u16_t len;
    } r; /* do_recv */
#if LWIP_IGMP
    struct {
      struct ip_addr *multiaddr;
      struct ip_addr *interface;
      enum netconn_igmp join_or_leave;
    } jl; /* do_join_leave_group */
#endif /* LWIP_IGMP */
  } msg;
};

struct api_msg {
  void (* function)(struct api_msg_msg *msg);
  struct api_msg_msg msg;
};

void do_newconn         ( struct api_msg_msg *msg);
void do_delconn         ( struct api_msg_msg *msg);
void do_bind            ( struct api_msg_msg *msg);
void do_connect         ( struct api_msg_msg *msg);
void do_disconnect      ( struct api_msg_msg *msg);
void do_listen          ( struct api_msg_msg *msg);
void do_send            ( struct api_msg_msg *msg);
void do_recv            ( struct api_msg_msg *msg);
void do_write           ( struct api_msg_msg *msg);
void do_close           ( struct api_msg_msg *msg);
#if LWIP_IGMP
void do_join_leave_group( struct api_msg_msg *msg);
#endif /* LWIP_IGMP */

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_API_MSG_H__ */
