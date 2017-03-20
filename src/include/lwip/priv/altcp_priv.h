/**
 * @file
 * Application layered TCP connection API (to be used from TCPIP thread)\n
 * This interface mimics the tcp callback API to the application while preventing
 * direct linking (much like virtual functions).
 * This way, an application can make use of other application layer protocols
 * on top of TCP without knowing the details (e.g. TLS, proxy connection).
 */

/*
 * Copyright (c) 2017 Simon Goldschmidt
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
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 *
 */
#ifndef LWIP_HDR_ALTCP_PRIV_H
#define LWIP_HDR_ALTCP_PRIV_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/altcp.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

struct altcp_pcb *altcp_alloc(void);
void altcp_free(struct altcp_pcb *conn);

/* Function prototypes for application layers */
typedef void (*altcp_set_poll_fn)(struct altcp_pcb *conn, u8_t interval);
typedef void (*altcp_recved_fn)(struct altcp_pcb *conn, u16_t len);
typedef err_t (*altcp_bind_fn)(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port);
typedef err_t (*altcp_connect_fn)(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected);

typedef struct altcp_pcb *(*altcp_listen_fn)(struct altcp_pcb *conn, u8_t backlog, err_t *err);

typedef void  (*altcp_abort_fn)(struct altcp_pcb *conn);
typedef err_t (*altcp_close_fn)(struct altcp_pcb *conn);
typedef err_t (*altcp_shutdown_fn)(struct altcp_pcb *conn, int shut_rx, int shut_tx);

typedef err_t (*altcp_write_fn)(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags);
typedef err_t (*altcp_output_fn)(struct altcp_pcb *conn);

typedef u16_t (*altcp_mss_fn)(struct altcp_pcb *conn);
typedef u16_t (*altcp_sndbuf_fn)(struct altcp_pcb *conn);
typedef u16_t (*altcp_sndqueuelen_fn)(struct altcp_pcb *conn);

typedef void  (*altcp_setprio_fn)(struct altcp_pcb *conn, u8_t prio);

typedef void  (*altcp_dealloc_fn)(struct altcp_pcb *conn);

struct altcp_functions {
  altcp_set_poll_fn     set_poll;
  altcp_recved_fn       recved;
  altcp_bind_fn         bind;
  altcp_connect_fn      connect;
  altcp_listen_fn       listen;
  altcp_abort_fn        abort;
  altcp_close_fn        close;
  altcp_shutdown_fn     shutdown;
  altcp_write_fn        write;
  altcp_output_fn       output;
  altcp_mss_fn          mss;
  altcp_sndbuf_fn       sndbuf;
  altcp_sndqueuelen_fn  sndqueuelen;
  altcp_setprio_fn      setprio;
  altcp_dealloc_fn      dealloc;
};


#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP */

#endif /* LWIP_HDR_ALTCP_PRIV_H */
