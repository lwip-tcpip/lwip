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
 * This file is part of and a contribution to the lwIP TCP/IP stack.
 *
 * Credits go to Adam Dunkels (and the current maintainers) of this software.
 *
 * Christiaan Simons rewrote this file to get a more stable echo example.
 */

/**
 * @file
 * TCP echo server example using altcp API.
 *
 * Echos all bytes sent by connecting client,
 * and passively closes when client is done.
 *
 */

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/altcp.h"
#include "tcpecho_altcp.h"

#if LWIP_ALTCP && LWIP_CALLBACK_API

static struct altcp_pcb *tcpecho_altcp_pcb;

enum tcpecho_altcp_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};

struct tcpecho_altcp_state
{
  u8_t state;
  u8_t retries;
  struct altcp_pcb *pcb;
  /* pbuf (chain) to recycle */
  struct pbuf *p;
};

static void
tcpecho_altcp_free(struct tcpecho_altcp_state *es)
{
  if (es != NULL) {
    if (es->p) {
      /* free the buffer chain if present */
      pbuf_free(es->p);
    }

    mem_free(es);
  }
}

static void
tcpecho_altcp_close(struct altcp_pcb *tpcb, struct tcpecho_altcp_state *es)
{
  altcp_arg(tpcb, NULL);
  altcp_sent(tpcb, NULL);
  altcp_recv(tpcb, NULL);
  altcp_err(tpcb, NULL);
  altcp_poll(tpcb, NULL, 0);

  tcpecho_altcp_free(es);

  altcp_close(tpcb);
}

static void
tcpecho_altcp_send(struct altcp_pcb *tpcb, struct tcpecho_altcp_state *es)
{
  struct pbuf *ptr;
  err_t wr_err = ERR_OK;

  while ((wr_err == ERR_OK) &&
         (es->p != NULL) &&
         (es->p->len <= altcp_sndbuf(tpcb))) {
    ptr = es->p;

    /* enqueue data for transmission */
    wr_err = altcp_write(tpcb, ptr->payload, ptr->len, 1);
    if (wr_err == ERR_OK) {
      u16_t plen;

      plen = ptr->len;
      /* continue with next pbuf in chain (if any) */
      es->p = ptr->next;
      if(es->p != NULL) {
        /* new reference! */
        pbuf_ref(es->p);
      }
      /* chop first pbuf from chain */
      pbuf_free(ptr);
      /* we can read more data now */
      altcp_recved(tpcb, plen);
    } else if(wr_err == ERR_MEM) {
      /* we are low on memory, try later / harder, defer to poll */
      es->p = ptr;
    } else {
      /* other problem ?? */
    }
  }
}

static void
tcpecho_altcp_error(void *arg, err_t err)
{
  struct tcpecho_altcp_state *es;

  LWIP_UNUSED_ARG(err);

  es = (struct tcpecho_altcp_state *)arg;

  tcpecho_altcp_free(es);
}

static err_t
tcpecho_altcp_poll(void *arg, struct altcp_pcb *tpcb)
{
  err_t ret_err;
  struct tcpecho_altcp_state *es;

  es = (struct tcpecho_altcp_state *)arg;
  if (es != NULL) {
    if (es->p != NULL) {
      /* there is a remaining pbuf (chain)  */
      tcpecho_altcp_send(tpcb, es);
    } else {
      /* no remaining pbuf (chain)  */
      if(es->state == ES_CLOSING) {
        tcpecho_altcp_close(tpcb, es);
      }
    }
    ret_err = ERR_OK;
  } else {
    /* nothing to be done */
    altcp_abort(tpcb);
    ret_err = ERR_ABRT;
  }
  return ret_err;
}

static err_t
tcpecho_altcp_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
  struct tcpecho_altcp_state *es;

  LWIP_UNUSED_ARG(len);

  es = (struct tcpecho_altcp_state *)arg;
  es->retries = 0;

  if(es->p != NULL) {
    /* still got pbufs to send */
    altcp_sent(tpcb, tcpecho_altcp_sent);
    tcpecho_altcp_send(tpcb, es);
  } else {
    /* no more pbufs to send */
    if(es->state == ES_CLOSING) {
      tcpecho_altcp_close(tpcb, es);
    }
  }
  return ERR_OK;
}

static err_t
tcpecho_altcp_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  struct tcpecho_altcp_state *es;
  err_t ret_err;

  LWIP_ASSERT("arg != NULL",arg != NULL);
  es = (struct tcpecho_altcp_state *)arg;
  if (p == NULL) {
    /* remote host closed connection */
    es->state = ES_CLOSING;
    if(es->p == NULL) {
      /* we're done sending, close it */
      tcpecho_altcp_close(tpcb, es);
    } else {
      /* we're not done yet */
      tcpecho_altcp_send(tpcb, es);
    }
    ret_err = ERR_OK;
  } else if(err != ERR_OK) {
    /* cleanup, for unknown reason */
    LWIP_ASSERT("no pbuf expected here", p == NULL);
    ret_err = err;
  }
  else if(es->state == ES_ACCEPTED) {
    /* first data chunk in p->payload */
    es->state = ES_RECEIVED;
    /* store reference to incoming pbuf (chain) */
    es->p = p;
    tcpecho_altcp_send(tpcb, es);
    ret_err = ERR_OK;
  } else if (es->state == ES_RECEIVED) {
    /* read some more data */
    if(es->p == NULL) {
      es->p = p;
      tcpecho_altcp_send(tpcb, es);
    } else {
      struct pbuf *ptr;

      /* chain pbufs to the end of what we recv'ed previously  */
      ptr = es->p;
      pbuf_cat(ptr,p);
    }
    ret_err = ERR_OK;
  } else {
    /* unknown es->state, trash data  */
    altcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    ret_err = ERR_OK;
  }
  return ret_err;
}

static err_t
tcpecho_altcp_accept(void *arg, struct altcp_pcb *newpcb, err_t err)
{
  err_t ret_err;
  struct tcpecho_altcp_state *es;

  LWIP_UNUSED_ARG(arg);
  if ((err != ERR_OK) || (newpcb == NULL)) {
    return ERR_VAL;
  }

  /* Unless this pcb should have NORMAL priority, set its priority now.
     When running out of pcbs, low priority pcbs can be aborted to create
     new pcbs of higher priority. */
  altcp_setprio(newpcb, TCP_PRIO_MIN);

  es = (struct tcpecho_altcp_state *)mem_malloc(sizeof(struct tcpecho_altcp_state));
  if (es != NULL) {
    es->state = ES_ACCEPTED;
    es->pcb = newpcb;
    es->retries = 0;
    es->p = NULL;
    /* pass newly allocated es to our callbacks */
    altcp_arg(newpcb, es);
    altcp_recv(newpcb, tcpecho_altcp_recv);
    altcp_err(newpcb, tcpecho_altcp_error);
    altcp_poll(newpcb, tcpecho_altcp_poll, 0);
    altcp_sent(newpcb, tcpecho_altcp_sent);
    ret_err = ERR_OK;
  } else {
    ret_err = ERR_MEM;
  }
  return ret_err;
}

void
tcpecho_altcp_init(void)
{
  tcpecho_altcp_pcb = altcp_new_ip_type(NULL, IPADDR_TYPE_ANY);
  if (tcpecho_altcp_pcb != NULL) {
    err_t err;

    err = altcp_bind(tcpecho_altcp_pcb, IP_ANY_TYPE, 7);
    if (err == ERR_OK) {
      tcpecho_altcp_pcb = altcp_listen(tcpecho_altcp_pcb);
      altcp_accept(tcpecho_altcp_pcb, tcpecho_altcp_accept);
    } else {
      /* abort? output diagnostic? */
    }
  } else {
    /* abort? output diagnostic? */
  }
}

#endif /* LWIP_TCP && LWIP_CALLBACK_API */
