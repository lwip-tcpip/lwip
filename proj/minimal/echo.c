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

#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"

struct echo_state {
  struct pbuf *p;
  u8_t failed;
#define FAILED_MAX 8
};
/*-----------------------------------------------------------------------------------*/
static void
echo_err(void *arg, err_t err)
{
  struct echo_state *es = arg;

  if(arg != NULL) {
    pbuf_free(es->p);
    mem_free(arg);
  }
}
/*-----------------------------------------------------------------------------------*/
static void
close_conn(struct tcp_pcb *pcb, struct echo_state *es)
{
  tcp_arg(pcb, NULL);
#if 0
  tcp_sent(pcb, NULL);  
  tcp_recv(pcb, NULL);
#endif /* 0 */
  if(es != NULL) {
    pbuf_free(es->p);
    mem_free(es);
  }
  tcp_close(pcb);
}
/*-----------------------------------------------------------------------------------*/
static void
send_buf(struct tcp_pcb *pcb, struct echo_state *es)
{
  struct pbuf *q;
  
  do {
    q = es->p;
    es->p = pbuf_dechain(q);
    if(tcp_write(pcb, q->payload, q->len, 1) == ERR_MEM) {
      pbuf_chain(q, es->p);
      es->p = q;
      return;
    }
    tcp_recved(pcb, q->len);
    pbuf_free(q);
  } while(es->p != NULL);   
}
/*-----------------------------------------------------------------------------------*/
static err_t
echo_poll(void *arg, struct tcp_pcb *pcb)
{
  struct echo_state *es;

  if(arg == NULL) {
    return tcp_close(pcb);
  }
  
  es = arg;

  if(es->failed >= FAILED_MAX) {
    close_conn(pcb, es);
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  
  if(es->p != NULL) {
    ++es->failed;
    send_buf(pcb, es);
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static err_t
echo_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
  struct echo_state *es;
  
  es = arg;

  if(es != NULL && es->p != NULL) {
    send_buf(pcb, es);
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static err_t
echo_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  struct echo_state *es;
  
  es = arg;

  if(p == NULL) {
    close_conn(pcb, es);
    return ERR_OK;
  }
  
  if(es->p != NULL) {
    pbuf_chain(es->p, p);
  } else {
    es->p = p;
  }

  send_buf(pcb, es);
  
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static err_t
echo_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct echo_state *es;

  tcp_setprio(pcb, TCP_PRIO_MIN);
  
  /* Allocate memory for the structure that holds the state of the
     connection. */
  es = mem_malloc(sizeof(struct echo_state));

  if(es == NULL) {
    return ERR_MEM;
  }
  
  /* Initialize the structure. */
  es->p = NULL;
  es->failed = 0;

  /* Tell TCP that this is the structure we wish to be passed for our
     callbacks. */
  tcp_arg(pcb, es);

  /* Tell TCP that we wish to be informed of incoming data by a call
     to the http_recv() function. */
#if 0
  tcp_recv(pcb, echo_recv);
  
  tcp_err(pcb, echo_err);
#endif  /* 0 */
  
  tcp_poll(pcb, echo_poll, 2);

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
void
echo_init(void)
{
  struct tcp_pcb *pcb;

  pcb = tcp_new();
  tcp_bind(pcb, IP_ADDR_ANY, 7);
  pcb = tcp_listen(pcb);
#if 0
  tcp_accept(pcb, echo_accept);
#endif /* 0 */
}
/*-----------------------------------------------------------------------------------*/
err_t
lwip_tcp_event(void *arg, struct tcp_pcb *pcb,
	       enum lwip_event ev, struct pbuf *p,
	       u16_t size, err_t err)
{
  switch(ev) {
  case LWIP_EVENT_ACCEPT:
    return echo_accept(arg, pcb, err);
  case LWIP_EVENT_SENT:
    return echo_sent(arg, pcb, size);
  case LWIP_EVENT_RECV:
    return echo_recv(arg, pcb, p, err);
  case LWIP_EVENT_ERR:
    echo_err(arg, err);
    break;
  case LWIP_EVENT_POLL:
    return echo_poll(arg, pcb);
  default:
    break;
  }
  
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/

