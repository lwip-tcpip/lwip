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
#include "lwip/def.h"
#include "netif/sioslipif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/stats.h"

/* The maximum size that an incoming packet can have. */
#define MAX_SIZE     1500

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

/* Define those to whatever is needed to send and receive one byte of
   data. */
#define SIO_SEND(c) 
#define SIO_RECV(c) 

static const unsigned char slip_end = SLIP_END, 
                           slip_esc = SLIP_ESC, 
                           slip_esc_end = SLIP_ESC_END, 
                           slip_esc_esc = SLIP_ESC_ESC;

/*-----------------------------------------------------------------------------------*/
static err_t
sioslipif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
  struct pbuf *q;
  int i;
  unsigned char *ptr;
  u8_t c;
  /* Send pbuf out on the serial I/O device. */
  SIO_SEND(slip_end);
  
  for(q = p; q != NULL; q = q->next) {
    ptr = q->payload;
    for(i = 0; i < q->len; i++) {
      c = *ptr++;
      switch(c) {
      case SLIP_END:
        SIO_SEND(slip_esc);
        SIO_SEND(slip_esc_end);
        break;
      case SLIP_ESC:
        SIO_SEND(slip_esc);
        SIO_SEND(slip_esc_esc);
        break;
      default:
        SIO_SEND(c);
        break;
      }
    }
  }
#ifdef LINK_STATS
  stats.link.xmit++;
#endif /* LINK_STATS */  
  SIO_SEND(slip_end);

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
sioslipif_input(void)
{
  u8_t c;
  struct pbuf *p, *q;
  int recved;
  int i;
  
  q = p = NULL;
  recved = i = 0;
  c = 0;
  
  while(1) {
    SIO_RECV(c);
    switch(c) {
    case SLIP_END:
      if(p == NULL) {
        return sioslipif_input();
      }
      if(recved > 0) {
        /* Received whole packet. */
        pbuf_realloc(q, recved);
#ifdef LINK_STATS
        stats.link.recv++;
#endif /* LINK_STATS */         
        return q;
      }
      break;
    case SLIP_ESC:
      SIO_RECV(c);
      switch(c) {
      case SLIP_ESC_END:
        c = SLIP_END;
        break;
      case SLIP_ESC_ESC:
        c = SLIP_ESC;
        break;
      }
      /* FALLTHROUGH */
    default:
      if(p == NULL) {      
        p = pbuf_alloc(PBUF_LINK, 128, PBUF_POOL);
#ifdef LINK_STATS           
        if(p == NULL) {
          stats.link.drop++;
        }
#endif /* LINK_STATS */                  
        if(q != NULL) {
          pbuf_chain(q, p);
        } else {
          q = p;
        }
      }
      if(p != NULL && recved < MAX_SIZE) {
        ((u8_t *)p->payload)[i] = c;
        recved++;
        i++;
        if(i >= p->len) {
          i = 0;
          p = NULL;
        }
      }
      break;
    }
    
  }
  return NULL;
}
/*-----------------------------------------------------------------------------------*/
static void
sioslipif_loop(void *arg)
{
  struct pbuf *p;
  struct netif *netif;

  netif = arg;
  while(1) {
    p = sioslipif_input();    
    netif->input(p, netif);
  }
}
/*-----------------------------------------------------------------------------------*/
void
sioslipif_init(struct netif *netif)
{
  netif->state = NULL;
  netif->name[0] = 's';
  netif->name[1] = 'l';
  netif->output = sioslipif_output;

  sys_thread_new((void *)sioslipif_loop, netif);
  /* Do some magic to make it possible to receive data from the serial I/O device. */
}
/*-----------------------------------------------------------------------------------*/
