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

#include "lwip/debug.h"
#include "lwip/def.h"
#include "netif/sioslipif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

/* This variable is used for passing the netif pointer between the
   threads. */
static struct netif *netif_pass;

static int infd, outfd;
/*-----------------------------------------------------------------------------------*/
static void
sio_send(u8_t c)
{
  write(outfd, &c, 1);
}
/*-----------------------------------------------------------------------------------*/
static u8_t
sio_recv(void)
{
  u8_t c;
  read(infd, &c, 1);
  return c;
}
/*-----------------------------------------------------------------------------------*/
static int
sioslipif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
  struct pbuf *q;
  int i;
  u8_t c;
  
  /* Send pbuf out on the serial I/O device. */
  sio_send(SLIP_END);
  
  for(q = p; q != NULL; q = q->next) {
    for(i = 0; i < q->len; i++) {
      c = ((u8_t *)q->payload)[i];
      switch(c) {
      case SLIP_END:
        sio_send(SLIP_ESC);
        sio_send(SLIP_ESC_END);
        break;
      case SLIP_ESC:
        sio_send(SLIP_ESC);
        sio_send(SLIP_ESC_ESC);
        break;
      default:
        sio_send(c);
        break;
      }
    }
  }
  sio_send(SLIP_END);
  return 0;
}
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
sioslipif_input(void)
{
  u8_t c;
  struct pbuf *p, *q;
  int recved;
  int i;

  p = pbuf_alloc(PBUF_LINK, PBUF_MAX_SIZE, PBUF_POOL);
  q = p;
  recved = i = 0;
  
  while(1) {
    c = sio_recv();
    switch(c) {
    case SLIP_END:
      if(recved > 0) {
        /* Received whole packet. */
        pbuf_realloc(p, recved);
        return p;
      }
      break;
    case SLIP_ESC:
      c = sio_recv();
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
      if(recved < p->tot_len && q != NULL) {
        ((u8_t *)q->payload)[i] = c;
        recved++;
        i++;
        if(i >= q->len) {
          i = 0;
          q = q->next;
        }
      }
      break;
    }
    
  }
}
/*-----------------------------------------------------------------------------------*/
static void
sioslipif_loop(void)
{
  struct pbuf *p;
  struct netif *netif;

  netif = netif_pass;
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

  netif_pass = netif;
  sys_thread_new((void *)sioslipif_loop, NULL);
  /* Do some magic to make it possible to receive data from the serial I/O device. */
}
/*-----------------------------------------------------------------------------------*/
