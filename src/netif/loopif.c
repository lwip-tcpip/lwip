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
#include "lwip/mem.h"
#include "lwip/opt.h"
#include "netif/loopif.h"

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
#include "netif/tcpdump.h"
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */

#include "lwip/tcp.h"
#include "lwip/ip.h"

/*-----------------------------------------------------------------------------------*/
static err_t
loopif_output(struct netif *netif, struct pbuf *p,
	     struct ip_addr *ipaddr)
{
  struct pbuf *q, *r;
  char *ptr;

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
  tcpdump(p);
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */
  
  r = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
  if(r != NULL) {
    ptr = r->payload;
    
    for(q = p; q != NULL; q = q->next) {
      memcpy(ptr, q->payload, q->len);
      ptr += q->len;
    }
    netif->input(r, netif);
    return ERR_OK;    
  }
  return ERR_MEM;
}
/*-----------------------------------------------------------------------------------*/
err_t
loopif_init(struct netif *netif)
{
  netif->name[0] = 'l';
  netif->name[1] = 'o';
  netif->output = loopif_output;
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/







