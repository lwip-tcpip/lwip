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

/*-----------------------------------------------------------------------------------*/
/* inet.c
 *
 * Functions common to all TCP/IP modules, such as the Internet checksum and the
 * byte order functions.
 *
 */
/*-----------------------------------------------------------------------------------*/

#include "lwip/debug.h"

#include "lwip/arch.h"

#include "lwip/def.h"
#include "lwip/inet.h"


/*-----------------------------------------------------------------------------------*/
static u16_t
lwip_chksum(void *dataptr, int len)
{
  u32_t acc;
    
  DEBUGF(INET_DEBUG, ("lwip_chksum(%p, %d)\n", dataptr, len));
  for(acc = 0; len > 1; len -= 2) {
//    acc = acc + *((u16_t *)dataptr)++;
    acc += *(u16_t *)dataptr;
    dataptr = (void *)((u16_t *)dataptr + 1);
  }

  /* add up any odd byte */
  if(len == 1) {
    acc += htons((u16_t)((*(u8_t *)dataptr) & 0xff) << 8);
    DEBUGF(INET_DEBUG, ("inet: chksum: odd byte %d\n", *(u8_t *)dataptr));
  } else {
    DEBUGF(INET_DEBUG, ("inet: chksum: no odd byte\n"));
  }
  acc = (acc >> 16) + (acc & 0xffffUL);

  if((acc & 0xffff0000) != 0) {
    acc = (acc >> 16) + (acc & 0xffffUL);
  }

  return (u16_t)acc;
}
/*-----------------------------------------------------------------------------------*/
/* inet_chksum_pseudo:
 *
 * Calculates the pseudo Internet checksum used by TCP and UDP for a pbuf chain.
 */
/*-----------------------------------------------------------------------------------*/
u16_t
inet_chksum_pseudo(struct pbuf *p,
		   struct ip_addr *src, struct ip_addr *dest,
		   u8_t proto, u16_t proto_len)
{
  u32_t acc;
  struct pbuf *q;
  u8_t swapped;

  acc = 0;
  swapped = 0;
  /* iterate through all pbuf in chain */
  for(q = p; q != NULL; q = q->next) {    
    DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): checksumming pbuf %p (has next %p) \n", q, q->next));
    acc += lwip_chksum(q->payload, q->len);
    //DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped lwip_chksum()=%lx \n", acc));
    while(acc >> 16) {
      acc = (acc & 0xffffUL) + (acc >> 16);
    }
    if(q->len % 2 != 0) {
      swapped = 1 - swapped;
      acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
    }
    //DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): wrapped lwip_chksum()=%lx \n", acc));
  }

  if(swapped) {
    acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
  }
  acc += (src->addr & 0xffffUL);
  acc += ((src->addr >> 16) & 0xffffUL);
  acc += (dest->addr & 0xffffUL);
  acc += ((dest->addr >> 16) & 0xffffUL);
  acc += (u32_t)htons((u16_t)proto);
  acc += (u32_t)htons(proto_len);  
  
  while(acc >> 16) {
    acc = (acc & 0xffffUL) + (acc >> 16);
  }    
  DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): pbuf chain lwip_chksum()=%lx\n", acc));
  return ~(acc & 0xffffUL);
}
/*-----------------------------------------------------------------------------------*/
/* inet_chksum:
 *
 * Calculates the Internet checksum over a portion of memory. Used primarely for IP
 * and ICMP.
 */
/*-----------------------------------------------------------------------------------*/
u16_t
inet_chksum(void *dataptr, u16_t len)
{
  u32_t acc;

  acc = lwip_chksum(dataptr, len);
  while(acc >> 16) {
    acc = (acc & 0xffff) + (acc >> 16);
  }    
  return ~(acc & 0xffff);
}
/*-----------------------------------------------------------------------------------*/
u16_t
inet_chksum_pbuf(struct pbuf *p)
{
  u32_t acc;
  struct pbuf *q;
  u8_t swapped;
  
  acc = 0;
  swapped = 0;
  for(q = p; q != NULL; q = q->next) {
    acc += lwip_chksum(q->payload, q->len);
    while(acc >> 16) {
      acc = (acc & 0xffffUL) + (acc >> 16);
    }    
    if(q->len % 2 != 0) {
      swapped = 1 - swapped;
      acc = (acc & 0x00ffUL << 8) | (acc & 0xff00UL >> 8);
    }
  }
 
  if(swapped) {
    acc = ((acc & 0x00ffUL) << 8) | ((acc & 0xff00UL) >> 8);
  }
  return ~(acc & 0xffffUL);
}


/*-----------------------------------------------------------------------------------*/
