/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 * $Id: lib.c,v 1.1 2002/11/29 11:03:34 likewise Exp $
 */

/* These are generic implementations of various library functions used
 * throughout the lwIP code. When porting, those should be optimized
 * for the particular processor architecture, preferably coded in
 * assembler.
 */

#include "lwip/arch.h"

#if BYTE_ORDER == LITTLE_ENDIAN
/*-----------------------------------------------------------------------------------*/
u16_t
htons(u16_t n)
{
  return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}
/*-----------------------------------------------------------------------------------*/
u16_t
ntohs(u16_t n)
{
  return htons(n);
}
/*-----------------------------------------------------------------------------------*/
u32_t
htonl(u32_t n)
{
  return ((n & 0xff) << 24) |
    ((n & 0xff00) << 8) |
    ((n & 0xff0000) >> 8) |
    ((n & 0xff000000) >> 24);
}
/*-----------------------------------------------------------------------------------*/
u32_t
ntohl(u32_t n)
{
  return htonl(n);
}
/*-----------------------------------------------------------------------------------*/
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

void
bcopy(const void *src, void *dst, unsigned int size)
{
  char *csrc, *cdst;
  int i;

  csrc = (char *)src;
  cdst = dst;
  
  for(i = 0; i < size; i++) {
    cdst[i] = csrc[i];
  }    
}
/*-----------------------------------------------------------------------------------*/
void
bzero(void *s, int n)
{
  for(n--; n > 0; n--) {
    ((char *)s)[n] = 0;
  }
}
/*-----------------------------------------------------------------------------------*/
