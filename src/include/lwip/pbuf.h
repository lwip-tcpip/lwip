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
/*-----------------------------------------------------------------------------------*/
#ifndef __LWIP_PBUF_H__
#define __LWIP_PBUF_H__

#include "lwip/debug.h"
#include "lwip/arch.h"


#define PBUF_TRANSPORT_HLEN 20
#define PBUF_IP_HLEN        20

typedef enum {
  PBUF_TRANSPORT,
  PBUF_IP,
  PBUF_LINK,
  PBUF_RAW
} pbuf_layer;

typedef enum {
  PBUF_RAM,
  PBUF_ROM,
  PBUF_POOL
} pbuf_flag;

/* Definitions for the pbuf flag field (these are not the flags that
   are passed to pbuf_alloc()). */
#define PBUF_FLAG_RAM   0x00    /* Flags that pbuf data is stored in RAM. */
#define PBUF_FLAG_ROM   0x01    /* Flags that pbuf data is stored in ROM. */
#define PBUF_FLAG_POOL  0x02    /* Flags that the pbuf comes from the
				   pbuf pool. */

struct pbuf {
  struct pbuf *next;

  /* Pointer to the actual data in the buffer. */
  void *payload;
  
  /* Total length of buffer + additionally chained buffers. */
  u16_t tot_len;
  
  /* Length of this buffer. */
  u16_t len;  

  /* Flags and reference count. */
  u16_t flags, ref;
  
};

/* pbuf_init():

   Initializes the pbuf module. The num parameter determines how many
   pbufs that should be allocated to the pbuf pool, and the size
   parameter specifies the size of the data allocated to those.  */
void pbuf_init(void);

/* pbuf_alloc():
   
   Allocates a pbuf at protocol layer l. The actual memory allocated
   for the pbuf is determined by the layer at which the pbuf is
   allocated and the requested size (from the size parameter). The
   flag parameter decides how and where the pbuf should be allocated
   as follows:
 
   * PBUF_RAM: buffer memory for pbuf is allocated as one large
               chunk. This includesprotocol headers as well.
   
   * RBUF_ROM: no buffer memory is allocated for the pbuf, even for
                protocol headers.  Additional headers must be
                prepended by allocating another pbuf and chain in to
                the front of the ROM pbuf.

   * PBUF_POOL: the pbuf is allocated as a pbuf chain, with pbufs from
                the pbuf pool that is allocated during pbuf_init().  */
struct pbuf *pbuf_alloc(pbuf_layer l, u16_t size, pbuf_flag flag);

/* pbuf_realloc():

   Shrinks the pbuf to the size given by the size parameter. 
 */
void pbuf_realloc(struct pbuf *p, u16_t size); 

/* pbuf_header():

   Tries to move the p->payload pointer header_size number of bytes
   upward within the pbuf. The return value is non-zero if it
   fails. If so, an additional pbuf should be allocated for the header
   and it should be chained to the front. */
u8_t pbuf_header(struct pbuf *p, s16_t header_size);

/* pbuf_ref():

   Increments the reference count of the pbuf p.
 */
void pbuf_ref(struct pbuf *p);
void pbuf_ref_chain(struct pbuf *p);
/* pbuf_free():

   Decrements the reference count and deallocates the pbuf if the
   reference count is zero. If the pbuf is a chain all pbufs in the
   chain are deallocated. */
u8_t pbuf_free(struct pbuf *p);

/* pbuf_clen():

   Returns the length of the pbuf chain. */
u8_t pbuf_clen(struct pbuf *p);  

/* pbuf_chain():

   Chains pbuf t on the end of pbuf h. Pbuf h will have it's tot_len
   field adjusted accordingly. Pbuf t should no be used any more after
   a call to this function, since pbuf t is now a part of pbuf h.  */
void pbuf_chain(struct pbuf *h, struct pbuf *t);

/* pbuf_dechain():

   Picks off the first pbuf from the pbuf chain p. Returns the tail of
   the pbuf chain or NULL if the pbuf p was not chained. */
struct pbuf *pbuf_dechain(struct pbuf *p);

#endif /* __LWIP_PBUF_H__ */
