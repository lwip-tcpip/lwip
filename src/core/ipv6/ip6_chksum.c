/**
 * @file
 *
 * IPv6 Checksum helper functions.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#include "lwip/opt.h"

#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */

#include "lwip/ip6_addr.h"
#include "lwip/ip6_chksum.h"
#include "lwip/inet_chksum.h"
#include "lwip/def.h"

#ifndef LWIP_CHKSUM
# define LWIP_CHKSUM lwip_standard_chksum
extern u16_t lwip_standard_chksum(void *dataptr, u16_t len);
#endif


/**
 * Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a pbuf chain.
 * IPv6 addresses are expected to be in network byte order.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data part)
 * @param src source ipv6 address (used for checksum of pseudo header)
 * @param dst destination ipv6 address (used for checksum of pseudo header)
 * @param proto ipv6 protocol/next header (used for checksum of pseudo header)
 * @param proto_len length of the ipv6 payload (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
ip6_chksum_pseudo(struct pbuf *p,
       ip6_addr_t *src, ip6_addr_t *dest,
       u8_t proto, u16_t proto_len)
{
  u32_t acc;
  u32_t addr;
  struct pbuf *q;
  u8_t swapped;

  acc = 0;
  swapped = 0;
  /* iterate through all pbuf in chain */
  for(q = p; q != NULL; q = q->next) {
    acc += LWIP_CHKSUM(q->payload, q->len);
    /* fold the upper bit down */
    acc = FOLD_U32T(acc);
    if (q->len % 2 != 0) {
      swapped = 1 - swapped;
      acc = SWAP_BYTES_IN_WORD(acc);
    }
  }
  if (swapped) {
    acc = SWAP_BYTES_IN_WORD(acc);
  }

  for (swapped = 0; swapped < 4; swapped++) {
    addr = src->addr[swapped];
    acc += (addr & 0xffffUL);
    acc += ((addr >> 16) & 0xffffUL);
    addr = dest->addr[swapped];
    acc += (addr & 0xffffUL);
    acc += ((addr >> 16) & 0xffffUL);
  }
  acc += (u32_t)htons((u16_t)proto);
  acc += (u32_t)htons(proto_len);

  /* Fold 32-bit sum to 16 bits
     calling this twice is propably faster than if statements... */
  acc = FOLD_U32T(acc);
  acc = FOLD_U32T(acc);
  LWIP_DEBUGF(INET_DEBUG, ("ip6_chksum_pseudo(): pbuf chain lwip_chksum()=%"X32_F"\n", acc));
  return (u16_t)~(acc & 0xffffUL);
}

/**
 * Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a pbuf chain.
 * IPv6 addresses are expected to be in network byte order. Will only compute for a
 * portion of the payload.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data part)
 * @param src source ipv6 address (used for checksum of pseudo header)
 * @param dst destination ipv6 address (used for checksum of pseudo header)
 * @param proto ipv6 protocol/next header (used for checksum of pseudo header)
 * @param proto_len length of the ipv6 payload (used for checksum of pseudo header)
 * @param chksum_len number of payload bytes used to compute chksum
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
ip6_chksum_pseudo_partial(struct pbuf *p,
       ip6_addr_t *src, ip6_addr_t *dest,
       u8_t proto, u16_t proto_len, u16_t chksum_len)
{
  u32_t acc;
  u32_t addr;
  struct pbuf *q;
  u8_t swapped;
  u16_t chklen;

  acc = 0;
  swapped = 0;
  /* iterate through all pbuf in chain */
  for(q = p; (q != NULL) && (chksum_len > 0); q = q->next) {
    chklen = q->len;
    if (chklen > chksum_len) {
      chklen = chksum_len;
    }
    acc += LWIP_CHKSUM(q->payload, chklen);
    chksum_len -= chklen;
    acc = FOLD_U32T(acc);
    if (q->len % 2 != 0) {
      swapped = 1 - swapped;
      acc = SWAP_BYTES_IN_WORD(acc);
    }
  }
  if (swapped) {
    acc = SWAP_BYTES_IN_WORD(acc);
  }

  for (swapped = 0; swapped < 4; swapped++) {
    addr = src->addr[swapped];
    acc += (addr & 0xffffUL);
    acc += ((addr >> 16) & 0xffffUL);
    addr = dest->addr[swapped];
    acc += (addr & 0xffffUL);
    acc += ((addr >> 16) & 0xffffUL);
  }
  acc += (u32_t)htons((u16_t)proto);
  acc += (u32_t)htons(proto_len);

  /* Fold 32-bit sum to 16 bits
     calling this twice is propably faster than if statements... */
  acc = FOLD_U32T(acc);
  acc = FOLD_U32T(acc);
  LWIP_DEBUGF(INET_DEBUG, ("ip6_chksum_pseudo_partial(): pbuf chain lwip_chksum()=%"X32_F"\n", acc));
  return (u16_t)~(acc & 0xffffUL);
}

#endif /* LWIP_IPV6 */
