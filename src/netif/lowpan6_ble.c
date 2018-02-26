/**
 * @file
 * 6LowPAN over BLE output for IPv6 (RFC7668).
*/

/*
 * Copyright (c) 2017 Benjamin Aigner
 * Copyright (c) 2015 Inico Technologies Ltd. , Author: Ivan Delamer <delamer@inicotech.com>
 * 
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
 * Author: Benjamin Aigner <aignerb@technikum-wien.at>
 * 
 * Based on the original 6lowpan implementation of lwIP ( @see 6lowpan.c)
 */


/**
 * @defgroup rfc7668if RFC7668 - 6LoWPAN over BLE netif
 * @ingroup netifs
 * This file implements a RFC7668 implementation for 6LoWPAN over
 * Bluetooth Low Energy. The specification is very similar to 6LoWPAN,
 * so most of the code is re-used.
 * Compared to 6LoWPAN, much functionality is already implemented in
 * lower BLE layers (fragmenting, session management,...).
 *
 * Usage:
 * - add this netif
 *   - don't add IPv4 addresses (no IPv4 support in RFC7668), pass 'NULL','NULL','NULL'
 *   - use the BLE to EUI64 conversation util to create an IPv6 link-local address from the BLE MAC ( @see ble_addr_to_eui64)
 *   - input function: @see rfc7668_input
 * - set the link output function, which transmits output data to an established L2CAP channel
 * - If data arrives (HCI event "L2CAP_DATA_PACKET"):
 *   - allocate a @see PBUF_RAW buffer
 *   - let the pbuf struct point to the incoming data or copy it to the buffer
 *   - call netif->input
 *
 * @todo:
 * - further testing
 * - support compression contexts
 * - support multiple addresses
 * - support multicast
 * - support neighbor discovery
 */


#include "netif/lowpan6_ble.h"

#if LWIP_IPV6 && LWIP_RFC7668

#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/nd6.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/tcpip.h"
#include "lwip/snmp.h"

#include <string.h>

#if LWIP_RFC7668_NUM_CONTEXTS > 0
  /** context memory, containing IPv6 addresses */
  static ip6_addr_t rfc7668_context[LWIP_RFC7668_NUM_CONTEXTS];
#endif

err_t tcpip_rfc7668_input(struct pbuf *p, struct netif *inp);
err_t rfc7668_set_context(u8_t index, const ip6_addr_t * context);


/** convert BT address to EUI64 addr
 * 
 * This method converts a Bluetooth MAC address to an EUI64 address,
 * which is used within IPv6 communication
 * 
 * @param dst IPv6 destination space
 * @param src BLE MAC address source
 * @param public_addr If the LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS
 * option is set, bit 0x02 will be set if param=0 (no public addr); cleared otherwise
 * 
 * @see LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS
 */
void ble_addr_to_eui64(uint8_t *dst, uint8_t *src, uint8_t public_addr)
{
  /* according to RFC7668 ch 3.2.2. */
  memcpy(dst, src, 3);
  dst[3] = 0xFF;
  dst[4] = 0xFE;
  memcpy(&dst[5], &src[3], 3);
#if LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS
  if(public_addr) {
    dst[0] &= ~0x02;
  } else {
    dst[0] |= 0x02;
  }
#else
  LWIP_UNUSED_ARG(public_addr);
#endif
}

/** convert EUI64 address to Bluetooth MAC addr
 * 
 * This method converts an EUI64 address to a Bluetooth MAC address,
 * 
 * @param src IPv6 source
 * @param dst BLE MAC address destination
 * 
 */
void eui64_to_ble_addr(uint8_t *dst, uint8_t *src)
{
  /* according to RFC7668 ch 3.2.2. */
  memcpy(dst,src,3);
  memcpy(&dst[3],&src[5],3);
}

/** context lookup; find context ID for IPv6 address
 * 
 * @param ip6addr Pointer to IPv6 address struct
 * 
 * @return The context id, if one found; -1 if no context id found
 */
static s8_t
rfc7668_context_lookup(const ip6_addr_t *ip6addr)
{
#if LWIP_RFC7668_NUM_CONTEXTS > 0
  s8_t i;
  /* iterate over all possible context addresses */
  for (i = 0; i < LWIP_RFC7668_NUM_CONTEXTS; i++) {
    /* if a match is found, return id */
    if (ip6_addr_netcmp(&rfc7668_context[i], ip6addr)) {
      return i;
    }
  }
#else
  LWIP_UNUSED_ARG(ip6addr);
#endif
  /* no address found, return -1 */
  return -1;
}

/** Determine unicast address compression mode
 * 
 * NOT IMPLEMENTED. This method will determine if an address should
 * be compressed either context-based or stateless.
 * 
 * @see rfc7668_get_address_mode_mc
 * 
 * @param ip6addr Pointer to IPv6 address struct
 * 
 * @return Currently not defined...
 */
static s8_t
rfc7668_get_address_mode(const ip6_addr_t *ip6addr)
{
  /* @todo implement the compression mode determination */
  LWIP_UNUSED_ARG(ip6addr);
  /* just return 1, means stateless compression */
  return 1;
}

/** Determine multicast address compression mode
 * 
 * NOT IMPLEMENTED. This method will determine if an address should
 * be compressed either context-based or stateless.
 * 
 * @see rfc7668_get_address_mode_mc
 * 
 * @param ip6addr Pointer to IPv6 address struct
 * 
 * @return Currently not defined...
 */
static s8_t
rfc7668_get_address_mode_mc(const ip6_addr_t *ip6addr)
{
  /* @todo implement the compression mode determination */
  LWIP_UNUSED_ARG(ip6addr);
  /* just return 0, no multicast compression */
  return 0;
}

/** Encapsulate IPv6 frames for BLE transmission
 * 
 * This method implements the IPv6 header compression:
 *  *) According to RFC6282
 *  *) See Figure 2, contains base format of bit positions
 *  *) Fragmentation not necessary (done at L2CAP layer of BLE)
 * @note Currently the pbuf allocation uses 256 bytes. If longer packets are used (possible due to MTU=1480Bytes), increase it here!
 * 
 * @param dst Pointer to IPv6 address struct (destination)
 * @param src Pointer to IPv6 address struct (source)
 * @param p Pbuf struct, containing the payload data
 * @param netif Output network interface. Should be of RFC7668 type
 * 
 * @return Same as netif->output.
 */
static err_t
rfc7668_frag(struct netif *netif, struct pbuf *p, const ip6_addr_t * src, const ip6_addr_t *dst)
{
  struct pbuf * p_frag;
  u16_t frag_len, remaining_len;
  u8_t * buffer;
  u8_t lowpan6_header_len;
  s8_t i;
  err_t err = ERR_IF;

  /* We'll use a dedicated pbuf for building BLE fragments. */
  p_frag = pbuf_alloc(PBUF_RAW, 256, PBUF_RAM);
  if (p_frag == NULL) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    return ERR_MEM;
  }
  /* Write IP6 header (with IPHC). */
  buffer  = (u8_t*)p_frag->payload;

  /* Perform IPv6 header compression according to RFC 6282 NECESSARY!*/
  {
    struct ip6_hdr *ip6hdr;

    /* Point to ip6 header and align copies of src/dest addresses. */
    ip6hdr = (struct ip6_hdr *)p->payload;
    ip_addr_copy_from_ip6_packed(ip_data.current_iphdr_dest, ip6hdr->dest);
    ip_addr_copy_from_ip6_packed(ip_data.current_iphdr_src, ip6hdr->src);

    /* Basic length of 6LowPAN header, set dispatch and clear fields. */
    lowpan6_header_len = 2;
    buffer[0] = 0x60;
    buffer[1] = 0;

    /* Determine whether there will be a Context Identifier Extension byte or not.
    * If so, set it already. */
#if LWIP_RFC7668_NUM_CONTEXTS > 0
    buffer[2] = 0;

    i = rfc7668_context_lookup(ip_2_ip6(&ip_data.current_iphdr_src));
    if (i >= 0) {
      /* Stateful source address compression. */
      buffer[1] |= 0x40;
      buffer[2] |= (i & 0x0f) << 4;
    }

    i = rfc7668_context_lookup(ip_2_ip6(&ip_data.current_iphdr_dest));
    if (i >= 0) {
      /* Stateful destination address compression. */
      buffer[1] |= 0x04;
      buffer[2] |= i & 0x0f;
    }

    if (buffer[2] != 0x00) {
      /* Context identifier extension byte is appended. */
      buffer[1] |= 0x80;
      lowpan6_header_len++;
    }
#endif /* LWIP_6LOWPAN_NUM_CONTEXTS > 0 */

    /* Determine TF field: Traffic Class, Flow Label */
    if (IP6H_FL(ip6hdr) == 0) {
      /* Flow label is elided. */
      buffer[0] |= 0x10;
      if (IP6H_TC(ip6hdr) == 0) {
        /* Traffic class (ECN+DSCP) elided too. */
        buffer[0] |= 0x08;
      } else {
        /* Traffic class (ECN+DSCP) appended. */
        buffer[lowpan6_header_len++] = IP6H_TC(ip6hdr);
      }
    } else {
      if (((IP6H_TC(ip6hdr) & 0x3f) == 0)) {
        /* DSCP portion of Traffic Class is elided, ECN and FL are appended (3 bytes) */
        buffer[0] |= 0x08;

        buffer[lowpan6_header_len] = IP6H_TC(ip6hdr) & 0xc0;
        buffer[lowpan6_header_len++] |= (IP6H_FL(ip6hdr) >> 16) & 0x0f;
        buffer[lowpan6_header_len++] = (IP6H_FL(ip6hdr) >> 8) & 0xff;
        buffer[lowpan6_header_len++] = IP6H_FL(ip6hdr) & 0xff;
      } else {
        /* Traffic class and flow label are appended (4 bytes) */
        buffer[lowpan6_header_len++] = IP6H_TC(ip6hdr);
        buffer[lowpan6_header_len++] = (IP6H_FL(ip6hdr) >> 16) & 0x0f;
        buffer[lowpan6_header_len++] = (IP6H_FL(ip6hdr) >> 8) & 0xff;
        buffer[lowpan6_header_len++] = IP6H_FL(ip6hdr) & 0xff;
      }
    }

    /* Compress NH?
    * Only if UDP for now. @todo support other NH compression. */
    if (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_UDP) {
      buffer[0] |= 0x04;
    } else {
      /* append nexth. */
      buffer[lowpan6_header_len++] = IP6H_NEXTH(ip6hdr);
    }

    /* Compress hop limit? */
    if (IP6H_HOPLIM(ip6hdr) == 255) {
      buffer[0] |= 0x03;
    } else if (IP6H_HOPLIM(ip6hdr) == 64) {
      buffer[0] |= 0x02;
    } else if (IP6H_HOPLIM(ip6hdr) == 1) {
      buffer[0] |= 0x01;
    } else {
      /* append hop limit */
      buffer[lowpan6_header_len++] = IP6H_HOPLIM(ip6hdr);
    }

    /* Compress source address */
    if (((buffer[1] & 0x40) != 0) ||
        (ip6_addr_islinklocal(ip_2_ip6(&ip_data.current_iphdr_src)))) {
      /* Context-based or link-local source address compression. */
      i = rfc7668_get_address_mode(src);
      buffer[1] |= (i & 0x03) << 4;
      if (i == 1) {
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 16, 8);
        lowpan6_header_len += 8;
      } else if (i == 2) {
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 22, 2);
        lowpan6_header_len += 2;
      }
    } else if (ip6_addr_isany(ip_2_ip6(&ip_data.current_iphdr_src))) {
      /* Special case: mark SAC and leave SAM=0 */
      buffer[1] |= 0x40;
    } else {
      /* Append full address. */
      MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 8, 16);
      lowpan6_header_len += 16;
    }

    /* Compress destination address */
    if (ip6_addr_ismulticast(ip_2_ip6(&ip_data.current_iphdr_dest))) {
      /* @todo support stateful multicast address compression */

      buffer[1] |= 0x08;

      i = rfc7668_get_address_mode_mc(ip_2_ip6(&ip_data.current_iphdr_dest));
      buffer[1] |= i & 0x03;
      if (i == 0) {
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 24, 16);
        lowpan6_header_len += 16;
      } else if (i == 1) {
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[25];
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 35, 5);
        lowpan6_header_len += 5;
      } else if (i == 2) {
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[25];
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 37, 3);
        lowpan6_header_len += 3;
      } else if (i == 3) {
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[39];
      }
    } else if (((buffer[1] & 0x04) != 0) ||
               (ip6_addr_islinklocal(ip_2_ip6(&ip_data.current_iphdr_dest)))) {
      /* Context-based or link-local destination address compression. */
      i = rfc7668_get_address_mode(dst);
      buffer[1] |= i & 0x03;
      if (i == 1) {
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 32, 8);
        lowpan6_header_len += 8;
      } else if (i == 2) {
        MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 38, 2);
        lowpan6_header_len += 2;
      }
    } else {
      /* Append full address. */
      MEMCPY(buffer + lowpan6_header_len, (u8_t*)p->payload + 24, 16);
      lowpan6_header_len += 16;
    }

    /* Move to payload. */
    pbuf_remove_header(p, IP6_HLEN);

    /* Compress UDP header? */
    if (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_UDP) {
      /* @todo support optional checksum compression */

      buffer[lowpan6_header_len] = 0xf0;

      /* determine port compression mode. */
      if ((((u8_t *)p->payload)[0] == 0xf0) && ((((u8_t *)p->payload)[1] & 0xf0) == 0xb0) &&
          (((u8_t *)p->payload)[2] == 0xf0) && ((((u8_t *)p->payload)[3] & 0xf0) == 0xb0)) {
        /* Compress source and dest ports. */
        buffer[lowpan6_header_len++] |= 0x03;
        buffer[lowpan6_header_len++] = ((((u8_t *)p->payload)[1] & 0x0f) << 4) | (((u8_t *)p->payload)[3] & 0x0f);
      } else if (((u8_t *)p->payload)[0] == 0xf0) {
        /* Compress source port. */
        buffer[lowpan6_header_len++] |= 0x02;
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[1];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[2];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[3];
      } else if (((u8_t *)p->payload)[2] == 0xf0) {
        /* Compress dest port. */
        buffer[lowpan6_header_len++] |= 0x01;
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[0];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[1];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[3];
      } else {
        /* append full ports. */
        lowpan6_header_len++;
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[0];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[1];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[2];
        buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[3];
      }

      /* elide length and copy checksum */
      buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[6];
      buffer[lowpan6_header_len++] = ((u8_t *)p->payload)[7];

      pbuf_remove_header(p, UDP_HLEN);
    }
  }

  /* Calculate remaining packet length */
  remaining_len = p->tot_len;

  /* It fits in one frame. */
  frag_len = remaining_len;

  /* Copy IPv6 packet */
  pbuf_copy_partial(p, buffer + lowpan6_header_len, frag_len, 0);
  remaining_len = 0;

  /* Calculate frame length */
  p_frag->len = p_frag->tot_len = frag_len + lowpan6_header_len;

  /* send the packet */
  MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
  LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_DBG_TRACE, ("rfc7668_send: sending packet %p\n", (void *)p));
  err = netif->linkoutput(netif, p_frag);

  pbuf_free(p_frag);

  return err;
}

/**
 * Set context id IPv6 address
 *
 * Store one IPv6 address to a given context id.
 *
 * @param idx Context id
 * @param context IPv6 addr for this context
 *
 * @return ERR_OK (if everything is fine), ERR_ARG (if the context id is out of range), ERR_VAL (if contexts disabled)
 */
err_t
rfc7668_set_context(u8_t idx, const ip6_addr_t *context)
{
#if LWIP_RFC7668_NUM_CONTEXTS > 0
  /* check if the ID is possible */
  if (idx >= LWIP_RFC7668_NUM_CONTEXTS) {
    return ERR_ARG;
  }
  /* copy IPv6 address to context storage */
  ip6_addr_set(&rfc7668_context[idx], context);  
  return ERR_OK;
#else
  LWIP_UNUSED_ARG(idx);
  LWIP_UNUSED_ARG(context);
  return ERR_VAL;
#endif
}

/**
 * Resolve and fill-in IEEE 802.15.4 address header for outgoing IPv6 packet.
 *
 * Perform Header Compression and fragment if necessary.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The pbuf(s) containing the IP packet to be sent.
 * @param ip6addr The IP address of the packet destination.
 *
 * @return See rfc7668_frag
 */
err_t
rfc7668_output(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr)
{
  return rfc7668_frag(netif, q, (ip6_addr_t *)netif->ip6_addr, ip6addr);
}

/**
 * Resolve the IPv6 address & metrics (NH, hops,...) from the compressed header
 *
 * Perform Header Deompression.
 *
 * @param p The pbuf containing the IP packet to be decompressed.
 * @param dest The IP address of the packet destination.
 * @param src The IP address of the packet source.
 *
 * @return pbuf pointer of the processed packet
 */
static struct pbuf *
rfc7668_decompress(struct pbuf * p, const ip6_addr_t * src, const ip6_addr_t * dest)
{
  struct pbuf * q;
  u16_t j;
  /* temp variable, ease up debug output/processing */
  u32_t header_temp;
  u8_t * lowpan6_buffer;
  s8_t lowpan6_offset;
  struct ip6_hdr *ip6hdr;
  s8_t ip6_offset = IP6_HLEN;

  LWIP_UNUSED_ARG(dest);

  /* allocate a new pbuf for the decompressed IPv6 packet */
  q = pbuf_alloc(PBUF_IP, p->len + IP6_HLEN + UDP_HLEN, PBUF_POOL);
  if (q == NULL) {
    LWIP_DEBUGF(LWIP_DBG_ON,("Out of memory, discarding!!!\n"));
    pbuf_free(p);
    return NULL;
  }

  /* set buffer pointer to payload */
  lowpan6_buffer = (u8_t *)p->payload;
  /* set pointer for new ip6 header */
  ip6hdr = (struct ip6_hdr *)q->payload;
  
  /* output the full compressed packet, if set in @see rfc7668_opt.h */
#if LWIP_RFC7668_IP_COMPRESSED_DEBUG
  LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_IP_COMPRESSED_DEBUG,("IP6 payload(compressed): \n"));
  for(j = 0; j<p->len;j++)
  {
    if((j%4)==0) LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_IP_COMPRESSED_DEBUG,("\n"));
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_IP_COMPRESSED_DEBUG,("%2X ",*((uint8_t *)p->payload+j)));
  }
  LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_IP_COMPRESSED_DEBUG,("\np->len: %d",p->len));
  printf("\np->len: %d\n",p->len);
#endif

  /* offset for inline IP headers (RFC 6282 ch3)*/
  lowpan6_offset = 2;

  /* if CID is set (context identifier), the context byte 
   * follows immediately after the header, so other IPHC fields are @+3 */
  if (lowpan6_buffer[1] & 0x80) {
    lowpan6_offset++;
  }

  /* Set IPv6 version, traffic class and flow label. (RFC6282, ch 3.1.1.)*/
  if ((lowpan6_buffer[0] & 0x18) == 0x00) {
    header_temp = ((lowpan6_buffer[lowpan6_offset+1] & 0x0f) << 16) | \
      (lowpan6_buffer[lowpan6_offset + 2] << 8) | lowpan6_buffer[lowpan6_offset+3];
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("TF: 00, ECN: 0x%2x, Flowlabel+DSCP: 0x%8X\n", \
      lowpan6_buffer[lowpan6_offset],header_temp));
    IP6H_VTCFL_SET(ip6hdr, 6, lowpan6_buffer[lowpan6_offset], header_temp);
    /* increase offset, processed 4 bytes here:
     * TF=00:  ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)*/
    lowpan6_offset += 4;
  } else if ((lowpan6_buffer[0] & 0x18) == 0x08) {
    header_temp = ((lowpan6_buffer[lowpan6_offset] & 0x0f) << 16) | (lowpan6_buffer[lowpan6_offset + 1] << 8) | lowpan6_buffer[lowpan6_offset+2];
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("TF: 01, ECN: 0x%2x, Flowlabel: 0x%2X, DSCP ignored\n", \
      lowpan6_buffer[lowpan6_offset] & 0xc0,header_temp));
    IP6H_VTCFL_SET(ip6hdr, 6, lowpan6_buffer[lowpan6_offset] & 0xc0, header_temp);
    /* increase offset, processed 3 bytes here:
     * TF=01:  ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided.*/
    lowpan6_offset += 3;
  } else if ((lowpan6_buffer[0] & 0x18) == 0x10) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("TF: 10, DCSP+ECN: 0x%2x, Flowlabel ignored\n",lowpan6_buffer[lowpan6_offset]));
    IP6H_VTCFL_SET(ip6hdr, 6, lowpan6_buffer[lowpan6_offset],0);
    /* increase offset, processed 1 byte here:
     * ECN + DSCP (1 byte), Flow Label is elided.*/
    lowpan6_offset += 1;
  } else if ((lowpan6_buffer[0] & 0x18) == 0x18) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("TF: 11, DCSP/ECN & Flowlabel ignored\n"));
    /* don't increase offset, no bytes processed here */
    IP6H_VTCFL_SET(ip6hdr, 6, 0, 0);
  }

  /* Set Next Header (NH)
   * 0: full next header byte carried inline (increase offset)*/
  if ((lowpan6_buffer[0] & 0x04) == 0x00) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("NH: 0x%2X\n",lowpan6_buffer[lowpan6_offset+1]));   
    IP6H_NEXTH_SET(ip6hdr, lowpan6_buffer[lowpan6_offset++]);
  /* 1: NH compression, LOWPAN_NHC (RFC6282, ch 4.1) */
  } else {
    /* We should fill this later with NHC decoding */
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("NH: skipped, later done with NHC\n"));
    IP6H_NEXTH_SET(ip6hdr, 0);
  }

  /* Set Hop Limit, either carried inline or 3 different hops (1,64,255) */
  if ((lowpan6_buffer[0] & 0x03) == 0x00) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("Hops: full value: %d\n",lowpan6_buffer[lowpan6_offset+1]));
    IP6H_HOPLIM_SET(ip6hdr, lowpan6_buffer[lowpan6_offset++]);
  } else if ((lowpan6_buffer[0] & 0x03) == 0x01) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("Hops: compressed: 1\n"));
    IP6H_HOPLIM_SET(ip6hdr, 1);
  } else if ((lowpan6_buffer[0] & 0x03) == 0x02) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("Hops: compressed: 64\n"));
    IP6H_HOPLIM_SET(ip6hdr, 64);
  } else if ((lowpan6_buffer[0] & 0x03) == 0x03) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("Hops: compressed: 255\n"));
    IP6H_HOPLIM_SET(ip6hdr, 255);
  }
  
  /* Source address decoding. */
  /* Source address compression (SAC) = 0 -> stateless compression */
  if ((lowpan6_buffer[1] & 0x40) == 0x00) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAC == 0, no context byte\n"));
    /* Stateless compression */
    if ((lowpan6_buffer[1] & 0x30) == 0x00) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 00, no src compression, fetching 128bits inline\n"));
      /* copy full address, increase offset by 16 Bytes */
      MEMCPY(&ip6hdr->src.addr[0], lowpan6_buffer + lowpan6_offset, 16);
      lowpan6_offset += 16;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x10) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 01, src compression, 64bits inline\n"));
      /* set 64 bits to link local */
      ip6hdr->src.addr[0] = PP_HTONL(0xfe800000UL);
      ip6hdr->src.addr[1] = 0;
      /* copy 8 Bytes, increase offset */
      MEMCPY(&ip6hdr->src.addr[2], lowpan6_buffer + lowpan6_offset, 8);
      lowpan6_offset += 8;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x20) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 10, src compression, 16bits inline\n"));
      /* set 96 bits to link local */
      ip6hdr->src.addr[0] = PP_HTONL(0xfe800000UL);
      ip6hdr->src.addr[1] = 0;
      ip6hdr->src.addr[2] = PP_HTONL(0x000000ffUL);
      /* extract remaining 16bits from inline bytes, increase offset */
      ip6hdr->src.addr[3] = htonl(0xfe000000UL | (lowpan6_buffer[lowpan6_offset] << 8) |
                                  lowpan6_buffer[lowpan6_offset+1]);
      lowpan6_offset += 2;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x30) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 11, src compression, 0bits inline, using other headers\n"));
      /* no information avalaible, using other layers, see RFC6282 ch 3.2.2 */
      ip6hdr->src.addr[0] = PP_HTONL(0xfe800000UL);
      ip6hdr->src.addr[1] = 0;
      MEMCPY(&ip6hdr->src.addr[2], (const uint8_t *)src->addr, 8);
    }
  /* Source address compression (SAC) = 1 -> stateful/context-based compression */  
  } else {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAC == 1, additional context byte\n"));
    /* Stateful compression */
    /* SAM=00, address=> :: (ANY) */
    if ((lowpan6_buffer[1] & 0x30) == 0x00) {
      /* ANY address */
      ip6hdr->src.addr[0] = 0;
      ip6hdr->src.addr[1] = 0;
      ip6hdr->src.addr[2] = 0;
      ip6hdr->src.addr[3] = 0;
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 00, context compression, ANY (::)\n"));
    } else {
      /* Set prefix from context info */
      if (lowpan6_buffer[1] & 0x80) {
        j = (lowpan6_buffer[2] >> 4) & 0x0f;
      } else {
        j = 0;
      }
      if (j >= LWIP_RFC7668_NUM_CONTEXTS) {
        /* Error, not possible (context id too high) */
        pbuf_free(p);
        pbuf_free(q);
        return NULL;
      }
#if LWIP_RFC7668_NUM_CONTEXTS > 0
      /* load prefix from context storage */
      ip6hdr->src.addr[0] = rfc7668_context[j].addr[0];
      ip6hdr->src.addr[1] = rfc7668_context[j].addr[1];
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == xx, context compression found @%d: %8X, %8X\n", j, ip6hdr->src.addr[0], ip6hdr->src.addr[1]));
#endif
    }

    /* determine further address bits */
    /* SAM=01, load additional 64bits */
    if ((lowpan6_buffer[1] & 0x30) == 0x10) {
      MEMCPY(&ip6hdr->src.addr[2], lowpan6_buffer + lowpan6_offset, 8);
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 01, context compression, 64bits inline\n"));
      lowpan6_offset += 8;
    /* SAM=01, load additional 16bits */
    } else if ((lowpan6_buffer[1] & 0x30) == 0x20) {
      ip6hdr->src.addr[2] = PP_HTONL(0x000000ffUL);
      ip6hdr->src.addr[3] = htonl(0xfe000000UL | (lowpan6_buffer[lowpan6_offset] << 8) | lowpan6_buffer[lowpan6_offset+1]);
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 10, context compression, 16bits inline\n"));
      lowpan6_offset += 2;
    /* SAM=11, address is fully elided, load from other layers */
    } else if ((lowpan6_buffer[1] & 0x30) == 0x30) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("SAM == 11, context compression, 0bits inline, using other headers\n"));
      /* no information avalaible, using other layers, see RFC6282 ch 3.2.2 */     
    }
  }

  /* Destination address + Multicast decoding. */
  if (lowpan6_buffer[1] & 0x08) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("M=1: multicast\n"));
    /* Multicast destination */
    if (lowpan6_buffer[1] & 0x04) {
      LWIP_DEBUGF(LWIP_DBG_ON,("DAC == 1, context multicast: unsupported!!!\n"));
      /* @todo support stateful multicast addressing */
      pbuf_free(p);
      pbuf_free(q);
      return NULL;
    } else {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAC == 0, stateless multicast\n"));

      if ((lowpan6_buffer[1] & 0x03) == 0x00) {
        /* DAM = 00, copy full address (128bits) */
        LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 00, no dst compression, fetching 128bits inline"));
        MEMCPY(&ip6hdr->dest.addr[0], lowpan6_buffer + lowpan6_offset, 16);
        lowpan6_offset += 16;
      } else if ((lowpan6_buffer[1] & 0x03) == 0x01) {
        /* DAM = 01, copy 4 bytes (32bits) */
        LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 01, dst address form (48bits): ffXX::00XX:XXXX:XXXX\n"));
        ip6hdr->dest.addr[0] = htonl(0xff000000UL | (lowpan6_buffer[lowpan6_offset++] << 16));
        ip6hdr->dest.addr[1] = 0;
        ip6hdr->dest.addr[2] = htonl(lowpan6_buffer[lowpan6_offset++]);
        ip6hdr->dest.addr[3] = htonl((lowpan6_buffer[lowpan6_offset] << 24) | (lowpan6_buffer[lowpan6_offset + 1] << 16) | (lowpan6_buffer[lowpan6_offset + 2] << 8) | lowpan6_buffer[lowpan6_offset + 3]);
        lowpan6_offset += 4;
      } else if ((lowpan6_buffer[1] & 0x03) == 0x02) {
        /* DAM = 10, copy 3 bytes (24bits) */
        LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 10, dst address form (32bits): ffXX::00XX:XXXX\n"));
        ip6hdr->dest.addr[0] = htonl(0xff000000UL | (lowpan6_buffer[lowpan6_offset++]<<16));
        ip6hdr->dest.addr[1] = 0;
        ip6hdr->dest.addr[2] = 0;
        ip6hdr->dest.addr[3] = htonl((lowpan6_buffer[lowpan6_offset] << 16) | (lowpan6_buffer[lowpan6_offset + 1] << 8) | lowpan6_buffer[lowpan6_offset + 2]);
        lowpan6_offset += 3;
      } else if ((lowpan6_buffer[1] & 0x03) == 0x03) {
        /* DAM = 11, copy 1 byte (8bits) */  
        LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 11, dst address form (8bits): ff02::00XX\n"));
        ip6hdr->dest.addr[0] = PP_HTONL(0xff020000UL);
        ip6hdr->dest.addr[1] = 0;
        ip6hdr->dest.addr[2] = 0;
        ip6hdr->dest.addr[3] = htonl(lowpan6_buffer[lowpan6_offset++]);
      }
    }
  } else {
    /* no Multicast (M=0) */
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("M=0: no multicast\n"));
    
    if (lowpan6_buffer[1] & 0x04) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAC == 1, stateful compression\n"));
      /* Stateful destination compression */
      /* Set prefix from context info */
      if (lowpan6_buffer[1] & 0x80) {
        j = lowpan6_buffer[2] & 0x0f;
      } else {
        j = 0;
      }
      if (j >= LWIP_RFC7668_NUM_CONTEXTS) {
        /* Error, context id not found */
        pbuf_free(p);
        pbuf_free(q);
        return NULL;
      }
#if LWIP_RFC7668_NUM_CONTEXTS > 0
      ip6hdr->dest.addr[0] = rfc7668_context[j].addr[0];
      ip6hdr->dest.addr[1] = rfc7668_context[j].addr[1];
#endif
    } else {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAC == 0, stateless compression, setting link local prefix\n"));
      /* Link local address compression */
      ip6hdr->dest.addr[0] = PP_HTONL(0xfe800000UL);
      ip6hdr->dest.addr[1] = 0;
    }

    /* M=0, DAC=0, determining destination address length via DAM=xx */
    if ((lowpan6_buffer[1] & 0x03) == 0x00) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 00, no dst compression, fetching 128bits inline"));
      /* DAM=00, copy full address */
      MEMCPY(&ip6hdr->dest.addr[0], lowpan6_buffer + lowpan6_offset, 16);
      lowpan6_offset += 16;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x01) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 01, dst compression, 64bits inline\n"));
      /* DAM=01, copy 64 inline bits, increase offset */
      MEMCPY(&ip6hdr->dest.addr[2], lowpan6_buffer + lowpan6_offset, 8);
      lowpan6_offset += 8;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x02) {
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 01, dst compression, 16bits inline\n"));
      /* DAM=10, copy 16 inline bits, increase offset */
      ip6hdr->dest.addr[2] = PP_HTONL(0x000000ffUL);
      ip6hdr->dest.addr[3] = htonl(0xfe000000UL | (lowpan6_buffer[lowpan6_offset] << 8) | lowpan6_buffer[lowpan6_offset + 1]);
      lowpan6_offset += 2;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x03) {
      /* DAM=11, no bits available, use other headers (not done here) */
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("DAM == 01, dst compression, 0bits inline, using other headers\n"));
    }
  }

  /* Next Header Compression (NHC) decoding? */
  if (lowpan6_buffer[0] & 0x04) {
    LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("NHC decoding\n"));

    /* NHC: UDP */
    if ((lowpan6_buffer[lowpan6_offset] & 0xf8) == 0xf0) {
      struct udp_hdr *udphdr;
      LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("NHC: UDP\n"));

      /* UDP compression */
      IP6H_NEXTH_SET(ip6hdr, IP6_NEXTH_UDP);
      udphdr = (struct udp_hdr *)((u8_t *)q->payload + ip6_offset);

      /* Checksum decompression */
      if (lowpan6_buffer[lowpan6_offset] & 0x04) {
        /* @todo support checksum decompress */
        LWIP_DEBUGF(LWIP_DBG_ON,("NHC: UDP chechsum decompression UNSUPPORTED\n"));
        pbuf_free(p);
        pbuf_free(q);
        return NULL;
      }

      /* Decompress ports, according to RFC4944 */
      j = lowpan6_buffer[lowpan6_offset++] & 0x03;
      if (j == 0) {
        udphdr->src = htons(lowpan6_buffer[lowpan6_offset] << 8 | lowpan6_buffer[lowpan6_offset + 1]);
        udphdr->dest = htons(lowpan6_buffer[lowpan6_offset + 2] << 8 | lowpan6_buffer[lowpan6_offset + 3]);
        lowpan6_offset += 4;
      } else if (j == 0x01) {
        udphdr->src = htons(lowpan6_buffer[lowpan6_offset] << 8 | lowpan6_buffer[lowpan6_offset + 1]);
        udphdr->dest = htons(0xf000 | lowpan6_buffer[lowpan6_offset + 2]);
        lowpan6_offset += 3;
      } else if (j == 0x02) {
        udphdr->src = htons(0xf000 | lowpan6_buffer[lowpan6_offset]);
        udphdr->dest = htons(lowpan6_buffer[lowpan6_offset + 1] << 8 | lowpan6_buffer[lowpan6_offset + 2]);
        lowpan6_offset += 3;
      } else if (j == 0x03) {
        udphdr->src = htons(0xf0b0 | ((lowpan6_buffer[lowpan6_offset] >> 4) & 0x0f));
        udphdr->dest = htons(0xf0b0 | (lowpan6_buffer[lowpan6_offset] & 0x0f));
        lowpan6_offset += 1;
      }

      udphdr->chksum = htons(lowpan6_buffer[lowpan6_offset] << 8 | lowpan6_buffer[lowpan6_offset + 1]);
      lowpan6_offset += 2;
      udphdr->len = htons(p->tot_len - lowpan6_offset + UDP_HLEN);

      ip6_offset += UDP_HLEN;
    } else {
      LWIP_DEBUGF(LWIP_DBG_ON,("NHC: unsupported protocol!\n"));
      /* @todo support NHC other than UDP */
      pbuf_free(p);
      pbuf_free(q);
      return NULL;
    }
  }

  /* Now we copy leftover contents from p to q, so we have all L2 and L3 headers (and L4?) in a single PBUF.
  * Replace p with q, and free p */
  LWIP_DEBUGF(LWIP_RFC7668_DEBUG|LWIP_RFC7668_DECOMPRESSION_DEBUG,("IPHC decompression completed, copying remains (%d bytes)\n",p->len-lowpan6_offset)); 
  
  MEMCPY((u8_t*)q->payload + ip6_offset, (u8_t *)p->payload + lowpan6_offset, p->len-lowpan6_offset);
  q->len = q->tot_len = ip6_offset + p->len - lowpan6_offset;
  if (p->next != NULL) {
    pbuf_cat(q, p->next);
  }
  p->next = NULL;
  pbuf_free(p);
  /* Infer IPv6 payload length for header */
  IP6H_PLEN_SET(ip6hdr, q->tot_len - IP6_HLEN);

  /* all done */
  return q;
}



/**
 * Process a received raw payload from an L2CAP channel
 *
 * @param p the received packet, p->payload pointing to the
 *        IPv6 header (maybe compressed)
 * @param netif the network interface on which the packet was received
 * 
 * @param src Source address of this packet
 * 
 * @return ERR_OK if everything was fine
 */
err_t
rfc7668_input(struct pbuf * p, struct netif *netif, const ip6_addr_t *src)
{
  u8_t * puc;
  ip6_addr_t dest;

  MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);

  /* Load first header byte */
  puc = (u8_t*)p->payload;
  
  /* no IP header compression */
  if (*puc == 0x41) {
    LWIP_DEBUGF(LWIP_RFC7668_DECOMPRESSION_DEBUG | LWIP_RFC7668_DEBUG, ("Completed packet, removing dispatch: 0x%2x \n", *puc));
    /* This is a complete IPv6 packet, just skip header byte. */
    pbuf_remove_header(p, 1);
  /* IPHC header compression */
  } else if ((*puc & 0xe0 )== 0x60) {
    LWIP_DEBUGF(LWIP_RFC7668_DECOMPRESSION_DEBUG | LWIP_RFC7668_DEBUG, ("Completed packet, decompress dispatch: 0x%2x \n", *puc));
    /* IPv6 headers are compressed using IPHC. */
    p = rfc7668_decompress(p, src, &dest);
    /* if no pbuf is returned, handle as discarded packet */
    if (p == NULL) {
      MIB2_STATS_NETIF_INC(netif, ifindiscards);
      return ERR_OK;
    }
  /* invalid header byte, discard */  
  } else {
    LWIP_DEBUGF(LWIP_RFC7668_DECOMPRESSION_DEBUG | LWIP_RFC7668_DEBUG, ("Completed packet, discarding: 0x%2x \n", *puc));
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
    pbuf_free(p);
    return ERR_OK;
  }
  /* @todo: distinguish unicast/multicast */
  MIB2_STATS_NETIF_INC(netif, ifinucastpkts);

#if LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG==LWIP_DBG_ON
  {
    u16_t i;
    LWIP_DEBUGF(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG | LWIP_RFC7668_DEBUG, ("IPv6 payload:\n"));
    for(i = 0; i<p->len;i++)
    {
      if((i%4)==0) LWIP_DEBUGF(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG | LWIP_RFC7668_DEBUG, ("\n"));
      LWIP_DEBUGF(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG | LWIP_RFC7668_DEBUG, ("%2X ", *((uint8_t *)p->payload+i)));
    }
    LWIP_DEBUGF(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG | LWIP_RFC7668_DEBUG, ("\np->len: %d\n", p->len));
  }
#endif
  /* pass data to ip6_input */
  return ip6_input(p, netif);
}

/**
 * Initialize the netif
 * 
 * No flags are used (broadcast not possible, not ethernet, ...)
 * The shortname for this netif is "BT"
 *
 * @param netif the network interface to be initialized as RFC7668 netif
 * 
 * @return ERR_OK if everything went fine
 */
err_t
rfc7668_if_init(struct netif *netif)
{
  netif->name[0] = 'b';
  netif->name[1] = 't';
  /* if compiled with LWIP_IPV4 -> set IPv4 output to NULL */
#if LWIP_IPV4
  netif->output = NULL;
#endif
  /* local function as IPv6 output */
  netif->output_ip6 = rfc7668_output;

  MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);

  /* maximum transfer unit, set according to RFC7668 ch2.4 */
  netif->mtu = 1280;

  /* no flags set (no broadcast, ethernet,...)*/
  netif->flags = 0;

  /* everything fine */
  return ERR_OK;
}


#if 0 /* TODO: tcpip_inpkt() can not take rfc7668_input as input callback */
/**
 * Pass a received packet to tcpip_thread for input processing
 *
 * @param p the received packet, p->payload pointing to the
 *          IEEE 802.15.4 header.
 * @param inp the network interface on which the packet was received
 * 
 * @return @see tcpip_inpkt , same return values
 */
err_t
tcpip_rfc7668_input(struct pbuf *p, struct netif *inp)
{
  /* send data to upper layer, return the result */
  return tcpip_inpkt(p, inp, rfc7668_input);
}
#endif /* TODO */

#endif /* LWIP_IPV6 && LWIP_RFC7668 */
