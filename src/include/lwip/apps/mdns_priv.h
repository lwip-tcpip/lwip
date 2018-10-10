/**
 * @file
 * MDNS responder private definitions
 */

 /*
 * Copyright (c) 2015 Verisure Innovation AB
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
 * Author: Erik Ekman <erik@kryo.se>
 *
 */
#ifndef LWIP_HDR_MDNS_PRIV_H
#define LWIP_HDR_MDNS_PRIV_H

#include "lwip/apps/mdns.h"
#include "lwip/apps/mdns_opts.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_MDNS_RESPONDER

#define MDNS_DOMAIN_MAXLEN 256
#define MDNS_READNAME_ERROR 0xFFFF
#define NUM_DOMAIN_OFFSETS 10

#define SRV_PRIORITY 0
#define SRV_WEIGHT   0

/* Domain structs - also visible for unit tests */

struct mdns_domain {
  /* Encoded domain name */
  u8_t name[MDNS_DOMAIN_MAXLEN];
  /* Total length of domain name, including zero */
  u16_t length;
  /* Set if compression of this domain is not allowed */
  u8_t skip_compression;
};

/** Description of a service */
struct mdns_service {
  /** TXT record to answer with */
  struct mdns_domain txtdata;
  /** Name of service, like 'myweb' */
  char name[MDNS_LABEL_MAXLEN + 1];
  /** Type of service, like '_http' */
  char service[MDNS_LABEL_MAXLEN + 1];
  /** Callback function and userdata
   * to update txtdata buffer */
  service_get_txt_fn_t txt_fn;
  void *txt_userdata;
  /** TTL in seconds of SRV/TXT replies */
  u32_t dns_ttl;
  /** Protocol, TCP or UDP */
  u16_t proto;
  /** Port of the service */
  u16_t port;
};

/** Description of a host/netif */
struct mdns_host {
  /** Hostname */
  char name[MDNS_LABEL_MAXLEN + 1];
  /** Pointer to services */
  struct mdns_service *services[MDNS_MAX_SERVICES];
  /** TTL in seconds of A/AAAA/PTR replies */
  u32_t dns_ttl;
  /** Number of probes sent for the current name */
  u8_t probes_sent;
  /** State in probing sequence */
  u8_t probing_state;
};

/** mDNS output packet */
struct mdns_outpacket {
  /** Packet data */
  struct pbuf *pbuf;
  /** Current write offset in packet */
  u16_t write_offset;
  /** Number of questions written */
  u16_t questions;
  /** Number of normal answers written */
  u16_t answers;
  /** Number of authoritative answers written */
  u16_t authoritative;
  /** Number of additional answers written */
  u16_t additional;
  /** Offsets for written domain names in packet.
   *  Used for compression */
  u16_t domain_offsets[NUM_DOMAIN_OFFSETS];
};

/** mDNS output message */
struct mdns_outmsg {
  /** Netif to send the packet on */
  struct netif *netif;
  /** Identifier. Used in legacy queries */
  u16_t tx_id;
  /** dns flags */
  u8_t flags;
  /** Destination IP/port if sent unicast */
  ip_addr_t dest_addr;
  u16_t dest_port;
  /** If all answers in packet should set cache_flush bit */
  u8_t cache_flush;
  /** If reply should be sent unicast */
  u8_t unicast_reply;
  /** If legacy query. (tx_id needed, and write
   *  question again in reply before answer) */
  u8_t legacy_query;
  /* Question bitmask for host information */
  u8_t host_questions;
  /* Questions bitmask per service */
  u8_t serv_questions[MDNS_MAX_SERVICES];
  /* Reply bitmask for host information */
  u8_t host_replies;
  /* Bitmask for which reverse IPv6 hosts to answer */
  u8_t host_reverse_v6_replies;
  /* Reply bitmask per service */
  u8_t serv_replies[MDNS_MAX_SERVICES];
};

#endif /* LWIP_MDNS_RESPONDER */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_MDNS_PRIV_H */
