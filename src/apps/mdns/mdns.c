/**
 * @file
 * MDNS responder implementation
 *
 * @defgroup mdns MDNS
 * @ingroup apps
 *
 * RFC 6762 - Multicast DNS\n
 * RFC 6763 - DNS-Based Service Discovery\n
 *
 * @verbinclude mdns.txt
 *
 * Things left to implement:
 * -------------------------
 *
 * - Tiebreaking for simultaneous probing
 * - Correct announcing method
 * - Sending goodbye messages (zero ttl) - shutdown, DHCP lease about to expire, DHCP turned off...
 * - Sending negative responses NSEC
 * - Fragmenting replies if required
 * - Handling multi-packet known answers (TC bit)
 * - Individual known answer detection for all local IPv6 addresses
 * - Dynamic size of outgoing packet
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
 * Author: Jasper Verschueren <jasper.verschueren@apart-audio.com>
 *
 */

#include "lwip/apps/mdns.h"
#include "lwip/apps/mdns_priv.h"
#include "lwip/apps/mdns_domain.h"
#include "lwip/apps/mdns_out.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/mem.h"
#include "lwip/prot/dns.h"
#include "lwip/prot/iana.h"
#include "lwip/timeouts.h"

#include <string.h>

#if LWIP_MDNS_RESPONDER

#if (LWIP_IPV4 && !LWIP_IGMP)
#error "If you want to use MDNS with IPv4, you have to define LWIP_IGMP=1 in your lwipopts.h"
#endif
#if (LWIP_IPV6 && !LWIP_IPV6_MLD)
#error "If you want to use MDNS with IPv6, you have to define LWIP_IPV6_MLD=1 in your lwipopts.h"
#endif
#if (!LWIP_UDP)
#error "If you want to use MDNS, you have to define LWIP_UDP=1 in your lwipopts.h"
#endif
#ifndef LWIP_RAND
#error "If you want to use MDNS, you have to define LWIP_RAND=(random function) in your lwipopts.h"
#endif

#if LWIP_IPV4
#include "lwip/igmp.h"
/* IPv4 multicast group 224.0.0.251 */
static const ip_addr_t v4group = DNS_MQUERY_IPV4_GROUP_INIT;
#endif

#if LWIP_IPV6
#include "lwip/mld6.h"
/* IPv6 multicast group FF02::FB */
static const ip_addr_t v6group = DNS_MQUERY_IPV6_GROUP_INIT;
#endif

#define MDNS_IP_TTL  255


static u8_t mdns_netif_client_id;
static struct udp_pcb *mdns_pcb;
#if MDNS_RESP_USENETIF_EXTCALLBACK
NETIF_DECLARE_EXT_CALLBACK(netif_callback)
#endif
static mdns_name_result_cb_t mdns_name_result_cb;

#define NETIF_TO_HOST(netif) (struct mdns_host*)(netif_get_client_data(netif, mdns_netif_client_id))

/** Delayed response defines */
#define MDNS_RESPONSE_DELAY_MAX   120
#define MDNS_RESPONSE_DELAY_MIN    20
#define MDNS_RESPONSE_DELAY (LWIP_RAND() %(MDNS_RESPONSE_DELAY_MAX - \
                             MDNS_RESPONSE_DELAY_MIN) + MDNS_RESPONSE_DELAY_MIN)

/** Probing defines */
#define MDNS_PROBE_DELAY_MS       250
#define MDNS_PROBE_COUNT          3
#ifdef LWIP_RAND
/* first probe timeout SHOULD be random 0-250 ms*/
#define MDNS_INITIAL_PROBE_DELAY_MS (LWIP_RAND() % MDNS_PROBE_DELAY_MS)
#else
#define MDNS_INITIAL_PROBE_DELAY_MS MDNS_PROBE_DELAY_MS
#endif

#define MDNS_PROBING_NOT_STARTED  0
#define MDNS_PROBING_ONGOING      1
#define MDNS_PROBING_COMPLETE     2

/** Information about received packet */
struct mdns_packet {
  /** Sender IP/port */
  ip_addr_t source_addr;
  u16_t source_port;
  /** If packet was received unicast */
  u16_t recv_unicast;
  /** Packet data */
  struct pbuf *pbuf;
  /** Current parsing offset in packet */
  u16_t parse_offset;
  /** Identifier. Used in legacy queries */
  u16_t tx_id;
  /** Number of questions in packet,
   *  read from packet header */
  u16_t questions;
  /** Number of unparsed questions */
  u16_t questions_left;
  /** Number of answers in packet */
  u16_t answers;
  /** Number of unparsed answers */
  u16_t answers_left;
  /** Number of authoritative answers in packet */
  u16_t authoritative;
  /** Number of unparsed authoritative answers */
  u16_t authoritative_left;
  /** Number of additional answers in packet */
  u16_t additional;
  /** Number of unparsed additional answers */
  u16_t additional_left;
};

/** Domain, type and class.
 *  Shared between questions and answers */
struct mdns_rr_info {
  struct mdns_domain domain;
  u16_t type;
  u16_t klass;
};

struct mdns_question {
  struct mdns_rr_info info;
  /** unicast reply requested */
  u16_t unicast;
};

struct mdns_answer {
  struct mdns_rr_info info;
  /** cache flush command bit */
  u16_t cache_flush;
  /* Validity time in seconds */
  u32_t ttl;
  /** Length of variable answer */
  u16_t rd_length;
  /** Offset of start of variable answer in packet */
  u16_t rd_offset;
};

static void mdns_probe(void* arg);

/**
 *  Construction to make mdns struct accessible from mdns_out.c
 *  TODO:
 *  can we add the mdns struct to the netif like we do for dhcp, autoip,...?
 *  Then this is not needed any more.
 *
 *  @param netif  The network interface
 *  @return       mdns struct
 */
struct mdns_host*
netif_mdns_data(struct netif *netif) {
  return NETIF_TO_HOST(netif);
}

/**
 *  Construction to access the mdns udp pcb.
 *
 *  @return   udp_pcb struct of mdns
 */
struct udp_pcb*
get_mdns_pcb(void)
{
  return mdns_pcb;
}

/**
 * Check which replies we should send for a host/netif based on question
 * @param netif The network interface that received the question
 * @param rr Domain/type/class from a question
 * @param reverse_v6_reply Bitmask of which IPv6 addresses to send reverse PTRs for
 *                         if reply bit has REPLY_HOST_PTR_V6 set
 * @return Bitmask of which replies to send
 */
static int
check_host(struct netif *netif, struct mdns_rr_info *rr, u8_t *reverse_v6_reply)
{
  err_t res;
  int replies = 0;
  struct mdns_domain mydomain;

  LWIP_UNUSED_ARG(reverse_v6_reply); /* if ipv6 is disabled */

  if (rr->klass != DNS_RRCLASS_IN && rr->klass != DNS_RRCLASS_ANY) {
    /* Invalid class */
    return replies;
  }

  /* Handle PTR for our addresses */
  if (rr->type == DNS_RRTYPE_PTR || rr->type == DNS_RRTYPE_ANY) {
#if LWIP_IPV6
    int i;
    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
      if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
        res = mdns_build_reverse_v6_domain(&mydomain, netif_ip6_addr(netif, i));
        if (res == ERR_OK && mdns_domain_eq(&rr->domain, &mydomain)) {
          replies |= REPLY_HOST_PTR_V6;
          /* Mark which addresses where requested */
          if (reverse_v6_reply) {
            *reverse_v6_reply |= (1 << i);
          }
        }
      }
    }
#endif
#if LWIP_IPV4
    if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
      res = mdns_build_reverse_v4_domain(&mydomain, netif_ip4_addr(netif));
      if (res == ERR_OK && mdns_domain_eq(&rr->domain, &mydomain)) {
        replies |= REPLY_HOST_PTR_V4;
      }
    }
#endif
  }

  res = mdns_build_host_domain(&mydomain, NETIF_TO_HOST(netif));
  /* Handle requests for our hostname */
  if (res == ERR_OK && mdns_domain_eq(&rr->domain, &mydomain)) {
    /* TODO return NSEC if unsupported protocol requested */
#if LWIP_IPV4
    if (!ip4_addr_isany_val(*netif_ip4_addr(netif))
        && (rr->type == DNS_RRTYPE_A || rr->type == DNS_RRTYPE_ANY)) {
      replies |= REPLY_HOST_A;
    }
#endif
#if LWIP_IPV6
    if (rr->type == DNS_RRTYPE_AAAA || rr->type == DNS_RRTYPE_ANY) {
      replies |= REPLY_HOST_AAAA;
    }
#endif
  }

  return replies;
}

/**
 * Check which replies we should send for a service based on question
 * @param service A registered MDNS service
 * @param rr Domain/type/class from a question
 * @return Bitmask of which replies to send
 */
static int
check_service(struct mdns_service *service, struct mdns_rr_info *rr)
{
  err_t res;
  int replies = 0;
  struct mdns_domain mydomain;

  if (rr->klass != DNS_RRCLASS_IN && rr->klass != DNS_RRCLASS_ANY) {
    /* Invalid class */
    return 0;
  }

  res = mdns_build_dnssd_domain(&mydomain);
  if (res == ERR_OK && mdns_domain_eq(&rr->domain, &mydomain) &&
      (rr->type == DNS_RRTYPE_PTR || rr->type == DNS_RRTYPE_ANY)) {
    /* Request for all service types */
    replies |= REPLY_SERVICE_TYPE_PTR;
  }

  res = mdns_build_service_domain(&mydomain, service, 0);
  if (res == ERR_OK && mdns_domain_eq(&rr->domain, &mydomain) &&
      (rr->type == DNS_RRTYPE_PTR || rr->type == DNS_RRTYPE_ANY)) {
    /* Request for the instance of my service */
    replies |= REPLY_SERVICE_NAME_PTR;
  }

  res = mdns_build_service_domain(&mydomain, service, 1);
  if (res == ERR_OK && mdns_domain_eq(&rr->domain, &mydomain)) {
    /* Request for info about my service */
    if (rr->type == DNS_RRTYPE_SRV || rr->type == DNS_RRTYPE_ANY) {
      replies |= REPLY_SERVICE_SRV;
    }
    if (rr->type == DNS_RRTYPE_TXT || rr->type == DNS_RRTYPE_ANY) {
      replies |= REPLY_SERVICE_TXT;
    }
  }

  return replies;
}

/**
 * Helper function for mdns_read_question/mdns_read_answer
 * Reads a domain, type and class from the packet
 * @param pkt The MDNS packet to read from. The parse_offset field will be
 *            incremented to point to the next unparsed byte.
 * @param info The struct to fill with domain, type and class
 * @return ERR_OK on success, an err_t otherwise
 */
static err_t
mdns_read_rr_info(struct mdns_packet *pkt, struct mdns_rr_info *info)
{
  u16_t field16, copied;
  pkt->parse_offset = mdns_readname(pkt->pbuf, pkt->parse_offset, &info->domain);
  if (pkt->parse_offset == MDNS_READNAME_ERROR) {
    return ERR_VAL;
  }

  copied = pbuf_copy_partial(pkt->pbuf, &field16, sizeof(field16), pkt->parse_offset);
  if (copied != sizeof(field16)) {
    return ERR_VAL;
  }
  pkt->parse_offset += copied;
  info->type = lwip_ntohs(field16);

  copied = pbuf_copy_partial(pkt->pbuf, &field16, sizeof(field16), pkt->parse_offset);
  if (copied != sizeof(field16)) {
    return ERR_VAL;
  }
  pkt->parse_offset += copied;
  info->klass = lwip_ntohs(field16);

  return ERR_OK;
}

/**
 * Read a question from the packet.
 * All questions have to be read before the answers.
 * @param pkt The MDNS packet to read from. The questions_left field will be decremented
 *            and the parse_offset will be updated.
 * @param question The struct to fill with question data
 * @return ERR_OK on success, an err_t otherwise
 */
static err_t
mdns_read_question(struct mdns_packet *pkt, struct mdns_question *question)
{
  /* Safety check */
  if (pkt->pbuf->tot_len < pkt->parse_offset) {
    return ERR_VAL;
  }

  if (pkt->questions_left) {
    err_t res;
    pkt->questions_left--;

    memset(question, 0, sizeof(struct mdns_question));
    res = mdns_read_rr_info(pkt, &question->info);
    if (res != ERR_OK) {
      return res;
    }

    /* Extract unicast flag from class field */
    question->unicast = question->info.klass & 0x8000;
    question->info.klass &= 0x7FFF;

    return ERR_OK;
  }
  return ERR_VAL;
}

/**
 * Read an answer from the packet
 * The variable length reply is not copied, its pbuf offset and length is stored instead.
 * @param pkt The MDNS packet to read. The num_left field will be decremented and
 *            the parse_offset will be updated.
 * @param answer    The struct to fill with answer data
 * @param num_left  number of answers left -> answers, authoritative or additional
 * @return ERR_OK on success, an err_t otherwise
 */
static err_t
mdns_read_answer(struct mdns_packet *pkt, struct mdns_answer *answer, u16_t *num_left)
{
  /* Read questions first */
  if (pkt->questions_left) {
    return ERR_VAL;
  }

  /* Safety check */
  if (pkt->pbuf->tot_len < pkt->parse_offset) {
    return ERR_VAL;
  }

  if (*num_left) {
    u16_t copied, field16;
    u32_t ttl;
    err_t res;
    (*num_left)--;

    memset(answer, 0, sizeof(struct mdns_answer));
    res = mdns_read_rr_info(pkt, &answer->info);
    if (res != ERR_OK) {
      return res;
    }

    /* Extract cache_flush flag from class field */
    answer->cache_flush = answer->info.klass & 0x8000;
    answer->info.klass &= 0x7FFF;

    copied = pbuf_copy_partial(pkt->pbuf, &ttl, sizeof(ttl), pkt->parse_offset);
    if (copied != sizeof(ttl)) {
      return ERR_VAL;
    }
    pkt->parse_offset += copied;
    answer->ttl = lwip_ntohl(ttl);

    copied = pbuf_copy_partial(pkt->pbuf, &field16, sizeof(field16), pkt->parse_offset);
    if (copied != sizeof(field16)) {
      return ERR_VAL;
    }
    pkt->parse_offset += copied;
    answer->rd_length = lwip_ntohs(field16);

    answer->rd_offset = pkt->parse_offset;
    pkt->parse_offset += answer->rd_length;

    return ERR_OK;
  }
  return ERR_VAL;
}

/**
 * Send unsolicited answer containing all our known data
 * @param netif The network interface to send on
 * @param destination The target address to send to (usually multicast address)
 */
static void
mdns_announce(struct netif *netif, const ip_addr_t *destination)
{
  struct mdns_outmsg announce;
  int i;
  struct mdns_host *mdns = NETIF_TO_HOST(netif);

  memset(&announce, 0, sizeof(announce));
  announce.cache_flush = 1;
#if LWIP_IPV4
  if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    announce.host_replies = REPLY_HOST_A | REPLY_HOST_PTR_V4;
  }
#endif
#if LWIP_IPV6
  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
      announce.host_replies |= REPLY_HOST_AAAA | REPLY_HOST_PTR_V6;
      announce.host_reverse_v6_replies |= (1 << i);
    }
  }
#endif

  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    struct mdns_service *serv = mdns->services[i];
    if (serv) {
      announce.serv_replies[i] = REPLY_SERVICE_TYPE_PTR | REPLY_SERVICE_NAME_PTR |
                                 REPLY_SERVICE_SRV | REPLY_SERVICE_TXT;
    }
  }

  announce.dest_port = LWIP_IANA_PORT_MDNS;
  SMEMCPY(&announce.dest_addr, destination, sizeof(announce.dest_addr));
  announce.flags = DNS_FLAG1_RESPONSE | DNS_FLAG1_AUTHORATIVE;
  mdns_send_outpacket(&announce, netif);
}

/**
 * Check the incomming packet and parse all questions
 *
 * @param netif network interface of incoming packet
 * @param pkt   incoming packet
 * @param reply outgoing message
 * @return err_t
 */
static err_t
mdns_parse_pkt_questions(struct netif *netif, struct mdns_packet *pkt,
                         struct mdns_outmsg *reply)
{
  struct mdns_host *mdns = NETIF_TO_HOST(netif);
  struct mdns_service *service;
  int i;
  err_t res;

  while (pkt->questions_left) {
    struct mdns_question q;

    res = mdns_read_question(pkt, &q);
    if (res != ERR_OK) {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Failed to parse question, skipping query packet\n"));
      return res;
    }

    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Query for domain "));
    mdns_domain_debug_print(&q.info.domain);
    LWIP_DEBUGF(MDNS_DEBUG, (" type %d class %d\n", q.info.type, q.info.klass));

    if (q.unicast) {
      /* Reply unicast if it is requested in the question */
      reply->unicast_reply_requested = 1;
    }

    reply->host_replies |= check_host(netif, &q.info, &reply->host_reverse_v6_replies);

    for (i = 0; i < MDNS_MAX_SERVICES; i++) {
      service = mdns->services[i];
      if (!service) {
        continue;
      }
      reply->serv_replies[i] |= check_service(service, &q.info);
    }
  }

  return ERR_OK;
}

/**
 * Check the incomming packet and parse all (known) answers
 *
 * @param netif network interface of incoming packet
 * @param pkt   incoming packet
 * @param reply outgoing message
 * @return err_t
 */
static err_t
mdns_parse_pkt_known_answers(struct netif *netif, struct mdns_packet *pkt,
                             struct mdns_outmsg *reply)
{
  struct mdns_host *mdns = NETIF_TO_HOST(netif);
  struct mdns_service *service;
  int i;
  err_t res;

  while (pkt->answers_left) {
    struct mdns_answer ans;
    u8_t rev_v6;
    int match;
    u32_t rr_ttl = MDNS_TTL_120;

    res = mdns_read_answer(pkt, &ans, &pkt->answers_left);
    if (res != ERR_OK) {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Failed to parse answer, skipping query packet\n"));
      return res;
    }

    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Known answer for domain "));
    mdns_domain_debug_print(&ans.info.domain);
    LWIP_DEBUGF(MDNS_DEBUG, (" type %d class %d\n", ans.info.type, ans.info.klass));


    if (ans.info.type == DNS_RRTYPE_ANY || ans.info.klass == DNS_RRCLASS_ANY) {
      /* Skip known answers for ANY type & class */
      continue;
    }

    rev_v6 = 0;
    match = reply->host_replies & check_host(netif, &ans.info, &rev_v6);
    if (match && (ans.ttl > (rr_ttl / 2))) {
      /* The RR in the known answer matches an RR we are planning to send,
       * and the TTL is less than half gone.
       * If the payload matches we should not send that answer.
       */
      if (ans.info.type == DNS_RRTYPE_PTR) {
        /* Read domain and compare */
        struct mdns_domain known_ans, my_ans;
        u16_t len;
        len = mdns_readname(pkt->pbuf, ans.rd_offset, &known_ans);
        res = mdns_build_host_domain(&my_ans, mdns);
        if (len != MDNS_READNAME_ERROR && res == ERR_OK && mdns_domain_eq(&known_ans, &my_ans)) {
#if LWIP_IPV4
          if (match & REPLY_HOST_PTR_V4) {
            LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: v4 PTR\n"));
            reply->host_replies &= ~REPLY_HOST_PTR_V4;
          }
#endif
#if LWIP_IPV6
          if (match & REPLY_HOST_PTR_V6) {
            LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: v6 PTR\n"));
            reply->host_reverse_v6_replies &= ~rev_v6;
            if (reply->host_reverse_v6_replies == 0) {
              reply->host_replies &= ~REPLY_HOST_PTR_V6;
            }
          }
#endif
        }
      } else if (match & REPLY_HOST_A) {
#if LWIP_IPV4
        if (ans.rd_length == sizeof(ip4_addr_t) &&
            pbuf_memcmp(pkt->pbuf, ans.rd_offset, netif_ip4_addr(netif), ans.rd_length) == 0) {
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: A\n"));
          reply->host_replies &= ~REPLY_HOST_A;
        }
#endif
      } else if (match & REPLY_HOST_AAAA) {
#if LWIP_IPV6
        if (ans.rd_length == sizeof(ip6_addr_p_t) &&
            /* TODO this clears all AAAA responses if first addr is set as known */
            pbuf_memcmp(pkt->pbuf, ans.rd_offset, netif_ip6_addr(netif, 0), ans.rd_length) == 0) {
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: AAAA\n"));
          reply->host_replies &= ~REPLY_HOST_AAAA;
        }
#endif
      }
    }

    for (i = 0; i < MDNS_MAX_SERVICES; i++) {
      service = mdns->services[i];
      if (!service) {
        continue;
      }
      match = reply->serv_replies[i] & check_service(service, &ans.info);
      if (match & REPLY_SERVICE_TYPE_PTR) {
        rr_ttl = MDNS_TTL_4500;
      }
      if (match && (ans.ttl > (rr_ttl / 2))) {
        /* The RR in the known answer matches an RR we are planning to send,
         * and the TTL is less than half gone.
         * If the payload matches we should not send that answer.
         */
        if (ans.info.type == DNS_RRTYPE_PTR) {
          /* Read domain and compare */
          struct mdns_domain known_ans, my_ans;
          u16_t len;
          len = mdns_readname(pkt->pbuf, ans.rd_offset, &known_ans);
          if (len != MDNS_READNAME_ERROR) {
            if (match & REPLY_SERVICE_TYPE_PTR) {
              res = mdns_build_service_domain(&my_ans, service, 0);
              if (res == ERR_OK && mdns_domain_eq(&known_ans, &my_ans)) {
                LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: service type PTR\n"));
                reply->serv_replies[i] &= ~REPLY_SERVICE_TYPE_PTR;
              }
            }
            if (match & REPLY_SERVICE_NAME_PTR) {
              res = mdns_build_service_domain(&my_ans, service, 1);
              if (res == ERR_OK && mdns_domain_eq(&known_ans, &my_ans)) {
                LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: service name PTR\n"));
                reply->serv_replies[i] &= ~REPLY_SERVICE_NAME_PTR;
              }
            }
          }
        } else if (match & REPLY_SERVICE_SRV) {
          /* Read and compare to my SRV record */
          u16_t field16, len, read_pos;
          struct mdns_domain known_ans, my_ans;
          read_pos = ans.rd_offset;
          do {
            /* Check priority field */
            len = pbuf_copy_partial(pkt->pbuf, &field16, sizeof(field16), read_pos);
            if (len != sizeof(field16) || lwip_ntohs(field16) != SRV_PRIORITY) {
              break;
            }
            read_pos += len;
            /* Check weight field */
            len = pbuf_copy_partial(pkt->pbuf, &field16, sizeof(field16), read_pos);
            if (len != sizeof(field16) || lwip_ntohs(field16) != SRV_WEIGHT) {
              break;
            }
            read_pos += len;
            /* Check port field */
            len = pbuf_copy_partial(pkt->pbuf, &field16, sizeof(field16), read_pos);
            if (len != sizeof(field16) || lwip_ntohs(field16) != service->port) {
              break;
            }
            read_pos += len;
            /* Check host field */
            len = mdns_readname(pkt->pbuf, read_pos, &known_ans);
            mdns_build_host_domain(&my_ans, mdns);
            if (len == MDNS_READNAME_ERROR || !mdns_domain_eq(&known_ans, &my_ans)) {
              break;
            }
            LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: SRV\n"));
            reply->serv_replies[i] &= ~REPLY_SERVICE_SRV;
          } while (0);
        } else if (match & REPLY_SERVICE_TXT) {
          mdns_prepare_txtdata(service);
          if (service->txtdata.length == ans.rd_length &&
              pbuf_memcmp(pkt->pbuf, ans.rd_offset, service->txtdata.name, ans.rd_length) == 0) {
            LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Skipping known answer: TXT\n"));
            reply->serv_replies[i] &= ~REPLY_SERVICE_TXT;
          }
        }
      }
    }
  }

  return ERR_OK;
}

/**
 * Check the incomming packet and parse all authoritative answers to see if the
 * query is a probe query.
 *
 * @param netif network interface of incoming packet
 * @param pkt   incoming packet
 * @param reply outgoing message
 * @return err_t
 */
static err_t
mdns_parse_pkt_authoritative_answers(struct netif *netif, struct mdns_packet *pkt,
                                     struct mdns_outmsg *reply)
{
  struct mdns_host *mdns = NETIF_TO_HOST(netif);
  struct mdns_service *service;
  int i;
  err_t res;

  while (pkt->authoritative_left) {
    struct mdns_answer ans;
    u8_t rev_v6;
    int match;

    res = mdns_read_answer(pkt, &ans, &pkt->authoritative_left);
    if (res != ERR_OK) {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Failed to parse answer, skipping query packet\n"));
      return res;
    }

    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Authoritative answer for domain "));
    mdns_domain_debug_print(&ans.info.domain);
    LWIP_DEBUGF(MDNS_DEBUG, (" type %d class %d\n", ans.info.type, ans.info.klass));


    if (ans.info.type == DNS_RRTYPE_ANY || ans.info.klass == DNS_RRCLASS_ANY) {
      /* Skip known answers for ANY type & class */
      continue;
    }

    rev_v6 = 0;
    match = reply->host_replies & check_host(netif, &ans.info, &rev_v6);
    if (match) {
      reply->probe_query_recv = 1;
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Probe for own host info received\r\n"));
    }

    for (i = 0; i < MDNS_MAX_SERVICES; i++) {
      service = mdns->services[i];
      if (!service) {
        continue;
      }
      match = reply->serv_replies[i] & check_service(service, &ans.info);

      if (match) {
        reply->probe_query_recv = 1;
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Probe for own service info received\r\n"));
      }
    }
  }

  return ERR_OK;
}

/**
 * Add / copy message to delaying message buffer.
 *
 * @param dest destination msg struct
 * @param src  source msg struct
 */
static void
mdns_add_msg_to_delayed(struct mdns_outmsg *dest, struct mdns_outmsg *src)
{
  dest->host_questions |= src->host_questions;
  dest->host_replies |= src->host_replies;
  dest->host_reverse_v6_replies |= src->host_reverse_v6_replies;
  for (int i = 0; i < MDNS_MAX_SERVICES; i++) {
    dest->serv_questions[i] |= src->serv_questions[i];
    dest->serv_replies[i] |= src->serv_replies[i];
  }

  dest->flags = src->flags;
  dest->cache_flush = src->cache_flush;
  dest->tx_id = src->tx_id;
  dest->legacy_query = src->legacy_query;
}

/**
 * Handle question MDNS packet
 * 1. Parse all questions and set bits what answers to send
 * 2. Clear pending answers if known answers are supplied
 * 3. Define which type of answer is requested
 * 4. Send out packet or put it on hold until after random time
 *
 * @param pkt   incoming packet
 * @param netif network interface of incoming packet
 */
static void
mdns_handle_question(struct mdns_packet *pkt, struct netif *netif)
{
  struct mdns_host *mdns = NETIF_TO_HOST(netif);
  struct mdns_outmsg reply;
  u8_t rrs_to_send;
  u8_t shared_answer = 0;
  u8_t delay_response = 1;
  u8_t send_unicast = 0;
  u8_t listen_to_QU_bit = 0;
  int i;
  err_t res;

  if (mdns->probing_state != MDNS_PROBING_COMPLETE) {
    /* Don't answer questions until we've verified our domains via probing */
    /* @todo we should check incoming questions during probing for tiebreaking */
    return;
  }

  memset(&reply, 0, sizeof(struct mdns_outmsg));

  /* Parse question */
  res = mdns_parse_pkt_questions(netif, pkt, &reply);
  if (res != ERR_OK) {
    return;
  }
  /* Parse answers -> count as known answers because it's a question */
  res = mdns_parse_pkt_known_answers(netif, pkt, &reply);
  if (res != ERR_OK) {
    return;
  }
  /* Parse authoritative answers -> probing */
  /* If it's a probe query, we need to directly answer via unicast. */
  res = mdns_parse_pkt_authoritative_answers(netif, pkt, &reply);
  if (res != ERR_OK) {
    return;
  }
  /* Ignore additional answers -> do not have any need for them at the moment */
  if(pkt->additional) {
    LWIP_DEBUGF(MDNS_DEBUG,
      ("MDNS: Query contains additional answers -> they are discarded \r\n"));
  }

  /* Any replies on question? */
  rrs_to_send = reply.host_replies | reply.host_questions;
  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    rrs_to_send |= reply.serv_replies[i] | reply.serv_questions[i];
  }

  if (!rrs_to_send) {
    /* This case is most common */
    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Nothing to answer\r\n"));
    return;
  }

  reply.flags =  DNS_FLAG1_RESPONSE | DNS_FLAG1_AUTHORATIVE;

  /* Detect if it's a legacy querier asking the question
   * How to detect legacy DNS query? (RFC6762 section 6.7)
   *  - source port != 5353
   *  - a legacy query can only contain 1 question
   */
  if (pkt->source_port != LWIP_IANA_PORT_MDNS) {
    if (pkt->questions == 1) {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: request from legacy querier\r\n"));
      reply.legacy_query = 1;
      reply.tx_id = pkt->tx_id;
      reply.cache_flush = 0;
    }
    else {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: ignore query if (src UDP port != 5353) && (!= legacy query)\r\n"));
      return;
    }
  }
  else {
    reply.cache_flush = 1;
  }

  /* Delaying response.
   * Always delay the response, unicast or multicast, except when:
   *  - Answering to a single question with a unique answer (RFC6762 section 6)
   *  - Answering to a probe query via unicast (RFC6762 section 6)
   *
   * unique answer? -> not if it includes service type or name ptr's
   */
  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    shared_answer |= (reply.serv_replies[i] &
                      (REPLY_SERVICE_TYPE_PTR | REPLY_SERVICE_NAME_PTR));
  }
  if (((pkt->questions == 1) && (!shared_answer)) || reply.probe_query_recv) {
    delay_response = 0;
  }
  LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: response %s delayed\r\n", (delay_response ? "randomly" : "not")));

  /* Unicast / multicast response:
   * Answering to (m)DNS querier via unicast response.
   * When:
   *  a) Unicast reply requested && recently multicasted 1/4ttl (RFC6762 section 5.4)
   *  b) Direct unicast query to port 5353 (RFC6762 section 5.5)
   *  c) Reply to Legacy DNS querier (RFC6762 section 6.7)
   *  d) A probe message is received (RFC6762 section 6)
   */

#if LWIP_IPV6
  if ((IP_IS_V6_VAL(pkt->source_addr) && mdns->ipv6.multicast_timeout_25TTL)) {
    listen_to_QU_bit = 1;
  }
#endif
#if LWIP_IPV4
  if ((IP_IS_V4_VAL(pkt->source_addr) && mdns->ipv4.multicast_timeout_25TTL)) {
    listen_to_QU_bit = 1;
  }
#endif
  if (   (reply.unicast_reply_requested && listen_to_QU_bit)
      || pkt->recv_unicast
      || reply.legacy_query
      || reply.probe_query_recv ) {
    send_unicast = 1;
  }
  LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: send response via %s\r\n", (send_unicast ? "unicast" : "multicast")));

  /* Send out or put on waiting list */
  if (delay_response) {
    if (send_unicast) {
#if LWIP_IPV6
      /* Add answers to IPv6 waiting list if:
       *  - it's a IPv6 incoming packet
       *  - no message is in it yet
       */
      if (IP_IS_V6_VAL(pkt->source_addr) && !mdns->ipv6.unicast_msg_in_use) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: add answers to unicast IPv6 waiting list\r\n"));
        SMEMCPY(&mdns->ipv6.delayed_msg_unicast.dest_addr, &pkt->source_addr, sizeof(ip_addr_t));
        mdns->ipv6.delayed_msg_unicast.dest_port = pkt->source_port;

        mdns_add_msg_to_delayed(&mdns->ipv6.delayed_msg_unicast, &reply);

        mdns_set_timeout(netif, MDNS_RESPONSE_DELAY, mdns_send_unicast_msg_delayed_ipv6,
                         &mdns->ipv6.unicast_msg_in_use);
      }
#endif
#if LWIP_IPV4
      /* Add answers to IPv4 waiting list if:
       *  - it's a IPv4 incoming packet
       *  - no message is in it yet
       */
      if (IP_IS_V4_VAL(pkt->source_addr) && !mdns->ipv4.unicast_msg_in_use) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: add answers to unicast IPv4 waiting list\r\n"));
        SMEMCPY(&mdns->ipv4.delayed_msg_unicast.dest_addr, &pkt->source_addr, sizeof(ip_addr_t));
        mdns->ipv4.delayed_msg_unicast.dest_port = pkt->source_port;

        mdns_add_msg_to_delayed(&mdns->ipv4.delayed_msg_unicast, &reply);

        mdns_set_timeout(netif, MDNS_RESPONSE_DELAY, mdns_send_unicast_msg_delayed_ipv4,
                         &mdns->ipv4.unicast_msg_in_use);
      }
#endif
    }
    else {
#if LWIP_IPV6
      /* Add answers to IPv6 waiting list if:
       *  - it's a IPv6 incoming packet
       *  - and the 1 second timeout is passed (RFC6762 section 6)
       */
      if (IP_IS_V6_VAL(pkt->source_addr) && !mdns->ipv6.multicast_timeout) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: add answers to multicast IPv6 waiting list\r\n"));

        mdns_add_msg_to_delayed(&mdns->ipv6.delayed_msg_multicast, &reply);

        mdns_set_timeout(netif, MDNS_RESPONSE_DELAY, mdns_send_multicast_msg_delayed_ipv6,
                         &mdns->ipv6.multicast_msg_waiting);
      }
#endif
#if LWIP_IPV4
      /* Add answers to IPv4 waiting list if:
       *  - it's a IPv4 incoming packet
       *  - and the 1 second timeout is passed (RFC6762 section 6)
       */
      if (IP_IS_V4_VAL(pkt->source_addr) && !mdns->ipv4.multicast_timeout) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: add answers to multicast IPv4 waiting list\r\n"));

        mdns_add_msg_to_delayed(&mdns->ipv4.delayed_msg_multicast, &reply);

        mdns_set_timeout(netif, MDNS_RESPONSE_DELAY, mdns_send_multicast_msg_delayed_ipv4,
                         &mdns->ipv4.multicast_msg_waiting);
      }
#endif
    }
  }
  else {
    if (send_unicast) {
      /* Copy source IP/port to use when responding unicast */
      SMEMCPY(&reply.dest_addr, &pkt->source_addr, sizeof(ip_addr_t));
      reply.dest_port = pkt->source_port;
      /* send answer directly via unicast */
      res = mdns_send_outpacket(&reply, netif);
      if (res != ERR_OK) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Unicast answer could not be send\r\n"));
      }
      else {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Unicast answer send successfully\r\n"));
      }
      return;
    }
    else {
      /* Set IP/port to use when responding multicast */
#if LWIP_IPV6
      if (IP_IS_V6_VAL(pkt->source_addr)) {
        if (mdns->ipv6.multicast_timeout) {
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: we just multicasted, ignore question\r\n"));
          return;
        }
        SMEMCPY(&reply.dest_addr, &v6group, sizeof(ip_addr_t));
      }
#endif
#if LWIP_IPV4
      if (IP_IS_V4_VAL(pkt->source_addr)) {
        if (mdns->ipv4.multicast_timeout) {
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: we just multicasted, ignore question\r\n"));
          return;
        }
        SMEMCPY(&reply.dest_addr, &v4group, sizeof(ip_addr_t));
      }
#endif
      reply.dest_port = LWIP_IANA_PORT_MDNS;
      /* send answer directly via multicast */
      res = mdns_send_outpacket(&reply, netif);
      if (res != ERR_OK) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Multicast answer could not be send\r\n"));
      }
      else {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Multicast answer send successfully\r\n"));
#if LWIP_IPV6
        if (IP_IS_V6_VAL(pkt->source_addr)) {
          mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT, mdns_multicast_timeout_reset_ipv6,
                           &mdns->ipv6.multicast_timeout);
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout started - IPv6\n"));
          mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT_25TTL, mdns_multicast_timeout_25ttl_reset_ipv6,
                           &mdns->ipv6.multicast_timeout_25TTL);
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout 1/4 of ttl started - IPv6\n"));
        }
#endif
#if LWIP_IPV4
        if (IP_IS_V4_VAL(pkt->source_addr)) {
          mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT, mdns_multicast_timeout_reset_ipv4,
                           &mdns->ipv4.multicast_timeout);
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout started - IPv4\n"));
          mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT_25TTL, mdns_multicast_timeout_25ttl_reset_ipv4,
                           &mdns->ipv4.multicast_timeout_25TTL);
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout 1/4 of ttl started - IPv4\n"));
        }
#endif
      }
      return;
    }
  }
}

/**
 * Handle response MDNS packet
 * Only prints debug for now. Will need more code to do conflict resolution.
 */
static void
mdns_handle_response(struct mdns_packet *pkt, struct netif *netif)
{
  struct mdns_host* mdns = NETIF_TO_HOST(netif);

  /* Ignore all questions */
  while (pkt->questions_left) {
    struct mdns_question q;
    err_t res;

    res = mdns_read_question(pkt, &q);
    if (res != ERR_OK) {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Failed to parse question, skipping response packet\n"));
      return;
    }
  }

  while (pkt->answers_left) {
    struct mdns_answer ans;
    err_t res;

    res = mdns_read_answer(pkt, &ans, &pkt->answers_left);
    if (res != ERR_OK) {
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Failed to parse answer, skipping response packet\n"));
      return;
    }

    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Answer for domain "));
    mdns_domain_debug_print(&ans.info.domain);
    LWIP_DEBUGF(MDNS_DEBUG, (" type %d class %d\n", ans.info.type, ans.info.klass));

    /*"Apparently conflicting Multicast DNS responses received *before* the first probe packet is sent MUST
      be silently ignored" so drop answer if we haven't started probing yet*/
    if ((mdns->probing_state == MDNS_PROBING_ONGOING) && (mdns->probes_sent > 0)) {
      struct mdns_domain domain;
      u8_t i;
      u8_t conflict = 0;

      res = mdns_build_host_domain(&domain, mdns);
      if (res == ERR_OK && mdns_domain_eq(&ans.info.domain, &domain)) {
        LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Probe response matches host domain!"));
        conflict = 1;
      }

      for (i = 0; i < MDNS_MAX_SERVICES; i++) {
        struct mdns_service* service = mdns->services[i];
        if (!service) {
          continue;
        }
        res = mdns_build_service_domain(&domain, service, 1);
        if ((res == ERR_OK) && mdns_domain_eq(&ans.info.domain, &domain)) {
          LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Probe response matches service domain!"));
          conflict = 1;
        }
      }

      if (conflict != 0) {
        sys_untimeout(mdns_probe, netif);
        if (mdns_name_result_cb != NULL) {
          mdns_name_result_cb(netif, MDNS_PROBING_CONFLICT);
        }
      }
    }
  }
}

/**
 * Receive input function for MDNS packets.
 * Handles both IPv4 and IPv6 UDP pcbs.
 */
static void
mdns_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  struct dns_hdr hdr;
  struct mdns_packet packet;
  struct netif *recv_netif = ip_current_input_netif();
  u16_t offset = 0;

  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(pcb);

  LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: Received IPv%d MDNS packet, len %d\n", IP_IS_V6(addr) ? 6 : 4, p->tot_len));

  if (NETIF_TO_HOST(recv_netif) == NULL) {
    /* From netif not configured for MDNS */
    goto dealloc;
  }

  if (pbuf_copy_partial(p, &hdr, SIZEOF_DNS_HDR, offset) < SIZEOF_DNS_HDR) {
    /* Too small */
    goto dealloc;
  }
  offset += SIZEOF_DNS_HDR;

  if (DNS_HDR_GET_OPCODE(&hdr)) {
    /* Ignore non-standard queries in multicast packets (RFC 6762, section 18.3) */
    goto dealloc;
  }

  memset(&packet, 0, sizeof(packet));
  SMEMCPY(&packet.source_addr, addr, sizeof(packet.source_addr));
  packet.source_port = port;
  packet.pbuf = p;
  packet.parse_offset = offset;
  packet.tx_id = lwip_ntohs(hdr.id);
  packet.questions = packet.questions_left = lwip_ntohs(hdr.numquestions);
  packet.answers = packet.answers_left = lwip_ntohs(hdr.numanswers);
  packet.authoritative = packet.authoritative_left = lwip_ntohs(hdr.numauthrr);
  packet.additional = packet.additional_left = lwip_ntohs(hdr.numextrarr);

  /*  Source address check (RFC6762 section 11) -> for responses.
   *  Source address check (RFC6762 section 5.5) -> for queries.
   *  When the dest addr == multicast addr we know the packet originated on that
   *  link. If not, we need to check the source address. We only accept queries
   *  that originated on the link. Others are discarded.
   */
#if LWIP_IPV6
  if (IP_IS_V6(ip_current_dest_addr())) {
    /* instead of having one 'v6group' per netif, just compare zoneless here */
    if (!ip_addr_cmp_zoneless(ip_current_dest_addr(), &v6group)) {
      packet.recv_unicast = 1;

      if (ip6_addr_ismulticast_global(ip_2_ip6(ip_current_src_addr()))
          || ip6_addr_isglobal(ip_2_ip6(ip_current_src_addr()))) {
        goto dealloc;
      }
    }
  }
#endif
#if LWIP_IPV4
  if (!IP_IS_V6(ip_current_dest_addr())) {
    if (!ip_addr_cmp(ip_current_dest_addr(), &v4group)) {
      packet.recv_unicast = 1;

      if (!ip4_addr_netcmp(ip_2_ip4(ip_current_src_addr()),
                          netif_ip4_addr(recv_netif),
                          netif_ip4_netmask(recv_netif))){
           goto dealloc;
         }
    }
  }
#endif

  if (hdr.flags1 & DNS_FLAG1_RESPONSE) {
    mdns_handle_response(&packet, recv_netif);
  } else {
    mdns_handle_question(&packet, recv_netif);
  }

dealloc:
  pbuf_free(p);
}

#if LWIP_NETIF_EXT_STATUS_CALLBACK && MDNS_RESP_USENETIF_EXTCALLBACK
static void
mdns_netif_ext_status_callback(struct netif *netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t *args)
{
  LWIP_UNUSED_ARG(args);

  /* MDNS enabled on netif? */
  if (NETIF_TO_HOST(netif) == NULL) {
    return;
  }

  if (reason & LWIP_NSC_STATUS_CHANGED) {
    if (args->status_changed.state != 0) {
      mdns_resp_restart(netif);
    }
    /* TODO: send goodbye message */
  }
  if (reason & LWIP_NSC_LINK_CHANGED) {
    if (args->link_changed.state != 0) {
      mdns_resp_restart(netif);
    }
  }
  if (reason & (LWIP_NSC_IPV4_ADDRESS_CHANGED | LWIP_NSC_IPV4_GATEWAY_CHANGED |
      LWIP_NSC_IPV4_NETMASK_CHANGED | LWIP_NSC_IPV4_SETTINGS_CHANGED |
      LWIP_NSC_IPV6_SET | LWIP_NSC_IPV6_ADDR_STATE_CHANGED)) {
    mdns_resp_announce(netif);
  }
}
#endif /* LWIP_NETIF_EXT_STATUS_CALLBACK && MDNS_RESP_USENETIF_EXTCALLBACK */

static err_t
mdns_send_probe(struct netif* netif, const ip_addr_t *destination)
{
  struct mdns_host* mdns;
  struct mdns_outmsg outmsg;
  u8_t i;
  err_t res;

  mdns = NETIF_TO_HOST(netif);

  memset(&outmsg, 0, sizeof(outmsg));

  /* Add unicast questions with rtype ANY for all our desired records */
  outmsg.host_questions = QUESTION_PROBE_HOST_ANY;

  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    struct mdns_service* service = mdns->services[i];
    if (!service) {
      continue;
    }
    outmsg.serv_questions[i] = QUESTION_PROBE_SERVICE_NAME_ANY;
  }

  /* Add answers to the questions above into the authority section for tiebreaking */
#if LWIP_IPV4
  if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    outmsg.host_replies = REPLY_HOST_A | REPLY_HOST_PTR_V4;
  }
#endif
#if LWIP_IPV6
  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
      outmsg.host_replies |= REPLY_HOST_AAAA | REPLY_HOST_PTR_V6;
      outmsg.host_reverse_v6_replies |= (1 << i);
    }
  }
#endif

  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    struct mdns_service *serv = mdns->services[i];
    if (serv) {
      outmsg.serv_replies[i] = REPLY_SERVICE_SRV | REPLY_SERVICE_TXT
                            | REPLY_SERVICE_TYPE_PTR | REPLY_SERVICE_NAME_PTR;
    }
  }

  outmsg.tx_id = 0;
  outmsg.dest_port = LWIP_IANA_PORT_MDNS;
  SMEMCPY(&outmsg.dest_addr, destination, sizeof(outmsg.dest_addr));
  res = mdns_send_outpacket(&outmsg, netif);

  return res;
}

/**
 * Timer callback for probing network.
 */
static void
mdns_probe(void* arg)
{
  struct netif *netif = (struct netif *)arg;
  struct mdns_host* mdns = NETIF_TO_HOST(netif);

  if(mdns->probes_sent >= MDNS_PROBE_COUNT) {
    /* probing successful, announce the new name */
    mdns->probing_state = MDNS_PROBING_COMPLETE;
    mdns_resp_announce(netif);
    if (mdns_name_result_cb != NULL) {
      mdns_name_result_cb(netif, MDNS_PROBING_SUCCESSFUL);
    }
  } else {
#if LWIP_IPV4
    /*if ipv4 wait with probing until address is set*/
    if (!ip4_addr_isany_val(*netif_ip4_addr(netif)) &&
        mdns_send_probe(netif, &v4group) == ERR_OK)
#endif
    {
#if LWIP_IPV6
      if (mdns_send_probe(netif, &v6group) == ERR_OK)
#endif
      {
        mdns->probes_sent++;
      }
    }
    sys_timeout(MDNS_PROBE_DELAY_MS, mdns_probe, netif);
  }
}

/**
 * @ingroup mdns
 * Activate MDNS responder for a network interface.
 * @param netif The network interface to activate.
 * @param hostname Name to use. Queries for &lt;hostname&gt;.local will be answered
 *                 with the IP addresses of the netif. The hostname will be copied, the
 *                 given pointer can be on the stack.
 * @return ERR_OK if netif was added, an err_t otherwise
 */
err_t
mdns_resp_add_netif(struct netif *netif, const char *hostname)
{
  err_t res;
  struct mdns_host *mdns;

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ERROR("mdns_resp_add_netif: netif != NULL", (netif != NULL), return ERR_VAL);
  LWIP_ERROR("mdns_resp_add_netif: Hostname too long", (strlen(hostname) <= MDNS_LABEL_MAXLEN), return ERR_VAL);

  LWIP_ASSERT("mdns_resp_add_netif: Double add", NETIF_TO_HOST(netif) == NULL);
  mdns = (struct mdns_host *) mem_calloc(1, sizeof(struct mdns_host));
  LWIP_ERROR("mdns_resp_add_netif: Alloc failed", (mdns != NULL), return ERR_MEM);

  netif_set_client_data(netif, mdns_netif_client_id, mdns);

  MEMCPY(&mdns->name, hostname, LWIP_MIN(MDNS_LABEL_MAXLEN, strlen(hostname)));
  mdns->probes_sent = 0;
  mdns->probing_state = MDNS_PROBING_NOT_STARTED;

  /* Init delayed message structs with address and port */
#if LWIP_IPV4
  mdns->ipv4.delayed_msg_multicast.dest_port = LWIP_IANA_PORT_MDNS;
  SMEMCPY(&mdns->ipv4.delayed_msg_multicast.dest_addr, &v4group,
            sizeof(ip_addr_t));
#endif

#if LWIP_IPV6
  mdns->ipv6.delayed_msg_multicast.dest_port = LWIP_IANA_PORT_MDNS;
  SMEMCPY(&mdns->ipv6.delayed_msg_multicast.dest_addr, &v6group,
            sizeof(ip_addr_t));
#endif

  /* Join multicast groups */
#if LWIP_IPV4
  res = igmp_joingroup_netif(netif, ip_2_ip4(&v4group));
  if (res != ERR_OK) {
    goto cleanup;
  }
#endif
#if LWIP_IPV6
  res = mld6_joingroup_netif(netif, ip_2_ip6(&v6group));
  if (res != ERR_OK) {
    goto cleanup;
  }
#endif

  mdns_resp_restart(netif);

  return ERR_OK;

cleanup:
  mem_free(mdns);
  netif_set_client_data(netif, mdns_netif_client_id, NULL);
  return res;
}

/**
 * @ingroup mdns
 * Stop responding to MDNS queries on this interface, leave multicast groups,
 * and free the helper structure and any of its services.
 * @param netif The network interface to remove.
 * @return ERR_OK if netif was removed, an err_t otherwise
 */
err_t
mdns_resp_remove_netif(struct netif *netif)
{
  int i;
  struct mdns_host *mdns;

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("mdns_resp_remove_netif: Null pointer", netif);
  mdns = NETIF_TO_HOST(netif);
  LWIP_ERROR("mdns_resp_remove_netif: Not an active netif", (mdns != NULL), return ERR_VAL);

  if (mdns->probing_state == MDNS_PROBING_ONGOING) {
    sys_untimeout(mdns_probe, netif);
  }

  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    struct mdns_service *service = mdns->services[i];
    if (service) {
      mem_free(service);
    }
  }

  /* Leave multicast groups */
#if LWIP_IPV4
  igmp_leavegroup_netif(netif, ip_2_ip4(&v4group));
#endif
#if LWIP_IPV6
  mld6_leavegroup_netif(netif, ip_2_ip6(&v6group));
#endif

  mem_free(mdns);
  netif_set_client_data(netif, mdns_netif_client_id, NULL);
  return ERR_OK;
}

/**
 * @ingroup mdns
 * Update MDNS hostname for a network interface.
 * @param netif The network interface to activate.
 * @param hostname Name to use. Queries for &lt;hostname&gt;.local will be answered
 *                 with the IP addresses of the netif. The hostname will be copied, the
 *                 given pointer can be on the stack.
 * @return ERR_OK if name could be set on netif, an err_t otherwise
 */
err_t
mdns_resp_rename_netif(struct netif *netif, const char *hostname)
{
  struct mdns_host *mdns;
  size_t len;

  LWIP_ASSERT_CORE_LOCKED();
  len = strlen(hostname);
  LWIP_ERROR("mdns_resp_rename_netif: netif != NULL", (netif != NULL), return ERR_VAL);
  LWIP_ERROR("mdns_resp_rename_netif: Hostname too long", (len <= MDNS_LABEL_MAXLEN), return ERR_VAL);
  mdns = NETIF_TO_HOST(netif);
  LWIP_ERROR("mdns_resp_rename_netif: Not an mdns netif", (mdns != NULL), return ERR_VAL);

  MEMCPY(&mdns->name, hostname, LWIP_MIN(MDNS_LABEL_MAXLEN, len));
  mdns->name[len] = '\0'; /* null termination in case new name is shorter than previous */

  mdns_resp_restart(netif);

  return ERR_OK;
}

/**
 * @ingroup mdns
 * Add a service to the selected network interface.
 * @param netif The network interface to publish this service on
 * @param name The name of the service
 * @param service The service type, like "_http"
 * @param proto The service protocol, DNSSD_PROTO_TCP for TCP ("_tcp") and DNSSD_PROTO_UDP
 *              for others ("_udp")
 * @param port The port the service listens to
 * @param txt_fn Callback to get TXT data. Will be called each time a TXT reply is created to
 *               allow dynamic replies.
 * @param txt_data Userdata pointer for txt_fn
 * @return service_id if the service was added to the netif, an err_t otherwise
 */
s8_t
mdns_resp_add_service(struct netif *netif, const char *name, const char *service, enum mdns_sd_proto proto, u16_t port, service_get_txt_fn_t txt_fn, void *txt_data)
{
  s8_t i;
  s8_t slot = -1;
  struct mdns_service *srv;
  struct mdns_host *mdns;

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("mdns_resp_add_service: netif != NULL", netif);
  mdns = NETIF_TO_HOST(netif);
  LWIP_ERROR("mdns_resp_add_service: Not an mdns netif", (mdns != NULL), return ERR_VAL);

  LWIP_ERROR("mdns_resp_add_service: Name too long", (strlen(name) <= MDNS_LABEL_MAXLEN), return ERR_VAL);
  LWIP_ERROR("mdns_resp_add_service: Service too long", (strlen(service) <= MDNS_LABEL_MAXLEN), return ERR_VAL);
  LWIP_ERROR("mdns_resp_add_service: Bad proto (need TCP or UDP)", (proto == DNSSD_PROTO_TCP || proto == DNSSD_PROTO_UDP), return ERR_VAL);

  for (i = 0; i < MDNS_MAX_SERVICES; i++) {
    if (mdns->services[i] == NULL) {
      slot = i;
      break;
    }
  }
  LWIP_ERROR("mdns_resp_add_service: Service list full (increase MDNS_MAX_SERVICES)", (slot >= 0), return ERR_MEM);

  srv = (struct mdns_service *)mem_calloc(1, sizeof(struct mdns_service));
  LWIP_ERROR("mdns_resp_add_service: Alloc failed", (srv != NULL), return ERR_MEM);

  MEMCPY(&srv->name, name, LWIP_MIN(MDNS_LABEL_MAXLEN, strlen(name)));
  MEMCPY(&srv->service, service, LWIP_MIN(MDNS_LABEL_MAXLEN, strlen(service)));
  srv->txt_fn = txt_fn;
  srv->txt_userdata = txt_data;
  srv->proto = (u16_t)proto;
  srv->port = port;

  mdns->services[slot] = srv;

  mdns_resp_restart(netif);

  return slot;
}

/**
 * @ingroup mdns
 * Delete a service on the selected network interface.
 * @param netif The network interface on which service should be removed
 * @param slot The service slot number returned by mdns_resp_add_service
 * @return ERR_OK if the service was removed from the netif, an err_t otherwise
 */
err_t
mdns_resp_del_service(struct netif *netif, s8_t slot)
{
  struct mdns_host *mdns;
  struct mdns_service *srv;
  LWIP_ASSERT("mdns_resp_del_service: netif != NULL", netif);
  mdns = NETIF_TO_HOST(netif);
  LWIP_ERROR("mdns_resp_del_service: Not an mdns netif", (mdns != NULL), return ERR_VAL);
  LWIP_ERROR("mdns_resp_del_service: Invalid Service ID", (slot >= 0) && (slot < MDNS_MAX_SERVICES), return ERR_VAL);
  LWIP_ERROR("mdns_resp_del_service: Invalid Service ID", (mdns->services[slot] != NULL), return ERR_VAL);

  srv = mdns->services[slot];
  mdns->services[slot] = NULL;
  mem_free(srv);
  return ERR_OK;
}

/**
 * @ingroup mdns
 * Update name for an MDNS service.
 * @param netif The network interface to activate.
 * @param slot The service slot number returned by mdns_resp_add_service
 * @param name The new name for the service
 * @return ERR_OK if name could be set on service, an err_t otherwise
 */
err_t
mdns_resp_rename_service(struct netif *netif, s8_t slot, const char *name)
{
  struct mdns_service *srv;
  struct mdns_host *mdns;
  size_t len;

  LWIP_ASSERT_CORE_LOCKED();
  len = strlen(name);
  LWIP_ASSERT("mdns_resp_rename_service: netif != NULL", netif);
  mdns = NETIF_TO_HOST(netif);
  LWIP_ERROR("mdns_resp_rename_service: Not an mdns netif", (mdns != NULL), return ERR_VAL);
  LWIP_ERROR("mdns_resp_rename_service: Name too long", (len <= MDNS_LABEL_MAXLEN), return ERR_VAL);
  LWIP_ERROR("mdns_resp_rename_service: Invalid Service ID", (slot >= 0) && (slot < MDNS_MAX_SERVICES), return ERR_VAL);
  LWIP_ERROR("mdns_resp_rename_service: Invalid Service ID", (mdns->services[slot] != NULL), return ERR_VAL);

  srv = mdns->services[slot];

  MEMCPY(&srv->name, name, LWIP_MIN(MDNS_LABEL_MAXLEN, len));
  srv->name[len] = '\0'; /* null termination in case new name is shorter than previous */

  mdns_resp_restart(netif);

  return ERR_OK;
}

/**
 * @ingroup mdns
 * Call this function from inside the service_get_txt_fn_t callback to add text data.
 * Buffer for TXT data is 256 bytes, and each field is prefixed with a length byte.
 * @param service The service provided to the get_txt callback
 * @param txt String to add to the TXT field.
 * @param txt_len Length of string
 * @return ERR_OK if the string was added to the reply, an err_t otherwise
 */
err_t
mdns_resp_add_service_txtitem(struct mdns_service *service, const char *txt, u8_t txt_len)
{
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("mdns_resp_add_service_txtitem: service != NULL", service);

  /* Use a mdns_domain struct to store txt chunks since it is the same encoding */
  return mdns_domain_add_label(&service->txtdata, txt, txt_len);
}

/**
 * @ingroup mdns
 * Send unsolicited answer containing all our known data
 * @param netif The network interface to send on
 */
void
mdns_resp_announce(struct netif *netif)
{
  struct mdns_host* mdns;
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ERROR("mdns_resp_announce: netif != NULL", (netif != NULL), return);

  mdns = NETIF_TO_HOST(netif);
  if (mdns == NULL) {
    return;
  }

  if (mdns->probing_state == MDNS_PROBING_COMPLETE) {
    /* Announce on IPv6 and IPv4 */
#if LWIP_IPV6
    mdns_announce(netif, &v6group);
    mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT, mdns_multicast_timeout_reset_ipv6,
                     &mdns->ipv6.multicast_timeout);
    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout started - IPv6\n"));
    mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT_25TTL, mdns_multicast_timeout_25ttl_reset_ipv6,
                     &mdns->ipv6.multicast_timeout_25TTL);
    LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout 1/4 of ttl started - IPv6\n"));
#endif
#if LWIP_IPV4
    if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
      mdns_announce(netif, &v4group);
      mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT, mdns_multicast_timeout_reset_ipv4,
                       &mdns->ipv4.multicast_timeout);
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout started - IPv4\n"));
      mdns_set_timeout(netif, MDNS_MULTICAST_TIMEOUT_25TTL, mdns_multicast_timeout_25ttl_reset_ipv4,
                       &mdns->ipv4.multicast_timeout_25TTL);
      LWIP_DEBUGF(MDNS_DEBUG, ("MDNS: multicast timeout 1/4 of ttl started - IPv4\n"));
    }
#endif
  } /* else: ip address changed while probing was ongoing? @todo reset counter to restart? */
}

/** Register a callback function that is called if probing is completed successfully
 * or with a conflict. */
void
mdns_resp_register_name_result_cb(mdns_name_result_cb_t cb)
{
  mdns_name_result_cb = cb;
}

/**
 * @ingroup mdns
 * Restart mdns responder. Call this when cable is connected after being disconnected or
 * administrative interface is set up after being down
 * @param netif The network interface to send on
 */
void
mdns_resp_restart(struct netif *netif)
{
  struct mdns_host* mdns;
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ERROR("mdns_resp_restart: netif != NULL", (netif != NULL), return);

  mdns = NETIF_TO_HOST(netif);
  if (mdns == NULL) {
    return;
  }

  if (mdns->probing_state == MDNS_PROBING_ONGOING) {
    sys_untimeout(mdns_probe, netif);
  }
  /* @todo if we've failed 15 times within a 10 second period we MUST wait 5 seconds (or wait 5 seconds every time except first)*/
  mdns->probes_sent = 0;
  mdns->probing_state = MDNS_PROBING_ONGOING;
  sys_timeout(MDNS_INITIAL_PROBE_DELAY_MS, mdns_probe, netif);
}

/**
 * @ingroup mdns
 * Initiate MDNS responder. Will open UDP sockets on port 5353
 */
void
mdns_resp_init(void)
{
  err_t res;

  /* LWIP_ASSERT_CORE_LOCKED(); is checked by udp_new() */

  mdns_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
  LWIP_ASSERT("Failed to allocate pcb", mdns_pcb != NULL);
#if LWIP_MULTICAST_TX_OPTIONS
  udp_set_multicast_ttl(mdns_pcb, MDNS_IP_TTL);
#else
  mdns_pcb->ttl = MDNS_IP_TTL;
#endif
  res = udp_bind(mdns_pcb, IP_ANY_TYPE, LWIP_IANA_PORT_MDNS);
  LWIP_UNUSED_ARG(res); /* in case of LWIP_NOASSERT */
  LWIP_ASSERT("Failed to bind pcb", res == ERR_OK);
  udp_recv(mdns_pcb, mdns_recv, NULL);

  mdns_netif_client_id = netif_alloc_client_data_id();

#if MDNS_RESP_USENETIF_EXTCALLBACK
  /* register for netif events when started on first netif */
  netif_add_ext_callback(&netif_callback, mdns_netif_ext_status_callback);
#endif
}

#endif /* LWIP_MDNS_RESPONDER */
