/**
 * @file
 * SNMP Agent message handling structures.
 */

/*
 * Copyright (c) 2006 Axon Digital Design B.V., The Netherlands.
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
 * Author: Christiaan Simons <christiaan.simons@axon.tv>
 *         Martin Hentschel <info@cl-soft.de>
 */

#ifndef LWIP_HDR_APPS_SNMP_MSG_H
#define LWIP_HDR_APPS_SNMP_MSG_H

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "snmp_pbuf_stream.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"


#ifdef __cplusplus
extern "C" {
#endif

/* The listen port of the SNMP agent. Clients have to make their requests to
   this port. Most standard clients won't work if you change this! */
#ifndef SNMP_IN_PORT
#define SNMP_IN_PORT 161
#endif
/* The remote port the SNMP agent sends traps to. Most standard trap sinks won't
   work if you change this! */
#ifndef SNMP_TRAP_PORT
#define SNMP_TRAP_PORT 162
#endif

/* version defines used in PDU */
#define SNMP_VERSION_1  0
#define SNMP_VERSION_2c 1

struct snmp_varbind
{
  /* object identifier */
  struct snmp_obj_id oid;

  /* value ASN1 type */
  u8_t type;
  /* object value length */
  u16_t value_len;
  /* object value */
  void *value;
};

struct snmp_varbind_enumerator
{
  struct snmp_pbuf_stream pbuf_stream;
  u16_t varbind_count;
};

typedef u8_t snmp_vb_enumerator_err_t;
#define SNMP_VB_ENUMERATOR_ERR_OK            0
#define SNMP_VB_ENUMERATOR_ERR_EOVB          1
#define SNMP_VB_ENUMERATOR_ERR_ASN1ERROR     2
#define SNMP_VB_ENUMERATOR_ERR_INVALIDLENGTH 3

void snmp_vb_enumerator_init(struct snmp_varbind_enumerator* enumerator, struct pbuf* p, u16_t offset, u16_t length);
snmp_vb_enumerator_err_t snmp_vb_enumerator_get_next(struct snmp_varbind_enumerator* enumerator, struct snmp_varbind* varbind);

struct snmp_request
{
  /* Communication handle */
  void *handle;
  /* source IP address */
  const ip_addr_t *source_ip;
  /* source UDP port */
  u16_t source_port;
  /* incoming snmp version */
  u8_t version;
  /* community name (zero terminated) */
  u8_t community[SNMP_MAX_COMMUNITY_STR_LEN + 1];
  /* community string length (exclusive zero term) */
  u16_t community_strlen;
  /* request type */
  u8_t request_type;
  /* request ID */
  s32_t request_id;
  /* error status */
  s32_t error_status;
  /* error index */
  s32_t error_index;
  /* non-repeaters (getBulkRequest (SNMPv2c)) */
  s32_t non_repeaters;
  /* max-repetitions (getBulkRequest (SNMPv2c)) */
  s32_t max_repetitions;
  
  struct pbuf *inbound_pbuf;
  struct snmp_varbind_enumerator inbound_varbind_enumerator;
  u16_t inbound_varbind_offset;
  u16_t inbound_varbind_len;

  struct pbuf *outbound_pbuf;
  struct snmp_pbuf_stream outbound_pbuf_stream;
  u16_t outbound_pdu_offset;
  u16_t outbound_error_status_offset;
  u16_t outbound_error_index_offset;
  u16_t outbound_varbind_offset;

  u8_t value_buffer[SNMP_MAX_VALUE_SIZE];
};

/** Agent community string */
extern const char *snmp_community;
/** Agent community string for write access */
extern const char *snmp_community_write;
/** handle for sending traps */
extern void* snmp_traps_handle;

void snmp_receive(void *handle, struct pbuf *p, const ip_addr_t *source_ip, u16_t port);
err_t snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port);
u8_t snmp_get_local_ip_for_dst(void* handle, const ip_addr_t *dst, ip_addr_t *result);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_SNMP */

#endif /* LWIP_HDR_APPS_SNMP_MSG_H */
