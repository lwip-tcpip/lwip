/**
 * @file
 * [EXPERIMENTAL] SNMP Agent message handling structures.
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
 */

#ifndef __LWIP_SNMP_MSG_H__
#define __LWIP_SNMP_MSG_H__

#include "lwip/opt.h"
#include "arch/cc.h"
#include "lwip/snmp.h"

#if SNMP_PRIVATE_MIB
#include "private_mib.h"
#endif

#define SNMP_IN_PORT 161
#define SNMP_TRAP_PORT 162

#define SNMP_ES_NOERROR 0
#define SNMP_ES_TOOBIG 1
#define SNMP_ES_NOSUCHNAME 2
#define SNMP_ES_BADVALUE 3
#define SNMP_ES_READONLY 4
#define SNMP_ES_GENERROR 5

struct snmp_varbind
{
  /* next pointer, NULL for last in list */
  struct snmp_varbind *next;
  /* previous pointer, NULL for first in list */
  struct snmp_varbind *prev;

  /* object identifier length (in s32_t) */
  u8_t ident_len;
  /* object identifier array */
  s32_t *ident;

  /* object value ASN1 type */
  u8_t value_type;
  /* object value length (in u8_t) */
  u8_t value_len;
  /* object value */
  void *value;

  /* encoding varbind seq length length */
  u8_t seqlenlen;
  /* encoding object identifier length length */
  u8_t olenlen;
  /* encoding object value length length */
  u8_t vlenlen;
  /* encoding varbind seq length */
  u16_t seqlen;
  /* encoding object identifier length */
  u16_t olen;
  /* encoding object value length */
  u16_t vlen;
};

struct snmp_varbind_root
{
  struct snmp_varbind *head;
  struct snmp_varbind *tail;
  /* number of variable bindings in list */
  u8_t count;
  /* encoding varbind-list seq length length */
  u8_t seqlenlen;
  /* encoding varbind-list seq length */
  u16_t seqlen;
};

/** output response message header length fields */
struct snmp_resp_header_lengths
{
  /* encoding error-index length length */
  u8_t erridxlenlen;
  /* encoding error-status length length */
  u8_t errstatlenlen;
  /* encoding request id length length */
  u8_t ridlenlen;
  /* encoding pdu length length */
  u8_t pdulenlen;
  /* encoding community length length */
  u8_t comlenlen;
  /* encoding version length length */
  u8_t verlenlen;
  /* encoding sequence length length */
  u8_t seqlenlen;

  /* encoding error-index length */
  u16_t erridxlen;
  /* encoding error-status length */
  u16_t errstatlen;
  /* encoding request id length */
  u16_t ridlen;
  /* encoding pdu length */
  u16_t pdulen;
  /* encoding community length */
  u16_t comlen;
  /* encoding version length */
  u16_t verlen;
  /* encoding sequence length */
  u16_t seqlen;
};

/** output response message header length fields */
struct snmp_trap_header_lengths
{
  /* encoding timestamp length length */
  u8_t tslenlen;
  /* encoding specific-trap length length */
  u8_t strplenlen;
  /* encoding generic-trap length length */
  u8_t gtrplenlen;
  /* encoding agent-addr length length */
  u8_t aaddrlenlen;
  /* encoding enterprise-id length length */
  u8_t eidlenlen;
  /* encoding pdu length length */
  u8_t pdulenlen;
  /* encoding community length length */
  u8_t comlenlen;
  /* encoding version length length */
  u8_t verlenlen;
  /* encoding sequence length length */
  u8_t seqlenlen;

  /* encoding timestamp length */
  u16_t tslen;
  /* encoding specific-trap length */
  u16_t strplen;
  /* encoding generic-trap length */
  u16_t gtrplen;
  /* encoding agent-addr length */
  u16_t aaddrlen;
  /* encoding enterprise-id length */
  u16_t eidlen;
  /* encoding pdu length */
  u16_t pdulen;
  /* encoding community length */
  u16_t comlen;
  /* encoding version length */
  u16_t verlen;
  /* encoding sequence length */
  u16_t seqlen;
};

/* can accept new SNMP message */
#define SNMP_MSG_EMPTY    0
/* decode SNMP variable binding */
#define SNMP_MSG_DEMUX    1
/* perform SNMP operation on varbind for in-memory case */
#define SNMP_MSG_INTERNAL 2
/* perform SNMP operation on private varbind external case */
#define SNMP_MSG_EXTERNAL 3


#define SNMP_COMMUNITY_STR_LEN 64
struct snmp_msg_pstat
{
#if 0
  struct snmp_msg_pstat *next;
#endif
  /* lwIP local port (161) binding */
  struct udp_pcb *pcb;
  /* source IP address */
  struct ip_addr sip;
  /* source UDP port */
  u16_t sp;
  /* request type */
  u8_t rt;
  /* request ID */
  s32_t rid;
  /* error status */
  s32_t error_status;
  /* error index */
  s32_t error_index;
  /* community name (zero terminated) */
  u8_t community[SNMP_COMMUNITY_STR_LEN + 1];
  /* community string length (exclusive zero term) */
  u8_t com_strlen;
  /* one out of MSG_EMPTY, MSG_DEMUX, MSG_MGMT, MSG_PRIVATE */
  u8_t state;
  /* list of variable bindings from input */
  struct snmp_varbind_root invb;
  /* list of variable bindings to output */
  struct snmp_varbind_root outvb;
  /* output response lengths used in ASN encoding */
  struct snmp_resp_header_lengths rhl;
#if SNMP_PRIVATE_MIB
  struct private_state ps;
#endif
};

struct snmp_msg_trap
{
#if 0
  struct snmp_msg_trap *next;
#endif
  /* lwIP local port (161) binding */
  struct udp_pcb *pcb;
  /* destination IP address in network order */
  struct ip_addr dip;

  /* source enterprise ID (sysObjectID) */
  struct snmp_obj_id *enterprise;
  /* source IP address, raw network order format */
  u8_t sip_raw[4];
  /* generic trap code */
  u32_t gen_trap;
  /* specific trap code */
  u32_t spc_trap;
  /* timestamp */
  u32_t ts;
  /* list of variable bindings to output */
  struct snmp_varbind_root outvb;
  /* output trap lengths used in ASN encoding */
  struct snmp_trap_header_lengths thl;
#if SNMP_PRIVATE_MIB
  /** @todo is this really needed? */
  struct private_state ps;
#endif
};

/** Agent Version constant, 0 = v1 oddity */
extern const s32_t snmp_version;
/** Agent default "public" community string */
extern const char snmp_publiccommunity[7];

extern struct snmp_msg_trap trap_msg;

/** Agent setup, start listening to port 161. */
void snmp_init(void);

err_t snmp_send_response(struct snmp_msg_pstat *m_stat);
err_t snmp_send_trap(struct ip_addr *dst, s8_t generic_trap, s32_t specific_trap);

#endif
