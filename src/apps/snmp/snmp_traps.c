/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Martin Hentschel
 *         Christiaan Simons <christiaan.simons@axon.tv>
 *
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/ip_addr.h"

#define snmp_community_trap snmp_community
/** Agent community string for sending traps */
extern const char *snmp_community_trap;

struct snmp_trap_dst
{
  /* destination IP address in network order */
  ip_addr_t dip;
  /* set to 0 when disabled, >0 when enabled */
  u8_t enable;
};
static struct snmp_trap_dst trap_dst[SNMP_TRAP_DESTINATIONS];

static u8_t snmp_auth_traps_enabled = 0;

/** TRAP message structure */
/*struct snmp_msg_trap trap_msg;*/

/**
 * Sets enable switch for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param enable switch if 0 destination is disabled >0 enabled.
 */
void
snmp_trap_dst_enable(u8_t dst_idx, u8_t enable)
{
  if (dst_idx < SNMP_TRAP_DESTINATIONS) {
    trap_dst[dst_idx].enable = enable;
  }
}

/**
 * Sets IPv4 address for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param dst IPv4 address in host order.
 */
void
snmp_trap_dst_ip_set(u8_t dst_idx, const ip_addr_t *dst)
{
  if (dst_idx < SNMP_TRAP_DESTINATIONS) {
    ip_addr_set(&trap_dst[dst_idx].dip, dst);
  }
}

void
snmp_set_auth_traps_enabled(u8_t enable)
{
  snmp_auth_traps_enabled = enable;
}

u8_t
snmp_get_auth_traps_enabled(void)
{
  return snmp_auth_traps_enabled;
}


/**
 * Sends an generic or enterprise specific trap message.
 *
 * @param generic_trap is the trap code
 * @param eoid points to enterprise object identifier
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the caller is responsible for filling in outvb in the trap_msg
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */
static err_t
snmp_send_trap(const struct snmp_obj_id *device_enterprise_oid, s32_t generic_trap, s32_t specific_trap)
{
  LWIP_UNUSED_ARG(device_enterprise_oid);
  LWIP_UNUSED_ARG(generic_trap);
  LWIP_UNUSED_ARG(specific_trap);
  return ERR_OK;
#if 0
  //struct snmp_trap_dst *td;
  //struct netif *dst_if;
  //const ip_addr_t* dst_ip;
  //struct pbuf *p;
  //u16_t i,tot_len;
  //err_t err = ERR_OK;

  //for (i = 0, td = &trap_dst[0]; i < SNMP_TRAP_DESTINATIONS; i++, td++) {
  //  if ((td->enable != 0) && !ip_addr_isany(&td->dip)) {
  //    /* network order trap destination */
  //    ip_addr_copy(trap_msg.dip, td->dip);
  //    /* lookup current source address for this dst */
  //    ip_route_get_local_ip(IP_IS_V6(trap_msg.lip), trap_msg.lip,
  //      &td->dip, dst_if, dst_ip);
  //    if ((dst_if != NULL) && (dst_ip != NULL)) {
  //      trap_msg.sip_raw_len = (IP_IS_V6_VAL(*dst_ip) ? 16 : 4);
  //      MEMCPY(trap_msg.sip_raw, dst_ip, trap_msg.sip_raw_len);

  //      if (device_enterprise_oid == NULL) {
  //        trap_msg.enterprise = snmp_get_device_enterprise_oid();
  //      } else {
  //        trap_msg.enterprise = device_enterprise_oid;
  //      }
  //      trap_msg.gen_trap = generic_trap;
  //      if (generic_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC) {
  //        trap_msg.spc_trap = specific_trap;
  //      } else {
  //        trap_msg.spc_trap = 0;
  //      }

  //      MIB2_COPY_SYSUPTIME_TO(&trap_msg.ts);

  //      /* pass 0, calculate length fields */
  //      tot_len = snmp_varbind_list_sum(&trap_msg.outvb);
  //      tot_len = snmp_trap_header_sum(&trap_msg, tot_len);

  //      /* allocate pbuf(s) */
  //      p = pbuf_alloc(PBUF_TRANSPORT, tot_len, PBUF_RAM);
  //      if (p != NULL) {
  //        u16_t ofs;

  //        /* pass 1, encode packet ino the pbuf(s) */
  //        ofs = snmp_trap_header_enc(&trap_msg, p);
  //        snmp_varbind_list_enc(&trap_msg.outvb, p, ofs);

  //        snmp_stats.outtraps++;
  //        snmp_stats.outpkts++;

  //        /** send to the TRAP destination */
  //        snmp_sendto(trap_msg.handle, p, &trap_msg.dip, SNMP_TRAP_PORT);
  //      } else {
  //        err = ERR_MEM;
  //      }
  //    } else {
  //      /* routing error */
  //      err = ERR_RTE;
  //    }
  //  }
  //}
  //return err;
#endif
}

err_t 
snmp_send_trap_generic(s32_t generic_trap)
{
  return snmp_send_trap(NULL, generic_trap, 0);
}

err_t snmp_send_trap_specific(s32_t specific_trap)
{
  return snmp_send_trap(NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap);
}


void
snmp_coldstart_trap(void)
{
  snmp_send_trap_generic(SNMP_GENTRAP_COLDSTART);
}

void
snmp_authfail_trap(void)
{
  if (snmp_auth_traps_enabled != 0) {
    snmp_send_trap_generic(SNMP_GENTRAP_AUTH_FAILURE);
  }
}

#if 0
//extern struct snmp_msg_trap trap_msg;

//struct snmp_msg_trap
//{
//  /* Communication handle */
//  void *handle;
//  /* local IP address */
//  ip_addr_t *lip;
//  /* destination IP address */
//  ip_addr_t dip;
//
//  /* source enterprise ID (sysObjectID) */
//  const struct snmp_obj_id *enterprise;
//  /* source IP address, raw network order format */
//  u8_t sip_raw[4];
//  /* source IP address length */
//  u8_t sip_raw_len;
//  /* generic trap code */
//  u32_t gen_trap;
//  /* specific trap code */
//  u32_t spc_trap;
//  /* timestamp */
//  u32_t ts;
//  ///* list of variable bindings to output */
//  //struct snmp_varbind_root outvb;
//  ///* output trap lengths used in ASN encoding */
//  //struct snmp_trap_header_lengths thl;
//};

/** output response message header length fields */
//struct snmp_trap_header_lengths
//{
//  /* encoding timestamp length length */
//  u8_t tslenlen;
//  /* encoding specific-trap length length */
//  u8_t strplenlen;
//  /* encoding generic-trap length length */
//  u8_t gtrplenlen;
//  /* encoding agent-addr length length */
//  u8_t aaddrlenlen;
//  /* encoding enterprise-id length length */
//  u8_t eidlenlen;
//  /* encoding pdu length length */
//  u8_t pdulenlen;
//  /* encoding community length length */
//  u8_t comlenlen;
//  /* encoding version length length */
//  u8_t verlenlen;
//  /* encoding sequence length length */
//  u8_t seqlenlen;
//
//  /* encoding timestamp length */
//  u16_t tslen;
//  /* encoding specific-trap length */
//  u16_t strplen;
//  /* encoding generic-trap length */
//  u16_t gtrplen;
//  /* encoding agent-addr length */
//  u16_t aaddrlen;
//  /* encoding enterprise-id length */
//  u16_t eidlen;
//  /* encoding pdu length */
//  u16_t pdulen;
//  /* encoding community length */
//  u16_t comlen;
//  /* encoding version length */
//  u16_t verlen;
//  /* encoding sequence length */
//  u16_t seqlen;
//};

/**
 * Sums trap header field lengths from tail to head and
 * returns trap_header_lengths for second encoding pass.
 *
 * @param vb_len varbind-list length
 * @param thl points to returned header lengths
 * @return the required length for encoding the trap header
 */
//static u16_t
//snmp_trap_header_sum(struct snmp_msg_trap *m_trap, u16_t vb_len)
//{
//  u16_t tot_len;
//  struct snmp_trap_header_lengths *thl;
//
//  thl = &m_trap->thl;
//  tot_len = vb_len;
//
//  snmp_asn1_enc_u32t_cnt(m_trap->ts, &thl->tslen);
//  snmp_asn1_enc_length_cnt(thl->tslen, &thl->tslenlen);
//  tot_len += 1 + thl->tslen + thl->tslenlen;
//
//  snmp_asn1_enc_s32t_cnt(m_trap->spc_trap, &thl->strplen);
//  snmp_asn1_enc_length_cnt(thl->strplen, &thl->strplenlen);
//  tot_len += 1 + thl->strplen + thl->strplenlen;
//
//  snmp_asn1_enc_s32t_cnt(m_trap->gen_trap, &thl->gtrplen);
//  snmp_asn1_enc_length_cnt(thl->gtrplen, &thl->gtrplenlen);
//  tot_len += 1 + thl->gtrplen + thl->gtrplenlen;
//
//  thl->aaddrlen = m_trap->sip_raw_len;
//  snmp_asn1_enc_length_cnt(thl->aaddrlen, &thl->aaddrlenlen);
//  tot_len += 1 + thl->aaddrlen + thl->aaddrlenlen;
//
//  snmp_asn1_enc_oid_cnt(&m_trap->enterprise->id[0], m_trap->enterprise->len, &thl->eidlen);
//  snmp_asn1_enc_length_cnt(thl->eidlen, &thl->eidlenlen);
//  tot_len += 1 + thl->eidlen + thl->eidlenlen;
//
//  thl->pdulen = tot_len;
//  snmp_asn1_enc_length_cnt(thl->pdulen, &thl->pdulenlen);
//  tot_len += 1 + thl->pdulenlen;
//
//  thl->comlen = (u16_t)strlen(snmp_community_trap);
//  snmp_asn1_enc_length_cnt(thl->comlen, &thl->comlenlen);
//  tot_len += 1 + thl->comlenlen + thl->comlen;
//
//  snmp_asn1_enc_s32t_cnt(snmp_version, &thl->verlen);
//  snmp_asn1_enc_length_cnt(thl->verlen, &thl->verlenlen);
//  tot_len += 1 + thl->verlen + thl->verlenlen;
//
//  thl->seqlen = tot_len;
//  snmp_asn1_enc_length_cnt(thl->seqlen, &thl->seqlenlen);
//  tot_len += 1 + thl->seqlenlen;
//
//  return tot_len;
//}

/**
 * Encodes trap header from head to tail.
 */
//static u16_t
//snmp_trap_header_enc(struct snmp_msg_trap *m_trap, struct pbuf *p)
//{
//  u16_t ofs;
//
//  ofs = 0;
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_SEQUENCE);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.seqlen);
//  ofs += m_trap->thl.seqlenlen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_INTEGER);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.verlen);
//  ofs += m_trap->thl.verlenlen;
//  snmp_asn1_enc_s32t(p, ofs, m_trap->thl.verlen, snmp_version);
//  ofs += m_trap->thl.verlen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_OCTET_STRING);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.comlen);
//  ofs += m_trap->thl.comlenlen;
//  snmp_asn1_enc_raw(p, ofs, m_trap->thl.comlen, (const u8_t *)&snmp_community_trap[0]);
//  ofs += m_trap->thl.comlen;
//
//  snmp_asn1_enc_type(p, ofs, (SNMP_ASN1_CLASS_CONTEXT | SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_TRAP));
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.pdulen);
//  ofs += m_trap->thl.pdulenlen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_OBJECT_ID);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.eidlen);
//  ofs += m_trap->thl.eidlenlen;
//  snmp_asn1_enc_oid(p, ofs, m_trap->enterprise->len, &m_trap->enterprise->id[0]);
//  ofs += m_trap->thl.eidlen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_IPADDR);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.aaddrlen);
//  ofs += m_trap->thl.aaddrlenlen;
//  snmp_asn1_enc_raw(p, ofs, m_trap->thl.aaddrlen, &m_trap->sip_raw[0]);
//  ofs += m_trap->thl.aaddrlen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_INTEGER);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.gtrplen);
//  ofs += m_trap->thl.gtrplenlen;
//  snmp_asn1_enc_u32t(p, ofs, m_trap->thl.gtrplen, m_trap->gen_trap);
//  ofs += m_trap->thl.gtrplen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_INTEGER);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.strplen);
//  ofs += m_trap->thl.strplenlen;
//  snmp_asn1_enc_u32t(p, ofs, m_trap->thl.strplen, m_trap->spc_trap);
//  ofs += m_trap->thl.strplen;
//
//  snmp_asn1_enc_type(p, ofs, SNMP_ASN1_TYPE_TIMETICKS);
//  ofs += 1;
//  snmp_asn1_enc_length(p, ofs, m_trap->thl.tslen);
//  ofs += m_trap->thl.tslenlen;
//  snmp_asn1_enc_u32t(p, ofs, m_trap->thl.tslen, m_trap->ts);
//  ofs += m_trap->thl.tslen;
//
//  return ofs;
//}
#endif

#endif /* LWIP_SNMP */
