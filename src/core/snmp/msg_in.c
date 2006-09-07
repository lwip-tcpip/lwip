/**
 * @file
 * [EXPERIMENTAL] SNMP input message processing (RFC1157).
 *
 * EXPERIMENTAL dumb echo, this is not how the agent should respond.
 * This is for test purposes only, DO NOT USE THIS CODE IN REAL WORLD!!
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

#include "lwip/opt.h"

#if LWIP_SNMP
#include <string.h>
#include "arch/cc.h"
#include "lwip/ip_addr.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/stats.h"

#include "lwip/snmp.h"
#include "lwip/snmp_asn1.h"
#include "lwip/snmp_msg.h"
#include "lwip/snmp_structs.h"

#define SNMP_CONCURRENT_REQUESTS 2

/* public (non-static) constants */
/** SNMP v1 == 0 */
const s32_t snmp_version = 0;
/** default SNMP community string */
const char snmp_publiccommunity[7] = "public";

/* statically allocated buffers for SNMP_CONCURRENT_REQUESTS */
struct snmp_msg_pstat msg_input_list[SNMP_CONCURRENT_REQUESTS];
/* UDP Protocol Control Block */
struct udp_pcb *snmp1_pcb = NULL;

static void snmp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port);
static err_t snmp_pdu_header_check(struct pbuf *p, u16_t ofs, u16_t pdu_len, u16_t *ofs_ret, struct snmp_msg_pstat *m_stat);
static err_t snmp_pdu_dec_varbindlist(struct pbuf *p, u16_t ofs, u16_t *ofs_ret, struct snmp_msg_pstat *m_stat);


/**
 * Starts SNMP Agent.
 * Allocates UDP pcb and binds it to IP_ADDR_ANY port 161.
 */
void
snmp_init(void)
{
  struct snmp_msg_pstat *msg_ps;
  u8_t i;
  
  snmp1_pcb = udp_new();
  if (snmp1_pcb != NULL)
  {
    udp_recv(snmp1_pcb, snmp_recv, (void *)SNMP_IN_PORT);
    udp_bind(snmp1_pcb, IP_ADDR_ANY, SNMP_IN_PORT);
  }
  msg_ps = &msg_input_list[0];
  for (i=0; i<SNMP_CONCURRENT_REQUESTS; i++)
  {
    msg_ps->state = SNMP_MSG_EMPTY;
    msg_ps->error_index = 0;
    msg_ps->error_status = 0;
    msg_ps++;
  }
  trap_msg.pcb = snmp1_pcb;
  /* The coldstart trap will only be output
     if our outgoing interface is up & configured  */
  snmp_coldstart_trap();
}

#if 0
/**
 * called for each variable binding (also for the fist one)
 */
void
snmp_msg_event(struct snmp_msg_pstat *msg_ps)
{
  struct mib_node *mn;
  struct obj_def object_def;

  if (msg_ps->state == SNMP_MSG_DEMUX)
  {
    if (msg_ps->vb_idx == 0)
    {
      msg_ps->vb_ptr = msg_ps->invb.head;
    }
    else
    {
      msg_ps->vb_ptr = msg_ps->vb_ptr->next;
      msg_ps->vb_idx += 1;
    }
    if (msg_ps->rt == SNMP_ASN1_PDU_GET_REQ)
    { 
      /** test object identifier for .iso.org.dod.internet prefix */
      if (snmp_iso_prefix_tst(msg_ps->vb_ptr->ident_len,  msg_ps->vb_ptr->ident))
      {
        mn = snmp_search_tree((struct mib_node*)&internet, msg_ps->vb_ptr->ident_len - 4,
                               msg_ps->vb_ptr->ident + 4, &object_def);
      }
      else
      {
        mn = NULL;
      }
      if (mn != NULL)
      {
        if (mn->node_type == MIB_NODE_EX)
        {
          /* external object */
          msg_ps->state = SNMP_MSG_EXTERNAL;
        }
        else
        {
          /* internal object */
          msg_ps->state = SNMP_MSG_INTERNAL;
        }
      }
      else
      {
        /* mn == NULL, noSuchName */
        snmp_varbind_list_free(&msg_ps->outvb);
        msg_ps->outvb = msg_ps->invb;
        msg_ps->invb.head = NULL;
        msg_ps->invb.tail = NULL;
        msg_ps->invb.count = 0;
        msg_ps->error_status = SNMP_ES_NOSUCHNAME;
        msg_ps->error_index = 1 + msg_ps->vb_idx;
        snmp_send_response(msg_ps);
        msg_ps->state = SNMP_MSG_EMPTY;
      }
    }
    else if (msg_ps->rt == SNMP_ASN1_PDU_GET_NEXT_REQ)
    {
    }
    else if (msg_ps->rt == SNMP_ASN1_PDU_SET_REQ)
    {
    }
    else
    {
      /** @todo not a request, return generror?? */
    }
  }
  else if (msg_ps->state == SNMP_MSG_INTERNAL)
  {
  }
  else if (msg_ps->state == SNMP_MSG_EXTERNAL)
  {
  }
}
#endif

/* lwIP UDP receive callback function */
static void
snmp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
  struct udp_hdr *udphdr;

  /* suppress unused argument warning */
  if (arg);
  /* peek in the UDP header (goto IP payload) */
  pbuf_header(p, UDP_HLEN);
  udphdr = p->payload;
  
  /* check if datagram is really directed at us (including broadcast requests) */
  if ((pcb == snmp1_pcb) && (ntohs(udphdr->dest) == 161))
  {
    struct snmp_msg_pstat *msg_ps;
    u8_t i;

    /* traverse input message process list, look for SNMP_MSG_EMPTY */
    msg_ps = &msg_input_list[0];
    i = 0;
    while ((i<SNMP_CONCURRENT_REQUESTS) && (msg_ps->state != SNMP_MSG_EMPTY))
    {
      i++;
      msg_ps++;
    }
    if (i != SNMP_CONCURRENT_REQUESTS)
    {
      err_t err_ret;
      u16_t payload_len;
      u16_t payload_ofs;
      u16_t varbind_ofs;

      /* accepting request */
      snmp_inc_snmpinpkts();
      /* register 'protocol control block' used */
      msg_ps->pcb = pcb;
      /* source address (network order) */
      msg_ps->sip = *addr;
      /* source port (host order (lwIP oddity)) */
      msg_ps->sp = port;
      /* demultiplex variable bindings */
      msg_ps->state = SNMP_MSG_DEMUX;
      /* first variable binding from list to inspect */
      msg_ps->vb_idx = 0;
      /* read UDP payload length from UDP header */
      payload_len = ntohs(udphdr->len) - UDP_HLEN;

      /* adjust to UDP payload */
      payload_ofs = UDP_HLEN;

      /* check total length, version, community, pdu type */
      err_ret = snmp_pdu_header_check(p, payload_ofs, payload_len, &varbind_ofs, msg_ps);
      if (err_ret == ERR_OK)
      {
        LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_recv ok, community %s\n", msg_ps->community));

       /* Builds a list of variable bindings. Copy the varbinds from the pbuf
         chain to glue them when these are divided over two or more pbuf's. */
        err_ret = snmp_pdu_dec_varbindlist(p, varbind_ofs, &varbind_ofs, msg_ps);
        if ((err_ret == ERR_OK) && (msg_ps->invb.count > 0))
        {          
          struct mib_node *mn;
          struct obj_def object_def;

          /* we've decoded the incoming message, release input msg now */
          pbuf_free(p);

          LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_recv varbind cnt=%"U16_F"\n",(u16_t)msg_ps->invb.count));

          if (msg_ps->rt == SNMP_ASN1_PDU_GET_REQ)
          { 
            /** test object identifier for .iso.org.dod.internet prefix */
            if (snmp_iso_prefix_tst(msg_ps->invb.head->ident_len, msg_ps->invb.head->ident))
            {
              mn = snmp_search_tree((struct mib_node*)&internet, msg_ps->invb.head->ident_len - 4,
                                     msg_ps->invb.head->ident + 4, &object_def);
            }
            else
            {
              mn = NULL;
            }
            if (mn != NULL)
            {
              struct snmp_varbind *vb;

              /* allocate output varbind */
              vb = (struct snmp_varbind *)mem_malloc(sizeof(struct snmp_varbind));
              if (vb != NULL)
              {
                vb->next = NULL;
                vb->prev = NULL;

                /* move name from invb to outvb */
                vb->ident = msg_ps->invb.head->ident;
                vb->ident_len = msg_ps->invb.head->ident_len;
                /* ensure this memory is refereced once only */
                msg_ps->invb.head->ident = NULL;
                msg_ps->invb.head->ident_len = 0;
                
                vb->value_type = object_def.asn_type;
                vb->value_len = object_def.v_len;
                vb->value = mem_malloc(object_def.v_len);                
                if (vb->value != NULL)
                {
                  mn->get_value(&object_def, object_def.v_len, vb->value);
                  snmp_varbind_tail_add(&msg_ps->outvb, vb);
                }
                else
                {
                  LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_recv couldn't allocate variable space"));
                }
              }
              else
              {
                 LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_recv couldn't allocate outvb space"));
              }
            }
            else
            {
              /* mn == NULL, noSuchName */
              /* @todo move used names back from outvb to invb */
              snmp_varbind_list_free(&msg_ps->outvb);
              msg_ps->outvb = msg_ps->invb;
              msg_ps->invb.head = NULL;
              msg_ps->invb.tail = NULL;
              msg_ps->invb.count = 0;
              msg_ps->error_status = SNMP_ES_NOSUCHNAME;
              msg_ps->error_index = 1 + msg_ps->vb_idx;
            }
          }
          else if (msg_ps->rt == SNMP_ASN1_PDU_GET_NEXT_REQ)
          {
            struct snmp_obj_id oid;

            if (snmp_iso_prefix_expand(msg_ps->invb.head->ident_len, msg_ps->invb.head->ident, &oid))
            {
              if (msg_ps->invb.head->ident_len > 3)
              {
                /* can offset ident_len and ident */
                mn = snmp_expand_tree((struct mib_node*)&internet,
                                      msg_ps->invb.head->ident_len - 4,
                                      msg_ps->invb.head->ident + 4, &oid);
              }
              else
              {
                /* can't offset ident_len -4, ident + 4 */
                mn = snmp_expand_tree((struct mib_node*)&internet, 0, NULL, &oid);
              }
            }
            else
            {
              mn = NULL;
            }
            if (mn != NULL)
            {
              struct snmp_varbind *vb;

              mn->get_object_def(1, &oid.id[oid.len - 1], &object_def);
              
              vb = snmp_varbind_alloc(&oid, object_def.asn_type, object_def.v_len);
              if (vb != NULL)
              {
                mn->get_value(&object_def, object_def.v_len, vb->value);
                snmp_varbind_tail_add(&msg_ps->outvb, vb);
              }
              else
              {
                LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_recv couldn't allocate outvb space"));
              }
            }
            else
            {
              /* mn == NULL, noSuchName */
              snmp_varbind_list_free(&msg_ps->outvb);
              msg_ps->outvb = msg_ps->invb;
              msg_ps->invb.head = NULL;
              msg_ps->invb.tail = NULL;
              msg_ps->invb.count = 0;
              msg_ps->error_status = SNMP_ES_NOSUCHNAME;
              msg_ps->error_index = 1 + msg_ps->vb_idx;
            }
          }
          else
          {
            /* request != GET */
            /** @todo EXPERIMENTAL dumb echo, this is not how the agent should respond.
                This is for test purposes only, do not use this in real world!! */
            msg_ps->outvb = msg_ps->invb;
            msg_ps->error_status = SNMP_ES_NOERROR;
            msg_ps->error_index = 0;
          }

/* when more variable bindings left msg_ps->state = SNMP_MSG_DEMUX */


/* when completed transaction */
          err_ret = snmp_send_response(msg_ps);
          if (err_ret == ERR_MEM)
          {
            /* serious memory problem, can't return tooBig */
#if LWIP_STATS
            LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_recv pbufs.used = %"U16_F"\n",lwip_stats.pbuf.used));
#endif
          }
          else
          {
            LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_response error_status = %"S32_F"\n",msg_ps->error_status));
          }
          /* free varbinds (if available) */
          snmp_varbind_list_free(&msg_ps->invb);
          snmp_varbind_list_free(&msg_ps->outvb);
          msg_ps->state = SNMP_MSG_EMPTY;
        }
        else
        {
          /* varbind-list decode failed, or varbind list empty (silly cmd for agent) */
          pbuf_free(p);
          LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_pdu_dec_varbindlist() failed"));
          msg_ps->error_status = SNMP_ES_GENERROR;
          msg_ps->error_index = 0;
          msg_ps->outvb.head = NULL;
          msg_ps->outvb.tail = NULL;
          msg_ps->outvb.count = 0;
          msg_ps->outvb.seqlen = 0;
          msg_ps->outvb.seqlenlen = 1;
          snmp_send_response(msg_ps);
        }
      }
      else
      {
        /* header check failed! */
        pbuf_free(p);
        LWIP_DEBUGF(SNMP_MSG_DEBUG, ("snmp_pdu_header_check() failed"));
      }      
    }
    else
    {
      /* exceeding number of concurrent requests */
      pbuf_free(p);
    }
  }
  else
  {
    /* datagram not for us */
    pbuf_free(p);
  }
}

/** 
 * Checks and decodes incoming SNMP message header, logs header errors.
 *
 * @param p points to pbuf chain of SNMP message (UDP payload)
 * @param ofs points to first octet of SNMP message
 * @param pdu_len the length of the UDP payload
 * @param ofs_ret returns the ofset of the variable bindings
 * @param m_stat points to the current message request state return
 * @return
 * - ERR_OK SNMP header is sane and accepted
 * - ERR_ARG SNMP header is either malformed or rejected
 */
static err_t
snmp_pdu_header_check(struct pbuf *p, u16_t ofs, u16_t pdu_len, u16_t *ofs_ret, struct snmp_msg_pstat *m_stat)
{
  err_t derr;
  u16_t len;
  u8_t  len_octets;
  u8_t  type;
  s32_t version;

  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if ((derr != ERR_OK) ||
      (pdu_len != (1 + len_octets + len)) ||
      (type != (SNMP_ASN1_UNIV | SNMP_ASN1_CONSTR | SNMP_ASN1_SEQ)))
  {
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  ofs += (1 + len_octets);
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if ((derr != ERR_OK) || (type != (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG)))
  {
    /* can't decode or no integer (version) */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  derr = snmp_asn1_dec_s32t(p, ofs + 1 + len_octets, len, &version);
  if (derr != ERR_OK)
  {
    /* can't decode */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  if (version != 0)
  {
    /* not version 1 */
    snmp_inc_snmpinbadversions();
    return ERR_ARG;
  }
  ofs += (1 + len_octets + len);
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if ((derr != ERR_OK) || (type != (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR)))
  {
    /* can't decode or no octet string (community) */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  derr = snmp_asn1_dec_raw(p, ofs + 1 + len_octets, len, SNMP_COMMUNITY_STR_LEN, m_stat->community);
  if (derr != ERR_OK)
  {
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  /* add zero terminator */
  len = ((len < (SNMP_COMMUNITY_STR_LEN))?(len):(SNMP_COMMUNITY_STR_LEN));
  m_stat->community[len] = 0;
  m_stat->com_strlen = len;
  if (strncmp(snmp_publiccommunity, (const char*)m_stat->community, SNMP_COMMUNITY_STR_LEN) != 0)
  {
    /** @todo: move this if we need to check more names */
    snmp_inc_snmpinbadcommunitynames();
    snmp_authfail_trap();
    return ERR_ARG;
  }
  ofs += (1 + len_octets + len);
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if (derr != ERR_OK)
  {
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  switch(type)
  {
    case (SNMP_ASN1_CONTXT | SNMP_ASN1_CONSTR | SNMP_ASN1_PDU_GET_REQ):
      /* GetRequest PDU */
      snmp_inc_snmpingetrequests();
      derr = ERR_OK;
      break;
    case (SNMP_ASN1_CONTXT | SNMP_ASN1_CONSTR | SNMP_ASN1_PDU_GET_NEXT_REQ):
      /* GetNextRequest PDU */
      snmp_inc_snmpingetnexts();
      derr = ERR_OK;
      break;
    case (SNMP_ASN1_CONTXT | SNMP_ASN1_CONSTR | SNMP_ASN1_PDU_GET_RESP):
      /* GetResponse PDU */ 
      snmp_inc_snmpingetresponses();
      derr = ERR_ARG;
      break;
    case (SNMP_ASN1_CONTXT | SNMP_ASN1_CONSTR | SNMP_ASN1_PDU_SET_REQ):
      /* SetRequest PDU */ 
      snmp_inc_snmpinsetrequests();
      derr = ERR_OK;
      break;
    case (SNMP_ASN1_CONTXT | SNMP_ASN1_CONSTR | SNMP_ASN1_PDU_TRAP):
      /* Trap PDU */ 
      snmp_inc_snmpintraps();
      derr = ERR_ARG;
      break;
    default:
      snmp_inc_snmpinasnparseerrs();
      derr = ERR_ARG;
      break;
  }
  if (derr != ERR_OK)
  {
    /* unsupported input PDU for this agent */
    return ERR_ARG;
  }
  m_stat->rt = type & 0x1F;
  ofs += (1 + len_octets);
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if ((derr != ERR_OK) || (type != (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG)))
  {
    /* can't decode or no integer (request ID) */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  derr = snmp_asn1_dec_s32t(p, ofs + 1 + len_octets, len, &m_stat->rid);
  if (derr != ERR_OK)
  {
    /* can't decode */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  ofs += (1 + len_octets + len);
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if ((derr != ERR_OK) || (type != (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG)))
  {
    /* can't decode or no integer (error-status) */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  /* usually noError (0) for incoming messages but log errors
     for mib-2 completeness and for debug purposes */
  derr = snmp_asn1_dec_s32t(p, ofs + 1 + len_octets, len, &m_stat->error_status);
  if (derr != ERR_OK)
  {
    /* can't decode */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  switch (m_stat->error_status)
  {
    case SNMP_ES_TOOBIG:
      snmp_inc_snmpintoobigs();
      break;
    case SNMP_ES_NOSUCHNAME:
      snmp_inc_snmpinnosuchnames();
      break;
    case SNMP_ES_BADVALUE:
      snmp_inc_snmpinbadvalues();
      break;
    case SNMP_ES_READONLY:
      snmp_inc_snmpinreadonlys();
      break;
    case SNMP_ES_GENERROR:
      snmp_inc_snmpingenerrs();
      break;
  }
  ofs += (1 + len_octets + len);
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
  if ((derr != ERR_OK) || (type != (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG)))
  {
    /* can't decode or no integer (error-index) */
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  /* skip 'error-index', usually 0 for incoming requests */
  ofs += (1 + len_octets + len);
  *ofs_ret = ofs;
  return ERR_OK;
}

static err_t
snmp_pdu_dec_varbindlist(struct pbuf *p, u16_t ofs, u16_t *ofs_ret, struct snmp_msg_pstat *m_stat)
{
  err_t derr;
  u16_t len, vb_len;
  u8_t  len_octets;
  u8_t type;

  /* variable binding list */  
  snmp_asn1_dec_type(p, ofs, &type);
  derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &vb_len);
  if ((derr != ERR_OK) ||
      (type != (SNMP_ASN1_UNIV | SNMP_ASN1_CONSTR | SNMP_ASN1_SEQ)))
  {
    snmp_inc_snmpinasnparseerrs();
    return ERR_ARG;
  }
  ofs += (1 + len_octets);
  
  /* start with empty list */
  m_stat->invb.count = 0;
  m_stat->invb.head = NULL;
  m_stat->invb.tail = NULL;

  while (vb_len > 0)
  {
    struct snmp_obj_id oid, oid_value;
    struct snmp_varbind *vb;

    snmp_asn1_dec_type(p, ofs, &type);
    derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
    if ((derr != ERR_OK) ||
        (type != (SNMP_ASN1_UNIV | SNMP_ASN1_CONSTR | SNMP_ASN1_SEQ)))
    {
      snmp_inc_snmpinasnparseerrs();
      /* free varbinds (if available) */
      snmp_varbind_list_free(&m_stat->invb);
      return ERR_ARG;
    }
    ofs += (1 + len_octets);
    vb_len -= (1 + len_octets);

    snmp_asn1_dec_type(p, ofs, &type);
    derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
    if ((derr != ERR_OK) || (type != (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID)))
    {
      /* can't decode object name length */
      snmp_inc_snmpinasnparseerrs();
      /* free varbinds (if available) */
      snmp_varbind_list_free(&m_stat->invb);
      return ERR_ARG;
    }
    derr = snmp_asn1_dec_oid(p, ofs + 1 + len_octets, len, &oid);
    if (derr != ERR_OK)
    {
      /* can't decode object name */
      snmp_inc_snmpinasnparseerrs();
      /* free varbinds (if available) */
      snmp_varbind_list_free(&m_stat->invb);
      return ERR_ARG;
    }
    ofs += (1 + len_octets + len);
    vb_len -= (1 + len_octets + len);

    snmp_asn1_dec_type(p, ofs, &type);
    derr = snmp_asn1_dec_length(p, ofs+1, &len_octets, &len);
    if (derr != ERR_OK)
    {
      /* can't decode object value length */
      snmp_inc_snmpinasnparseerrs();
      /* free varbinds (if available) */
      snmp_varbind_list_free(&m_stat->invb);
      return ERR_ARG;
    }

    switch (type)
    {
      case (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG):
        vb = snmp_varbind_alloc(&oid, type, sizeof(s32_t));
        if (vb != NULL)
        {
          s32_t *vptr = vb->value;
          
          derr = snmp_asn1_dec_s32t(p, ofs + 1 + len_octets, len, vptr);
          snmp_varbind_tail_add(&m_stat->invb, vb);
        }
        else
        {
          derr = ERR_ARG;
        }
        break;
      case (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER):        
      case (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_GAUGE):
      case (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_TIMETICKS):
        vb = snmp_varbind_alloc(&oid, type, sizeof(u32_t));
        if (vb != NULL)
        {
          u32_t *vptr = vb->value;
          
          derr = snmp_asn1_dec_u32t(p, ofs + 1 + len_octets, len, vptr);
          snmp_varbind_tail_add(&m_stat->invb, vb);
        }
        else
        {
          derr = ERR_ARG;
        }
        break;
      case (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR):
      case (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_OPAQUE):
        vb = snmp_varbind_alloc(&oid, type, len);
        if (vb != NULL)
        {
          derr = snmp_asn1_dec_raw(p, ofs + 1 + len_octets, len, vb->value_len, vb->value);
          snmp_varbind_tail_add(&m_stat->invb, vb);
        }
        else
        {
          derr = ERR_ARG;
        }
        break;
      case (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_NUL):
        vb = snmp_varbind_alloc(&oid, type, 0);
        if (vb != NULL)
        {
          snmp_varbind_tail_add(&m_stat->invb, vb);
          derr = ERR_OK;
        }
        else
        {
          derr = ERR_ARG;
        }
        break;
      case (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID):
        derr = snmp_asn1_dec_oid(p, ofs + 1 + len_octets, len, &oid_value);
        if (derr == ERR_OK)
        {
          vb = snmp_varbind_alloc(&oid, type, oid_value.len * sizeof(s32_t));
          if (vb != NULL)
          {
            u8_t i = oid_value.len;
            s32_t *vptr = vb->value;
                     
            while(i > 0)
            {
              i--;
              vptr[i] = oid_value.id[i];
            }
            snmp_varbind_tail_add(&m_stat->invb, vb);
            derr = ERR_OK;
          }
          else
          {
            derr = ERR_ARG;
          }
        }
        break;
      case (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR):
        if (len == 4)
        {
          /* must be exactly 4 octets! */
          vb = snmp_varbind_alloc(&oid, type, 4);
          if (vb != NULL)
          {
            derr = snmp_asn1_dec_raw(p, ofs + 1 + len_octets, len, vb->value_len, vb->value);
            snmp_varbind_tail_add(&m_stat->invb, vb);
          }
          else
          {
            derr = ERR_ARG;
          }
        }
        else
        {
          derr = ERR_ARG;
        }
        break;
      default:
        derr = ERR_ARG;
        break;
    }
    if (derr != ERR_OK)
    {
      snmp_inc_snmpinasnparseerrs();
      /* free varbinds (if available) */
      snmp_varbind_list_free(&m_stat->invb);
      return ERR_ARG;
    }
    ofs += (1 + len_octets + len);
    vb_len -= (1 + len_octets + len);
  }

  if (m_stat->rt == SNMP_ASN1_PDU_SET_REQ)
  {
    snmp_add_snmpintotalsetvars(m_stat->invb.count);
  }
  else
  {
    snmp_add_snmpintotalreqvars(m_stat->invb.count);
  }

  *ofs_ret = ofs;
  return ERR_OK;
}

struct snmp_varbind*
snmp_varbind_alloc(struct snmp_obj_id *oid, u8_t type, u8_t len)
{
  struct snmp_varbind *vb;

  vb = (struct snmp_varbind *)mem_malloc(sizeof(struct snmp_varbind));
  if (vb != NULL)
  {
    u8_t i;
    
    vb->next = NULL;
    vb->prev = NULL;
    i = oid->len;
    vb->ident_len = i;
    if (i > 0)
    {
      /* allocate array of s32_t for our object identifier */
      vb->ident = (s32_t*)mem_malloc(sizeof(s32_t) * i);
      if (vb->ident == NULL)
      {
        mem_free(vb);
        return NULL;
      }
      while(i > 0)
      {
        i--;
        vb->ident[i] = oid->id[i];
      }
    }
    else
    {
      /* i == 0, pass zero length object identifier */
      vb->ident = NULL;
    }
    vb->value_type = type;
    vb->value_len = len;
    if (len > 0)
    {
      /* allocate raw bytes for our object value */
      vb->value = mem_malloc(len);
      if (vb->value == NULL)
      {
        if (vb->ident != NULL)
        {
          mem_free(vb->ident);
        }
        mem_free(vb);
        return NULL;
      }
    }
    else
    {
      /* ASN1_NUL type, or zero length ASN1_OC_STR */
      vb->value = NULL;
    }
  }
  return vb;
}

void
snmp_varbind_free(struct snmp_varbind *vb)
{
  if (vb->value != NULL )
  {
    mem_free(vb->value);
  }
  if (vb->ident != NULL )
  {
    mem_free(vb->ident);
  }
  mem_free(vb);
}

void
snmp_varbind_list_free(struct snmp_varbind_root *root)
{
  struct snmp_varbind *vb, *prev;

  vb = root->tail;
  while ( vb != NULL )
  {
    prev = vb->prev;
    snmp_varbind_free(vb);
    vb = prev;
  }
  root->count = 0;
  root->head = NULL;
  root->tail = NULL;
}

void
snmp_varbind_tail_add(struct snmp_varbind_root *root, struct snmp_varbind *vb)
{
  if (root->count == 0)
  {
    /* add first varbind to list */
    root->head = vb;
    root->tail = vb;
  }
  else
  {
    /* add nth varbind to list tail */
    root->tail->next = vb;
    vb->prev = root->tail;
    root->tail = vb;
  }
  root->count += 1;
}

struct snmp_varbind*
snmp_varbind_tail_remove(struct snmp_varbind_root *root)
{
  struct snmp_varbind* vb;

  if (root->count > 0)
  {
    /* remove tail varbind */
    vb = root->tail;
    root->tail = vb->prev;
    vb->prev->next = NULL;
    root->count -= 1;
  }
  else
  {
    /* nothing to remove */
    vb = NULL;
  }
  return vb;
}

#endif /* LWIP_SNMP */
