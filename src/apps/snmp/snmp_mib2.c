/**
 * @file
 * Management Information Base II (RFC1213) objects and functions.
 *
 * @note the object identifiers for this MIB-2 and private MIB tree
 * must be kept in sorted ascending order. This to ensure correct getnext operation.
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */
#if SNMP_LWIP_MIB2

#if !LWIP_STATS
#error LWIP_SNMP MIB2 needs LWIP_STATS (for MIB2)
#endif
#if !MIB2_STATS
#error LWIP_SNMP MIB2 needs MIB2_STATS (for MIB2)
#endif

#include "lwip/snmp.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmp_mib2.h"
#include "lwip/apps/snmp_scalar.h"
#include "lwip/apps/snmp_table.h"
#include "lwip/apps/snmp_threadsync.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/mem.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip/sys.h"
#include "netif/etharp.h"
#include "lwip/stats.h"

#include <string.h>

static u8_t
netif_to_num(const struct netif *netif)
{
  u8_t result = 0;
  struct netif *netif_iterator = netif_list;

  while (netif_iterator != NULL) {
    result++;

    if(netif_iterator == netif) {
      return result;
    }

    netif_iterator = netif_iterator->next;
  }

  LWIP_ASSERT("netif not found in netif_list", 0);
  return 0;
}

#define MIB2_AUTH_TRAPS_ENABLED  1
#define MIB2_AUTH_TRAPS_DISABLED 2

#if SNMP_USE_NETCONN
#include "lwip/tcpip.h"
void
snmp_mib2_lwip_synchronizer(snmp_threadsync_called_fn fn, void* arg)
{
  tcpip_callback_with_block(fn, arg, 1);
}

struct snmp_threadsync_instance snmp_mib2_lwip_locks;

#define SYNC_NODE_NAME(node_name) node_name ## _synced
#define CREATE_LWIP_SYNC_NODE(oid, node_name) \
   static const struct snmp_threadsync_node node_name ## _synced = SNMP_CREATE_THREAD_SYNC_NODE(oid, &node_name.node, &snmp_mib2_lwip_locks);
#else
#define SYNC_NODE_NAME(node_name) node_name
#define CREATE_LWIP_SYNC_NODE(oid, node_name)
#endif

/* --- snmp .1.3.6.1.2.1.11 ----------------------------------------------------- */
static u16_t snmp_get_value(const struct snmp_scalar_array_node_def *node, void *value);
static snmp_err_t snmp_set_test(const struct snmp_scalar_array_node_def *node, u16_t len, void *value);
static snmp_err_t snmp_set_value(const struct snmp_scalar_array_node_def *node, u16_t len, void *value);

/* the following nodes access variables in SNMP stack (snmp_stats) from SNMP worker thread -> OK, no sync needed */ 
static const struct snmp_scalar_array_node_def snmp_nodes[] = {
  { 1, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInPkts */
  { 2, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutPkts */
  { 3, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInBadVersions */
  { 4, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInBadCommunityNames */
  { 5, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInBadCommunityUses */
  { 6, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInASNParseErrs */
  { 8, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInTooBigs */
  { 9, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInNoSuchNames */
  {10, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInBadValues */
  {11, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInReadOnlys */
  {12, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInGenErrs */
  {13, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInTotalReqVars */
  {14, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInTotalSetVars */
  {15, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInGetRequests */
  {16, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInGetNexts */
  {17, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInSetRequests */
  {18, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInGetResponses */
  {19, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpInTraps */
  {20, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutTooBigs */
  {21, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutNoSuchNames */
  {22, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutBadValues */
  {24, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutGenErrs */
  {25, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutGetRequests */
  {26, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutGetNexts */
  {27, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutSetRequests */
  {28, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutGetResponses */
  {29, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpOutTraps */
  {30, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_WRITE}, /* snmpEnableAuthenTraps */
  {31, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_ONLY},  /* snmpSilentDrops */
  {32, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_ONLY}   /* snmpProxyDrops */
};
static const struct snmp_scalar_array_node snmp_root = SNMP_SCALAR_CREATE_ARRAY_NODE(11, snmp_nodes, snmp_get_value, snmp_set_test, snmp_set_value);

/* dot3 and EtherLike MIB not planned. (transmission .1.3.6.1.2.1.10) */
/* historical (some say hysterical). (cmot .1.3.6.1.2.1.9) */
/* lwIP has no EGP, thus may not implement it. (egp .1.3.6.1.2.1.8) */

/* --- udp .1.3.6.1.2.1.7 ----------------------------------------------------- */
#if LWIP_UDP
static u16_t udp_get_value(struct snmp_node_instance* instance, void* value);

static const struct snmp_scalar_node udp_inDatagrams    = SNMP_SCALAR_CREATE_NODE_READONLY(1, SNMP_ASN1_TYPE_COUNTER,   udp_get_value);
static const struct snmp_scalar_node udp_noPorts        = SNMP_SCALAR_CREATE_NODE_READONLY(2, SNMP_ASN1_TYPE_COUNTER,   udp_get_value);
static const struct snmp_scalar_node udp_inErrors       = SNMP_SCALAR_CREATE_NODE_READONLY(3, SNMP_ASN1_TYPE_COUNTER,   udp_get_value);
static const struct snmp_scalar_node udp_outDatagrams   = SNMP_SCALAR_CREATE_NODE_READONLY(4, SNMP_ASN1_TYPE_COUNTER,   udp_get_value);
static const struct snmp_scalar_node udp_HCInDatagrams  = SNMP_SCALAR_CREATE_NODE_READONLY(8, SNMP_ASN1_TYPE_COUNTER64, udp_get_value);
static const struct snmp_scalar_node udp_HCOutDatagrams = SNMP_SCALAR_CREATE_NODE_READONLY(9, SNMP_ASN1_TYPE_COUNTER64, udp_get_value);

#if LWIP_IPV4
static snmp_err_t  udp_Table_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  udp_Table_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);

static const struct snmp_table_simple_col_def udp_Table_columns[] = {
  { 1, SNMP_ASN1_TYPE_IPADDR,  SNMP_VARIANT_VALUE_TYPE_U32 }, /* udpLocalAddress */
  { 2, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }  /* udpLocalPort */
};
static const struct snmp_table_simple_node udp_Table = SNMP_TABLE_CREATE_SIMPLE(5, udp_Table_columns, udp_Table_get_cell_value, udp_Table_get_next_cell_instance_and_value);
#endif /* LWIP_IPV4 */

static snmp_err_t  udp_endpointTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  udp_endpointTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);

static const struct snmp_table_simple_col_def udp_endpointTable_columns[] = {
  /* all items except udpEndpointProcess are declared as not-accessible */   
  { 8, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }  /* udpEndpointProcess */
};

static const struct snmp_table_simple_node udp_endpointTable = SNMP_TABLE_CREATE_SIMPLE(7, udp_endpointTable_columns, udp_endpointTable_get_cell_value, udp_endpointTable_get_next_cell_instance_and_value);

/* the following nodes access variables in LWIP stack from SNMP worker thread and must therefore be synced to LWIP (TCPIP) thread */ 
CREATE_LWIP_SYNC_NODE(1, udp_inDatagrams)
CREATE_LWIP_SYNC_NODE(2, udp_noPorts)
CREATE_LWIP_SYNC_NODE(3, udp_inErrors)
CREATE_LWIP_SYNC_NODE(4, udp_outDatagrams)
#if LWIP_IPV4
CREATE_LWIP_SYNC_NODE(5, udp_Table)
#endif /* LWIP_IPV4 */
CREATE_LWIP_SYNC_NODE(7, udp_endpointTable)
CREATE_LWIP_SYNC_NODE(8, udp_HCInDatagrams)
CREATE_LWIP_SYNC_NODE(9, udp_HCOutDatagrams)

static const struct snmp_node* udp_nodes[] = {
  &SYNC_NODE_NAME(udp_inDatagrams).node.node,
  &SYNC_NODE_NAME(udp_noPorts).node.node,
  &SYNC_NODE_NAME(udp_inErrors).node.node,
  &SYNC_NODE_NAME(udp_outDatagrams).node.node,
#if LWIP_IPV4
  &SYNC_NODE_NAME(udp_Table).node.node,
#endif /* LWIP_IPV4 */
  &SYNC_NODE_NAME(udp_endpointTable).node.node,
  &SYNC_NODE_NAME(udp_HCInDatagrams).node.node,
  &SYNC_NODE_NAME(udp_HCOutDatagrams).node.node
};

static const struct snmp_tree_node udp_root = SNMP_CREATE_TREE_NODE(7, udp_nodes);
#endif /* LWIP_UDP */


/* --- tcp .1.3.6.1.2.1.6 ----------------------------------------------------- */
/* implement this group only, if the TCP protocol is available */
#if LWIP_TCP
static u16_t tcp_get_value(struct snmp_node_instance* instance, void* value);

static const struct snmp_scalar_node tcp_RtoAlgorithm  = SNMP_SCALAR_CREATE_NODE_READONLY(1, SNMP_ASN1_TYPE_INTEGER, tcp_get_value);
static const struct snmp_scalar_node tcp_RtoMin        = SNMP_SCALAR_CREATE_NODE_READONLY(2, SNMP_ASN1_TYPE_INTEGER, tcp_get_value);
static const struct snmp_scalar_node tcp_RtoMax        = SNMP_SCALAR_CREATE_NODE_READONLY(3, SNMP_ASN1_TYPE_INTEGER, tcp_get_value);
static const struct snmp_scalar_node tcp_MaxConn       = SNMP_SCALAR_CREATE_NODE_READONLY(4, SNMP_ASN1_TYPE_INTEGER, tcp_get_value);
static const struct snmp_scalar_node tcp_ActiveOpens   = SNMP_SCALAR_CREATE_NODE_READONLY(5, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_PassiveOpens  = SNMP_SCALAR_CREATE_NODE_READONLY(6, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_AttemptFails  = SNMP_SCALAR_CREATE_NODE_READONLY(7, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_EstabResets   = SNMP_SCALAR_CREATE_NODE_READONLY(8, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_CurrEstab     = SNMP_SCALAR_CREATE_NODE_READONLY(9, SNMP_ASN1_TYPE_GAUGE, tcp_get_value);
static const struct snmp_scalar_node tcp_InSegs        = SNMP_SCALAR_CREATE_NODE_READONLY(10, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_OutSegs       = SNMP_SCALAR_CREATE_NODE_READONLY(11, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_RetransSegs   = SNMP_SCALAR_CREATE_NODE_READONLY(12, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_InErrs        = SNMP_SCALAR_CREATE_NODE_READONLY(14, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_OutRsts       = SNMP_SCALAR_CREATE_NODE_READONLY(15, SNMP_ASN1_TYPE_COUNTER, tcp_get_value);
static const struct snmp_scalar_node tcp_HCInSegs      = SNMP_SCALAR_CREATE_NODE_READONLY(17, SNMP_ASN1_TYPE_COUNTER64, tcp_get_value);
static const struct snmp_scalar_node tcp_HCOutSegs     = SNMP_SCALAR_CREATE_NODE_READONLY(18, SNMP_ASN1_TYPE_COUNTER64, tcp_get_value);

#if LWIP_IPV4
static snmp_err_t  tcp_ConnTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  tcp_ConnTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);

static const struct snmp_table_simple_col_def tcp_ConnTable_columns[] = {
  {  1, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }, /* tcpConnState */
  {  2, SNMP_ASN1_TYPE_IPADDR,  SNMP_VARIANT_VALUE_TYPE_U32 }, /* tcpConnLocalAddress */
  {  3, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }, /* tcpConnLocalPort */
  {  4, SNMP_ASN1_TYPE_IPADDR,  SNMP_VARIANT_VALUE_TYPE_U32 }, /* tcpConnRemAddress */
  {  5, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }  /* tcpConnRemPort */
};

static const struct snmp_table_simple_node tcp_ConnTable = SNMP_TABLE_CREATE_SIMPLE(13, tcp_ConnTable_columns, tcp_ConnTable_get_cell_value, tcp_ConnTable_get_next_cell_instance_and_value);
#endif /* LWIP_IPV4 */

static snmp_err_t  tcp_ConnectionTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  tcp_ConnectionTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);

static const struct snmp_table_simple_col_def tcp_ConnectionTable_columns[] = {
  /* all items except tcpConnectionState and tcpConnectionProcess are declared as not-accessible */   
  { 7, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }, /* tcpConnectionState */
  { 8, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }  /* tcpConnectionProcess */
};

static const struct snmp_table_simple_node tcp_ConnectionTable = SNMP_TABLE_CREATE_SIMPLE(19, tcp_ConnectionTable_columns, tcp_ConnectionTable_get_cell_value, tcp_ConnectionTable_get_next_cell_instance_and_value);


static snmp_err_t  tcp_ListenerTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  tcp_ListenerTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);

static const struct snmp_table_simple_col_def tcp_ListenerTable_columns[] = {
  /* all items except tcpListenerProcess are declared as not-accessible */   
  { 4, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }  /* tcpListenerProcess */
};

static const struct snmp_table_simple_node tcp_ListenerTable = SNMP_TABLE_CREATE_SIMPLE(20, tcp_ListenerTable_columns, tcp_ListenerTable_get_cell_value, tcp_ListenerTable_get_next_cell_instance_and_value);

/* the following nodes access variables in LWIP stack from SNMP worker thread and must therefore be synced to LWIP (TCPIP) thread */ 
CREATE_LWIP_SYNC_NODE( 1, tcp_RtoAlgorithm)
CREATE_LWIP_SYNC_NODE( 2, tcp_RtoMin)
CREATE_LWIP_SYNC_NODE( 3, tcp_RtoMax)
CREATE_LWIP_SYNC_NODE( 4, tcp_MaxConn)
CREATE_LWIP_SYNC_NODE( 5, tcp_ActiveOpens)
CREATE_LWIP_SYNC_NODE( 6, tcp_PassiveOpens)
CREATE_LWIP_SYNC_NODE( 7, tcp_AttemptFails)
CREATE_LWIP_SYNC_NODE( 8, tcp_EstabResets)
CREATE_LWIP_SYNC_NODE( 9, tcp_CurrEstab)
CREATE_LWIP_SYNC_NODE(10, tcp_InSegs)
CREATE_LWIP_SYNC_NODE(11, tcp_OutSegs)
CREATE_LWIP_SYNC_NODE(12, tcp_RetransSegs)
#if LWIP_IPV4
CREATE_LWIP_SYNC_NODE(13, tcp_ConnTable)
#endif /* LWIP_IPV4 */
CREATE_LWIP_SYNC_NODE(14, tcp_InErrs)
CREATE_LWIP_SYNC_NODE(15, tcp_OutRsts)
CREATE_LWIP_SYNC_NODE(17, tcp_HCInSegs)
CREATE_LWIP_SYNC_NODE(18, tcp_HCOutSegs)
CREATE_LWIP_SYNC_NODE(19, tcp_ConnectionTable)
CREATE_LWIP_SYNC_NODE(20, tcp_ListenerTable)

static const struct snmp_node* tcp_nodes[] = {
  &SYNC_NODE_NAME(tcp_RtoAlgorithm).node.node,
  &SYNC_NODE_NAME(tcp_RtoMin).node.node,
  &SYNC_NODE_NAME(tcp_RtoMax).node.node,
  &SYNC_NODE_NAME(tcp_MaxConn).node.node,
  &SYNC_NODE_NAME(tcp_ActiveOpens).node.node,
  &SYNC_NODE_NAME(tcp_PassiveOpens).node.node,
  &SYNC_NODE_NAME(tcp_AttemptFails).node.node,
  &SYNC_NODE_NAME(tcp_EstabResets).node.node,
  &SYNC_NODE_NAME(tcp_CurrEstab).node.node,
  &SYNC_NODE_NAME(tcp_InSegs).node.node,
  &SYNC_NODE_NAME(tcp_OutSegs).node.node,
  &SYNC_NODE_NAME(tcp_RetransSegs).node.node,
#if LWIP_IPV4
  &SYNC_NODE_NAME(tcp_ConnTable).node.node,
#endif /* LWIP_IPV4 */
  &SYNC_NODE_NAME(tcp_InErrs).node.node,
  &SYNC_NODE_NAME(tcp_OutRsts).node.node,
  &SYNC_NODE_NAME(tcp_HCInSegs).node.node,
  &SYNC_NODE_NAME(tcp_HCOutSegs).node.node,
  &SYNC_NODE_NAME(tcp_ConnectionTable).node.node,
  &SYNC_NODE_NAME(tcp_ListenerTable).node.node
};

static const struct snmp_tree_node tcp_root = SNMP_CREATE_TREE_NODE(6, tcp_nodes);
#endif /* LWIP_TCP */

/* --- icmp .1.3.6.1.2.1.5 ----------------------------------------------------- */
#if LWIP_ICMP
static u16_t icmp_get_value(const struct snmp_scalar_array_node_def *node, void *value);

static const struct snmp_scalar_array_node_def icmp_nodes[] = {
  { 1, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 2, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 3, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 4, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 5, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 6, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 7, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 8, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  { 9, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {10, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {11, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {12, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {13, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {14, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {15, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {16, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {17, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {18, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {19, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {20, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {21, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {22, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {23, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {24, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {25, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
  {26, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY}
};
static const struct snmp_scalar_array_node icmp_root = SNMP_SCALAR_CREATE_ARRAY_NODE(5, icmp_nodes, icmp_get_value, NULL, NULL);
#endif /* LWIP_ICMP */

#if LWIP_IPV4
/* --- ip .1.3.6.1.2.1.4 ----------------------------------------------------- */
static u16_t ip_get_value(struct snmp_node_instance* instance, void* value);
static snmp_err_t  ip_set_test(struct snmp_node_instance* instance, u16_t len, void *value);
static snmp_err_t  ip_set_value(struct snmp_node_instance* instance, u16_t len, void *value);

static snmp_err_t  ip_AddrTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  ip_AddrTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  ip_RouteTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  ip_RouteTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  ip_NetToMediaTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len);
static snmp_err_t  ip_NetToMediaTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len);

static const struct snmp_scalar_node ip_Forwarding      = SNMP_SCALAR_CREATE_NODE(1, SNMP_NODE_INSTANCE_READ_WRITE, SNMP_ASN1_TYPE_INTEGER, ip_get_value, ip_set_test, ip_set_value);
static const struct snmp_scalar_node ip_DefaultTTL      = SNMP_SCALAR_CREATE_NODE(2, SNMP_NODE_INSTANCE_READ_WRITE, SNMP_ASN1_TYPE_INTEGER, ip_get_value, ip_set_test, ip_set_value);
static const struct snmp_scalar_node ip_InReceives      = SNMP_SCALAR_CREATE_NODE_READONLY(3, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_InHdrErrors     = SNMP_SCALAR_CREATE_NODE_READONLY(4, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_InAddrErrors    = SNMP_SCALAR_CREATE_NODE_READONLY(5, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_ForwDatagrams   = SNMP_SCALAR_CREATE_NODE_READONLY(6, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_InUnknownProtos = SNMP_SCALAR_CREATE_NODE_READONLY(7, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_InDiscards      = SNMP_SCALAR_CREATE_NODE_READONLY(8, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_InDelivers      = SNMP_SCALAR_CREATE_NODE_READONLY(9, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_OutRequests     = SNMP_SCALAR_CREATE_NODE_READONLY(10, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_OutDiscards     = SNMP_SCALAR_CREATE_NODE_READONLY(11, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_OutNoRoutes     = SNMP_SCALAR_CREATE_NODE_READONLY(12, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_ReasmTimeout    = SNMP_SCALAR_CREATE_NODE_READONLY(13, SNMP_ASN1_TYPE_INTEGER, ip_get_value);
static const struct snmp_scalar_node ip_ReasmReqds      = SNMP_SCALAR_CREATE_NODE_READONLY(14, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_ReasmOKs        = SNMP_SCALAR_CREATE_NODE_READONLY(15, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_ReasmFails      = SNMP_SCALAR_CREATE_NODE_READONLY(16, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_FragOKs         = SNMP_SCALAR_CREATE_NODE_READONLY(17, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_FragFails       = SNMP_SCALAR_CREATE_NODE_READONLY(18, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_FragCreates     = SNMP_SCALAR_CREATE_NODE_READONLY(19, SNMP_ASN1_TYPE_COUNTER, ip_get_value);
static const struct snmp_scalar_node ip_RoutingDiscards = SNMP_SCALAR_CREATE_NODE_READONLY(23, SNMP_ASN1_TYPE_COUNTER, ip_get_value);

static const struct snmp_table_simple_col_def ip_AddrTable_columns[] = {
  { 1, SNMP_ASN1_TYPE_IPADDR,  SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipAdEntAddr */
  { 2, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipAdEntIfIndex */
  { 3, SNMP_ASN1_TYPE_IPADDR,  SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipAdEntNetMask */
  { 4, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipAdEntBcastAddr */
  { 5, SNMP_ASN1_TYPE_INTEGER, SNMP_VARIANT_VALUE_TYPE_U32 }  /* ipAdEntReasmMaxSize */
};

static const struct snmp_table_simple_node ip_AddrTable = SNMP_TABLE_CREATE_SIMPLE(20, ip_AddrTable_columns, ip_AddrTable_get_cell_value, ip_AddrTable_get_next_cell_instance_and_value);

static const struct snmp_table_simple_col_def ip_RouteTable_columns[] = {
  {  1, SNMP_ASN1_TYPE_IPADDR,    SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteDest */
  {  2, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteIfIndex */
  {  3, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_S32 }, /* ipRouteMetric1 */
  {  4, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_S32 }, /* ipRouteMetric2 */
  {  5, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_S32 }, /* ipRouteMetric3 */
  {  6, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_S32 }, /* ipRouteMetric4 */
  {  7, SNMP_ASN1_TYPE_IPADDR,    SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteNextHop */
  {  8, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteType */
  {  9, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteProto */
  { 10, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteAge */
  { 11, SNMP_ASN1_TYPE_IPADDR,    SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipRouteMask */
  { 12, SNMP_ASN1_TYPE_INTEGER,   SNMP_VARIANT_VALUE_TYPE_S32 }, /* ipRouteMetric5 */
  { 13, SNMP_ASN1_TYPE_OBJECT_ID, SNMP_VARIANT_VALUE_TYPE_PTR }  /* ipRouteInfo */
};

static const struct snmp_table_simple_node ip_RouteTable = SNMP_TABLE_CREATE_SIMPLE(21, ip_RouteTable_columns, ip_RouteTable_get_cell_value, ip_RouteTable_get_next_cell_instance_and_value);
#endif /* LWIP_IPV4 */

#if LWIP_ARP && LWIP_IPV4
static const struct snmp_table_simple_col_def ip_NetToMediaTable_columns[] = {
  {  1, SNMP_ASN1_TYPE_INTEGER,      SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipNetToMediaIfIndex */
  {  2, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_VARIANT_VALUE_TYPE_PTR }, /* ipNetToMediaPhysAddress */
  {  3, SNMP_ASN1_TYPE_IPADDR,       SNMP_VARIANT_VALUE_TYPE_U32 }, /* ipNetToMediaNetAddress */
  {  4, SNMP_ASN1_TYPE_INTEGER,      SNMP_VARIANT_VALUE_TYPE_U32 }  /* ipNetToMediaType */
};

static const struct snmp_table_simple_node ip_NetToMediaTable = SNMP_TABLE_CREATE_SIMPLE(22, ip_NetToMediaTable_columns, ip_NetToMediaTable_get_cell_value, ip_NetToMediaTable_get_next_cell_instance_and_value);
#endif /* LWIP_ARP && LWIP_IPV4 */

#if LWIP_IPV4
/* the following nodes access variables in LWIP stack from SNMP worker thread and must therefore be synced to LWIP (TCPIP) thread */ 
CREATE_LWIP_SYNC_NODE( 1, ip_Forwarding)
CREATE_LWIP_SYNC_NODE( 2, ip_DefaultTTL)
CREATE_LWIP_SYNC_NODE( 3, ip_InReceives)
CREATE_LWIP_SYNC_NODE( 4, ip_InHdrErrors)
CREATE_LWIP_SYNC_NODE( 5, ip_InAddrErrors)
CREATE_LWIP_SYNC_NODE( 6, ip_ForwDatagrams)
CREATE_LWIP_SYNC_NODE( 7, ip_InUnknownProtos)
CREATE_LWIP_SYNC_NODE( 8, ip_InDiscards)
CREATE_LWIP_SYNC_NODE( 9, ip_InDelivers)
CREATE_LWIP_SYNC_NODE(10, ip_OutRequests)
CREATE_LWIP_SYNC_NODE(11, ip_OutDiscards)
CREATE_LWIP_SYNC_NODE(12, ip_OutNoRoutes)
CREATE_LWIP_SYNC_NODE(13, ip_ReasmTimeout)
CREATE_LWIP_SYNC_NODE(14, ip_ReasmReqds)
CREATE_LWIP_SYNC_NODE(15, ip_ReasmOKs)
CREATE_LWIP_SYNC_NODE(15, ip_ReasmFails)
CREATE_LWIP_SYNC_NODE(17, ip_FragOKs)
CREATE_LWIP_SYNC_NODE(18, ip_FragFails)
CREATE_LWIP_SYNC_NODE(19, ip_FragCreates)
CREATE_LWIP_SYNC_NODE(20, ip_AddrTable)
CREATE_LWIP_SYNC_NODE(21, ip_RouteTable)
#if LWIP_ARP
CREATE_LWIP_SYNC_NODE(22, ip_NetToMediaTable)
#endif /* LWIP_ARP */
CREATE_LWIP_SYNC_NODE(23, ip_RoutingDiscards)

static const struct snmp_node* ip_nodes[] = {
  &SYNC_NODE_NAME(ip_Forwarding).node.node,
  &SYNC_NODE_NAME(ip_DefaultTTL).node.node,
  &SYNC_NODE_NAME(ip_InReceives).node.node,
  &SYNC_NODE_NAME(ip_InHdrErrors).node.node,
  &SYNC_NODE_NAME(ip_InAddrErrors).node.node,
  &SYNC_NODE_NAME(ip_ForwDatagrams).node.node,
  &SYNC_NODE_NAME(ip_InUnknownProtos).node.node,
  &SYNC_NODE_NAME(ip_InDiscards).node.node,
  &SYNC_NODE_NAME(ip_InDelivers).node.node,
  &SYNC_NODE_NAME(ip_OutRequests).node.node,
  &SYNC_NODE_NAME(ip_OutDiscards).node.node,
  &SYNC_NODE_NAME(ip_OutNoRoutes).node.node,
  &SYNC_NODE_NAME(ip_ReasmTimeout).node.node,
  &SYNC_NODE_NAME(ip_ReasmReqds).node.node,
  &SYNC_NODE_NAME(ip_ReasmOKs).node.node,
  &SYNC_NODE_NAME(ip_ReasmFails).node.node,
  &SYNC_NODE_NAME(ip_FragOKs).node.node,
  &SYNC_NODE_NAME(ip_FragFails).node.node,
  &SYNC_NODE_NAME(ip_FragCreates).node.node,
  &SYNC_NODE_NAME(ip_AddrTable).node.node,
  &SYNC_NODE_NAME(ip_RouteTable).node.node,
#if LWIP_ARP
  &SYNC_NODE_NAME(ip_NetToMediaTable).node.node,
#endif /* LWIP_ARP */
  &SYNC_NODE_NAME(ip_RoutingDiscards).node.node
};

static const struct snmp_tree_node ip_root = SNMP_CREATE_TREE_NODE(4, ip_nodes);
#endif /* LWIP_IPV4 */

/* --- at .1.3.6.1.2.1.3 ----------------------------------------------------- */

#if LWIP_ARP && LWIP_IPV4
/* at node table is a subset of ip_nettomedia table (same rows but less columns) */
static const struct snmp_table_simple_col_def at_Table_columns[] = {
  { 1, SNMP_ASN1_TYPE_INTEGER,      SNMP_VARIANT_VALUE_TYPE_U32 }, /* atIfIndex */
  { 2, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_VARIANT_VALUE_TYPE_PTR }, /* atPhysAddress */
  { 3, SNMP_ASN1_TYPE_IPADDR,       SNMP_VARIANT_VALUE_TYPE_U32 }  /* atNetAddress */
};

static const struct snmp_table_simple_node at_Table = SNMP_TABLE_CREATE_SIMPLE(1, at_Table_columns, ip_NetToMediaTable_get_cell_value, ip_NetToMediaTable_get_next_cell_instance_and_value);

/* the following nodes access variables in LWIP stack from SNMP worker thread and must therefore be synced to LWIP (TCPIP) thread */ 
CREATE_LWIP_SYNC_NODE(1, at_Table)

static const struct snmp_node* at_nodes[] = {
  &SYNC_NODE_NAME(at_Table).node.node
};

static const struct snmp_tree_node at_root = SNMP_CREATE_TREE_NODE(3, at_nodes);
#endif /* LWIP_ARP && LWIP_IPV4 */

/* --- interfaces .1.3.6.1.2.1.2 ----------------------------------------------------- */
static u16_t interfaces_get_value(struct snmp_node_instance* instance, void* value);
static snmp_err_t  interfaces_Table_get_cell_instance(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, struct snmp_node_instance* cell_instance);
static snmp_err_t  interfaces_Table_get_next_cell_instance(const u32_t* column, struct snmp_obj_id* row_oid, struct snmp_node_instance* cell_instance);
static u16_t interfaces_Table_get_value(struct snmp_node_instance* instance, void* value);
#if !SNMP_SAFE_REQUESTS
static snmp_err_t  interfaces_Table_set_test(struct snmp_node_instance* instance, u16_t len, void *value);
static snmp_err_t  interfaces_Table_set_value(struct snmp_node_instance* instance, u16_t len, void *value);
#endif

static const struct snmp_scalar_node interfaces_Number = SNMP_SCALAR_CREATE_NODE_READONLY(1, SNMP_ASN1_TYPE_INTEGER, interfaces_get_value);

static const struct snmp_table_col_def interfaces_Table_columns[] = {
  {  1, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifIndex */
  {  2, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY }, /* ifDescr */
  {  3, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifType */
  {  4, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifMtu */
  {  5, SNMP_ASN1_TYPE_GAUGE,        SNMP_NODE_INSTANCE_READ_ONLY }, /* ifSpeed */
  {  6, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY }, /* ifPhysAddress */
#if !SNMP_SAFE_REQUESTS
  {  7, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_WRITE }, /* ifAdminStatus */
#else
  {  7, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifAdminStatus */
#endif
  {  8, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOperStatus */
  {  9, SNMP_ASN1_TYPE_TIMETICKS,    SNMP_NODE_INSTANCE_READ_ONLY }, /* ifLastChange */
  { 10, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInOctets */
  { 11, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInUcastPkts */
  { 12, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInNUcastPkts */
  { 13, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInDiscarts */
  { 14, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInErrors */
  { 15, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInUnkownProtos */
  { 16, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutOctets */
  { 17, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutUcastPkts */
  { 18, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutNUcastPkts */
  { 19, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutDiscarts */
  { 20, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutErrors */
  { 21, SNMP_ASN1_TYPE_GAUGE,        SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutQLen */
  { 22, SNMP_ASN1_TYPE_OBJECT_ID,    SNMP_NODE_INSTANCE_READ_ONLY }  /* ifSpecific */
};

#if !SNMP_SAFE_REQUESTS
static const struct snmp_table_node interfaces_Table = SNMP_TABLE_CREATE(
  2, interfaces_Table_columns, 
  interfaces_Table_get_cell_instance, interfaces_Table_get_next_cell_instance, 
  interfaces_Table_get_value, interfaces_Table_set_test, interfaces_Table_set_value);
#else
static const struct snmp_table_node interfaces_Table = SNMP_TABLE_CREATE(
  2, interfaces_Table_columns, 
  interfaces_Table_get_cell_instance, interfaces_Table_get_next_cell_instance, 
  interfaces_Table_get_value, NULL, NULL);
#endif

/* the following nodes access variables in LWIP stack from SNMP worker thread and must therefore be synced to LWIP (TCPIP) thread */ 
CREATE_LWIP_SYNC_NODE(1, interfaces_Number)
CREATE_LWIP_SYNC_NODE(2, interfaces_Table)

static const struct snmp_node* interface_nodes[] = {
  &SYNC_NODE_NAME(interfaces_Number).node.node,
  &SYNC_NODE_NAME(interfaces_Table).node.node
};

static const struct snmp_tree_node interface_root = SNMP_CREATE_TREE_NODE(2, interface_nodes);

/* --- system .1.3.6.1.2.1.1 ----------------------------------------------------- */
static u16_t system_get_value(const struct snmp_scalar_array_node_def *node, void *value);
static snmp_err_t system_set_test(const struct snmp_scalar_array_node_def *node, u16_t len, void *value);
static snmp_err_t system_set_value(const struct snmp_scalar_array_node_def *node, u16_t len, void *value);

static const struct snmp_scalar_array_node_def system_nodes[] = {
  {1, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY},  /* sysDescr */
  {2, SNMP_ASN1_TYPE_OBJECT_ID,    SNMP_NODE_INSTANCE_READ_ONLY},  /* sysObjectID */
  {3, SNMP_ASN1_TYPE_TIMETICKS,    SNMP_NODE_INSTANCE_READ_ONLY},  /* sysUpTime */
  {4, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_WRITE}, /* sysContact */
  {5, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_WRITE}, /* sysName */
  {6, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_WRITE}, /* sysLocation */
  {7, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY}   /* sysServices */
};

static const struct snmp_scalar_array_node system_node = SNMP_SCALAR_CREATE_ARRAY_NODE(1, system_nodes, system_get_value, system_set_test, system_set_value);

/* --- mib-2 .1.3.6.1.2.1 ----------------------------------------------------- */
static const struct snmp_node* mib2_nodes[] = {
  &system_node.node.node,
  &interface_root.node,
#if LWIP_ARP && LWIP_IPV4
  &at_root.node,
#endif /* LWIP_ARP && LWIP_IPV4 */
#if LWIP_IPV4
  &ip_root.node,
#endif /* LWIP_IPV4 */
#if LWIP_ICMP
  &icmp_root.node.node,
#endif /* LWIP_ICMP */
#if LWIP_TCP && LWIP_IPV4
  &tcp_root.node,
#endif /* LWIP_TCP && LWIP_IPV4 */
#if LWIP_UDP && LWIP_IPV4
  &udp_root.node,
#endif /* LWIP_UDP && LWIP_IPV4 */
  &snmp_root.node.node
};

static const struct snmp_tree_node mib2_root = SNMP_CREATE_TREE_NODE(1, mib2_nodes);

static const u32_t  mib2_base_oid_arr[] = { 1,3,6,1,2,1 };
const struct snmp_mib mib2 = SNMP_MIB_CREATE(mib2_base_oid_arr, &mib2_root.node);

/** mib-2.system.sysDescr */
static const u8_t   sysdescr_default[] = SNMP_LWIP_MIB2_SYSDESC;
static const u8_t*  sysdescr           = sysdescr_default;
static const u16_t* sysdescr_len       = NULL; /* use strlen for determining len */

/** mib-2.system.sysContact */
static const u8_t   syscontact_default[]     = SNMP_LWIP_MIB2_SYSCONTACT;
static const u8_t*  syscontact               = syscontact_default;
static const u16_t* syscontact_len           = NULL; /* use strlen for determining len */
static u8_t*        syscontact_wr            = NULL; /* if writable, points to the same buffer as syscontact (required for correct constness) */
static u16_t*       syscontact_wr_len        = NULL; /* if writable, points to the same buffer as syscontact_len (required for correct constness) */
static u16_t        syscontact_bufsize       = 0;    /* 0=not writable */

/** mib-2.system.sysName */
static const u8_t   sysname_default[]        = SNMP_LWIP_MIB2_SYSNAME;
static const u8_t*  sysname                  = sysname_default;
static const u16_t* sysname_len              = NULL; /* use strlen for determining len */
static u8_t*        sysname_wr               = NULL; /* if writable, points to the same buffer as sysname (required for correct constness) */
static u16_t*       sysname_wr_len           = NULL; /* if writable, points to the same buffer as sysname_len (required for correct constness) */
static u16_t        sysname_bufsize          = 0;    /* 0=not writable */

/** mib-2.system.sysLocation */
static const u8_t   syslocation_default[]    = SNMP_LWIP_MIB2_SYSLOCATION;
static const u8_t*  syslocation              = syslocation_default;
static const u16_t* syslocation_len           = NULL; /* use strlen for determining len */
static u8_t*        syslocation_wr            = NULL; /* if writable, points to the same buffer as syslocation (required for correct constness) */
static u16_t*       syslocation_wr_len        = NULL; /* if writable, points to the same buffer as syslocation_len (required for correct constness) */
static u16_t        syslocation_bufsize       = 0;    /* 0=not writable */

/**
 * Initializes sysDescr pointers.
 *
 * @param str if non-NULL then copy str pointer
 * @param len points to string length, excluding zero terminator
 */
void snmp_mib2_set_sysdescr(const u8_t *str, const u16_t *len)
{
  if (str != NULL) {
    sysdescr     = str;
    sysdescr_len = len;
  }
}

/**
 * Initializes sysContact pointers,
 * e.g. ptrs to non-volatile memory external to lwIP.
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator. 
 *        if set to NULL it is assumed that ocstr is NULL-terminated.
 * @param bufsize size of the buffer in bytes.
 *        (this is required because the buffer can be overwritten by snmp-set)
 *        if ocstrlen is NULL buffer needs space for terminating 0 byte.
 *        otherwise complete buffer is used for string.
 *        if bufsize is set to 0, the value is regarded as read-only.
 */
void snmp_mib2_set_syscontact(u8_t *ocstr, u16_t *ocstrlen, u16_t bufsize)
{
  if (ocstr != NULL) {
    syscontact         = ocstr;
    syscontact_wr      = ocstr;
    syscontact_len     = ocstrlen;
    syscontact_wr_len  = ocstrlen;
    syscontact_bufsize = bufsize;
  }
}

void snmp_mib2_set_syscontact_readonly(const u8_t *ocstr, const u16_t *ocstrlen)
{
  if (ocstr != NULL) {
    syscontact         = ocstr;
    syscontact_len     = ocstrlen;
    syscontact_wr      = NULL;
    syscontact_wr_len  = NULL;
    syscontact_bufsize = 0;
  }
}


/**
 * Initializes sysName pointers,
 * e.g. ptrs to non-volatile memory external to lwIP.
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator. 
 *        if set to NULL it is assumed that ocstr is NULL-terminated.
 * @param bufsize size of the buffer in bytes.
 *        (this is required because the buffer can be overwritten by snmp-set)
 *        if ocstrlen is NULL buffer needs space for terminating 0 byte.
 *        otherwise complete buffer is used for string.
 *        if bufsize is set to 0, the value is regarded as read-only.
 */
void snmp_mib2_set_sysname(u8_t *ocstr, u16_t *ocstrlen, u16_t bufsize)
{
  if (ocstr != NULL) {
    sysname         = ocstr;
    sysname_wr      = ocstr;
    sysname_len     = ocstrlen;
    sysname_wr_len  = ocstrlen;
    sysname_bufsize = bufsize;
  }
}

void snmp_mib2_set_sysname_readonly(const u8_t *ocstr, const u16_t *ocstrlen)
{
  if (ocstr != NULL) {
    sysname         = ocstr;
    sysname_len     = ocstrlen;
    sysname_wr      = NULL;
    sysname_wr_len  = NULL;
    sysname_bufsize = 0;
  }
}

/**
 * Initializes sysLocation pointers,
 * e.g. ptrs to non-volatile memory external to lwIP.
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator. 
 *        if set to NULL it is assumed that ocstr is NULL-terminated.
 * @param bufsize size of the buffer in bytes.
 *        (this is required because the buffer can be overwritten by snmp-set)
 *        if ocstrlen is NULL buffer needs space for terminating 0 byte.
 *        otherwise complete buffer is used for string.
 *        if bufsize is set to 0, the value is regarded as read-only.
 */
void snmp_mib2_set_syslocation(u8_t *ocstr, u16_t *ocstrlen, u16_t bufsize)
{
  if (ocstr != NULL) {
    syslocation         = ocstr;
    syslocation_wr      = ocstr;
    syslocation_len     = ocstrlen;
    syslocation_wr_len  = ocstrlen;
    syslocation_bufsize = bufsize;
  }
}

void snmp_mib2_set_syslocation_readonly(const u8_t *ocstr, const u16_t *ocstrlen)
{
  if (ocstr != NULL) {
    syslocation         = ocstr;
    syslocation_len     = ocstrlen;
    syslocation_wr      = NULL;
    syslocation_wr_len  = NULL;
    syslocation_bufsize = 0;
  }
}


/* --- system .1.3.6.1.2.1.1 ----------------------------------------------------- */

static u16_t
system_get_value(const struct snmp_scalar_array_node_def *node, void *value)
{
  const u8_t*  var = NULL;
  const u16_t* var_len;
  u16_t result;

  switch (node->oid) {
  case 1: /* sysDescr */
    var     = sysdescr;
    var_len = sysdescr_len;
    break;
  case 2: /* sysObjectID */
    {
      const struct snmp_obj_id* dev_enterprise_oid = snmp_get_device_enterprise_oid();
      MEMCPY(value, dev_enterprise_oid->id, dev_enterprise_oid->len * sizeof(u32_t));
      return dev_enterprise_oid->len * sizeof(u32_t);
    }
  case 3: /* sysUpTime */
    MIB2_COPY_SYSUPTIME_TO((u32_t*)value);
    return sizeof(u32_t);
  case 4: /* sysContact */
    var     = syscontact;
    var_len = syscontact_len;
    break;
  case 5: /* sysName */
    var     = sysname;
    var_len = sysname_len;
    break;
  case 6: /* sysLocation */
    var     = syslocation;
    var_len = syslocation_len;
    break;
  case 7: /* sysServices */
    *(s32_t*)value = SNMP_SYSSERVICES;
    return sizeof(s32_t);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_get_value(): unknown id: %"S32_F"\n", node->oid));
    return 0;
  }

  /* handle string values (OID 1,4,5 and 6) */
  LWIP_ASSERT("", (value != NULL));
  if (var_len == NULL) {
    result = (u16_t)strlen((const char*)var);
  } else {
    result = *var_len;
  }
  MEMCPY(value, var, result);
  return result;
}

static snmp_err_t 
system_set_test(const struct snmp_scalar_array_node_def *node, u16_t len, void *value)
{
  snmp_err_t ret = SNMP_ERR_WRONGVALUE;
  const u16_t* var_bufsize  = NULL;
  const u16_t* var_wr_len;

  LWIP_UNUSED_ARG(value);

  switch (node->oid) {
  case 4: /* sysContact */
    var_bufsize  = &syscontact_bufsize;
    var_wr_len   = syscontact_wr_len;
    break;
  case 5: /* sysName */
    var_bufsize  = &sysname_bufsize;
    var_wr_len   = sysname_wr_len;
    break;
  case 6: /* sysLocation */
    var_bufsize  = &syslocation_bufsize;
    var_wr_len   = syslocation_wr_len;
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_set_test(): unknown id: %"S32_F"\n", node->oid));
    return ret;
  }

  /* check if value is writable at all */
  if (*var_bufsize > 0) {
    if (var_wr_len == NULL) {
      /* we have to take the terminating 0 into account */
      if (len < *var_bufsize) {
        ret = SNMP_ERR_NOERROR;
      }
    } else {
      if (len <= *var_bufsize) {
        ret = SNMP_ERR_NOERROR;
      }
    }
  } else {
    ret = SNMP_ERR_NOTWRITABLE;
  }

  return ret;
}

static snmp_err_t 
system_set_value(const struct snmp_scalar_array_node_def *node, u16_t len, void *value)
{
  u8_t*  var_wr = NULL;
  u16_t* var_wr_len;

  switch (node->oid) {
  case 4: /* sysContact */
    var_wr     = syscontact_wr;
    var_wr_len = syscontact_wr_len;
    break;
  case 5: /* sysName */
    var_wr     = sysname_wr;
    var_wr_len = sysname_wr_len;
    break;
  case 6: /* sysLocation */
    var_wr     = syslocation_wr;
    var_wr_len = syslocation_wr_len;
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_set_value(): unknown id: %"S32_F"\n", node->oid));
    return SNMP_ERR_GENERROR;
  }

  /* no need to check size of target buffer, this was already done in set_test method */
  LWIP_ASSERT("", var_wr != NULL);
  MEMCPY(var_wr, value, len);
  
  if (var_wr_len == NULL) {
    /* add terminating 0 */
    var_wr[len] = 0;
  } else {
    *var_wr_len = len;
  }

  return SNMP_ERR_NOERROR;
}

/* --- interfaces .1.3.6.1.2.1.2 ----------------------------------------------------- */

static u16_t 
interfaces_get_value(struct snmp_node_instance* instance, void* value)
{
  if (instance->node->oid == 1) {
    s32_t *sint_ptr = (s32_t*)value;
    s32_t num_netifs = 0;

    struct netif *netif = netif_list;
    while (netif != NULL) {
      num_netifs++;
      netif = netif->next;
    }

    *sint_ptr = num_netifs;
    return sizeof(*sint_ptr);
  }

  return 0;
}

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range interfaces_Table_oid_ranges[] = {
  { 1, 0xff } /* netif->num is u8_t */
};

static const u8_t iftable_ifOutQLen         = 0;

static const u8_t iftable_ifOperStatus_up   = 1;
static const u8_t iftable_ifOperStatus_down = 2;

static const u8_t iftable_ifAdminStatus_up             = 1;
static const u8_t iftable_ifAdminStatus_lowerLayerDown = 7;
static const u8_t iftable_ifAdminStatus_down           = 2;

static snmp_err_t interfaces_Table_get_cell_instance(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, struct snmp_node_instance* cell_instance)
{
  u32_t ifIndex;
  struct netif *netif;

  LWIP_UNUSED_ARG(column);

  /* check if incoming OID length and if values are in plausible range */
  if(!snmp_oid_in_range(row_oid, row_oid_len, interfaces_Table_oid_ranges, LWIP_ARRAYSIZE(interfaces_Table_oid_ranges))) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* get netif index from incoming OID */
  ifIndex = row_oid[0];

  /* find netif with index */
  netif = netif_list;
  while (netif != NULL) {
    if(netif_to_num(netif) == ifIndex) {
      /* store netif pointer for subsequent operations (get/test/set) */
      cell_instance->reference.ptr = netif;
      return SNMP_ERR_NOERROR;
    }
    netif = netif->next;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t interfaces_Table_get_next_cell_instance(const u32_t* column, struct snmp_obj_id* row_oid, struct snmp_node_instance* cell_instance)
{
  struct netif *netif;
  struct snmp_next_oid_state state;
  u32_t result_temp[LWIP_ARRAYSIZE(interfaces_Table_oid_ranges)];

  LWIP_UNUSED_ARG(column);
  
  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(interfaces_Table_oid_ranges));

  /* iterate over all possible OIDs to find the next one */
  netif = netif_list;
  while (netif != NULL) {
    u32_t test_oid[LWIP_ARRAYSIZE(interfaces_Table_oid_ranges)];
    test_oid[0] = netif_to_num(netif);

    /* check generated OID: is it a candidate for the next one? */
    snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(interfaces_Table_oid_ranges), netif);

    netif = netif->next;
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* store netif pointer for subsequent operations (get/test/set) */
    cell_instance->reference.ptr = /* (struct netif*) */state.reference;
    return SNMP_ERR_NOERROR;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static u16_t interfaces_Table_get_value(struct snmp_node_instance* instance, void* value)
{
  struct netif *netif = (struct netif*)instance->reference.ptr;
  u32_t* value_u32 = (u32_t*)value;
  s32_t* value_s32 = (s32_t*)value;
  u16_t value_len;

  switch (SNMP_TABLE_GET_COLUMN_FROM_OID(instance->instance_oid.id))
  {
  case 1: /* ifIndex */
    *value_s32 = netif_to_num(netif);
    value_len = sizeof(*value_s32);
    break;
  case 2: /* ifDescr */
    value_len = sizeof(netif->name);
    MEMCPY(value, netif->name, value_len);
    break;
  case 3: /* ifType */
    *value_s32 = netif->link_type;
    value_len = sizeof(*value_s32);
    break;
  case 4: /* ifMtu */
    *value_s32 = netif->mtu;
    value_len = sizeof(*value_s32);
    break;
  case 5: /* ifSpeed */
    *value_u32 = netif->link_speed;
    value_len = sizeof(*value_u32);
    break;
  case 6: /* ifPhysAddress */
    value_len = sizeof(netif->hwaddr);
    MEMCPY(value, &netif->hwaddr, value_len);
    break;
  case 7: /* ifAdminStatus */
    if (netif_is_up(netif)) {
      *value_s32 = iftable_ifOperStatus_up;
    } else {
      *value_s32 = iftable_ifOperStatus_down;
    }
    value_len = sizeof(*value_s32);
    break;
  case 8: /* ifOperStatus */
    if (netif_is_up(netif)) {
      if (netif_is_link_up(netif)) {
        *value_s32 = iftable_ifAdminStatus_up;
      } else {
        *value_s32 = iftable_ifAdminStatus_lowerLayerDown;
      }
    } else {
      *value_s32 = iftable_ifAdminStatus_down;
    }
    value_len = sizeof(*value_s32);
    break;
  case 9: /* ifLastChange */
    *value_u32 = netif->ts;
    value_len = sizeof(*value_u32);
    break;
  case 10: /* ifInOctets */
    *value_u32 = netif->mib2_counters.ifinoctets;
    value_len = sizeof(*value_u32);
    break;
  case 11: /* ifInUcastPkts */
    *value_u32 = netif->mib2_counters.ifinucastpkts;
    value_len = sizeof(*value_u32);
    break;
  case 12: /* ifInNUcastPkts */
    *value_u32 = netif->mib2_counters.ifinnucastpkts;
    value_len = sizeof(*value_u32);
    break;
  case 13: /* ifInDiscards */
    *value_u32 = netif->mib2_counters.ifindiscards;
    value_len = sizeof(*value_u32);
    break;
  case 14: /* ifInErrors */
    *value_u32 = netif->mib2_counters.ifinerrors;
    value_len = sizeof(*value_u32);
    break;
  case 15: /* ifInUnkownProtos */
    *value_u32 = netif->mib2_counters.ifinunknownprotos;
    value_len = sizeof(*value_u32);
    break;
  case 16: /* ifOutOctets */
    *value_u32 = netif->mib2_counters.ifoutoctets;
    value_len = sizeof(*value_u32);
    break;
  case 17: /* ifOutUcastPkts */
    *value_u32 = netif->mib2_counters.ifoutucastpkts;
    value_len = sizeof(*value_u32);
    break;
  case 18: /* ifOutNUcastPkts */
    *value_u32 = netif->mib2_counters.ifoutnucastpkts;
    value_len = sizeof(*value_u32);
    break;
  case 19: /* ifOutDiscarts */
    *value_u32 = netif->mib2_counters.ifoutdiscards;
    value_len = sizeof(*value_u32);
    break;
  case 20: /* ifOutErrors */
    *value_u32 = netif->mib2_counters.ifouterrors;
    value_len = sizeof(*value_u32);
    break;
  case 21: /* ifOutQLen */
    *value_u32 = iftable_ifOutQLen;
    value_len = sizeof(*value_u32);
    break;
  /** @note returning zeroDotZero (0.0) no media specific MIB support */
  case 22: /* ifSpecific */
    value_len = snmp_zero_dot_zero.len * sizeof(u32_t);
    MEMCPY(value, snmp_zero_dot_zero.id, value_len);
    break;
  default:
    return 0;
  }

  return value_len;
}

#if !SNMP_SAFE_REQUESTS

static snmp_err_t interfaces_Table_set_test(struct snmp_node_instance* instance, u16_t len, void *value)
{
  s32_t *sint_ptr = (s32_t*)value;

  /* stack should never call this method for another column,
  because all other columns are set to readonly */
  LWIP_ASSERT("Invalid column", (SNMP_TABLE_GET_COLUMN_FROM_OID(instance->instance_oid.id) == 7));
  LWIP_UNUSED_ARG(len);

  if (*sint_ptr == 1 || *sint_ptr == 2)
  {
    return SNMP_ERR_NOERROR;
  }
    
  return SNMP_ERR_WRONGVALUE;
}

static snmp_err_t interfaces_Table_set_value(struct snmp_node_instance* instance, u16_t len, void *value)
{
  struct netif *netif = (struct netif*)instance->reference.ptr;
  s32_t *sint_ptr = (s32_t*)value;

  /* stack should never call this method for another column,
  because all other columns are set to readonly */
  LWIP_ASSERT("Invalid column", (SNMP_TABLE_GET_COLUMN_FROM_OID(instance->instance_oid.id) == 7));
  LWIP_UNUSED_ARG(len);

  if (*sint_ptr == 1) {
    netif_set_up(netif);
  } else if (*sint_ptr == 2) {
    netif_set_down(netif);
  }

  return SNMP_ERR_NOERROR;
}

#endif /* SNMP_SAFE_REQUESTS */

#if LWIP_IPV4
/* --- ip .1.3.6.1.2.1.4 ----------------------------------------------------- */

static u16_t 
ip_get_value(struct snmp_node_instance* instance, void* value)
{
  s32_t* sint_ptr = (s32_t*)value;
  u32_t* uint_ptr = (u32_t*)value;

  switch (instance->node->oid) {
  case 1: /* ipForwarding */
#if IP_FORWARD
    /* forwarding */
    *sint_ptr = 1;
#else
    /* not-forwarding */
    *sint_ptr = 2;
#endif
    return sizeof(*sint_ptr);
  case 2: /* ipDefaultTTL */
    *sint_ptr = IP_DEFAULT_TTL;
    return sizeof(*sint_ptr);
  case 3: /* ipInReceives */
    *uint_ptr = STATS_GET(mib2.ipinreceives);
    return sizeof(*uint_ptr);
  case 4: /* ipInHdrErrors */
    *uint_ptr = STATS_GET(mib2.ipinhdrerrors);
    return sizeof(*uint_ptr);
  case 5: /* ipInAddrErrors */
    *uint_ptr = STATS_GET(mib2.ipinaddrerrors);
    return sizeof(*uint_ptr);
  case 6: /* ipForwDatagrams */
    *uint_ptr = STATS_GET(mib2.ipforwdatagrams);
    return sizeof(*uint_ptr);
  case 7: /* ipInUnknownProtos */
    *uint_ptr = STATS_GET(mib2.ipinunknownprotos);
    return sizeof(*uint_ptr);
  case 8: /* ipInDiscards */
    *uint_ptr = STATS_GET(mib2.ipindiscards);
    return sizeof(*uint_ptr);
  case 9: /* ipInDelivers */
    *uint_ptr = STATS_GET(mib2.ipindelivers);
    return sizeof(*uint_ptr);
  case 10: /* ipOutRequests */
    *uint_ptr = STATS_GET(mib2.ipoutrequests);
    return sizeof(*uint_ptr);
  case 11: /* ipOutDiscards */
    *uint_ptr = STATS_GET(mib2.ipoutdiscards);
    return sizeof(*uint_ptr);
  case 12: /* ipOutNoRoutes */
    *uint_ptr = STATS_GET(mib2.ipoutnoroutes);
    return sizeof(*uint_ptr);
  case 13: /* ipReasmTimeout */
#if IP_REASSEMBLY
    *sint_ptr = IP_REASS_MAXAGE;
#else
    *sint_ptr = 0;
#endif
    return sizeof(*sint_ptr);
  case 14: /* ipReasmReqds */
    *uint_ptr = STATS_GET(mib2.ipreasmreqds);
    return sizeof(*uint_ptr);
  case 15: /* ipReasmOKs */
    *uint_ptr = STATS_GET(mib2.ipreasmoks);
    return sizeof(*uint_ptr);
  case 16: /* ipReasmFails */
    *uint_ptr = STATS_GET(mib2.ipreasmfails);
    return sizeof(*uint_ptr);
  case 17: /* ipFragOKs */
    *uint_ptr = STATS_GET(mib2.ipfragoks);
    return sizeof(*uint_ptr);
  case 18: /* ipFragFails */
    *uint_ptr = STATS_GET(mib2.ipfragfails);
    return sizeof(*uint_ptr);
  case 19: /* ipFragCreates */
    *uint_ptr = STATS_GET(mib2.ipfragcreates);
    return sizeof(*uint_ptr);
  case 23: /* ipRoutingDiscards: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_get_value(): unknown id: %"S32_F"\n", instance->node->oid));
    break;
  }

  return 0;
}

/**
 * Test ip object value before setting.
 *
 * @param od is the object definition
 * @param len return value space (in bytes)
 * @param value points to (varbind) space to copy value from.
 *
 * @note we allow set if the value matches the hardwired value,
 *   otherwise return badvalue.
 */
static snmp_err_t
ip_set_test(struct snmp_node_instance* instance, u16_t len, void *value)
{
  snmp_err_t ret = SNMP_ERR_WRONGVALUE;
  s32_t *sint_ptr = (s32_t*)value;

  LWIP_UNUSED_ARG(len);
  switch (instance->node->oid) {
  case 1: /* ipForwarding */
#if IP_FORWARD
    /* forwarding */
    if (*sint_ptr == 1)
#else
    /* not-forwarding */
    if (*sint_ptr == 2)
#endif
    {
      ret = SNMP_ERR_NOERROR;
    }
    break;
  case 2: /* ipDefaultTTL */
    if (*sint_ptr == IP_DEFAULT_TTL) {
      ret = SNMP_ERR_NOERROR;
    }
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_set_test(): unknown id: %"S32_F"\n", instance->node->oid));
    break;
  }

  return ret;
}

static snmp_err_t
ip_set_value(struct snmp_node_instance* instance, u16_t len, void *value)
{
  LWIP_UNUSED_ARG(instance);
  LWIP_UNUSED_ARG(len);
  LWIP_UNUSED_ARG(value);
  /* nothing to do here because in set_test we only accept values being the same as our own stored value -> no need to store anything */
  return SNMP_ERR_NOERROR;
}

/* --- ipAddrTable --- */

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range ip_AddrTable_oid_ranges[] = {
  { 0, 0xff }, /* IP A */
  { 0, 0xff }, /* IP B */
  { 0, 0xff }, /* IP C */
  { 0, 0xff }  /* IP D */
};

static snmp_err_t
ip_AddrTable_get_cell_value_core(struct netif *netif, const u32_t* column, union snmp_variant_value* value, u32_t* value_len)
{
  LWIP_UNUSED_ARG(value_len);

  switch (*column) {
  case 1: /* ipAdEntAddr */
    value->u32 = netif_ip4_addr(netif)->addr;
    break;
  case 2: /* ipAdEntIfIndex */
    value->u32 = netif_to_num(netif);
    break;
  case 3: /* ipAdEntNetMask */
    value->u32 = netif_ip4_netmask(netif)->addr;
    break;
  case 4: /* ipAdEntBcastAddr */
    /* lwIP oddity, there's no broadcast
       address in the netif we can rely on */
    value->u32 = IPADDR_BROADCAST & 1;
    break;
  case 5: /* ipAdEntReasmMaxSize */
#if IP_REASSEMBLY
    /* @todo The theoretical maximum is IP_REASS_MAX_PBUFS * size of the pbufs,
     * but only if receiving one fragmented packet at a time.
     * The current solution is to calculate for 2 simultaneous packets...
     */
    value->u32 = (IP_HLEN + ((IP_REASS_MAX_PBUFS/2) *
        (PBUF_POOL_BUFSIZE - PBUF_LINK_ENCAPSULATION_HLEN - PBUF_LINK_HLEN - IP_HLEN)));
#else
    /** @todo returning MTU would be a bad thing and
        returning a wild guess like '576' isn't good either */
    value->u32 = 0;
#endif
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t
ip_AddrTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip4_addr_t ip;
  struct netif *netif;

  /* check if incoming OID length and if values are in plausible range */
  if(!snmp_oid_in_range(row_oid, row_oid_len, ip_AddrTable_oid_ranges, LWIP_ARRAYSIZE(ip_AddrTable_oid_ranges))) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* get IP from incoming OID */
  snmp_oid_to_ip4(&row_oid[0], &ip); /* we know it succeeds because of oid_in_range check above */

  /* find netif with requested ip */
  netif = netif_list;
  while (netif != NULL) {
    if(ip4_addr_cmp(&ip, netif_ip4_addr(netif))) {
      /* fill in object properties */
      return ip_AddrTable_get_cell_value_core(netif, column, value, value_len);
    }

    netif = netif->next;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t
ip_AddrTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  struct netif *netif;
  struct snmp_next_oid_state state;
  u32_t result_temp[LWIP_ARRAYSIZE(ip_AddrTable_oid_ranges)];

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(ip_AddrTable_oid_ranges));

  /* iterate over all possible OIDs to find the next one */
  netif = netif_list;
  while (netif != NULL) {
    u32_t test_oid[LWIP_ARRAYSIZE(ip_AddrTable_oid_ranges)];
    snmp_ip4_to_oid(netif_ip4_addr(netif), &test_oid[0]);

    /* check generated OID: is it a candidate for the next one? */
    snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(ip_AddrTable_oid_ranges), netif);

    netif = netif->next;
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return ip_AddrTable_get_cell_value_core((struct netif*)state.reference, column, value, value_len);
  }
  
  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

/* --- ipRouteTable --- */

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range ip_RouteTable_oid_ranges[] = {
  { 0, 0xff }, /* IP A */
  { 0, 0xff }, /* IP B */
  { 0, 0xff }, /* IP C */
  { 0, 0xff }, /* IP D */
};

static snmp_err_t
ip_RouteTable_get_cell_value_core(struct netif *netif, u8_t default_route, const u32_t* column, union snmp_variant_value* value, u32_t* value_len)
{
  switch (*column) {
  case 1: /* ipRouteDest */
    if (default_route) {
       /* default rte has 0.0.0.0 dest */
      value->u32 = IP4_ADDR_ANY->addr;
    } else {
      /* netifs have netaddress dest */
      ip4_addr_t tmp;
      ip4_addr_get_network(&tmp, netif_ip4_addr(netif), netif_ip4_netmask(netif));
      value->u32 = tmp.addr;
    }
    break;
  case 2: /* ipRouteIfIndex */
    value->u32 = netif_to_num(netif);
    break;
  case 3: /* ipRouteMetric1 */
    if (default_route) {
      value->s32 = 1; /* default */
    } else {
      value->s32 = 0; /* normal */
    }
    break;
  case 4: /* ipRouteMetric2 */
  case 5: /* ipRouteMetric3 */
  case 6: /* ipRouteMetric4 */
    value->s32 = -1; /* none */
    break;
  case 7: /* ipRouteNextHop */
    if (default_route) {
      /* default rte: gateway */
      value->u32 = netif_ip4_gw(netif)->addr;
    } else {
      /* other rtes: netif ip_addr  */
      value->u32 = netif_ip4_addr(netif)->addr;
    }
    break;
  case 8: /* ipRouteType */
    if (default_route) {
      /* default rte is indirect */
      value->u32 = 4; /* indirect */
    } else {
      /* other rtes are direct */
      value->u32 = 3; /* direct */
    }
    break;
  case 9: /* ipRouteProto */
    /* locally defined routes */
    value->u32 = 2; /* local */
    break;
  case 10: /* ipRouteAge */
    /* @todo (sysuptime - timestamp last change) / 100 */
    value->u32 = 0;
    break;
  case 11: /* ipRouteMask */
    if (default_route) {
      /* default rte use 0.0.0.0 mask */
      value->u32 = IP4_ADDR_ANY->addr;
    } else {
      /* other rtes use netmask */
      value->u32 = netif_ip4_netmask(netif)->addr;
    }
    break;
  case 12: /* ipRouteMetric5 */
    value->s32 = -1; /* none */
    break;
  case 13: /* ipRouteInfo */
    value->const_ptr = snmp_zero_dot_zero.id;
    *value_len = snmp_zero_dot_zero.len * sizeof(u32_t);
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t
ip_RouteTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip4_addr_t test_ip;
  struct netif *netif;

  /* check if incoming OID length and if values are in plausible range */
  if(!snmp_oid_in_range(row_oid, row_oid_len, ip_RouteTable_oid_ranges, LWIP_ARRAYSIZE(ip_RouteTable_oid_ranges))) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* get IP and port from incoming OID */
  snmp_oid_to_ip4(&row_oid[0], &test_ip); /* we know it succeeds because of oid_in_range check above */

  /* default route is on default netif */
  if(ip4_addr_isany_val(test_ip) && (netif_default != NULL)) {
    /* fill in object properties */
    return ip_RouteTable_get_cell_value_core(netif_default, 1, column, value, value_len);
  }

  /* find netif with requested route */
  netif = netif_list;
  while (netif != NULL) {
    ip4_addr_t dst;
    ip4_addr_get_network(&dst, netif_ip4_addr(netif), netif_ip4_netmask(netif));

    if(ip4_addr_cmp(&dst, &test_ip)) {
      /* fill in object properties */
      return ip_RouteTable_get_cell_value_core(netif, 0, column, value, value_len);
    }

    netif = netif->next;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t
ip_RouteTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  struct netif *netif;
  struct snmp_next_oid_state state;
  u32_t result_temp[LWIP_ARRAYSIZE(ip_RouteTable_oid_ranges)];
  u32_t test_oid[LWIP_ARRAYSIZE(ip_RouteTable_oid_ranges)];

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(ip_RouteTable_oid_ranges));

  /* check default route */
  if(netif_default != NULL) {
    snmp_ip4_to_oid(IP4_ADDR_ANY, &test_oid[0]);
    snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(ip_RouteTable_oid_ranges), netif_default);
  }

  /* iterate over all possible OIDs to find the next one */
  netif = netif_list;
  while (netif != NULL) {
    ip4_addr_t dst;
    ip4_addr_get_network(&dst, netif_ip4_addr(netif), netif_ip4_netmask(netif));

    /* check generated OID: is it a candidate for the next one? */
    if (!ip4_addr_isany_val(dst)) {
      snmp_ip4_to_oid(&dst, &test_oid[0]);
      snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(ip_RouteTable_oid_ranges), netif);
    }
    
    netif = netif->next;
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    ip4_addr_t dst;
    snmp_oid_to_ip4(&result_temp[0], &dst);
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return ip_RouteTable_get_cell_value_core((struct netif*)state.reference, ip4_addr_isany_val(dst), column, value, value_len);
  } else {
    /* not found */
    return SNMP_ERR_NOSUCHINSTANCE;
  }
}

/* --- ipNetToMediaTable --- */

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range ip_NetToMediaTable_oid_ranges[] = {
  { 1, 0xff }, /* IfIndex */
  { 0, 0xff }, /* IP A    */
  { 0, 0xff }, /* IP B    */
  { 0, 0xff }, /* IP C    */
  { 0, 0xff }  /* IP D    */
};

static snmp_err_t
ip_NetToMediaTable_get_cell_value_core(u8_t arp_table_index, const u32_t* column, union snmp_variant_value* value, u32_t* value_len)
{
  ip4_addr_t *ip;
  struct netif *netif;
  struct eth_addr *ethaddr;

  etharp_get_entry(arp_table_index, &ip, &netif, &ethaddr);

  /* value */
  switch (*column) {
  case 1: /* atIfIndex / ipNetToMediaIfIndex */
    value->u32 = netif_to_num(netif);
    break;
  case 2: /* atPhysAddress / ipNetToMediaPhysAddress */
    value->ptr = ethaddr;
    *value_len = sizeof(*ethaddr);
    break;
  case 3: /* atNetAddress / ipNetToMediaNetAddress */
    value->u32 = ip->addr;
    break;
  case 4: /* ipNetToMediaType */
    value->u32 = 3; /* dynamic*/
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t
ip_NetToMediaTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip4_addr_t ip_in;
  u8_t netif_index;
  u8_t i;

  /* check if incoming OID length and if values are in plausible range */
  if(!snmp_oid_in_range(row_oid, row_oid_len, ip_NetToMediaTable_oid_ranges, LWIP_ARRAYSIZE(ip_NetToMediaTable_oid_ranges))) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* get IP from incoming OID */
  netif_index = (u8_t)row_oid[0];
  snmp_oid_to_ip4(&row_oid[1], &ip_in); /* we know it succeeds because of oid_in_range check above */

  /* find requested entry */
  for(i=0; i<ARP_TABLE_SIZE; i++) {
    ip4_addr_t *ip;
    struct netif *netif;
    struct eth_addr *ethaddr;

    if(etharp_get_entry(i, &ip, &netif, &ethaddr)) {
      if((netif_index == netif_to_num(netif)) && ip4_addr_cmp(&ip_in, ip)) {
        /* fill in object properties */
        return ip_NetToMediaTable_get_cell_value_core(i, column, value, value_len);
      }
    }
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t
ip_NetToMediaTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  u8_t i;
  struct snmp_next_oid_state state;
  u32_t result_temp[LWIP_ARRAYSIZE(ip_NetToMediaTable_oid_ranges)];

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(ip_NetToMediaTable_oid_ranges));

  /* iterate over all possible OIDs to find the next one */
  for(i=0; i<ARP_TABLE_SIZE; i++) {
    ip4_addr_t *ip;
    struct netif *netif;
    struct eth_addr *ethaddr;

    if(etharp_get_entry(i, &ip, &netif, &ethaddr)) {
      u32_t test_oid[LWIP_ARRAYSIZE(ip_NetToMediaTable_oid_ranges)];

      test_oid[0] = netif_to_num(netif);
      snmp_ip4_to_oid(ip, &test_oid[1]);

      /* check generated OID: is it a candidate for the next one? */
      snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(ip_NetToMediaTable_oid_ranges), (void*)(size_t)i);
    }
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return ip_NetToMediaTable_get_cell_value_core((u8_t)(size_t)state.reference, column, value, value_len);
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}
#endif /* LWIP_IPV4 */

/* --- icmp .1.3.6.1.2.1.5 ----------------------------------------------------- */

#if LWIP_ICMP

static u16_t
icmp_get_value(const struct snmp_scalar_array_node_def *node, void *value)
{
  u32_t *uint_ptr = (u32_t*)value;

  switch (node->oid) {
  case 1: /* icmpInMsgs */
    *uint_ptr = STATS_GET(mib2.icmpinmsgs);
    return sizeof(*uint_ptr);
  case 2: /* icmpInErrors */
    *uint_ptr = STATS_GET(mib2.icmpinerrors);
    return sizeof(*uint_ptr);
  case 3: /* icmpInDestUnreachs */
    *uint_ptr = STATS_GET(mib2.icmpindestunreachs);
    return sizeof(*uint_ptr);
  case 4: /* icmpInTimeExcds */
    *uint_ptr = STATS_GET(mib2.icmpintimeexcds);
    return sizeof(*uint_ptr);
  case 5: /* icmpInParmProbs */
    *uint_ptr = STATS_GET(mib2.icmpinparmprobs);
    return sizeof(*uint_ptr);
  case 6: /* icmpInSrcQuenchs */
    *uint_ptr = STATS_GET(mib2.icmpinsrcquenchs);
    return sizeof(*uint_ptr);
  case 7: /* icmpInRedirects */
    *uint_ptr = STATS_GET(mib2.icmpinredirects);
    return sizeof(*uint_ptr);
  case 8: /* icmpInEchos */
    *uint_ptr = STATS_GET(mib2.icmpinechos);
    return sizeof(*uint_ptr);
  case 9: /* icmpInEchoReps */
    *uint_ptr = STATS_GET(mib2.icmpinechoreps);
    return sizeof(*uint_ptr);
  case 10: /* icmpInTimestamps */
    *uint_ptr = STATS_GET(mib2.icmpintimestamps);
    return sizeof(*uint_ptr);
  case 11: /* icmpInTimestampReps */
    *uint_ptr = STATS_GET(mib2.icmpintimestampreps);
    return sizeof(*uint_ptr);
  case 12: /* icmpInAddrMasks */
    *uint_ptr = STATS_GET(mib2.icmpinaddrmasks);
    return sizeof(*uint_ptr);
  case 13: /* icmpInAddrMaskReps */
    *uint_ptr = STATS_GET(mib2.icmpinaddrmaskreps);
    return sizeof(*uint_ptr);
  case 14: /* icmpOutMsgs */
    *uint_ptr = STATS_GET(mib2.icmpoutmsgs);
    return sizeof(*uint_ptr);
  case 15: /* icmpOutErrors */
    *uint_ptr = STATS_GET(mib2.icmpouterrors);
    return sizeof(*uint_ptr);
  case 16: /* icmpOutDestUnreachs */
    *uint_ptr = STATS_GET(mib2.icmpoutdestunreachs);
    return sizeof(*uint_ptr);
  case 17: /* icmpOutTimeExcds */
    *uint_ptr = STATS_GET(mib2.icmpouttimeexcds);
    return sizeof(*uint_ptr);
  case 18: /* icmpOutParmProbs: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 19: /* icmpOutSrcQuenchs: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 20: /* icmpOutRedirects: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 21: /* icmpOutEchos */
    *uint_ptr = STATS_GET(mib2.icmpoutechos);
    return sizeof(*uint_ptr);
  case 22: /* icmpOutEchoReps */
    *uint_ptr = STATS_GET(mib2.icmpoutechoreps);
    return sizeof(*uint_ptr);
  case 23: /* icmpOutTimestamps: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 24: /* icmpOutTimestampReps: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 25: /* icmpOutAddrMasks: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 26: /* icmpOutAddrMaskReps: not supported -> always 0 */
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("icmp_get_value(): unknown id: %"S32_F"\n", node->oid));
    break;
  }

  return 0;
}

#endif /* LWIP_ICMP */

/* --- tcp .1.3.6.1.2.1.6 ----------------------------------------------------- */

#if LWIP_TCP

static u16_t 
tcp_get_value(struct snmp_node_instance* instance, void* value)
{
  u32_t *uint_ptr = (u32_t*)value;
  s32_t *sint_ptr = (s32_t*)value;

  switch (instance->node->oid) {
  case 1: /* tcpRtoAlgorithm, vanj(4) */
    *sint_ptr = 4;
    return sizeof(*sint_ptr);
  case 2: /* tcpRtoMin */
    /* @todo not the actual value, a guess,
        needs to be calculated */
    *sint_ptr = 1000;
    return sizeof(*sint_ptr);
  case 3: /* tcpRtoMax */
    /* @todo not the actual value, a guess,
        needs to be calculated */
    *sint_ptr = 60000;
    return sizeof(*sint_ptr);
  case 4: /* tcpMaxConn */
    *sint_ptr = MEMP_NUM_TCP_PCB;
    return sizeof(*sint_ptr);
  case 5: /* tcpActiveOpens */
    *uint_ptr = STATS_GET(mib2.tcpactiveopens);
    return sizeof(*uint_ptr);
  case 6: /* tcpPassiveOpens */
    *uint_ptr = STATS_GET(mib2.tcppassiveopens);
    return sizeof(*uint_ptr);
  case 7: /* tcpAttemptFails */
    *uint_ptr = STATS_GET(mib2.tcpattemptfails);
    return sizeof(*uint_ptr);
  case 8: /* tcpEstabResets */
    *uint_ptr = STATS_GET(mib2.tcpestabresets);
    return sizeof(*uint_ptr);
  case 9: /* tcpCurrEstab */
    {
      u16_t tcpcurrestab = 0;
      struct tcp_pcb *pcb = tcp_active_pcbs;
      while (pcb != NULL) {
        if ((pcb->state == ESTABLISHED) ||
            (pcb->state == CLOSE_WAIT)) {
          tcpcurrestab++;
        }
        pcb = pcb->next;
      }
      *uint_ptr = tcpcurrestab;
    }
    return sizeof(*uint_ptr);
  case 10: /* tcpInSegs */
    *uint_ptr = STATS_GET(mib2.tcpinsegs);
    return sizeof(*uint_ptr);
  case 11: /* tcpOutSegs */
    *uint_ptr = STATS_GET(mib2.tcpoutsegs);
    return sizeof(*uint_ptr);
  case 12: /* tcpRetransSegs */
    *uint_ptr = STATS_GET(mib2.tcpretranssegs);
    return sizeof(*uint_ptr);
  case 14: /* tcpInErrs */
    *uint_ptr = STATS_GET(mib2.tcpinerrs);
    return sizeof(*uint_ptr);
  case 15: /* tcpOutRsts */
    *uint_ptr = STATS_GET(mib2.tcpoutrsts);
    return sizeof(*uint_ptr);
  case 17: /* tcpHCInSegs */
    memset(value, 0, 2*sizeof(u32_t)); /* not supported */
    return 2*sizeof(u32_t);
  case 18: /* tcpHCOutSegs */
    memset(value, 0, 2*sizeof(u32_t)); /* not supported */
    return 2*sizeof(u32_t);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("tcp_get_value(): unknown id: %"S32_F"\n", instance->node->oid));
    break;
  }

  return 0;
}

/* --- tcpConnTable --- */

#if LWIP_IPV4

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range tcp_ConnTable_oid_ranges[] = {
  { 0, 0xff   }, /* IP A */
  { 0, 0xff   }, /* IP B */
  { 0, 0xff   }, /* IP C */
  { 0, 0xff   }, /* IP D */
  { 0, 0xffff }, /* Port */
  { 0, 0xff   }, /* IP A */
  { 0, 0xff   }, /* IP B */
  { 0, 0xff   }, /* IP C */
  { 0, 0xff   }, /* IP D */
  { 0, 0xffff }  /* Port */
};

static snmp_err_t 
tcp_ConnTable_get_cell_value_core(struct tcp_pcb *pcb, const u32_t* column, union snmp_variant_value* value, u32_t* value_len)
{
  LWIP_UNUSED_ARG(value_len);

  /* value */
  switch (*column) {
  case 1: /* tcpConnState */
    value->u32 = pcb->state + 1;
    break;
  case 2: /* tcpConnLocalAddress */
    value->u32 = ip_2_ip4(&pcb->local_ip)->addr;
    break;
  case 3: /* tcpConnLocalPort */
    value->u32 = pcb->local_port;
    break;
  case 4: /* tcpConnRemAddress */
    if(pcb->state == LISTEN) {
      value->u32 = IP4_ADDR_ANY->addr;
    } else {
      value->u32 = ip_2_ip4(&pcb->remote_ip)->addr;
    }
    break;
  case 5: /* tcpConnRemPort */
    if(pcb->state == LISTEN) {
      value->u32 = 0;
    } else {
      value->u32 = pcb->remote_port;
    }
    break;
  default:
    LWIP_ASSERT("invalid id", 0);
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t
tcp_ConnTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  u8_t i;
  ip4_addr_t local_ip;
  ip4_addr_t remote_ip;
  u16_t local_port;
  u16_t remote_port;
  struct tcp_pcb *pcb;

  /* check if incoming OID length and if values are in plausible range */
  if(!snmp_oid_in_range(row_oid, row_oid_len, tcp_ConnTable_oid_ranges, LWIP_ARRAYSIZE(tcp_ConnTable_oid_ranges))) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* get IPs and ports from incoming OID */
  snmp_oid_to_ip4(&row_oid[0], &local_ip); /* we know it succeeds because of oid_in_range check above */
  local_port = (u16_t)row_oid[4];
  snmp_oid_to_ip4(&row_oid[5], &remote_ip); /* we know it succeeds because of oid_in_range check above */
  remote_port = (u16_t)row_oid[9];
  
  /* find tcp_pcb with requested ips and ports */
  for(i=0; i<LWIP_ARRAYSIZE(tcp_pcb_lists); i++) {
    pcb = *tcp_pcb_lists[i];

    while (pcb != NULL) {
      /* do local IP and local port match? */
      if(!IP_IS_V6_VAL(pcb->local_ip) &&
         ip4_addr_cmp(&local_ip, ip_2_ip4(&pcb->local_ip)) && (local_port == pcb->local_port)) {

        /* PCBs in state LISTEN are not connected and have no remote_ip or remote_port */
        if(pcb->state == LISTEN) {
          if(ip4_addr_cmp(&remote_ip, IP4_ADDR_ANY) && (remote_port == 0)) {
            /* fill in object properties */
            return tcp_ConnTable_get_cell_value_core(pcb, column, value, value_len);
          }
        } else {
          if(!IP_IS_V6_VAL(pcb->remote_ip) &&
             ip4_addr_cmp(&remote_ip, ip_2_ip4(&pcb->remote_ip)) && (remote_port == pcb->remote_port)) {
            /* fill in object properties */
            return tcp_ConnTable_get_cell_value_core(pcb, column, value, value_len);
          }
        }
      }

      pcb = pcb->next;
    }
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t
tcp_ConnTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  u8_t i;
  struct tcp_pcb *pcb;
  struct snmp_next_oid_state state;
  u32_t result_temp[LWIP_ARRAYSIZE(tcp_ConnTable_oid_ranges)];

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(tcp_ConnTable_oid_ranges));

  /* iterate over all possible OIDs to find the next one */
  for(i=0; i<LWIP_ARRAYSIZE(tcp_pcb_lists); i++) {
    pcb = *tcp_pcb_lists[i];
    while (pcb != NULL) {
      u32_t test_oid[LWIP_ARRAYSIZE(tcp_ConnTable_oid_ranges)];
            
      if(!IP_IS_V6_VAL(pcb->local_ip)) {
        snmp_ip4_to_oid(ip_2_ip4(&pcb->local_ip), &test_oid[0]);
        test_oid[4] = pcb->local_port;

        /* PCBs in state LISTEN are not connected and have no remote_ip or remote_port */
        if(pcb->state == LISTEN) {
          snmp_ip4_to_oid(IP4_ADDR_ANY, &test_oid[5]);
          test_oid[9] = 0;
        } else {
          if(IP_IS_V6_VAL(pcb->remote_ip)) { /* should never happen */
            continue;
          }
          snmp_ip4_to_oid(ip_2_ip4(&pcb->remote_ip), &test_oid[5]);
          test_oid[9] = pcb->remote_port;
        }

        /* check generated OID: is it a candidate for the next one? */
        snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(tcp_ConnTable_oid_ranges), pcb);
      }
    
      pcb = pcb->next;
    }
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return tcp_ConnTable_get_cell_value_core((struct tcp_pcb*)state.reference, column, value, value_len);
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

#endif /* LWIP_IPV4 */

/* --- tcpConnectionTable --- */

static snmp_err_t 
tcp_ConnectionTable_get_cell_value_core(const u32_t* column, struct tcp_pcb *pcb, union snmp_variant_value* value)
{
  /* all items except tcpConnectionState and tcpConnectionProcess are declared as not-accessible */   
  switch (*column) {
  case 7: /* tcpConnectionState */
    value->u32 = pcb->state + 1;
    break;
  case 8: /* tcpConnectionProcess */
    value->u32 = 0; /* not supported */
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t
tcp_ConnectionTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip_addr_t local_ip, remote_ip;
  u16_t local_port, remote_port;
  struct tcp_pcb *pcb;
  u8_t idx = 0;
  u8_t i;
  struct tcp_pcb ** const tcp_pcb_nonlisten_lists[] = {&tcp_bound_pcbs, &tcp_active_pcbs, &tcp_tw_pcbs};

  LWIP_UNUSED_ARG(value_len);

  /* tcpConnectionLocalAddressType + tcpConnectionLocalAddress + tcpConnectionLocalPort */
  idx += snmp_oid_to_ip_port(&row_oid[idx], row_oid_len-idx, &local_ip, &local_port);
  if(idx == 0) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }
  
  /* tcpConnectionRemAddressType + tcpConnectionRemAddress + tcpConnectionRemPort */
  idx += snmp_oid_to_ip_port(&row_oid[idx], row_oid_len-idx, &remote_ip, &remote_port);
  if(idx == 0) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* find tcp_pcb with requested ip and port*/
  for(i=0; i<LWIP_ARRAYSIZE(tcp_pcb_nonlisten_lists); i++) {
    pcb = *tcp_pcb_nonlisten_lists[i];
    
    while (pcb != NULL) {
      if(ip_addr_cmp(&local_ip, &pcb->local_ip) &&
         (local_port == pcb->local_port) &&
         ip_addr_cmp(&remote_ip, &pcb->remote_ip) &&
         (remote_port == pcb->remote_port)) {
        /* fill in object properties */
        return tcp_ConnectionTable_get_cell_value_core(column, pcb, value);
      }
      pcb = pcb->next;
    }
  }
  
  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;  
}

static snmp_err_t
tcp_ConnectionTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  struct tcp_pcb *pcb;
  struct snmp_next_oid_state state;
  /* 1x tcpConnectionLocalAddressType  + 16x tcpConnectionLocalAddress  + 1x tcpConnectionLocalPort
   * 1x tcpConnectionRemAddressType    + 16x tcpConnectionRemAddress    + 1x tcpConnectionRemPort */
  u32_t  result_temp[36];
  u8_t i;
  struct tcp_pcb ** const tcp_pcb_nonlisten_lists[] = {&tcp_bound_pcbs, &tcp_active_pcbs, &tcp_tw_pcbs};

  LWIP_UNUSED_ARG(value_len);

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(result_temp));

  /* iterate over all possible OIDs to find the next one */
  for(i=0; i<LWIP_ARRAYSIZE(tcp_pcb_nonlisten_lists); i++) {
    pcb = *tcp_pcb_nonlisten_lists[i];

    while (pcb != NULL) {
      u8_t idx = 0;
      u32_t test_oid[LWIP_ARRAYSIZE(result_temp)];

      /* tcpConnectionLocalAddressType + tcpConnectionLocalAddress + tcpConnectionLocalPort */
      idx += snmp_ip_port_to_oid(&pcb->local_ip, pcb->local_port, &test_oid[idx]);

      /* tcpConnectionRemAddressType + tcpConnectionRemAddress + tcpConnectionRemPort */
      idx += snmp_ip_port_to_oid(&pcb->remote_ip, pcb->remote_port, &test_oid[idx]);

      /* check generated OID: is it a candidate for the next one? */
      snmp_next_oid_check(&state, test_oid, idx, pcb);
    
      pcb = pcb->next;
    }
  }
  
  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return tcp_ConnectionTable_get_cell_value_core(column, (struct tcp_pcb*)state.reference, value);
  } else {
    /* not found */
    return SNMP_ERR_NOSUCHINSTANCE;
  }
}

/* --- tcpListenerTable --- */

static snmp_err_t 
tcp_ListenerTable_get_cell_value_core(const u32_t* column, union snmp_variant_value* value)
{
  /* all items except tcpListenerProcess are declared as not-accessible */   
  switch (*column) {
  case 4: /* tcpListenerProcess */
    value->u32 = 0; /* not supported */
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t
tcp_ListenerTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip_addr_t local_ip;
  u16_t local_port;
  struct tcp_pcb_listen *pcb;
  u8_t idx = 0;

  LWIP_UNUSED_ARG(value_len);

  /* tcpListenerLocalAddressType + tcpListenerLocalAddress + tcpListenerLocalPort */
  idx += snmp_oid_to_ip_port(&row_oid[idx], row_oid_len-idx, &local_ip, &local_port);
  if(idx == 0) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }
  
  /* find tcp_pcb with requested ip and port*/
  pcb = tcp_listen_pcbs.listen_pcbs;
  while (pcb != NULL) {
    if(ip_addr_cmp(&local_ip, &pcb->local_ip) &&
       (local_port == pcb->local_port)) {
      /* fill in object properties */
      return tcp_ListenerTable_get_cell_value_core(column, value);
    }
    pcb = pcb->next;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;  
}

static snmp_err_t
tcp_ListenerTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  struct tcp_pcb_listen *pcb;
  struct snmp_next_oid_state state;
  /* 1x tcpListenerLocalAddressType  + 16x tcpListenerLocalAddress  + 1x tcpListenerLocalPort */
  u32_t  result_temp[18];

  LWIP_UNUSED_ARG(value_len);

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(result_temp));

  /* iterate over all possible OIDs to find the next one */
  pcb = tcp_listen_pcbs.listen_pcbs;
  while (pcb != NULL) {
    u8_t idx = 0;
    u32_t test_oid[LWIP_ARRAYSIZE(result_temp)];
            
    /* tcpListenerLocalAddressType + tcpListenerLocalAddress + tcpListenerLocalPort */
    idx += snmp_ip_port_to_oid(&pcb->local_ip, pcb->local_port, &test_oid[idx]);

    /* check generated OID: is it a candidate for the next one? */
    snmp_next_oid_check(&state, test_oid, idx, NULL);
    
    pcb = pcb->next;
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return tcp_ListenerTable_get_cell_value_core(column, value);
  } else {
    /* not found */
    return SNMP_ERR_NOSUCHINSTANCE;
  }
}

#endif /* LWIP_TCP */

/* --- udp .1.3.6.1.2.1.7 ----------------------------------------------------- */

#if LWIP_UDP

static u16_t 
udp_get_value(struct snmp_node_instance* instance, void* value)
{
  u32_t *uint_ptr = (u32_t*)value;

  switch (instance->node->oid) {
  case 1: /* udpInDatagrams */
    *uint_ptr = STATS_GET(mib2.udpindatagrams);
    return sizeof(*uint_ptr);
  case 2: /* udpNoPorts */
    *uint_ptr = STATS_GET(mib2.udpnoports);
    return sizeof(*uint_ptr);
  case 3: /* udpInErrors */
    *uint_ptr = STATS_GET(mib2.udpinerrors);
    return sizeof(*uint_ptr);
  case 4: /* udpOutDatagrams */
    *uint_ptr = STATS_GET(mib2.udpoutdatagrams);
    return sizeof(*uint_ptr);
  case 8: /* udpHCInDatagrams */
    memset(value, 0, 2*sizeof(u32_t)); /* not supported */
    return 2*sizeof(u32_t);
  case 9: /* udpHCOutDatagrams */
    memset(value, 0, 2*sizeof(u32_t)); /* not supported */
    return 2*sizeof(u32_t);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("udp_get_value(): unknown id: %"S32_F"\n", instance->node->oid));
    break;
  }

  return 0;
}

/* --- udpEndpointTable --- */

static snmp_err_t 
udp_endpointTable_get_cell_value_core(const u32_t* column, union snmp_variant_value* value)
{
  /* all items except udpEndpointProcess are declared as not-accessible */   
  switch (*column) {
  case 8: /* udpEndpointProcess */
    value->u32 = 0; /* not supported */
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t 
udp_endpointTable_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip_addr_t local_ip, remote_ip;
  u16_t local_port, remote_port;
  struct udp_pcb *pcb;
  u8_t idx = 0;

  LWIP_UNUSED_ARG(value_len);

  /* udpEndpointLocalAddressType + udpEndpointLocalAddress + udpEndpointLocalPort */
  idx += snmp_oid_to_ip_port(&row_oid[idx], row_oid_len-idx, &local_ip, &local_port);
  if(idx == 0) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* udpEndpointRemoteAddressType + udpEndpointRemoteAddress + udpEndpointRemotePort */
  idx += snmp_oid_to_ip_port(&row_oid[idx], row_oid_len-idx, &remote_ip, &remote_port);
  if(idx == 0) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* udpEndpointInstance */
  if(row_oid_len < (idx+1)) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }
  if(row_oid[idx] != 0) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }
  
  /* find udp_pcb with requested ip and port*/
  pcb = udp_pcbs;
  while (pcb != NULL) {
    if(ip_addr_cmp(&local_ip, &pcb->local_ip) &&
       (local_port == pcb->local_port) &&
       ip_addr_cmp(&remote_ip, &pcb->remote_ip) &&
       (remote_port == pcb->remote_port)) {
      /* fill in object properties */
      return udp_endpointTable_get_cell_value_core(column, value);
    }
    pcb = pcb->next;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t 
udp_endpointTable_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  struct udp_pcb *pcb;
  struct snmp_next_oid_state state;
  /* 1x udpEndpointLocalAddressType  + 16x udpEndpointLocalAddress  + 1x udpEndpointLocalPort  +
   * 1x udpEndpointRemoteAddressType + 16x udpEndpointRemoteAddress + 1x udpEndpointRemotePort +
   * 1x udpEndpointInstance = 37
   */
  u32_t  result_temp[37];

  LWIP_UNUSED_ARG(value_len);

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(result_temp));

  /* iterate over all possible OIDs to find the next one */
  pcb = udp_pcbs;
  while (pcb != NULL) {
    u32_t test_oid[LWIP_ARRAYSIZE(result_temp)];
    u8_t idx = 0;

    /* udpEndpointLocalAddressType + udpEndpointLocalAddress + udpEndpointLocalPort */
    idx += snmp_ip_port_to_oid(&pcb->local_ip, pcb->local_port, &test_oid[idx]);

    /* udpEndpointRemoteAddressType + udpEndpointRemoteAddress + udpEndpointRemotePort */
    idx += snmp_ip_port_to_oid(&pcb->remote_ip, pcb->remote_port, &test_oid[idx]);

    test_oid[idx] = 0; /* udpEndpointInstance */    
    idx++;
    
    /* check generated OID: is it a candidate for the next one? */
    snmp_next_oid_check(&state, test_oid, idx, NULL);
    
    pcb = pcb->next;
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return udp_endpointTable_get_cell_value_core(column, value);
  } else {
    /* not found */
    return SNMP_ERR_NOSUCHINSTANCE;
  }
}

#endif /* LWIP_UDP */

/* --- udpTable --- */

#if LWIP_UDP && LWIP_IPV4

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range udp_Table_oid_ranges[] = {
  { 0, 0xff   }, /* IP A        */
  { 0, 0xff   }, /* IP B        */
  { 0, 0xff   }, /* IP C        */
  { 0, 0xff   }, /* IP D        */
  { 1, 0xffff }  /* Port        */
};

static snmp_err_t 
udp_Table_get_cell_value_core(struct udp_pcb *pcb, const u32_t* column, union snmp_variant_value* value, u32_t* value_len)
{
  LWIP_UNUSED_ARG(value_len);

  switch (*column) {
  case 1: /* udpLocalAddress */
    /* set reference to PCB local IP and return a generic node that copies IP4 addresses */
    value->u32 = ip_2_ip4(&pcb->local_ip)->addr;
    break;
  case 2: /* udpLocalPort */
    /* set reference to PCB local port and return a generic node that copies u16_t values */
    value->u32 = pcb->local_port;
    break;
  default:
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  return SNMP_ERR_NOERROR;
}

static snmp_err_t 
udp_Table_get_cell_value(const u32_t* column, const u32_t* row_oid, u8_t row_oid_len, union snmp_variant_value* value, u32_t* value_len)
{
  ip4_addr_t ip;
  u16_t port;
  struct udp_pcb *pcb;

  /* check if incoming OID length and if values are in plausible range */
  if(!snmp_oid_in_range(row_oid, row_oid_len, udp_Table_oid_ranges, LWIP_ARRAYSIZE(udp_Table_oid_ranges))) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* get IP and port from incoming OID */
  snmp_oid_to_ip4(&row_oid[0], &ip); /* we know it succeeds because of oid_in_range check above */
  port = (u16_t)row_oid[4];

  /* find udp_pcb with requested ip and port*/
  pcb = udp_pcbs;
  while (pcb != NULL) {
    if(!IP_IS_V6_VAL(pcb->local_ip)) {
      if(ip4_addr_cmp(&ip, ip_2_ip4(&pcb->local_ip)) && (port == pcb->local_port)) {
        /* fill in object properties */
        return udp_Table_get_cell_value_core(pcb, column, value, value_len);
      }
    }
    pcb = pcb->next;
  }

  /* not found */
  return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t 
udp_Table_get_next_cell_instance_and_value(const u32_t* column, struct snmp_obj_id* row_oid, union snmp_variant_value* value, u32_t* value_len)
{
  struct udp_pcb *pcb;
  struct snmp_next_oid_state state;
  u32_t  result_temp[LWIP_ARRAYSIZE(udp_Table_oid_ranges)];

  /* init struct to search next oid */
  snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp, LWIP_ARRAYSIZE(udp_Table_oid_ranges));

  /* iterate over all possible OIDs to find the next one */
  pcb = udp_pcbs;
  while (pcb != NULL) {
    u32_t test_oid[LWIP_ARRAYSIZE(udp_Table_oid_ranges)];

    if(!IP_IS_V6_VAL(pcb->local_ip)) {
      snmp_ip4_to_oid(ip_2_ip4(&pcb->local_ip), &test_oid[0]);
      test_oid[4] = pcb->local_port;

      /* check generated OID: is it a candidate for the next one? */
      snmp_next_oid_check(&state, test_oid, LWIP_ARRAYSIZE(udp_Table_oid_ranges), pcb);
    }
    
    pcb = pcb->next;
  }

  /* did we find a next one? */
  if(state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    /* fill in object properties */
    return udp_Table_get_cell_value_core((struct udp_pcb*)state.reference, column, value, value_len);
  } else {
    /* not found */
    return SNMP_ERR_NOSUCHINSTANCE;
  }
}

#endif /* LWIP_UDP && LWIP_IPV4 */

/* --- snmp .1.3.6.1.2.1.11 ----------------------------------------------------- */

static u16_t
snmp_get_value(const struct snmp_scalar_array_node_def *node, void *value)
{
  u32_t *uint_ptr = (u32_t*)value;
  switch (node->oid) {
  case 1: /* snmpInPkts */
    *uint_ptr = snmp_stats.inpkts;
    break;
  case 2: /* snmpOutPkts */
    *uint_ptr = snmp_stats.outpkts;
    break;
  case 3: /* snmpInBadVersions */
    *uint_ptr = snmp_stats.inbadversions;
    break;
  case 4: /* snmpInBadCommunityNames */
    *uint_ptr = snmp_stats.inbadcommunitynames;
    break;
  case 5: /* snmpInBadCommunityUses */
    *uint_ptr = snmp_stats.inbadcommunityuses;
    break;
  case 6: /* snmpInASNParseErrs */
    *uint_ptr = snmp_stats.inasnparseerrs;
    break;
  case 8: /* snmpInTooBigs */
    *uint_ptr = snmp_stats.intoobigs;
    break;
  case 9: /* snmpInNoSuchNames */
    *uint_ptr = snmp_stats.innosuchnames;
    break;
  case 10: /* snmpInBadValues */
    *uint_ptr = snmp_stats.inbadvalues;
    break;
  case 11: /* snmpInReadOnlys */
    *uint_ptr = snmp_stats.inreadonlys;
    break;
  case 12: /* snmpInGenErrs */
    *uint_ptr = snmp_stats.ingenerrs;
    break;
  case 13: /* snmpInTotalReqVars */
    *uint_ptr = snmp_stats.intotalreqvars;
    break;
  case 14: /* snmpInTotalSetVars */
    *uint_ptr = snmp_stats.intotalsetvars;
    break;
  case 15: /* snmpInGetRequests */
    *uint_ptr = snmp_stats.ingetrequests;
    break;
  case 16: /* snmpInGetNexts */
    *uint_ptr = snmp_stats.ingetnexts;
    break;
  case 17: /* snmpInSetRequests */
    *uint_ptr = snmp_stats.insetrequests;
    break;
  case 18: /* snmpInGetResponses */
    *uint_ptr = snmp_stats.ingetresponses;
    break;
  case 19: /* snmpInTraps */
    *uint_ptr = snmp_stats.intraps;
    break;
  case 20: /* snmpOutTooBigs */
    *uint_ptr = snmp_stats.outtoobigs;
    break;
  case 21: /* snmpOutNoSuchNames */
    *uint_ptr = snmp_stats.outnosuchnames;
    break;
  case 22: /* snmpOutBadValues */
    *uint_ptr = snmp_stats.outbadvalues;
    break;
  case 24: /* snmpOutGenErrs */
    *uint_ptr = snmp_stats.outgenerrs;
    break;
  case 25: /* snmpOutGetRequests */
    *uint_ptr = snmp_stats.outgetrequests;
    break;
  case 26: /* snmpOutGetNexts */
    *uint_ptr = snmp_stats.outgetnexts;
    break;
  case 27: /* snmpOutSetRequests */
    *uint_ptr = snmp_stats.outsetrequests;
    break;
  case 28: /* snmpOutGetResponses */
    *uint_ptr = snmp_stats.outgetresponses;
    break;
  case 29: /* snmpOutTraps */
    *uint_ptr = snmp_stats.outtraps;
    break;
  case 30: /* snmpEnableAuthenTraps */
    if (snmp_get_auth_traps_enabled() == SNMP_AUTH_TRAPS_DISABLED) {
      *uint_ptr = MIB2_AUTH_TRAPS_DISABLED;
    } else {
      *uint_ptr = MIB2_AUTH_TRAPS_ENABLED;
    }
    break;
  case 31: /* snmpSilentDrops */
    *uint_ptr = 0; /* not supported */
    break;
  case 32: /* snmpProxyDrops */
    *uint_ptr = 0; /* not supported */
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_get_value(): unknown id: %"S32_F"\n", node->oid));
    return 0;
  }

  return sizeof(*uint_ptr);
}

static snmp_err_t
snmp_set_test(const struct snmp_scalar_array_node_def *node, u16_t len, void *value)
{
  snmp_err_t ret = SNMP_ERR_WRONGVALUE;
  LWIP_UNUSED_ARG(len);

  if (node->oid == 30) {
    /* snmpEnableAuthenTraps */
    s32_t *sint_ptr = (s32_t*)value;

    /* we should have writable non-volatile mem here */
    if ((*sint_ptr == MIB2_AUTH_TRAPS_DISABLED) || (*sint_ptr == MIB2_AUTH_TRAPS_ENABLED)) {
      ret = SNMP_ERR_NOERROR;
    }
  }
  return ret;
}

static snmp_err_t
snmp_set_value(const struct snmp_scalar_array_node_def *node, u16_t len, void *value)
{
  LWIP_UNUSED_ARG(len);

  if (node->oid == 30) {
    /* snmpEnableAuthenTraps */
    s32_t *sint_ptr = (s32_t*)value;
    if (*sint_ptr == MIB2_AUTH_TRAPS_DISABLED) {
      snmp_set_auth_traps_enabled(SNMP_AUTH_TRAPS_DISABLED);
    } else {
      snmp_set_auth_traps_enabled(SNMP_AUTH_TRAPS_ENABLED);
    }
  }

  return SNMP_ERR_NOERROR;
}

#endif /* SNMP_LWIP_MIB2 */
#endif /* LWIP_SNMP */
