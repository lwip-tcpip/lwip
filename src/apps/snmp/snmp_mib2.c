/**
 * @file
 * Management Information Base II (RFC1213) objects and functions.
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
 *         Christiaan Simons <christiaan.simons@axon.tv>
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
#include "lwip/sys.h"
#include "netif/etharp.h"

#include <string.h>

#if SNMP_USE_NETCONN
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"
void
snmp_mib2_lwip_synchronizer(snmp_threadsync_called_fn fn, void* arg)
{
#if LWIP_TCPIP_CORE_LOCKING
  LOCK_TCPIP_CORE();
  fn(arg);
  UNLOCK_TCPIP_CORE();
#else
  tcpip_callback_with_block(fn, arg, 1);
#endif
}

struct snmp_threadsync_instance snmp_mib2_lwip_locks;

#define SYNC_NODE_NAME(node_name) node_name ## _synced
#define CREATE_LWIP_SYNC_NODE(oid, node_name) \
   static const struct snmp_threadsync_node node_name ## _synced = SNMP_CREATE_THREAD_SYNC_NODE(oid, &node_name.node, &snmp_mib2_lwip_locks);
#else
#define SYNC_NODE_NAME(node_name) node_name
#define CREATE_LWIP_SYNC_NODE(oid, node_name)
#endif

/* dot3 and EtherLike MIB not planned. (transmission .1.3.6.1.2.1.10) */
/* historical (some say hysterical). (cmot .1.3.6.1.2.1.9) */
/* lwIP has no EGP, thus may not implement it. (egp .1.3.6.1.2.1.8) */

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

static const struct snmp_node* const ip_nodes[] = {
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

static const struct snmp_node* const at_nodes[] = {
  &SYNC_NODE_NAME(at_Table).node.node
};

static const struct snmp_tree_node at_root = SNMP_CREATE_TREE_NODE(3, at_nodes);
#endif /* LWIP_ARP && LWIP_IPV4 */

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
extern const struct snmp_scalar_array_node snmp_mib2_snmp_root;
extern const struct snmp_tree_node snmp_mib2_udp_root;
extern const struct snmp_tree_node snmp_mib2_tcp_root;
extern const struct snmp_scalar_array_node snmp_mib2_icmp_root;
extern const struct snmp_tree_node snmp_mib2_interface_root;

static const struct snmp_node* const mib2_nodes[] = {
  &system_node.node.node,
  &snmp_mib2_interface_root.node,
#if LWIP_ARP && LWIP_IPV4
  &at_root.node,
#endif /* LWIP_ARP && LWIP_IPV4 */
#if LWIP_IPV4
  &ip_root.node,
#endif /* LWIP_IPV4 */
#if LWIP_ICMP
  &snmp_mib2_icmp_root.node.node,
#endif /* LWIP_ICMP */
#if LWIP_TCP
  &snmp_mib2_tcp_root.node,
#endif /* LWIP_TCP */
#if LWIP_UDP
  &snmp_mib2_udp_root.node,
#endif /* LWIP_UDP */
  &snmp_mib2_snmp_root.node.node
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

#endif /* SNMP_LWIP_MIB2 */
#endif /* LWIP_SNMP */
