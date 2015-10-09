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
 * Author: Christiaan Simons <christiaan.simons@axon.tv>
 */

#include "lwip/opt.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/snmp.h"
#include "lwip/snmp_mib2.h"

#if !LWIP_MIB2_CALLBACKS
#error LWIP_SNMP MIB2 needs LWIP_MIB2_CALLBACKS (for MIB2)
#endif
#if !LWIP_STATS
#error LWIP_SNMP MIB2 needs LWIP_STATS (for MIB2)
#endif
#if !MIB2_STATS
#error LWIP_SNMP MIB2 needs MIB2_STATS (for MIB2)
#endif

#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/mem.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip/snmp_asn1.h"
#include "lwip/snmp_structs.h"
#include "lwip/sys.h"
#include "netif/etharp.h"
#include "lwip/stats.h"

#include <string.h>

/**
 * IANA assigned enterprise ID for lwIP is 26381
 * @see http://www.iana.org/assignments/enterprise-numbers
 *
 * @note this enterprise ID is assigned to the lwIP project,
 * all object identifiers living under this ID are assigned
 * by the lwIP maintainers (contact Christiaan Simons)!
 * @note don't change this define, use snmp_set_sysobjid()
 *
 * If you need to create your own private MIB you'll need
 * to apply for your own enterprise ID with IANA:
 * http://www.iana.org/numbers.html
 */
#define SNMP_ENTERPRISE_ID 26381
#define SNMP_SYSOBJID_LEN 7
#define SNMP_SYSOBJID {1, 3, 6, 1, 4, 1, SNMP_ENTERPRISE_ID}

#ifndef SNMP_SYSSERVICES
#define SNMP_SYSSERVICES ((1 << 6) | (1 << 3) | ((IP_FORWARD) << 2))
#endif

static void system_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t system_get_value(struct obj_def *od, void *value);
static u8_t system_set_test(struct obj_def *od, u16_t len, void *value);
static void system_set_value(struct obj_def *od, u16_t len, void *value);
static void interfaces_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t interfaces_get_value(struct obj_def *od, void *value);
static void ifentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t ifentry_get_value(struct obj_def *od, void *value);
#if !SNMP_SAFE_REQUESTS
static u8_t ifentry_set_test (struct obj_def *od, u16_t len, void *value);
static void ifentry_set_value (struct obj_def *od, u16_t len, void *value);
#endif /* SNMP_SAFE_REQUESTS */
static void atentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t atentry_get_value(struct obj_def *od, void *value);
static void ip_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t ip_get_value(struct obj_def *od, void *value);
static u8_t ip_set_test(struct obj_def *od, u16_t len, void *value);
static void ip_addrentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t ip_addrentry_get_value(struct obj_def *od, void *value);
static void ip_rteentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t ip_rteentry_get_value(struct obj_def *od, void *value);
static void ip_ntomentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t ip_ntomentry_get_value(struct obj_def *od, void *value);
static void icmp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t icmp_get_value(struct obj_def *od, void *value);
#if LWIP_TCP
static void tcp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t tcp_get_value(struct obj_def *od, void *value);
#ifdef THIS_SEEMS_UNUSED
static void tcpconnentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static void tcpconnentry_get_value(struct obj_def *od, u16_t len, void *value);
#endif
#endif
static void udp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t udp_get_value(struct obj_def *od, void *value);
static void udpentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t udpentry_get_value(struct obj_def *od, void *value);
static void snmp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static u16_t snmp_get_value(struct obj_def *od, void *value);
static u8_t snmp_set_test(struct obj_def *od, u16_t len, void *value);
static void snmp_set_value(struct obj_def *od, u16_t len, void *value);


/* snmp .1.3.6.1.2.1.11 */
static const struct mib_scalar_node snmp_scalar = {
  { MIB_NODE_SC },
  &snmp_get_object_def,
  &snmp_get_value,
  &snmp_set_test,
  &snmp_set_value,
};
static const struct mib_array_node_entry snmp_nodes[] = {
  {1, &snmp_scalar.node}, {2, &snmp_scalar.node},
  {3, &snmp_scalar.node}, {4, &snmp_scalar.node},
  {5, &snmp_scalar.node}, {6, &snmp_scalar.node},
  {8, &snmp_scalar.node}, {9, &snmp_scalar.node},
  {10, &snmp_scalar.node}, {11, &snmp_scalar.node},
  {12, &snmp_scalar.node}, {13, &snmp_scalar.node},
  {14, &snmp_scalar.node}, {15, &snmp_scalar.node},
  {16, &snmp_scalar.node}, {17, &snmp_scalar.node},
  {18, &snmp_scalar.node}, {19, &snmp_scalar.node},
  {20, &snmp_scalar.node}, {21, &snmp_scalar.node},
  {22, &snmp_scalar.node}, {24, &snmp_scalar.node},
  {25, &snmp_scalar.node}, {26, &snmp_scalar.node},
  {27, &snmp_scalar.node}, {28, &snmp_scalar.node},
  {29, &snmp_scalar.node}, {30, &snmp_scalar.node}
};
static const struct mib_array_node snmp = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(snmp_nodes),
  snmp_nodes
};

/* dot3 and EtherLike MIB not planned. (transmission .1.3.6.1.2.1.10) */
/* historical (some say hysterical). (cmot .1.3.6.1.2.1.9) */
/* lwIP has no EGP, thus may not implement it. (egp .1.3.6.1.2.1.8) */

/* udp .1.3.6.1.2.1.7 */
/** index root node for udpTable */
static struct mib_list_rootnode udp_root = {
  {
    { MIB_NODE_LR },
    &noleafs_get_object_def,
    &noleafs_get_value,
    &noleafs_set_test,
    &noleafs_set_value
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry udpentry_nodes[] = {
  {1, &udp_root.scalar.node}, {2, &udp_root.scalar.node}
};
static const struct mib_array_node udpentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(udpentry_nodes),
  udpentry_nodes
};

static const struct mib_array_node_entry udptable_node = {1, &udpentry.node};
static struct mib_array_node udptable = {
  { MIB_NODE_AR },
  0,
  &udptable_node
};

static const struct mib_scalar_node udp_scalar = {
  { MIB_NODE_SC },
  &udp_get_object_def,
  &udp_get_value,
  &noleafs_set_test,
  &noleafs_set_value
};
static const struct mib_array_node_entry udp_nodes[] = {
  {1, &udp_scalar.node}, {2, &udp_scalar.node},
  {3, &udp_scalar.node}, {4, &udp_scalar.node},
  {5, &udptable.node}
};
static const struct mib_array_node udp = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(udp_nodes),
  udp_nodes
};

/* tcp .1.3.6.1.2.1.6 */
#if LWIP_TCP
/* only if the TCP protocol is available may implement this group */
/** index root node for tcpConnTable */
static struct mib_list_rootnode tcpconntree_root = {
  {
    { MIB_NODE_LR },
    &noleafs_get_object_def,
    &noleafs_get_value,
    &noleafs_set_test,
    &noleafs_set_value
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry tcpconnentry_nodes[] = {
  {1, &tcpconntree_root.scalar.node}, {2, &tcpconntree_root.scalar.node},
  {3, &tcpconntree_root.scalar.node}, {4, &tcpconntree_root.scalar.node},
  {5, &tcpconntree_root.scalar.node}
};
static struct mib_array_node tcpconnentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(tcpconnentry_nodes),
  tcpconnentry_nodes
};

static const struct mib_array_node_entry tcpconntable_node = {1, &tcpconnentry.node};
static struct mib_array_node tcpconntable = {
  { MIB_NODE_AR },
/** @todo update maxlength when inserting / deleting from table
   0 when table is empty, 1 when more than one entry */
  0,
  &tcpconntable_node
};

static const struct mib_scalar_node tcp_scalar = {
  { MIB_NODE_SC },
  &tcp_get_object_def,
  &tcp_get_value,
  &noleafs_set_test,
  &noleafs_set_value
};
static const struct mib_array_node_entry tcp_nodes[] = {
  {1, &tcp_scalar.node}, {2, &tcp_scalar.node},
  {3, &tcp_scalar.node}, {4, &tcp_scalar.node},
  {5, &tcp_scalar.node}, {6, &tcp_scalar.node},
  {7, &tcp_scalar.node}, {8, &tcp_scalar.node},
  {9, &tcp_scalar.node}, {10, &tcp_scalar.node},
  {11, &tcp_scalar.node}, {12, &tcp_scalar.node},
  {13, &tcpconntable.node}, {14, &tcp_scalar.node},
  {15, &tcp_scalar.node}
};
static const struct mib_array_node tcp = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(tcp_nodes),
  tcp_nodes
};
#endif

/* icmp .1.3.6.1.2.1.5 */
static const struct mib_scalar_node icmp_scalar = {
  { MIB_NODE_SC },
  &icmp_get_object_def,
  &icmp_get_value,
  &noleafs_set_test,
  &noleafs_set_value
};
static const struct mib_array_node_entry icmp_nodes[] = {
  {1, &icmp_scalar.node}, {2, &icmp_scalar.node},
  {3, &icmp_scalar.node}, {4, &icmp_scalar.node},
  {5, &icmp_scalar.node}, {6, &icmp_scalar.node},
  {7, &icmp_scalar.node}, {8, &icmp_scalar.node},
  {9, &icmp_scalar.node}, {10, &icmp_scalar.node},
  {11, &icmp_scalar.node}, {12, &icmp_scalar.node},
  {13, &icmp_scalar.node}, {14, &icmp_scalar.node},
  {15, &icmp_scalar.node}, {16, &icmp_scalar.node},
  {17, &icmp_scalar.node}, {18, &icmp_scalar.node},
  {19, &icmp_scalar.node}, {20, &icmp_scalar.node},
  {21, &icmp_scalar.node}, {22, &icmp_scalar.node},
  {23, &icmp_scalar.node}, {24, &icmp_scalar.node},
  {25, &icmp_scalar.node}, {26, &icmp_scalar.node}
};
static const struct mib_array_node icmp = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(icmp_nodes),
  icmp_nodes
};

/** index root node for ipNetToMediaTable */
static struct mib_list_rootnode ipntomtree_root = {
  {
    { MIB_NODE_LR },
    &noleafs_get_object_def,
    &noleafs_get_value,
    &noleafs_set_test,
    &noleafs_set_value
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry ipntomentry_nodes[] = {
  {1, &ipntomtree_root.scalar.node}, {2, &ipntomtree_root.scalar.node},
  {3, &ipntomtree_root.scalar.node}, {4, &ipntomtree_root.scalar.node}
};
static const struct mib_array_node ipntomentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(ipntomentry_nodes),
  ipntomentry_nodes
};

static const struct mib_array_node_entry ipntomtable_node = {1, &ipntomentry.node};
static struct mib_array_node ipntomtable = {
  { MIB_NODE_AR },
  0,
  &ipntomtable_node
};

/** index root node for ipRouteTable */
static struct mib_list_rootnode iprtetree_root = {
  {
    { MIB_NODE_LR },
    &noleafs_get_object_def,
    &noleafs_get_value,
    &noleafs_set_test,
    &noleafs_set_value
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry iprteentry_nodes[] = {
  {1, &iprtetree_root.scalar.node}, {2, &iprtetree_root.scalar.node},
  {3, &iprtetree_root.scalar.node}, {4, &iprtetree_root.scalar.node},
  {5, &iprtetree_root.scalar.node}, {6, &iprtetree_root.scalar.node},
  {7, &iprtetree_root.scalar.node}, {8, &iprtetree_root.scalar.node},
  {9, &iprtetree_root.scalar.node}, {10, &iprtetree_root.scalar.node},
  {11, &iprtetree_root.scalar.node}, {12, &iprtetree_root.scalar.node},
  {13, &iprtetree_root.scalar.node}
};
static const struct mib_array_node iprteentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(iprteentry_nodes),
  iprteentry_nodes
};

static const struct mib_array_node_entry iprtetable_node = {1, &iprteentry.node};
static struct mib_array_node iprtetable = {
  { MIB_NODE_AR },
  0,
  &iprtetable_node
};

/** index root node for ipAddrTable */
static struct mib_list_rootnode ipaddrtree_root = {
  {
    { MIB_NODE_LR },
    &noleafs_get_object_def,
    &noleafs_get_value,
    &noleafs_set_test,
    &noleafs_set_value
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry ipaddrentry_nodes[] = {
  {1, &ipaddrtree_root.scalar.node},
  {2, &ipaddrtree_root.scalar.node},
  {3, &ipaddrtree_root.scalar.node},
  {4, &ipaddrtree_root.scalar.node},
  {5, &ipaddrtree_root.scalar.node}
};
static const struct mib_array_node ipaddrentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(ipaddrentry_nodes),
  ipaddrentry_nodes
};

static const struct mib_array_node_entry ipaddrtable_node = {1, &ipaddrentry.node};
static struct mib_array_node ipaddrtable = {
  { MIB_NODE_AR },
  0,
  &ipaddrtable_node
};

/* ip .1.3.6.1.2.1.4 */
static const struct mib_scalar_node ip_scalar = {
  { MIB_NODE_SC, },
  &ip_get_object_def,
  &ip_get_value,
  &ip_set_test,
  &noleafs_set_value
};
static const struct mib_array_node_entry ip_nodes[] = {
  {1, &ip_scalar.node}, {2, &ip_scalar.node},
  {3, &ip_scalar.node}, {4, &ip_scalar.node},
  {5, &ip_scalar.node}, {6, &ip_scalar.node},
  {7, &ip_scalar.node}, {8, &ip_scalar.node},
  {9, &ip_scalar.node}, {10, &ip_scalar.node},
  {11, &ip_scalar.node}, {12, &ip_scalar.node},
  {13, &ip_scalar.node}, {14, &ip_scalar.node},
  {15, &ip_scalar.node}, {16, &ip_scalar.node},
  {17, &ip_scalar.node}, {18, &ip_scalar.node},
  {19, &ip_scalar.node}, {20, &ipaddrtable.node},
  {21, &iprtetable.node}, {22, &ipntomtable.node},
  {23, &ip_scalar.node}
};
static const struct mib_array_node mib2_ip = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(ip_nodes),
  ip_nodes
};

/** index root node for atTable */
static struct mib_list_rootnode arptree_root = {
  {
    { MIB_NODE_LR },
    &noleafs_get_object_def,
    &noleafs_get_value,
    &noleafs_set_test,
    &noleafs_set_value
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry atentry_nodes[] = {
  {1, &arptree_root.scalar.node},
  {2, &arptree_root.scalar.node},
  {3, &arptree_root.scalar.node}
};
static const struct mib_array_node atentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(atentry_nodes),
  atentry_nodes
};

static const struct mib_array_node_entry attable_node = {1, &atentry.node};
static const struct mib_array_node attable = {
  { MIB_NODE_AR },
  1,
  &attable_node
};

/* at .1.3.6.1.2.1.3 */
static const struct mib_array_node_entry mib2_at_node = {1, &attable.node};
static struct mib_array_node at = {
  { MIB_NODE_AR },
  0,
  &mib2_at_node
};

/** index root node for ifTable */
static struct mib_list_rootnode iflist_root = {
  {
    { MIB_NODE_LR },
    &ifentry_get_object_def,
    &ifentry_get_value,
#if SNMP_SAFE_REQUESTS
    &noleafs_set_test,
    &noleafs_set_value
#else /* SNMP_SAFE_REQUESTS */
    &ifentry_set_test,
    &ifentry_set_value
#endif /* SNMP_SAFE_REQUESTS */
  },
  NULL,
  NULL,
  0
};
static const struct mib_array_node_entry ifentry_nodes[] = {
  {1, &iflist_root.scalar.node}, {2, &iflist_root.scalar.node},
  {3, &iflist_root.scalar.node}, {4, &iflist_root.scalar.node},
  {5, &iflist_root.scalar.node}, {6, &iflist_root.scalar.node},
  {7, &iflist_root.scalar.node}, {8, &iflist_root.scalar.node},
  {9, &iflist_root.scalar.node}, {10, &iflist_root.scalar.node},
  {11, &iflist_root.scalar.node}, {12, &iflist_root.scalar.node},
  {13, &iflist_root.scalar.node}, {14, &iflist_root.scalar.node},
  {15, &iflist_root.scalar.node}, {16, &iflist_root.scalar.node},
  {17, &iflist_root.scalar.node}, {18, &iflist_root.scalar.node},
  {19, &iflist_root.scalar.node}, {20, &iflist_root.scalar.node},
  {21, &iflist_root.scalar.node}, {22, &iflist_root.scalar.node}
};
static const struct mib_array_node ifentry = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(ifentry_nodes),
  ifentry_nodes
};

static const struct mib_array_node_entry iftable_node = {1, &ifentry.node};
static struct mib_array_node iftable = {
  { MIB_NODE_AR },
  0,
  &iftable_node
};

/* interfaces .1.3.6.1.2.1.2 */
static const struct mib_scalar_node interfaces_scalar = {
  { MIB_NODE_SC },
  &interfaces_get_object_def,
  &interfaces_get_value,
  &noleafs_set_test,
  &noleafs_set_value
};
static const struct mib_array_node_entry interfaces_nodes[] = {
  {1, &interfaces_scalar.node}, {2, &iftable.node}
};
static const struct mib_array_node interfaces = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(interfaces_nodes),
  interfaces_nodes
};


/*             0 1 2 3 4 5 6 */
/* system .1.3.6.1.2.1.1 */
static const struct mib_scalar_node system_scalar = {
  { MIB_NODE_SC },
  &system_get_object_def,
  &system_get_value,
  &system_set_test,
  &system_set_value
};
static const struct mib_array_node_entry system_nodes[] = {
  {1, &system_scalar.node}, {2, &system_scalar.node},
  {3, &system_scalar.node}, {4, &system_scalar.node},
  {5, &system_scalar.node}, {6, &system_scalar.node},
  {7, &system_scalar.node}
};
/* work around name issue with 'sys_tem', some compiler(s?) seem to reserve 'system' */
static const struct mib_array_node sys_tem = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(system_nodes),
  system_nodes
};

/* mib-2 .1.3.6.1.2.1 */
static const struct mib_array_node_entry mib2_nodes[] = {
  {1, &sys_tem.node},
  {2, &interfaces.node},
  {3, &at.node},
  {4, &mib2_ip.node},
  {5, &icmp.node},
#if LWIP_TCP
  {6, &tcp.node},
#endif
  {7, &udp.node},
  {11, &snmp.node}
};

static const struct mib_array_node mib2 = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(mib2_nodes),
  mib2_nodes
};

/* mgmt .1.3.6.1.2 */
const struct mib_array_node_entry mgmt_nodes[] = { {1, &mib2.node} };
const struct mib_array_node mgmt = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(mgmt_nodes),
  mgmt_nodes
};

/* internet .1.3.6.1 */
const struct mib_array_node_entry internet_nodes[] = {
  {2, &mgmt.node}
#if SNMP_PRIVATE_MIB
/* When using a private MIB, you have to create a file 'private_mib.h' that contains
 * a 'struct mib_array_node mib_private' which contains your MIB. */
  , {4, &mib_private.node}
#endif /* SNMP_PRIVATE_MIB */
};
const struct mib_array_node internet = {
  { MIB_NODE_AR },
  LWIP_ARRAYSIZE(internet_nodes),
  internet_nodes
};

/** mib-2.system.sysObjectID  */
static const struct snmp_obj_id sysobjid_default = {SNMP_SYSOBJID_LEN, SNMP_SYSOBJID};
static const struct snmp_obj_id* sysobjid_ptr = &sysobjid_default;
/** enterprise ID for generic TRAPs, .iso.org.dod.internet.mgmt.mib-2.snmp */
static const struct snmp_obj_id snmpgrp_id = {7,{1,3,6,1,2,1,11}};
/** mib-2.system.sysServices */
static const s32_t sysservices = SNMP_SYSSERVICES;

/** mib-2.system.sysDescr */
static const u8_t sysdescr_len_default = 4;
static const u8_t sysdescr_default[] = "lwIP";
static const u8_t* sysdescr_len_ptr = &sysdescr_len_default;
static const u8_t* sysdescr_ptr = &sysdescr_default[0];
/** mib-2.system.sysContact */
static u8_t syscontact_len_default = 0;
static u8_t syscontact_default[] = "";
static u8_t syscontact_size = 1;
static u8_t* syscontact_len_ptr = &syscontact_len_default;
static u8_t* syscontact_ptr = &syscontact_default[0];
/** mib-2.system.sysName */
static u8_t sysname_len_default = 8;
static u8_t sysname_default[] = "FQDN-unk";
static u8_t sysname_size = 9;
static u8_t* sysname_len_ptr = &sysname_len_default;
static u8_t* sysname_ptr = &sysname_default[0];
/** mib-2.system.sysLocation */
static u8_t syslocation_len_default = 0;
static u8_t syslocation_default[] = "";
static u8_t syslocation_size = 1;
static u8_t* syslocation_len_ptr = &syslocation_len_default;
static u8_t* syslocation_ptr = &syslocation_default[0];
/** mib-2.snmp.snmpEnableAuthenTraps */
static u8_t snmpenableauthentraps_default = 2; /* disabled */
static u8_t* snmpenableauthentraps_ptr = &snmpenableauthentraps_default;

/** mib-2.interfaces.ifTable.ifEntry.ifSpecific (zeroDotZero) */
static const struct snmp_obj_id ifspecific = {2, {0, 0}};
/** mib-2.ip.ipRouteTable.ipRouteEntry.ipRouteInfo (zeroDotZero) */
static const struct snmp_obj_id iprouteinfo = {2, {0, 0}};


/* mib-2.snmp counter(s) */
static u32_t snmpinpkts = 0,
             snmpoutpkts = 0,
             snmpinbadversions = 0,
             snmpinbadcommunitynames = 0,
             snmpinbadcommunityuses = 0,
             snmpinasnparseerrs = 0,
             snmpintoobigs = 0,
             snmpinnosuchnames = 0,
             snmpinbadvalues = 0,
             snmpinreadonlys = 0,
             snmpingenerrs = 0,
             snmpintotalreqvars = 0,
             snmpintotalsetvars = 0,
             snmpingetrequests = 0,
             snmpingetnexts = 0,
             snmpinsetrequests = 0,
             snmpingetresponses = 0,
             snmpintraps = 0,
             snmpouttoobigs = 0,
             snmpoutnosuchnames = 0,
             snmpoutbadvalues = 0,
             snmpoutgenerrs = 0,
             snmpoutgetrequests = 0,
             snmpoutgetnexts = 0,
             snmpoutsetrequests = 0,
             snmpoutgetresponses = 0,
             snmpouttraps = 0;


/**
 * Initializes sysDescr pointers.
 *
 * @param str if non-NULL then copy str pointer
 * @param len points to string length, excluding zero terminator
 */
void snmp_set_sysdescr(const u8_t *str, const u8_t *len)
{
  if (str != NULL) {
    sysdescr_ptr = str;
    sysdescr_len_ptr = len;
  }
}

void snmp_get_sysobjid_ptr(const struct snmp_obj_id **oid)
{
  *oid = sysobjid_ptr;
}

/**
 * Initializes sysObjectID value.
 *
 * @param oid points to stuct snmp_obj_id to copy
 */
void snmp_set_sysobjid(const struct snmp_obj_id *oid)
{
  sysobjid_ptr = oid;
}

/**
 * Initializes sysContact pointers,
 * e.g. ptrs to non-volatile memory external to lwIP.
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator
 * @param bufsize size of the buffer in bytes, including space for zero terminator
 *        (this is required because the buffer can be overwritten by snmp-set)
 */
void snmp_set_syscontact(u8_t *ocstr, u8_t *ocstrlen, u8_t bufsize)
{
  if (ocstr != NULL) {
    syscontact_ptr = ocstr;
    syscontact_len_ptr = ocstrlen;
    syscontact_size = bufsize;
  }
}

/**
 * Initializes sysName pointers,
 * e.g. ptrs to non-volatile memory external to lwIP.
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator
 * @param bufsize size of the buffer in bytes, including space for zero terminator
 *        (this is required because the buffer can be overwritten by snmp-set)
 */
void snmp_set_sysname(u8_t *ocstr, u8_t *ocstrlen, u8_t bufsize)
{
  if (ocstr != NULL) {
    sysname_ptr = ocstr;
    sysname_len_ptr = ocstrlen;
    sysname_size = bufsize;
  }
}

/**
 * Initializes sysLocation pointers,
 * e.g. ptrs to non-volatile memory external to lwIP.
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator
 * @param bufsize size of the buffer in bytes, including space for zero terminator
 *        (this is required because the buffer can be overwritten by snmp-set)
 */
void snmp_set_syslocation(u8_t *ocstr, u8_t *ocstrlen, u8_t bufsize)
{
  if (ocstr != NULL) {
    syslocation_ptr = ocstr;
    syslocation_len_ptr = ocstrlen;
    syslocation_size = bufsize;
  }
}

void mib2_netif_added(struct netif *ni)
{
  struct mib_list_node *if_node = NULL;

  LWIP_UNUSED_ARG(ni);

  snmp_mib_node_insert(&iflist_root, iflist_root.count + 1, &if_node);
  /* enable getnext traversal on filled table */
  iftable.maxlength = 1;
}

void mib2_netif_removed(struct netif *ni)
{
  LWIP_UNUSED_ARG(ni);

  snmp_mib_node_delete(&iflist_root, iflist_root.tail);
  /* disable getnext traversal on empty table */
  if (iflist_root.count == 0) {
    iftable.maxlength = 0;
  }
}

/**
 * Inserts ARP table indexes (.xIfIndex.xNetAddress)
 * into arp table index trees (both atTable and ipNetToMediaTable).
 */
void mib2_add_arp_entry(struct netif *ni, ip4_addr_t *ip)
{
  struct mib_list_rootnode *at_rn;
  struct mib_list_node *at_node;
  s32_t arpidx[5];
  u8_t level, tree;

  LWIP_ASSERT("ni != NULL", ni != NULL);
  snmp_netiftoifindex(ni, &arpidx[0]);
  snmp_iptooid(ip, &arpidx[1]);

  for (tree = 0; tree < 2; tree++) {
    if (tree == 0) {
      at_rn = &arptree_root;
    } else {
      at_rn = &ipntomtree_root;
    }
    for (level = 0; level < 5; level++) {
      at_node = NULL;
      snmp_mib_node_insert(at_rn, arpidx[level], &at_node);
      if ((level != 4) && (at_node != NULL)) {
        if (at_node->nptr == NULL) {
          at_rn = snmp_mib_lrn_alloc();
          at_node->nptr = &at_rn->scalar.node;
          if (at_rn != NULL) {
            if (level == 3) {
              if (tree == 0) {
                at_rn->scalar.get_object_def = atentry_get_object_def;
                at_rn->scalar.get_value = atentry_get_value;
              } else {
                at_rn->scalar.get_object_def = ip_ntomentry_get_object_def;
                at_rn->scalar.get_value = ip_ntomentry_get_value;
              }
              at_rn->scalar.set_test = noleafs_set_test;
              at_rn->scalar.set_value = noleafs_set_value;
            }
          } else {
            /* at_rn == NULL, malloc failure */
            LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_insert_arpidx_tree() insert failed, mem full"));
            break;
          }
        } else {
          at_rn = (struct mib_list_rootnode*)(void*)at_node->nptr;
        }
      }
    }
  }
  /* enable getnext traversal on filled tables */
  at.maxlength = 1;
  ipntomtable.maxlength = 1;
}

/**
 * Removes ARP table indexes (.xIfIndex.xNetAddress)
 * from arp table index trees.
 */
void mib2_remove_arp_entry(struct netif *ni, ip4_addr_t *ip)
{
  struct mib_list_rootnode *at_rn, *next, *del_rn[5];
  struct mib_list_node *at_n, *del_n[5];
  s32_t arpidx[5];
  u8_t fc, tree, level, del_cnt;

  snmp_netiftoifindex(ni, &arpidx[0]);
  snmp_iptooid(ip, &arpidx[1]);

  for (tree = 0; tree < 2; tree++) {
    /* mark nodes for deletion */
    if (tree == 0) {
      at_rn = &arptree_root;
    } else {
      at_rn = &ipntomtree_root;
    }
    level = 0;
    del_cnt = 0;
    while ((level < 5) && (at_rn != NULL)) {
      fc = snmp_mib_node_find(at_rn, arpidx[level], &at_n);
      if (fc == 0) {
        /* arpidx[level] does not exist */
        del_cnt = 0;
        at_rn = NULL;
      } else if (fc == 1) {
        del_rn[del_cnt] = at_rn;
        del_n[del_cnt] = at_n;
        del_cnt++;
        at_rn = (struct mib_list_rootnode*)(void*)at_n->nptr;
      } else if (fc == 2) {
        /* reset delete (2 or more childs) */
        del_cnt = 0;
        at_rn = (struct mib_list_rootnode*)(void*)at_n->nptr;
      }
      level++;
    }
    /* delete marked index nodes */
    while (del_cnt > 0) {
      del_cnt--;

      at_rn = del_rn[del_cnt];
      at_n = del_n[del_cnt];

      next = snmp_mib_node_delete(at_rn, at_n);
      if (next != NULL) {
        LWIP_ASSERT("next_count == 0",next->count == 0);
        snmp_mib_lrn_free(next);
      }
    }
  }
  /* disable getnext traversal on empty tables */
  if (arptree_root.count == 0) {
    at.maxlength = 0;
  }
  if (ipntomtree_root.count == 0) {
    ipntomtable.maxlength = 0;
  }
}

/**
 * Inserts ipAddrTable indexes (.ipAdEntAddr)
 * into index tree.
 */
void mib2_add_ip4(struct netif *ni)
{
  struct mib_list_rootnode *ipa_rn;
  struct mib_list_node *ipa_node;
  s32_t ipaddridx[4];
  u8_t level;

  LWIP_ASSERT("ni != NULL", ni != NULL);
  snmp_iptooid(netif_ip4_addr(ni), &ipaddridx[0]);

  level = 0;
  ipa_rn = &ipaddrtree_root;
  while (level < 4) {
    ipa_node = NULL;
    snmp_mib_node_insert(ipa_rn, ipaddridx[level], &ipa_node);
    if ((level != 3) && (ipa_node != NULL)) {
      if (ipa_node->nptr == NULL) {
        ipa_rn = snmp_mib_lrn_alloc();
        ipa_node->nptr = &ipa_rn->scalar.node;
        if (ipa_rn != NULL) {
          if (level == 2) {
            ipa_rn->scalar.get_object_def = ip_addrentry_get_object_def;
            ipa_rn->scalar.get_value = ip_addrentry_get_value;
            ipa_rn->scalar.set_test = noleafs_set_test;
            ipa_rn->scalar.set_value = noleafs_set_value;
          }
        } else {
          /* ipa_rn == NULL, malloc failure */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_insert_ipaddridx_tree() insert failed, mem full"));
          break;
        }
      } else {
        ipa_rn = (struct mib_list_rootnode*)(void*)ipa_node->nptr;
      }
    }
    level++;
  }
  /* enable getnext traversal on filled table */
  ipaddrtable.maxlength = 1;
}

/**
 * Removes ipAddrTable indexes (.ipAdEntAddr)
 * from index tree.
 */
void mib2_remove_ip4(struct netif *ni)
{
  struct mib_list_rootnode *ipa_rn, *next, *del_rn[4];
  struct mib_list_node *ipa_n, *del_n[4];
  s32_t ipaddridx[4];
  u8_t fc, level, del_cnt;

  LWIP_ASSERT("ni != NULL", ni != NULL);
  snmp_iptooid(netif_ip4_addr(ni), &ipaddridx[0]);

  /* mark nodes for deletion */
  level = 0;
  del_cnt = 0;
  ipa_rn = &ipaddrtree_root;
  while ((level < 4) && (ipa_rn != NULL)) {
    fc = snmp_mib_node_find(ipa_rn, ipaddridx[level], &ipa_n);
    if (fc == 0) {
      /* ipaddridx[level] does not exist */
      del_cnt = 0;
      ipa_rn = NULL;
    } else if (fc == 1) {
      del_rn[del_cnt] = ipa_rn;
      del_n[del_cnt] = ipa_n;
      del_cnt++;
      ipa_rn = (struct mib_list_rootnode*)(void*)ipa_n->nptr;
    } else if (fc == 2) {
      /* reset delete (2 or more childs) */
      del_cnt = 0;
      ipa_rn = (struct mib_list_rootnode*)(void*)ipa_n->nptr;
    }
    level++;
  }
  /* delete marked index nodes */
  while (del_cnt > 0) {
    del_cnt--;

    ipa_rn = del_rn[del_cnt];
    ipa_n = del_n[del_cnt];

    next = snmp_mib_node_delete(ipa_rn, ipa_n);
    if (next != NULL) {
      LWIP_ASSERT("next_count == 0",next->count == 0);
      snmp_mib_lrn_free(next);
    }
  }
  /* disable getnext traversal on empty table */
  if (ipaddrtree_root.count == 0) {
    ipaddrtable.maxlength = 0;
  }
}

/**
 * Inserts ipRouteTable indexes (.ipRouteDest)
 * into index tree.
 *
 * @param dflt non-zero for the default rte, zero for network rte
 * @param ni points to network interface for this rte
 *
 * @todo record sysuptime for _this_ route when it is installed
 *   (needed for ipRouteAge) in the netif.
 */
void mib2_add_route_ip4(u8_t dflt, struct netif *ni)
{
  u8_t insert = 0;
  ip4_addr_t dst;

  if (dflt != 0) {
    /* the default route 0.0.0.0 */
    ip4_addr_set_any(&dst);
    insert = 1;
  } else {
    /* route to the network address */
    ip4_addr_get_network(&dst, netif_ip4_addr(ni), netif_ip4_netmask(ni));
    /* exclude 0.0.0.0 network (reserved for default rte) */
    if (!ip4_addr_isany_val(dst)) {
      insert = 1;
    }
  }
  if (insert) {
    struct mib_list_rootnode *iprte_rn;
    struct mib_list_node *iprte_node;
    s32_t iprteidx[4];
    u8_t level;

    snmp_iptooid(&dst, &iprteidx[0]);
    level = 0;
    iprte_rn = &iprtetree_root;
    while (level < 4) {
      iprte_node = NULL;
      snmp_mib_node_insert(iprte_rn, iprteidx[level], &iprte_node);
      if ((level != 3) && (iprte_node != NULL))
      {
        if (iprte_node->nptr == NULL) {
          iprte_rn = snmp_mib_lrn_alloc();
          iprte_node->nptr = &iprte_rn->scalar.node;
          if (iprte_rn != NULL) {
            if (level == 2) {
              iprte_rn->scalar.get_object_def = ip_rteentry_get_object_def;
              iprte_rn->scalar.get_value = ip_rteentry_get_value;
              iprte_rn->scalar.set_test = noleafs_set_test;
              iprte_rn->scalar.set_value = noleafs_set_value;
            }
          } else {
            /* iprte_rn == NULL, malloc failure */
            LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_insert_iprteidx_tree() insert failed, mem full"));
            break;
          }
        } else {
          iprte_rn = (struct mib_list_rootnode*)(void*)iprte_node->nptr;
        }
      }
      level++;
    }
  }
  /* enable getnext traversal on filled table */
  iprtetable.maxlength = 1;
}

/**
 * Removes ipRouteTable indexes (.ipRouteDest)
 * from index tree.
 *
 * @param dflt non-zero for the default rte, zero for network rte
 * @param ni points to network interface for this rte or NULL
 *   for default route to be removed.
 */
void mib2_remove_route_ip4(u8_t dflt, struct netif *ni)
{
  u8_t del = 0;
  ip4_addr_t dst;

  if (dflt != 0) {
    /* the default route 0.0.0.0 */
    ip4_addr_set_any(&dst);
    del = 1;
  } else {
    /* route to the network address */
    ip4_addr_get_network(&dst, netif_ip4_addr(ni), netif_ip4_netmask(ni));
    /* exclude 0.0.0.0 network (reserved for default rte) */
    if (!ip4_addr_isany_val(dst)) {
      del = 1;
    }
  }
  if (del) {
    struct mib_list_rootnode *iprte_rn, *next, *del_rn[4];
    struct mib_list_node *iprte_n, *del_n[4];
    s32_t iprteidx[4];
    u8_t fc, level, del_cnt;

    snmp_iptooid(&dst, &iprteidx[0]);
    /* mark nodes for deletion */
    level = 0;
    del_cnt = 0;
    iprte_rn = &iprtetree_root;
    while ((level < 4) && (iprte_rn != NULL)) {
      fc = snmp_mib_node_find(iprte_rn, iprteidx[level], &iprte_n);
      if (fc == 0) {
        /* iprteidx[level] does not exist */
        del_cnt = 0;
        iprte_rn = NULL;
      } else if (fc == 1) {
        del_rn[del_cnt] = iprte_rn;
        del_n[del_cnt] = iprte_n;
        del_cnt++;
        iprte_rn = (struct mib_list_rootnode*)(void*)iprte_n->nptr;
      } else if (fc == 2) {
        /* reset delete (2 or more childs) */
        del_cnt = 0;
        iprte_rn = (struct mib_list_rootnode*)(void*)iprte_n->nptr;
      }
      level++;
    }
    /* delete marked index nodes */
    while (del_cnt > 0) {
      del_cnt--;

      iprte_rn = del_rn[del_cnt];
      iprte_n = del_n[del_cnt];

      next = snmp_mib_node_delete(iprte_rn, iprte_n);
      if (next != NULL) {
        LWIP_ASSERT("next_count == 0",next->count == 0);
        snmp_mib_lrn_free(next);
      }
    }
  }
  /* disable getnext traversal on empty table */
  if (iprtetree_root.count == 0) {
    iprtetable.maxlength = 0;
  }
}


/**
 * Inserts udpTable indexes (.udpLocalAddress.udpLocalPort)
 * into index tree.
 */
void mib2_udp_bind(struct udp_pcb *pcb)
{
  struct mib_list_rootnode *udp_rn;
  struct mib_list_node *udp_node;
  s32_t udpidx[5];
  u8_t level;

  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  if (IP_IS_V6(&pcb->local_ip)) {
    /* @todo: support IPv6: .udpLocalAddress.udpLocalPort is DEPRECATED */
    return;
  }
  snmp_iptooid(ip_2_ip4(&pcb->local_ip), &udpidx[0]);
  udpidx[4] = pcb->local_port;

  udp_rn = &udp_root;
  for (level = 0; level < 5; level++) {
    udp_node = NULL;
    snmp_mib_node_insert(udp_rn, udpidx[level], &udp_node);
    if ((level != 4) && (udp_node != NULL)) {
      if (udp_node->nptr == NULL) {
        udp_rn = snmp_mib_lrn_alloc();
        udp_node->nptr = &udp_rn->scalar.node;
        if (udp_rn != NULL) {
          if (level == 3) {
            udp_rn->scalar.get_object_def = udpentry_get_object_def;
            udp_rn->scalar.get_value = udpentry_get_value;
            udp_rn->scalar.set_test = noleafs_set_test;
            udp_rn->scalar.set_value = noleafs_set_value;
          }
        } else {
          /* udp_rn == NULL, malloc failure */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_insert_udpidx_tree() insert failed, mem full"));
          break;
        }
      } else {
        udp_rn = (struct mib_list_rootnode*)(void*)udp_node->nptr;
      }
    }
  }
  udptable.maxlength = 1;
}

/**
 * Removes udpTable indexes (.udpLocalAddress.udpLocalPort)
 * from index tree.
 */
void mib2_udp_unbind(struct udp_pcb *pcb)
{
  struct udp_pcb *npcb;
  struct mib_list_rootnode *udp_rn, *next, *del_rn[5];
  struct mib_list_node *udp_n, *del_n[5];
  s32_t udpidx[5];
  u8_t bindings, fc, level, del_cnt;

  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  if (IP_IS_V6(&pcb->local_ip)) {
    /* @todo: support IPv6: .udpLocalAddress.udpLocalPort is DEPRECATED */
    return;
  }
  snmp_iptooid(ip_2_ip4(&pcb->local_ip), &udpidx[0]);
  udpidx[4] = pcb->local_port;

  /* count PCBs for a given binding
     (e.g. when reusing ports or for temp output PCBs) */
  bindings = 0;
  npcb = udp_pcbs;
  while ((npcb != NULL)) {
    if (ip_addr_cmp(&npcb->local_ip, &pcb->local_ip) &&
        (npcb->local_port == udpidx[4])) {
      bindings++;
    }
    npcb = npcb->next;
  }
  if (bindings == 1) {
    /* selectively remove */
    /* mark nodes for deletion */
    level = 0;
    del_cnt = 0;
    udp_rn = &udp_root;
    while ((level < 5) && (udp_rn != NULL)) {
      fc = snmp_mib_node_find(udp_rn, udpidx[level], &udp_n);
      if (fc == 0) {
        /* udpidx[level] does not exist */
        del_cnt = 0;
        udp_rn = NULL;
      } else if (fc == 1) {
        del_rn[del_cnt] = udp_rn;
        del_n[del_cnt] = udp_n;
        del_cnt++;
        udp_rn = (struct mib_list_rootnode*)(void*)udp_n->nptr;
      } else if (fc == 2) {
        /* reset delete (2 or more childs) */
        del_cnt = 0;
        udp_rn = (struct mib_list_rootnode*)(void*)udp_n->nptr;
      }
      level++;
    }
    /* delete marked index nodes */
    while (del_cnt > 0) {
      del_cnt--;

      udp_rn = del_rn[del_cnt];
      udp_n = del_n[del_cnt];

      next = snmp_mib_node_delete(udp_rn, udp_n);
      if (next != NULL) {
        LWIP_ASSERT("next_count == 0",next->count == 0);
        snmp_mib_lrn_free(next);
      }
    }
  }
  /* disable getnext traversal on empty table */
  if (udp_root.count == 0) {
    udptable.maxlength = 0;
  }
}


void mib2_inc_snmpinpkts(void)
{
  snmpinpkts++;
}

void mib2_inc_snmpoutpkts(void)
{
  snmpoutpkts++;
}

void mib2_inc_snmpinbadversions(void)
{
  snmpinbadversions++;
}

void mib2_inc_snmpinbadcommunitynames(void)
{
  snmpinbadcommunitynames++;
}

void mib2_inc_snmpinbadcommunityuses(void)
{
  snmpinbadcommunityuses++;
}

void mib2_inc_snmpinasnparseerrs(void)
{
  snmpinasnparseerrs++;
}

void mib2_inc_snmpintoobigs(void)
{
  snmpintoobigs++;
}

void mib2_inc_snmpinnosuchnames(void)
{
  snmpinnosuchnames++;
}

void mib2_inc_snmpinbadvalues(void)
{
  snmpinbadvalues++;
}

void mib2_inc_snmpinreadonlys(void)
{
  snmpinreadonlys++;
}

void mib2_inc_snmpingenerrs(void)
{
  snmpingenerrs++;
}

void mib2_add_snmpintotalreqvars(u8_t value)
{
  snmpintotalreqvars += value;
}

void mib2_add_snmpintotalsetvars(u8_t value)
{
  snmpintotalsetvars += value;
}

void mib2_inc_snmpingetrequests(void)
{
  snmpingetrequests++;
}

void mib2_inc_snmpingetnexts(void)
{
  snmpingetnexts++;
}

void mib2_inc_snmpinsetrequests(void)
{
  snmpinsetrequests++;
}

void mib2_inc_snmpingetresponses(void)
{
  snmpingetresponses++;
}

void mib2_inc_snmpintraps(void)
{
  snmpintraps++;
}

void mib2_inc_snmpouttoobigs(void)
{
  snmpouttoobigs++;
}

void mib2_inc_snmpoutnosuchnames(void)
{
  snmpoutnosuchnames++;
}

void mib2_inc_snmpoutbadvalues(void)
{
  snmpoutbadvalues++;
}

void mib2_inc_snmpoutgenerrs(void)
{
  snmpoutgenerrs++;
}

void mib2_inc_snmpoutgetrequests(void)
{
  snmpoutgetrequests++;
}

void mib2_inc_snmpoutgetnexts(void)
{
  snmpoutgetnexts++;
}

void mib2_inc_snmpoutsetrequests(void)
{
  snmpoutsetrequests++;
}

void mib2_inc_snmpoutgetresponses(void)
{
  snmpoutgetresponses++;
}

void mib2_inc_snmpouttraps(void)
{
  snmpouttraps++;
}

void mib2_get_snmpgrpid_ptr(const struct snmp_obj_id **oid)
{
  *oid = &snmpgrp_id;
}

void snmp_set_snmpenableauthentraps(u8_t *value)
{
  if (value != NULL) {
    snmpenableauthentraps_ptr = value;
  }
}

void mib2_get_snmpenableauthentraps(u8_t *value)
{
  *value = *snmpenableauthentraps_ptr;
}

/**
 * Returns systems object definitions.
 *
 * @param ident_len the address length (2)
 * @param ident points to objectname.0 (object id trailer)
 * @param od points to object definition.
 */
static void
system_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  u8_t id;

  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if (ident_len == 2) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def system.%"U16_F".0\n",(u16_t)id));
    switch (id) {
    case 1: /* sysDescr */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 2: /* sysObjectID */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID);
      break;
    case 3: /* sysUpTime */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_TIMETICKS);
      break;
    case 4: /* sysContact */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 5: /* sysName */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 6: /* sysLocation */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 7: /* sysServices */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

/**
 * Returns system object value.
 */
static u16_t
system_get_value(struct obj_def *od, void *value)
{
  u8_t id;

  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 1: /* sysDescr */
    MEMCPY(value, sysdescr_ptr, *sysdescr_len_ptr);
    return *sysdescr_len_ptr;
  case 2: /* sysObjectID */
    MEMCPY(value, sysobjid_ptr->id, sysobjid_ptr->len * sizeof(s32_t));
    return sysobjid_ptr->len * sizeof(s32_t);
  case 3: /* sysUpTime */
    MIB2_COPY_SYSUPTIME_TO((u32_t*)value);
    return sizeof(u32_t);
  case 4: /* sysContact */
    MEMCPY(value, syscontact_ptr, *syscontact_len_ptr);
    return *syscontact_len_ptr;
  case 5: /* sysName */
    MEMCPY(value, sysname_ptr, *sysname_len_ptr);
    return *sysname_len_ptr;
  case 6: /* sysLocation */
    MEMCPY(value, syslocation_ptr, *syslocation_len_ptr);
    return *syslocation_len_ptr;
  case 7: /* sysServices */
    *(s32_t*)value = sysservices;
    return sizeof(s32_t);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_get_value(): unknown id: %d\n", id));
    break;
  }

  return 0;
}

static u8_t
system_set_test(struct obj_def *od, u16_t len, void *value)
{
  u8_t id, set_ok;

  LWIP_UNUSED_ARG(value);
  set_ok = 0;
  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 4: /* sysContact */
    if (len < syscontact_size) {
      set_ok = 1;
    }
    break;
  case 5: /* sysName */
    if (len < sysname_size) {
      set_ok = 1;
    }
    break;
  case 6: /* sysLocation */
    if (len < syslocation_size) {
      set_ok = 1;
    }
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_set_test(): unknown id: %d\n", id));
    break;
  }
  return set_ok;
}

static void
system_set_value(struct obj_def *od, u16_t len, void *value)
{
  u8_t id;

  LWIP_ASSERT("invalid len", len <= 0xff);
  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 4: /* sysContact (size already checked in system_set_test) */
    MEMCPY(syscontact_ptr, value, len);
    *syscontact_len_ptr = (u8_t)len;
    break;
  case 5: /* sysName (size already checked in system_set_test) */
    MEMCPY(sysname_ptr, value, len);
    *sysname_len_ptr = (u8_t)len;
    break;
  case 6: /* sysLocation (size already checked in system_set_test) */
    MEMCPY(syslocation_ptr, value, len);
    *syslocation_len_ptr = (u8_t)len;
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_set_value(): unknown id: %d\n", id));
    break;
  }
}

/**
 * Returns interfaces.ifnumber object definition.
 *
 * @param ident_len the address length (2)
 * @param ident points to objectname.index
 * @param od points to object definition.
 */
static void
interfaces_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if (ident_len == 2) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    od->instance = MIB_OBJECT_SCALAR;
    od->access = MIB_OBJECT_READ_ONLY;
    od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("interfaces_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

/**
 * Returns interfaces.ifnumber object value.
 */
static u16_t
interfaces_get_value(struct obj_def *od, void *value)
{
  if (od->id_inst_ptr[0] == 1) {
    s32_t *sint_ptr = (s32_t*)value;
    *sint_ptr = iflist_root.count;
    return sizeof(*sint_ptr);
  }

  return 0;
}

/**
 * Returns ifentry object definitions.
 *
 * @param ident_len the address length (2)
 * @param ident points to objectname.index
 * @param od points to object definition.
 */
static void
ifentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  u8_t id;

  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if (ident_len == 2) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def ifentry.%"U16_F"\n",(u16_t)id));
    switch (id) {
    case 1: /* ifIndex */
    case 3: /* ifType */
    case 4: /* ifMtu */
    case 8: /* ifOperStatus */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 2: /* ifDescr */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 5: /* ifSpeed */
    case 21: /* ifOutQLen */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_GAUGE);
      break;
    case 6: /* ifPhysAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 7: /* ifAdminStatus */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 9: /* ifLastChange */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_TIMETICKS);
      break;
    case 10: /* ifInOctets */
    case 11: /* ifInUcastPkts */
    case 12: /* ifInNUcastPkts */
    case 13: /* ifInDiscarts */
    case 14: /* ifInErrors */
    case 15: /* ifInUnkownProtos */
    case 16: /* ifOutOctets */
    case 17: /* ifOutUcastPkts */
    case 18: /* ifOutNUcastPkts */
    case 19: /* ifOutDiscarts */
    case 20: /* ifOutErrors */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER);
      break;
    case 22: /* ifSpecific */
      /** @note returning zeroDotZero (0.0) no media specific MIB support */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ifentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ifentry_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

/**
 * Returns ifentry object value.
 */
static u16_t
ifentry_get_value(struct obj_def *od, void *value)
{
  struct netif *netif;
  u8_t id;
  s32_t *sint_ptr;
  u32_t *uint_ptr;

  snmp_ifindextonetif(od->id_inst_ptr[1], &netif);
  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 1: /* ifIndex */
    sint_ptr = (s32_t*)value;
    *sint_ptr = od->id_inst_ptr[1];
    return sizeof(*sint_ptr);
  case 2: /* ifDescr */
    MEMCPY(value, netif->name, 2);
    /** @todo this should be some sort of sizeof(struct netif.name) */
    return 2;
  case 3: /* ifType */
    sint_ptr = (s32_t*)value;
    *sint_ptr = netif->link_type;
    return sizeof(*sint_ptr);
  case 4: /* ifMtu */
    sint_ptr = (s32_t*)value;
    *sint_ptr = netif->mtu;
    return sizeof(*sint_ptr);
  case 5: /* ifSpeed */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->link_speed;
    return sizeof(*uint_ptr);
  case 6: /* ifPhysAddress */
    MEMCPY(value, netif->hwaddr, netif->hwaddr_len);
    return netif->hwaddr_len;
  case 7: /* ifAdminStatus */
    sint_ptr = (s32_t*)value;
    if (netif_is_up(netif)) {
      if (netif_is_link_up(netif)) {
        *sint_ptr = 1; /* up */
      } else {
        *sint_ptr = 7; /* lowerLayerDown */
      }
    } else {
      *sint_ptr = 2; /* down */
    }
    return sizeof(*sint_ptr);
  case 8: /* ifOperStatus */
    sint_ptr = (s32_t*)value;
    if (netif_is_up(netif)) {
      *sint_ptr = 1;
    } else {
      *sint_ptr = 2;
    }
    return sizeof(*sint_ptr);
  case 9: /* ifLastChange */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->ts;
    return sizeof(*uint_ptr);
  case 10: /* ifInOctets */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifinoctets;
    return sizeof(*uint_ptr);
  case 11: /* ifInUcastPkts */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifinucastpkts;
    return sizeof(*uint_ptr);
  case 12: /* ifInNUcastPkts */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifinnucastpkts;
    return sizeof(*uint_ptr);
  case 13: /* ifInDiscards */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifindiscards;
    return sizeof(*uint_ptr);
  case 14: /* ifInErrors */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifinerrors;
    return sizeof(*uint_ptr);
  case 15: /* ifInUnkownProtos */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifinunknownprotos;
    return sizeof(*uint_ptr);
  case 16: /* ifOutOctets */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifoutoctets;
    return sizeof(*uint_ptr);
  case 17: /* ifOutUcastPkts */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifoutucastpkts;
    return sizeof(*uint_ptr);
  case 18: /* ifOutNUcastPkts */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifoutnucastpkts;
    return sizeof(*uint_ptr);
  case 19: /* ifOutDiscarts */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifoutdiscards;
    return sizeof(*uint_ptr);
  case 20: /* ifOutErrors */
    uint_ptr = (u32_t*)value;
    *uint_ptr = netif->mib2_counters.ifouterrors;
    return sizeof(*uint_ptr);
  case 21: /* ifOutQLen */
    /** @todo figure out if this must be 0 (no queue) or 1? */
    uint_ptr = (u32_t*)value;
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  case 22: /* ifSpecific */
    MEMCPY(value, ifspecific.id, ifspecific.len * sizeof(s32_t));
    return ifspecific.len * sizeof(s32_t);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ifentry_get_value(): unknown id: %d\n", id));
    break;
  }

  return 0;
}

#if !SNMP_SAFE_REQUESTS
static u8_t
ifentry_set_test(struct obj_def *od, u16_t len, void *value)
{
  struct netif *netif;
  u8_t id, set_ok;
  LWIP_UNUSED_ARG(len);

  set_ok = 0;
  snmp_ifindextonetif(od->id_inst_ptr[1], &netif);
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 7: /* ifAdminStatus */
    {
      s32_t *sint_ptr = (s32_t*)value;
      if (*sint_ptr == 1 || *sint_ptr == 2)
        set_ok = 1;
    }
    break;
  }
  return set_ok;
}

static void
ifentry_set_value(struct obj_def *od, u16_t len, void *value)
{
  struct netif *netif;
  u8_t id;
  LWIP_UNUSED_ARG(len);

  snmp_ifindextonetif(od->id_inst_ptr[1], &netif);
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 7: /* ifAdminStatus */
    {
      s32_t *sint_ptr = (s32_t*)value;
      if (*sint_ptr == 1) {
        netif_set_up(netif);
      } else if (*sint_ptr == 2) {
        netif_set_down(netif);
      }
    }
    break;
  }
}
#endif /* SNMP_SAFE_REQUESTS */

/**
 * Returns atentry object definitions.
 *
 * @param ident_len the address length (6)
 * @param ident points to objectname.atifindex.atnetaddress
 * @param od points to object definition.
 */
static void
atentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (5) */
  ident_len += 5;
  ident -= 5;

  if (ident_len == 6) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    switch (ident[0]) {
    case 1: /* atIfIndex */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 2: /* atPhysAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 3: /* atNetAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("atentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("atentry_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
atentry_get_value(struct obj_def *od, void *value)
{
#if LWIP_ARP
  u8_t id;
  struct eth_addr* ethaddr_ret;
  const ip4_addr_t* ipaddr_ret;
  ip4_addr_t ip;
  struct netif *netif;
#endif /* LWIP_ARP */

  LWIP_UNUSED_ARG(value);/* if !LWIP_ARP */

#if LWIP_ARP /** @todo implement a netif_find_addr */
  snmp_ifindextonetif(od->id_inst_ptr[1], &netif);
  snmp_oidtoip(&od->id_inst_ptr[2], &ip);

  if (etharp_find_addr(netif, &ip, &ethaddr_ret, &ipaddr_ret) > -1) {
    LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
    id = (u8_t)od->id_inst_ptr[0];
    switch (id) {
    case 1: /* atIfIndex */
      {
        s32_t *sint_ptr = (s32_t*)value;
        *sint_ptr = od->id_inst_ptr[1];
        return sizeof(*sint_ptr);
      }
    case 2: /* atPhysAddress */
      {
        struct eth_addr *dst = (struct eth_addr*)value;
        *dst = *ethaddr_ret;
        return sizeof(*dst); /** @todo try to use netif::hwaddr_len */
      }
    case 3: /* atNetAddress */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;
        *dst = *ipaddr_ret;
        return sizeof(*dst);
      }
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("atentry_get_value(): unknown id: %d\n", id));
      break;
    }
  }

  return 0;
#endif /* LWIP_ARP */
}

static void
ip_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  u8_t id;

  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if (ident_len == 2) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def ip.%"U16_F".0\n",(u16_t)id));
    switch (id) {
    case 1: /* ipForwarding */
    case 2: /* ipDefaultTTL */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 3: /* ipInReceives */
    case 4: /* ipInHdrErrors */
    case 5: /* ipInAddrErrors */
    case 6: /* ipForwDatagrams */
    case 7: /* ipInUnknownProtos */
    case 8: /* ipInDiscards */
    case 9: /* ipInDelivers */
    case 10: /* ipOutRequests */
    case 11: /* ipOutDiscards */
    case 12: /* ipOutNoRoutes */
    case 14: /* ipReasmReqds */
    case 15: /* ipReasmOKs */
    case 16: /* ipReasmFails */
    case 17: /* ipFragOKs */
    case 18: /* ipFragFails */
    case 19: /* ipFragCreates */
    case 23: /* ipRoutingDiscards */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER);
      break;
    case 13: /* ipReasmTimeout */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
ip_get_value(struct obj_def *od, void *value)
{
  u8_t id;
  s32_t *sint_ptr;
  u32_t *uint_ptr;

  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 1: /* ipForwarding */
    sint_ptr = (s32_t*)value;
#if IP_FORWARD
    /* forwarding */
    *sint_ptr = 1;
#else
    /* not-forwarding */
    *sint_ptr = 2;
#endif
    return sizeof(*sint_ptr);
  case 2: /* ipDefaultTTL */
    sint_ptr = (s32_t*)value;
    *sint_ptr = IP_DEFAULT_TTL;
    return sizeof(*sint_ptr);
  case 3: /* ipInReceives */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipinreceives);
    return sizeof(*uint_ptr);
  case 4: /* ipInHdrErrors */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipinhdrerrors);
    return sizeof(*uint_ptr);
  case 5: /* ipInAddrErrors */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipinaddrerrors);
    return sizeof(*uint_ptr);
  case 6: /* ipForwDatagrams */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipforwdatagrams);
    return sizeof(*uint_ptr);
  case 7: /* ipInUnknownProtos */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipinunknownprotos);
    return sizeof(*uint_ptr);
  case 8: /* ipInDiscards */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipindiscards);
    return sizeof(*uint_ptr);
  case 9: /* ipInDelivers */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipindelivers);
    return sizeof(*uint_ptr);
  case 10: /* ipOutRequests */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipoutrequests);
    return sizeof(*uint_ptr);
  case 11: /* ipOutDiscards */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipoutdiscards);
    return sizeof(*uint_ptr);
  case 12: /* ipOutNoRoutes */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipoutnoroutes);
    return sizeof(*uint_ptr);
  case 13: /* ipReasmTimeout */
    sint_ptr = (s32_t*)value;
#if IP_REASSEMBLY
    *sint_ptr = IP_REASS_MAXAGE;
#else
    *sint_ptr = 0;
#endif
    return sizeof(*sint_ptr);
  case 14: /* ipReasmReqds */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipreasmreqds);
    return sizeof(*uint_ptr);
  case 15: /* ipReasmOKs */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipreasmoks);
    return sizeof(*uint_ptr);
  case 16: /* ipReasmFails */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipreasmfails);
    return sizeof(*uint_ptr);
  case 17: /* ipFragOKs */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipfragoks);
    return sizeof(*uint_ptr);
  case 18: /* ipFragFails */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipfragfails);
    return sizeof(*uint_ptr);
  case 19: /* ipFragCreates */
    uint_ptr = (u32_t*)value;
    *uint_ptr = STATS_GET(mib2.ipfragcreates);
    return sizeof(*uint_ptr);
  case 23: /* ipRoutingDiscards: not supported -> always 0 */
    uint_ptr = (u32_t*)value;
    *uint_ptr = 0;
    return sizeof(*uint_ptr);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_get_value(): unknown id: %d\n", id));
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
static u8_t
ip_set_test(struct obj_def *od, u16_t len, void *value)
{
  u8_t id, set_ok;
  s32_t *sint_ptr = (s32_t*)value;

  LWIP_UNUSED_ARG(len);
  set_ok = 0;
  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 1: /* ipForwarding */
#if IP_FORWARD
    /* forwarding */
    if (*sint_ptr == 1)
#else
    /* not-forwarding */
    if (*sint_ptr == 2)
#endif
    {
      set_ok = 1;
    }
    break;
  case 2: /* ipDefaultTTL */
    if (*sint_ptr == IP_DEFAULT_TTL) {
      set_ok = 1;
    }
    break;
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_set_test(): unknown id: %d\n", id));
    break;
  }
  return set_ok;
}

static void
ip_addrentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (4) */
  ident_len += 4;
  ident -= 4;

  if (ident_len == 5) {
    u8_t id;

    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    switch (id) {
    case 1: /* ipAdEntAddr */
    case 3: /* ipAdEntNetMask */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR);
      break;
    case 2: /* ipAdEntIfIndex */
    case 4: /* ipAdEntBcastAddr */
    case 5: /* ipAdEntReasmMaxSize */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_addrentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_addrentry_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
ip_addrentry_get_value(struct obj_def *od, void *value)
{
  u8_t id;
  u16_t ifidx;
  ip4_addr_t ip;
  struct netif *netif = netif_list;

  snmp_oidtoip(&od->id_inst_ptr[1], &ip);
  ifidx = 0;
  while ((netif != NULL) && !ip4_addr_cmp(&ip, netif_ip4_addr(netif))) {
    netif = netif->next;
    ifidx++;
  }

  if (netif != NULL) {
    LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
    id = (u8_t)od->id_inst_ptr[0];
    switch (id) {
    case 1: /* ipAdEntAddr */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;
        *dst = *netif_ip4_addr(netif);
        return sizeof(dst->addr);
      }
    case 2: /* ipAdEntIfIndex */
      {
        s32_t *sint_ptr = (s32_t*)value;
        *sint_ptr = ifidx + 1;
        return sizeof(*sint_ptr);
      }
    case 3: /* ipAdEntNetMask */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;
        *dst = *netif_ip4_netmask(netif);
        return sizeof(*dst);
      }
    case 4: /* ipAdEntBcastAddr */
      {
        s32_t *sint_ptr = (s32_t*)value;

        /* lwIP oddity, there's no broadcast
          address in the netif we can rely on */
        *sint_ptr = IPADDR_BROADCAST & 1;
        return sizeof(*sint_ptr);
      }
    case 5: /* ipAdEntReasmMaxSize */
      {
        s32_t *sint_ptr = (s32_t*)value;
#if IP_REASSEMBLY
        /* @todo The theoretical maximum is IP_REASS_MAX_PBUFS * size of the pbufs,
          * but only if receiving one fragmented packet at a time.
          * The current solution is to calculate for 2 simultaneous packets...
          */
        *sint_ptr = (IP_HLEN + ((IP_REASS_MAX_PBUFS/2) *
          (PBUF_POOL_BUFSIZE - PBUF_LINK_ENCAPSULATION_HLEN - PBUF_LINK_HLEN - IP_HLEN)));
#else
        /** @todo returning MTU would be a bad thing and
            returning a wild guess like '576' isn't good either */
        *sint_ptr = 0;
#endif
        return sizeof(*sint_ptr);
      }
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_addrentry_get_value(): unknown id: %d\n", id));
      break;
    }
  }

  return 0;
}

/**
 * @note
 * lwIP IP routing is currently using the network addresses in netif_list.
 * if no suitable network IP is found in netif_list, the default_netif is used.
 */
static void
ip_rteentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  u8_t id;

  /* return to object name, adding index depth (4) */
  ident_len += 4;
  ident -= 4;

  if (ident_len == 5) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    switch (id) {
    case 1: /* ipRouteDest */
    case 7: /* ipRouteNextHop */
    case 11: /* ipRouteMask */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR);
      break;
    case 2: /* ipRouteIfIndex */
    case 3: /* ipRouteMetric1 */
    case 4: /* ipRouteMetric2 */
    case 5: /* ipRouteMetric3 */
    case 6: /* ipRouteMetric4 */
    case 8: /* ipRouteType */
    case 10: /* ipRouteAge */
    case 12: /* ipRouteMetric5 */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 9: /* ipRouteProto */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 13: /* ipRouteInfo */
      /** @note returning zeroDotZero (0.0) no routing protocol specific MIB */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_rteentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_rteentry_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
ip_rteentry_get_value(struct obj_def *od, void *value)
{
  struct netif *netif;
  ip4_addr_t dest;
  s32_t *ident;
  u8_t id;

  ident = od->id_inst_ptr;
  snmp_oidtoip(&ident[1], &dest);

  if (ip4_addr_isany_val(dest)) {
    /* ip_route() uses default netif for default route */
    netif = netif_default;
  } else {
    /* not using ip_route(), need exact match! */
    netif = netif_list;
    while ((netif != NULL) &&
            !ip4_addr_netcmp(&dest, netif_ip4_addr(netif), netif_ip4_netmask(netif))) {
      netif = netif->next;
    }
  }
  if (netif != NULL) {
    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    switch (id) {
    case 1: /* ipRouteDest */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;

        if (ip4_addr_isany_val(dest)) {
          /* default rte has 0.0.0.0 dest */
          ip4_addr_set_zero(dst);
        } else {
          /* netifs have netaddress dest */
          ip4_addr_get_network(dst, netif_ip4_addr(netif), netif_ip4_netmask(netif));
        }

        return sizeof(*dst);
      }
    case 2: /* ipRouteIfIndex */
      {
        s32_t *sint_ptr = (s32_t*)value;

        snmp_netiftoifindex(netif, sint_ptr);
        return sizeof(*sint_ptr);
      }
    case 3: /* ipRouteMetric1 */
      {
        s32_t *sint_ptr = (s32_t*)value;

        if (ip4_addr_isany_val(dest)) {
          /* default rte has metric 1 */
          *sint_ptr = 1;
        } else {
          /* other rtes have metric 0 */
          *sint_ptr = 0;
        }
        return sizeof(*sint_ptr);
      }
    case 4: /* ipRouteMetric2 */
    case 5: /* ipRouteMetric3 */
    case 6: /* ipRouteMetric4 */
    case 12: /* ipRouteMetric5 */
      {
        s32_t *sint_ptr = (s32_t*)value;
        /* not used */
        *sint_ptr = -1;
        return sizeof(*sint_ptr);
      }
    case 7: /* ipRouteNextHop */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;

        if (ip4_addr_isany_val(dest)) {
          /* default rte: gateway */
          *dst = *netif_ip4_gw(netif);
        } else {
          /* other rtes: netif ip_addr  */
          *dst = *netif_ip4_addr(netif);
        }

        return sizeof(*dst);
      }
    case 8: /* ipRouteType */
      {
        s32_t *sint_ptr = (s32_t*)value;

        if (ip4_addr_isany_val(dest)) {
          /* default rte is indirect */
          *sint_ptr = 4;
        } else {
          /* other rtes are direct */
          *sint_ptr = 3;
        }
        return sizeof(*sint_ptr);
      }
    case 9: /* ipRouteProto */
      {
        s32_t *sint_ptr = (s32_t*)value;
        /* locally defined routes */
        *sint_ptr = 2;
        return sizeof(*sint_ptr);
      }
    case 10: /* ipRouteAge */
      {
        s32_t *sint_ptr = (s32_t*)value;
        /** @todo (sysuptime - timestamp last change) / 100
            @see snmp_insert_iprteidx_tree() */
        *sint_ptr = 0;
        return sizeof(*sint_ptr);
      }
    case 11: /* ipRouteMask */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;

        if (ip4_addr_isany_val(dest)) {
          /* default rte use 0.0.0.0 mask */
          ip4_addr_set_zero(dst);
        } else {
          /* other rtes use netmask */
          *dst = *netif_ip4_netmask(netif);
        }

        return sizeof(*dst);
      }
    case 13: /* ipRouteInfo */
      MEMCPY(value, iprouteinfo.id, iprouteinfo.len * sizeof(s32_t));
      return iprouteinfo.len * sizeof(s32_t);
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_rteentry_get_value(): unknown id: %d\n", id));
      break;
    }
  }

  return 0;
}

static void
ip_ntomentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (5) */
  ident_len += 5;
  ident -= 5;

  if (ident_len == 6) {
    u8_t id;

    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    switch (id) {
    case 1: /* ipNetToMediaIfIndex */
    case 4: /* ipNetToMediaType */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 2: /* ipNetToMediaPhysAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
      break;
    case 3: /* ipNetToMediaNetAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_ntomentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_ntomentry_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
ip_ntomentry_get_value(struct obj_def *od, void *value)
{
#if LWIP_ARP
  u8_t id;
  struct eth_addr* ethaddr_ret;
  const ip4_addr_t* ipaddr_ret;
#endif /* LWIP_ARP */
  ip4_addr_t ip;
  struct netif *netif;

  LWIP_UNUSED_ARG(value);/* if !LWIP_ARP */

  snmp_ifindextonetif(od->id_inst_ptr[1], &netif);
  snmp_oidtoip(&od->id_inst_ptr[2], &ip);

#if LWIP_ARP /** @todo implement a netif_find_addr */
  if (etharp_find_addr(netif, &ip, &ethaddr_ret, &ipaddr_ret) > -1) {
    LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
    id = (u8_t)od->id_inst_ptr[0];
    switch (id) {
    case 1: /* ipNetToMediaIfIndex */
      {
        s32_t *sint_ptr = (s32_t*)value;
        *sint_ptr = od->id_inst_ptr[1];
        return sizeof(*sint_ptr);
      }
    case 2: /* ipNetToMediaPhysAddress */
      {
        struct eth_addr *dst = (struct eth_addr*)value;

        *dst = *ethaddr_ret;
        return sizeof(*dst); /** @todo try to use netif::hwaddr_len */
      }
    case 3: /* ipNetToMediaNetAddress */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;

        *dst = *ipaddr_ret;
        return sizeof(*dst);
      }
    case 4: /* ipNetToMediaType */
      {
        s32_t *sint_ptr = (s32_t*)value;
        /* dynamic (?) */
        *sint_ptr = 3;
        return sizeof(*sint_ptr);
      }
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("ip_ntomentry_get_value(): unknown id: %d\n", id));
      break;
    }
  }
#endif /* LWIP_ARP */

  return 0;
}

static void
icmp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if ((ident_len == 2) &&
      (ident[0] > 0) && (ident[0] < 27)) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    od->instance = MIB_OBJECT_SCALAR;
    od->access = MIB_OBJECT_READ_ONLY;
    od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER);
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("icmp_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
icmp_get_value(struct obj_def *od, void *value)
{
  u32_t *uint_ptr = (u32_t*)value;
  u8_t id;

  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
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
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("icmp_get_value(): unknown id: %d\n", id));
    break;
  }

  return 0;
}

#if LWIP_TCP
/** @todo tcp grp */
static void
tcp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  u8_t id;

  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if (ident_len == 2) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def tcp.%"U16_F".0\n",(u16_t)id));

    switch (id) {
    case 1: /* tcpRtoAlgorithm */
    case 2: /* tcpRtoMin */
    case 3: /* tcpRtoMax */
    case 4: /* tcpMaxConn */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    case 5: /* tcpActiveOpens */
    case 6: /* tcpPassiveOpens */
    case 7: /* tcpAttemptFails */
    case 8: /* tcpEstabResets */
    case 10: /* tcpInSegs */
    case 11: /* tcpOutSegs */
    case 12: /* tcpRetransSegs */
    case 14: /* tcpInErrs */
    case 15: /* tcpOutRsts */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER);
      break;
    case 9: /* tcpCurrEstab */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_GAUGE);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("tcp_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("tcp_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
tcp_get_value(struct obj_def *od, void *value)
{
  u32_t *uint_ptr = (u32_t*)value;
  s32_t *sint_ptr = (s32_t*)value;
  u8_t id;

  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
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
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("tcp_get_value(): unknown id: %d\n", id));
    break;
  }

  return 0;
}
#ifdef THIS_SEEMS_UNUSED
static void
tcpconnentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (10) */
  ident_len += 10;
  ident -= 10;

  if (ident_len == 11) {
    u8_t id;

    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    id = ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def tcp.%"U16_F".0\n",(u16_t)id));

    switch (id) {
    case 1: /* tcpConnState */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      od->v_len = sizeof(s32_t);
      break;
    case 2: /* tcpConnLocalAddress */
    case 4: /* tcpConnRemAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR);
      od->v_len = 4;
      break;
    case 3: /* tcpConnLocalPort */
    case 5: /* tcpConnRemPort */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      od->v_len = sizeof(s32_t);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("tcpconnentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("tcpconnentry_get_object_def: no such object\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static void
tcpconnentry_get_value(struct obj_def *od, u16_t len, void *value)
{
  ip_addr_t lip, rip;
  u16_t lport, rport;
  s32_t *ident;

  ident = od->id_inst_ptr;
  snmp_oidtoip(&ident[1], &lip);
  lport = ident[5];
  snmp_oidtoip(&ident[6], &rip);
  rport = ident[10];

  /** @todo find matching PCB */
}
#endif /* if 0 */
#endif

static void
udp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if ((ident_len == 2) &&
      (ident[0] > 0) && (ident[0] < 6)) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    od->instance = MIB_OBJECT_SCALAR;
    od->access = MIB_OBJECT_READ_ONLY;
    od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER);
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("udp_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
udp_get_value(struct obj_def *od, void *value)
{
  u32_t *uint_ptr = (u32_t*)value;
  u8_t id;

  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
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
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("udp_get_value(): unknown id: %d\n", id));
    break;
  }

  return 0;
}

static void
udpentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (5) */
  ident_len += 5;
  ident -= 5;

  if (ident_len == 6) {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    switch (ident[0]) {
    case 1: /* udpLocalAddress */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_IPADDR);
      break;
    case 2: /* udpLocalPort */
      od->instance = MIB_OBJECT_TAB;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("udpentry_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("udpentry_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
udpentry_get_value(struct obj_def *od, void *value)
{
  u8_t id;
  struct udp_pcb *pcb;
  ip_addr_t ip;
  u16_t port;

  snmp_oidtoip(&od->id_inst_ptr[1], ip_2_ip4(&ip));
  IP_SET_TYPE_VAL(ip, IPADDR_TYPE_V4);
  LWIP_ASSERT("invalid port", (od->id_inst_ptr[5] >= 0) && (od->id_inst_ptr[5] <= 0xffff));
  port = (u16_t)od->id_inst_ptr[5];

  pcb = udp_pcbs;
  while ((pcb != NULL) &&
         !(ip_addr_cmp(&pcb->local_ip, &ip) &&
           (pcb->local_port == port))) {
    pcb = pcb->next;
  }

  if (pcb != NULL) {
    LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
    id = (u8_t)od->id_inst_ptr[0];
    switch (id) {
    case 1: /* udpLocalAddress */
      {
        ip4_addr_t *dst = (ip4_addr_t*)value;
        ip4_addr_copy(*dst, *(ip_2_ip4(&pcb->local_ip)));
        return sizeof(*dst);
      }
      break;
    case 2: /* udpLocalPort */
      {
        s32_t *sint_ptr = (s32_t*)value;
        *sint_ptr = pcb->local_port;
        return sizeof(*sint_ptr);
      }
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("udpentry_get_value(): unknown id: %d\n", id));
      break;
    }
  }

  return 0;
}

static void
snmp_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  /* return to object name, adding index depth (1) */
  ident_len += 1;
  ident -= 1;
  if (ident_len == 2) {
    u8_t id;

    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    LWIP_ASSERT("invalid id", (ident[0] >= 0) && (ident[0] <= 0xff));
    id = (u8_t)ident[0];
    switch (id) {
    case 1: /* snmpInPkts */
    case 2: /* snmpOutPkts */
    case 3: /* snmpInBadVersions */
    case 4: /* snmpInBadCommunityNames */
    case 5: /* snmpInBadCommunityUses */
    case 6: /* snmpInASNParseErrs */
    case 8: /* snmpInTooBigs */
    case 9: /* snmpInNoSuchNames */
    case 10: /* snmpInBadValues */
    case 11: /* snmpInReadOnlys */
    case 12: /* snmpInGenErrs */
    case 13: /* snmpInTotalReqVars */
    case 14: /* snmpInTotalSetVars */
    case 15: /* snmpInGetRequests */
    case 16: /* snmpInGetNexts */
    case 17: /* snmpInSetRequests */
    case 18: /* snmpInGetResponses */
    case 19: /* snmpInTraps */
    case 20: /* snmpOutTooBigs */
    case 21: /* snmpOutNoSuchNames */
    case 22: /* snmpOutBadValues */
    case 24: /* snmpOutGenErrs */
    case 25: /* snmpOutGetRequests */
    case 26: /* snmpOutGetNexts */
    case 27: /* snmpOutSetRequests */
    case 28: /* snmpOutGetResponses */
    case 29: /* snmpOutTraps */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_ONLY;
      od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_COUNTER);
      break;
    case 30: /* snmpEnableAuthenTraps */
      od->instance = MIB_OBJECT_SCALAR;
      od->access = MIB_OBJECT_READ_WRITE;
      od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
      break;
    default:
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_get_object_def: no such object\n"));
      od->instance = MIB_OBJECT_NONE;
      break;
    }
  } else {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_get_object_def: no scalar\n"));
    od->instance = MIB_OBJECT_NONE;
  }
}

static u16_t
snmp_get_value(struct obj_def *od, void *value)
{
  u32_t *uint_ptr = (u32_t*)value;
  u8_t id;

  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  switch (id) {
  case 1: /* snmpInPkts */
    *uint_ptr = snmpinpkts;
    return sizeof(*uint_ptr);
  case 2: /* snmpOutPkts */
    *uint_ptr = snmpoutpkts;
    return sizeof(*uint_ptr);
  case 3: /* snmpInBadVersions */
    *uint_ptr = snmpinbadversions;
    return sizeof(*uint_ptr);
  case 4: /* snmpInBadCommunityNames */
    *uint_ptr = snmpinbadcommunitynames;
    return sizeof(*uint_ptr);
  case 5: /* snmpInBadCommunityUses */
    *uint_ptr = snmpinbadcommunityuses;
    return sizeof(*uint_ptr);
  case 6: /* snmpInASNParseErrs */
    *uint_ptr = snmpinasnparseerrs;
    return sizeof(*uint_ptr);
  case 8: /* snmpInTooBigs */
    *uint_ptr = snmpintoobigs;
    return sizeof(*uint_ptr);
  case 9: /* snmpInNoSuchNames */
    *uint_ptr = snmpinnosuchnames;
    return sizeof(*uint_ptr);
  case 10: /* snmpInBadValues */
    *uint_ptr = snmpinbadvalues;
    return sizeof(*uint_ptr);
  case 11: /* snmpInReadOnlys */
    *uint_ptr = snmpinreadonlys;
    return sizeof(*uint_ptr);
  case 12: /* snmpInGenErrs */
    *uint_ptr = snmpingenerrs;
    return sizeof(*uint_ptr);
  case 13: /* snmpInTotalReqVars */
    *uint_ptr = snmpintotalreqvars;
    return sizeof(*uint_ptr);
  case 14: /* snmpInTotalSetVars */
    *uint_ptr = snmpintotalsetvars;
    return sizeof(*uint_ptr);
  case 15: /* snmpInGetRequests */
    *uint_ptr = snmpingetrequests;
    return sizeof(*uint_ptr);
  case 16: /* snmpInGetNexts */
    *uint_ptr = snmpingetnexts;
    return sizeof(*uint_ptr);
  case 17: /* snmpInSetRequests */
    *uint_ptr = snmpinsetrequests;
    return sizeof(*uint_ptr);
  case 18: /* snmpInGetResponses */
    *uint_ptr = snmpingetresponses;
    return sizeof(*uint_ptr);
  case 19: /* snmpInTraps */
    *uint_ptr = snmpintraps;
    return sizeof(*uint_ptr);
  case 20: /* snmpOutTooBigs */
    *uint_ptr = snmpouttoobigs;
    return sizeof(*uint_ptr);
  case 21: /* snmpOutNoSuchNames */
    *uint_ptr = snmpoutnosuchnames;
    return sizeof(*uint_ptr);
  case 22: /* snmpOutBadValues */
    *uint_ptr = snmpoutbadvalues;
    return sizeof(*uint_ptr);
  case 24: /* snmpOutGenErrs */
    *uint_ptr = snmpoutgenerrs;
    return sizeof(*uint_ptr);
  case 25: /* snmpOutGetRequests */
    *uint_ptr = snmpoutgetrequests;
    return sizeof(*uint_ptr);
  case 26: /* snmpOutGetNexts */
    *uint_ptr = snmpoutgetnexts;
    return sizeof(*uint_ptr);
  case 27: /* snmpOutSetRequests */
    *uint_ptr = snmpoutsetrequests;
    return sizeof(*uint_ptr);
  case 28: /* snmpOutGetResponses */
    *uint_ptr = snmpoutgetresponses;
    return sizeof(*uint_ptr);
  case 29: /* snmpOutTraps */
    *uint_ptr = snmpouttraps;
    return sizeof(*uint_ptr);
  case 30: /* snmpEnableAuthenTraps */
    *uint_ptr = *snmpenableauthentraps_ptr;
    return sizeof(*uint_ptr);
  default:
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("snmp_get_value(): unknown id: %d\n", id));
    break;
  }

  return 0;
}

/**
 * Test snmp object value before setting.
 *
 * @param od is the object definition
 * @param len return value space (in bytes)
 * @param value points to (varbind) space to copy value from.
 */
static u8_t
snmp_set_test(struct obj_def *od, u16_t len, void *value)
{
  u8_t id, set_ok;

  LWIP_UNUSED_ARG(len);
  set_ok = 0;
  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  if (id == 30) {
    /* snmpEnableAuthenTraps */
    s32_t *sint_ptr = (s32_t*)value;

    /* we should have writable non-volatile mem here */
    if ((*sint_ptr == 1) || (*sint_ptr == 2)) {
      set_ok = 1;
    }
  }
  return set_ok;
}

static void
snmp_set_value(struct obj_def *od, u16_t len, void *value)
{
  u8_t id;

  LWIP_UNUSED_ARG(len);
  LWIP_ASSERT("invalid id", (od->id_inst_ptr[0] >= 0) && (od->id_inst_ptr[0] <= 0xff));
  id = (u8_t)od->id_inst_ptr[0];
  if (id == 30) {
    /* snmpEnableAuthenTraps */
    s32_t *ptr = (s32_t*)value;
    *snmpenableauthentraps_ptr = (u8_t)*ptr;
  }
}

#endif /* LWIP_SNMP */
