/**
 * @file
 * [EXPERIMENTAL] Management Information Base II (RFC1213) objects and functions
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

#include "arch/cc.h"
#include "lwip/opt.h"
#include "lwip/snmp.h"
#include "lwip/netif.h"
#include "lwip/snmp_asn1.h"
#include "lwip/snmp_structs.h"

#if LWIP_SNMP

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
#define SNMP_SYSOBJID_LEN 5
#define SNMP_SYSOBJID {6, 1, 4, 1, SNMP_ENTERPRISE_ID}

#ifndef SNMP_SYSSERVICES
#define SNMP_SYSSERVICES ((1 << 6) | (1 << 3) | ((IP_FORWARD) << 2))
#endif

/** @todo publish this in snmp.h (for use in private mib) */
void noleafs_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
void noleafs_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value);

static void system_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static void system_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value);
static void interfaces_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static void interfaces_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value);
static void ifentry_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
static void ifentry_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value);

/* snmp .1.3.6.1.2.1.11 */
const s32_t snmp_ids[29] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30
};
struct mib_node* const snmp_nodes[29] = {
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};
const struct mib_array_node snmp = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  29,
  snmp_ids,
  snmp_nodes 
};

/* dot3 and EtherLike MIB not planned. (transmission .1.3.6.1.2.1.10) */
/* historical (some say hysterical). (cmot .1.3.6.1.2.1.9) */
/* lwIP has no EGP, thus may not implement it. (egp .1.3.6.1.2.1.8) */

/* udp .1.3.6.1.2.1.7 */
const s32_t udp_ids[5] = { 1, 2, 3, 4, 5 };
struct mib_node* const udp_nodes[5] = {
  NULL, NULL, NULL, NULL, /** @todo udpTable */ NULL
};
const struct mib_array_node udp = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  5,
  udp_ids,
  udp_nodes
};

/* tcp .1.3.6.1.2.1.6 */
const s32_t tcp_ids[15] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
struct mib_node* const tcp_nodes[15] = {
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  /** @todo tcpConnTable */ NULL, NULL, NULL
};
const struct mib_array_node tcp = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  15,
  tcp_ids,
  tcp_nodes
};

/* icmp .1.3.6.1.2.1.5 */
const s32_t icmp_ids[26] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26 };
struct mib_node* const icmp_nodes[26] = {
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
const struct mib_array_node icmp = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  26,
  icmp_ids,
  icmp_nodes
};

/* ip .1.3.6.1.2.1.4 */
const s32_t ip_ids[23] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };
struct mib_node* const ip_nodes[23] = {
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, /** @todo ipAddrTable */ NULL, /** @todo ipRouteTable */ NULL, /** @todo ipNetToMediaTable */ NULL, NULL
};
const struct mib_array_node ip = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  23,
  ip_ids,
  ip_nodes
};

/* at .1.3.6.1.2.1.3 */
const s32_t at_ids[1] = { 1 };
struct mib_node* const at_nodes[1] = { /** @todo atTable*/ NULL };
const struct mib_array_node at = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  1,
  at_ids,
  at_nodes
};

const s32_t ifentry_ids[22] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };
struct mib_node* const ifentry_nodes[22] = {
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
const struct mib_array_node ifentry = {
  &ifentry_get_object_def,
  &ifentry_get_value,
  MIB_NODE_AR,
  22,
  ifentry_ids,
  ifentry_nodes
};

const s32_t iftable_id = 1;
struct mib_node* const iftable_node = (struct mib_node* const)&ifentry;
const struct mib_array_node iftable = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  1,
  &iftable_id,
  &iftable_node
};

/* interfaces .1.3.6.1.2.1.2 */
const s32_t interfaces_ids[2] = { 1, 2 };
struct mib_node* const interfaces_nodes[2] = { NULL, (struct mib_node* const)&iftable };
const struct mib_array_node interfaces = {
  &interfaces_get_object_def,
  &interfaces_get_value,
  MIB_NODE_AR,
  2,
  interfaces_ids,
  interfaces_nodes
};

/*             0 1 2 3 4 5 6 */
/* system .1.3.6.1.2.1.1 */
const s32_t sys_tem_ids[7] = { 1, 2, 3, 4, 5, 6, 7 };
struct mib_node* const sys_tem_nodes[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
/* work around name issue with 'sys_tem', some compiler(s?) seem to reserve 'system' */
const struct mib_array_node sys_tem = {
  &system_get_object_def,
  &system_get_value,
  MIB_NODE_AR,
  7,
  sys_tem_ids,
  sys_tem_nodes
};

/* mib-2 .1.3.6.1.2.1 */
const s32_t mib2_ids[8] = { 1, 2, 3, 4, 5, 6, 7, 11 };
struct mib_node* const mib2_nodes[8] = {
  (struct mib_node* const)&sys_tem,
  (struct mib_node* const)&interfaces,
  (struct mib_node* const)&at,
  (struct mib_node* const)&ip,
  (struct mib_node* const)&icmp,
  (struct mib_node* const)&tcp,
  (struct mib_node* const)&udp,
  (struct mib_node* const)&snmp
};
const struct mib_array_node mib2 = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  8,
  mib2_ids,
  mib2_nodes
};

/* mgmt .1.3.6.1.2 */
const s32_t mgmt_ids[1] = { 1 };
struct mib_node* const mgmt_nodes[1] = { (struct mib_node* const)&mib2 };
const struct mib_array_node mgmt = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  1,
  mgmt_ids,
  mgmt_nodes
};

/* internet .1.3.6.1 */
#if SNMP_PRIVATE_MIB
s32_t internet_ids[2] = { 2, 4 };
struct mib_node* const internet_nodes[2] = { (struct mib_node* const)&mgmt, (struct mib_node* const)&private };
const struct mib_array_node internet = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  2,
  internet_ids,
  internet_nodes
};
#else
const s32_t internet_ids[1] = { 2 };
struct mib_node* const internet_nodes[1] = { (struct mib_node* const)&mgmt };
const struct mib_array_node internet = {
  &noleafs_get_object_def,
  &noleafs_get_value,
  MIB_NODE_AR,
  1,
  internet_ids,
  internet_nodes
};
#endif

/** .iso.org.dod.internet.mgmt.mib-2.sysObjectID  */
static struct snmp_obj_id sysobjid = {SNMP_SYSOBJID_LEN, SNMP_SYSOBJID};
/** enterprise ID for generic TRAPs, .iso.org.dod.internet.mgmt.mib-2.snmp */
static struct snmp_obj_id snmpgrp_id = {5,{6,1,2,1,11}};
/** .iso.org.dod.internet.mgmt.mib-2.sysServices */
static const s32_t sysservices = SNMP_SYSSERVICES;

/** .iso.org.dod.internet.mgmt.mib-2.sysDescr */
static u8_t sysdescr_len = 4;
static u8_t sysdescr[255] = "lwIP";
static u8_t syscontact_len = 0;
static u8_t syscontact[255];
static u8_t sysname_len = 0;
static u8_t sysname[255];
static u8_t syslocation_len = 0;
static u8_t syslocation[255];
/** .iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifSpecific */
static const struct snmp_obj_id ifspecific = {0, {0}};

/* mib-2.system counter(s) */
static u32_t sysuptime = 0;

/* mib-2.ip counter(s) */
static u32_t ipindelivers = 0,
             ipinreceives = 0,
             ipindiscards = 0,
             ipoutdiscards = 0,
             ipoutrequests = 0,
             ipunknownprotos = 0;
/* mib-2.icmp counter(s) */
static u32_t icmpinmsgs = 0,
             icmpinerrors = 0,
             icmpindestunreachs = 0,
             icmpintimeexcds = 0,
             icmpinparmprobs = 0,
             icmpinsrcquenchs = 0,
             icmpinredirects = 0,
             icmpinechos = 0,
             icmpinechoreps = 0,
             icmpintimestamps = 0,
             icmpintimestampreps = 0,
             icmpinaddrmasks = 0,
             icmpinaddrmaskreps = 0,
             icmpoutmsgs = 0,
             icmpouterrors = 0,
             icmpoutdestunreachs = 0,
             icmpouttimeexcds = 0,
             icmpoutparmprobs = 0,
             icmpoutsrcquenchs = 0,
             icmpoutredirects = 0,
             icmpoutechos = 0,
             icmpoutechoreps = 0,
             icmpouttimestamps = 0,
             icmpouttimestampreps = 0,
             icmpoutaddrmasks = 0,
             icmpoutaddrmaskreps = 0;
/* mib-2.tcp counter(s) */
static u32_t tcpactiveopens = 0,
             tcppassiveopens = 0,
             tcpattemptfails = 0,
             tcpestabresets = 0,
             tcpcurrestab = 0,
             tcpinsegs = 0,
             tcpoutsegs = 0,
             tcpretranssegs = 0,
             tcpinerrs = 0,
             tcpoutrsts = 0;
/* mib-2.udp counter(s) */
static u32_t udpindatagrams = 0,
             udpnoports = 0,
             udpinerrors = 0,
             udpoutdatagrams = 0;
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



/* prototypes of the following functions are in lwip/src/include/lwip/snmp.h */
/**
 * Copy octet string.
 *
 * @param dst points to destination
 * @param src points to source
 * @param n number of octets to copy.
 */
void ocstrncpy(u8_t *dst, u8_t *src, u8_t n)
{
  while (n > 0)
  {
    n--;
    *dst++ = *src++;
  }
}

/**
 * Copy object identifier (s32_t) array.
 *
 * @param dst points to destination
 * @param src points to source
 * @param n number of sub identifiers to copy.
 */
void objectidncpy(s32_t *dst, s32_t *src, u8_t n)
{
  while(n > 0)
  {
    n--;
    *dst++ = *src++;
  }
}

/**
 * Initializes sysDescr value.
 *
 * @param str if non-NULL then copy str
 * @param strlen string length, excluding zero terminator
 */
void snmp_set_sysdesr(u8_t* str, u8_t strlen)
{
  if (str != NULL)
  {
    strlen = ((strlen < sizeof(sysdescr))?(strlen):(sizeof(sysdescr)));
    ocstrncpy(sysdescr, str, strlen);
  }
}

void snmp_get_sysobjid_ptr(struct snmp_obj_id **oid)
{
  *oid = &sysobjid;
}

/**
 * Initializes sysObjectID value.
 *
 * @param oid points to stuct snmp_obj_id to copy
 */
void snmp_set_sysobjid(struct snmp_obj_id *oid)
{
  sysobjid = *oid;
}

/**
 * Must be called at regular 10 msec interval from a timer interrupt
 * or signal handler depending on your runtime environment.
 */
void snmp_inc_sysuptime(void)
{
  sysuptime++;
}

void snmp_get_sysuptime(u32_t *value)
{
  *value = sysuptime;
}

/**
 * Initializes sysContact value (from lwIP external non-volatile memory).
 *
 * @param str if non-NULL then copy str
 * @param strlen string length, excluding zero terminator
 */
void snmp_set_syscontact(u8_t *ocstr, u8_t ocstrlen)
{
  if (ocstr != NULL)
  {
    ocstrlen = ((ocstrlen < sizeof(syscontact))?(ocstrlen):(sizeof(syscontact)));
    ocstrncpy(syscontact, ocstr, ocstrlen);
  }
}

/**
 * Initializes sysName value (from lwIP external non-volatile memory).
 *
 * @param str if non-NULL then copy str
 * @param strlen string length, excluding zero terminator
 */
void snmp_set_sysname(u8_t *ocstr, u8_t ocstrlen)
{
  if (ocstr != NULL)
  {
    ocstrlen = ((ocstrlen < sizeof(sysname))?(ocstrlen):(sizeof(sysname)));
    ocstrncpy(sysname, ocstr, ocstrlen);
  }
}

/**
 * Initializes sysLocation value (from lwIP external non-volatile memory).
 *
 * @param str if non-NULL then copy str
 * @param strlen string length, excluding zero terminator
 */
void snmp_set_syslocation(u8_t *ocstr, u8_t ocstrlen)
{
  if (ocstr != NULL)
  {
    ocstrlen = ((ocstrlen < sizeof(syslocation))?(ocstrlen):(sizeof(syslocation)));
    ocstrncpy(syslocation, ocstr, ocstrlen);
  }
}


void snmp_add_ifinoctets(struct netif *ni, u32_t value)
{
  ni->ifinoctets += value;  
}

void snmp_inc_ifinucastpkts(struct netif *ni)
{
  (ni->ifinucastpkts)++;
}

void snmp_inc_ifinnucastpkts(struct netif *ni)
{
  (ni->ifinnucastpkts)++;
}

void snmp_inc_ifindiscards(struct netif *ni)
{
  (ni->ifindiscards)++;
}

void snmp_add_ifoutoctets(struct netif *ni, u32_t value)
{
  ni->ifoutoctets += value;  
}

void snmp_inc_ifoutucastpkts(struct netif *ni)
{
  (ni->ifoutucastpkts)++;
}

void snmp_inc_ifoutnucastpkts(struct netif *ni)
{
  (ni->ifoutnucastpkts)++;
}

void snmp_inc_ifoutdiscards(struct netif *ni)
{
  (ni->ifoutdiscards)++;
}

void snmp_inc_ipindelivers(void)
{
  ipindelivers++;
}

void snmp_inc_ipinreceives(void)
{
  ipinreceives++;
}

void snmp_inc_ipindiscards(void)
{
  ipindiscards++;
}

void snmp_inc_ipoutdiscards(void)
{
  ipoutdiscards++;
}

void snmp_inc_ipoutrequests(void)
{
  ipoutrequests++;
}

void snmp_inc_ipunknownprotos(void)
{
  ipunknownprotos++;
}


void snmp_inc_icmpinmsgs(void)
{
  icmpinmsgs++;
}

void snmp_inc_icmpinerrors(void)
{
  icmpinerrors++;
}

void snmp_inc_icmpindestunreachs(void)
{
  icmpindestunreachs++;
}

void snmp_inc_icmpintimeexcds(void)
{
  icmpintimeexcds++;
}

void snmp_inc_icmpinparmprobs(void)
{
  icmpinparmprobs++;
}

void snmp_inc_icmpinsrcquenchs(void)
{
  icmpinsrcquenchs++;
}

void snmp_inc_icmpinredirects(void)
{
  icmpinredirects++;
}

void snmp_inc_icmpinechos(void)
{
  icmpinechos++;
}

void snmp_inc_icmpinechoreps(void)
{ 
  icmpinechoreps++;
}

void snmp_inc_icmpintimestamps(void)
{
  icmpintimestamps++;
}

void snmp_inc_icmpintimestampreps(void)
{
  icmpintimestampreps++;
}

void snmp_inc_icmpinaddrmasks(void)
{
  icmpinaddrmasks++;
} 

void snmp_inc_icmpinaddrmaskreps(void)
{
  icmpinaddrmaskreps++;
} 

void snmp_inc_icmpoutmsgs(void)
{
  icmpoutmsgs++;
}

void snmp_inc_icmpouterrors(void)
{
  icmpouterrors++;
}

void snmp_inc_icmpoutdestunreachs(void)
{
  icmpoutdestunreachs++;
} 

void snmp_inc_icmpouttimeexcds(void)
{
  icmpouttimeexcds++;
}

void snmp_inc_icmpoutparmprobs(void)
{
  icmpoutparmprobs++;
}

void snmp_inc_icmpoutsrcquenchs(void)
{
  icmpoutsrcquenchs++;
}

void snmp_inc_icmpoutredirects(void)
{
  icmpoutredirects++;
} 

void snmp_inc_icmpoutechos(void)
{
  icmpoutechos++;
}

void snmp_inc_icmpoutechoreps(void)
{
  icmpoutechoreps++;
}

void snmp_inc_icmpouttimestamps(void)
{
  icmpouttimestamps++;
}

void snmp_inc_icmpouttimestampreps(void)
{
  icmpouttimestampreps++;
}

void snmp_inc_icmpoutaddrmasks(void)
{
  icmpoutaddrmasks++;
}

void snmp_inc_icmpoutaddrmaskreps(void)
{
  icmpoutaddrmaskreps++;
}

void snmp_inc_tcpactiveopens(void)
{
  tcpactiveopens++;
}

void snmp_inc_tcppassiveopens(void)
{
  tcppassiveopens++;
}

void snmp_inc_tcpattemptfails(void)
{
  tcpattemptfails++;
}

void snmp_inc_tcpestabresets(void)
{
  tcpestabresets++;
} 

void snmp_inc_tcpcurrestab(void)
{
  tcpcurrestab++; 
}

void snmp_inc_tcpinsegs(void)
{
  tcpinsegs++;
}

void snmp_inc_tcpoutsegs(void)
{
  tcpoutsegs++;
}

void snmp_inc_tcpretranssegs(void)
{
  tcpretranssegs++;
}

void snmp_inc_tcpinerrs(void)
{
  tcpinerrs++;
}

void snmp_inc_tcpoutrsts(void)
{
  tcpoutrsts++;
}

void snmp_inc_udpindatagrams(void)
{
  udpindatagrams++;
}

void snmp_inc_udpnoports(void)
{
  udpnoports++;
}

void snmp_inc_udpinerrors(void)
{
  udpinerrors++;
}

void snmp_inc_udpoutdatagrams(void)
{
  udpoutdatagrams++;
}

void snmp_inc_snmpinpkts(void)
{
  snmpinpkts++;
}

void snmp_inc_snmpoutpkts(void)
{
  snmpoutpkts++;
}

void snmp_inc_snmpinbadversions(void)
{
  snmpinbadversions++;
}

void snmp_inc_snmpinbadcommunitynames(void)
{
  snmpinbadcommunitynames++;
}

void snmp_inc_snmpinbadcommunityuses(void)
{
  snmpinbadcommunityuses++;
}

void snmp_inc_snmpinasnparseerrs(void)
{
  snmpinasnparseerrs++;
}

void snmp_inc_snmpintoobigs(void)
{
  snmpintoobigs++;
}

void snmp_inc_snmpinnosuchnames(void)
{
  snmpinnosuchnames++;
}

void snmp_inc_snmpinbadvalues(void)
{
  snmpinbadvalues++;
}

void snmp_inc_snmpinreadonlys(void)
{
  snmpinreadonlys++;
}

void snmp_inc_snmpingenerrs(void)
{
  snmpingenerrs++;
}

void snmp_add_snmpintotalreqvars(u8_t value)
{
  snmpintotalreqvars += value;
}

void snmp_add_snmpintotalsetvars(u8_t value)
{
  snmpintotalsetvars += value;
}

void snmp_inc_snmpingetrequests(void)
{
  snmpingetrequests++;
}

void snmp_inc_snmpingetnexts(void)
{
  snmpingetnexts++;
}

void snmp_inc_snmpinsetrequests(void)
{
  snmpinsetrequests++;
}

void snmp_inc_snmpingetresponses(void)
{
  snmpingetresponses++;
}

void snmp_inc_snmpintraps(void)
{
  snmpintraps++;
}

void snmp_inc_snmpouttoobigs(void)
{
  snmpouttoobigs++;
}

void snmp_inc_snmpoutnosuchnames(void)
{
  snmpoutnosuchnames++;
}

void snmp_inc_snmpoutbadvalues(void)
{
  snmpoutbadvalues++;
}

void snmp_inc_snmpoutgenerrs(void)
{
  snmpoutgenerrs++;
}

void snmp_inc_snmpoutgetrequests(void)
{
  snmpoutgetrequests++;
}

void snmp_inc_snmpoutgetnexts(void)
{
  snmpoutgetnexts++;
}

void snmp_inc_snmpoutsetrequests(void)
{
  snmpoutsetrequests++;
}

void snmp_inc_snmpoutgetresponses(void)
{
  snmpoutgetresponses++;
}

void snmp_inc_snmpouttraps(void)
{
  snmpouttraps++;
}

void snmp_get_snmpgrpid_ptr(struct snmp_obj_id **oid)
{
  *oid = &snmpgrp_id;
}


void
noleafs_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od)
{
  if(ident_len){}
  if(ident){}
  od->instance = MIB_OBJECT_NONE;
}

void                                                  
noleafs_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value)
{
  if(ident_len){}
  if(ident){}
  if(len){}
  if(value){}
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

  if ((ident_len == 2) && (ident[1] == 0))
  { 
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;
    
    id = ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def system.%"U16_F".0",(u16_t)id));
    switch (id)
    {
      case 1: /* sysDescr */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
        od->v_len = sysdescr_len;
        break;
      case 2: /* sysObjectID */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID);
        od->v_len = SNMP_SYSOBJID_LEN * sizeof(s32_t);
        break;
      case 3: /* sysUpTime */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_TIMETICKS);
        od->v_len = sizeof(u32_t);
        break;
      case 4: /* sysContact */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_WRITE;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
        od->v_len = syscontact_len;
        break;
      case 5: /* sysName */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_WRITE;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
        od->v_len = sysname_len;
        break;
      case 6: /* sysLocation */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_WRITE;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
        od->v_len = syslocation_len;
        break;
      case 7: /* sysServices */
        od->instance = MIB_OBJECT_SCALAR;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
        od->v_len = sizeof(s32_t);
        break;
      default:
        od->instance = MIB_OBJECT_NONE;
        break;
    };
  }
  else
  {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("system_get_object_def: no scalar"));
    od->instance = MIB_OBJECT_NONE;
  }
}

/**
 * Returns system object value.
 *
 * @param ident_len the address length (2)
 * @param ident points to objectname.0 (object id trailer)
 * @param len return value space (in bytes)
 * @param value points to (varbind) space to copy value into.
 */
static void                                                  
system_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value)
{
  u8_t id;

  id = ident[0];
  switch (id)
  {
    case 1: /* sysDescr */
      ocstrncpy(value,sysdescr,len);
      break;
    case 2: /* sysObjectID */
      objectidncpy((s32_t*)value,(s32_t*)sysobjid.id,len / sizeof(s32_t));
      break;
    case 3: /* sysUpTime */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;

        *uint_ptr = sysuptime;
      }
      break;
    case 4: /* sysContact */
      ocstrncpy(value,syscontact,len);
      break;
    case 5: /* sysName */
      ocstrncpy(value,sysname,len);
      break;
    case 6: /* sysLocation */
      ocstrncpy(value,syslocation,len);
      break;
    case 7: /* sysServices */
      if (len == sizeof(s32_t))
      {
        s32_t *sint_ptr = value;

        *sint_ptr = sysservices;
      }
      break;
    default:
      break;
  };
  if (ident_len){}
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
  if ((ident_len == 2) && (ident[0] == 1) && (ident[1] == 0))
  {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;

    od->instance = MIB_OBJECT_SCALAR;
    od->access = MIB_OBJECT_READ_ONLY;
    od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
    od->v_len = sizeof(s32_t);
  }
  else
  {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("interfaces_get_object_def: no scalar"));
    od->instance = MIB_OBJECT_NONE;
  }
  if (ident_len){}
}

/**
 * Returns interfaces.ifnumber object value.
 *
 * @param ident_len the address length (2)
 * @param ident points to objectname.0 (object id trailer)
 * @param len return value space (in bytes)
 * @param value points to (varbind) space to copy value into.
 */
static void                                                  
interfaces_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value)
{
  if (ident[0] == 1)
  {
    if (len == sizeof(s32_t))
    {
      s32_t *sint_ptr = value;
      *sint_ptr = netif_cnt;
    }
  }
  if (ident_len){}
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

  if ((ident_len == 2) && (ident[1] > 0) && (ident[1] <= netif_cnt))
  {
    od->id_inst_len = ident_len;
    od->id_inst_ptr = ident;
    
    id = ident[0];
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("get_object_def ifentry.%"U16_F".",(u16_t)id));
    switch (id)
    {
      case 1: /* ifIndex */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
        od->v_len = sizeof(s32_t);
        break;
      case 2: /* ifDescr */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
        /** @todo this should be some sort of sizeof(struct netif.name) */
        od->v_len = 2;
        break;
      case 3: /* ifType */
      case 4: /* ifMtu */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
        od->v_len = sizeof(s32_t);
        break;
      case 5: /* ifSpeed */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_GAUGE);
        od->v_len = sizeof(u32_t);
        break;
      case 6: /* ifPhysAddress */
        {
          struct netif *netif = netif_list;
          u16_t i, ifidx;

          ifidx = ident[1] - 1;
          i = 0;
          while ((netif != NULL) && (i < ifidx))
          {
            netif = netif->next;
            i++;
          }
          od->instance = MIB_OBJECT_TAB;
          od->access = MIB_OBJECT_READ_ONLY;
          od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OC_STR);
          od->v_len = netif->hwaddr_len;
        }
        break;
      case 7: /* ifAdminStatus */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_WRITE;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
        od->v_len = sizeof(s32_t);
        break;
      case 8: /* ifOperStatus */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_INTEG);
        od->v_len = sizeof(s32_t);
        break;
      case 9: /* ifLastChange */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_TIMETICKS);
        od->v_len = sizeof(u32_t);
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
        od->v_len = sizeof(u32_t);
        break;
      case 21: /* ifOutQLen */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_APPLIC | SNMP_ASN1_PRIMIT | SNMP_ASN1_GAUGE);
        od->v_len = sizeof(u32_t);
        break;
      case 22: /* ifSpecific */
        /* @bug not returning null object id ... */
        od->instance = MIB_OBJECT_TAB;
        od->access = MIB_OBJECT_READ_ONLY;
        od->asn_type = (SNMP_ASN1_UNIV | SNMP_ASN1_PRIMIT | SNMP_ASN1_OBJ_ID);
        od->v_len = ifspecific.len * sizeof(s32_t);
        break;
      default:
        od->instance = MIB_OBJECT_NONE;
        break;
    };
  }
  else
  {
    LWIP_DEBUGF(SNMP_MIB_DEBUG,("ifentry_get_object_def: no scalar"));
    od->instance = MIB_OBJECT_NONE;
  }
}

/**
 * Returns ifentry object value.
 *
 * @param ident_len the address length (2)
 * @param ident points to objectname.0 (object id trailer)
 * @param len return value space (in bytes)
 * @param value points to (varbind) space to copy value into.
 */
static void                                                  
ifentry_get_value(u8_t ident_len, s32_t *ident, u16_t len, void *value)
{
  struct netif *netif = netif_list;
  u16_t i, ifidx;
  u8_t id;

  ifidx = ident[1] - 1;
  i = 0;
  while ((netif != NULL) && (i < ifidx))
  {
    netif = netif->next;
    i++;
  }
  id = ident[0];
  switch (id)
  {
    case 1: /* ifIndex */
      if (len == sizeof(s32_t))
      {
        s32_t *sint_ptr = value;
        *sint_ptr = ident[1];
      }
      break;
    case 2: /* ifDescr */
      ocstrncpy(value,(u8_t*)netif->name,len);
      break;
    case 3: /* ifType */
      if (len == sizeof(s32_t))
      {
        s32_t *sint_ptr = value;
        *sint_ptr = netif->link_type;
      }
      break;
    case 4: /* ifMtu */
      if (len == sizeof(s32_t))
      {
        s32_t *sint_ptr = value;
        *sint_ptr = netif->mtu;
      }
      break;
    case 5: /* ifSpeed */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->link_speed;
      }
      break;
    case 6: /* ifPhysAddress */
      ocstrncpy(value,netif->hwaddr,len);
      break;
    case 7: /* ifAdminStatus */
    case 8: /* ifOperStatus */
      if (len == sizeof(s32_t))
      {
        s32_t *sint_ptr = value;
        if (netif_is_up(netif))
        {
          *sint_ptr = 1;
        }
        else
        {
          *sint_ptr = 2;
        }
      }
      break;
    case 9: /* ifLastChange */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ts;
      }
      break;
    case 10: /* ifInOctets */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifinoctets;
      }
      break;
    case 11: /* ifInUcastPkts */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifinucastpkts;
      }
      break;
    case 12: /* ifInNUcastPkts */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifinnucastpkts;
      }
      break;
    case 13: /* ifInDiscarts */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifindiscards;
      }
      break;
    case 14: /* ifInErrors */
    case 15: /* ifInUnkownProtos */
      /** @todo add these counters! */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = 0;
      }
      break;
    case 16: /* ifOutOctets */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifoutoctets;
      }
      break;
    case 17: /* ifOutUcastPkts */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifoutucastpkts;
      }
      break;
    case 18: /* ifOutNUcastPkts */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifoutnucastpkts;
      }
      break;
    case 19: /* ifOutDiscarts */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = netif->ifoutdiscards;
      }
      break;
    case 20: /* ifOutErrors */
       /** @todo add this counter! */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = 0;
      }
      break;
    case 21: /* ifOutQLen */
      /** @todo figure out if this must be 0 (no queue) or 1? */
      if (len == sizeof(u32_t))
      {
        u32_t *uint_ptr = value;
        *uint_ptr = 0;
      }
      break;
    case 22: /* ifSpecific */
      objectidncpy((s32_t*)value,(s32_t*)ifspecific.id,len / sizeof(s32_t));
      break;
    default:
      break;
  };
  if (ident_len){}
}

#endif /* LWIP_SNMP */