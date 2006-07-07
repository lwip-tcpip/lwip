/**
 * @file
 * [EXPIRIMENTAL] Management Information Base II (RFC1213) objects and functions
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
#include "lwip/snmp_asn1.h"
/* #include "lwip/snmp_structs.h" */

#if LWIP_SNMP

#ifndef SNMP_ENTERPRISE_ID
/** 
 * IANA assigned enterprise ID for lwIP is 26381
 * @see http://www.iana.org/assignments/enterprise-numbers
 * @note this enterprise ID is assigned to the lwIP project,
 * all object identifiers living under this ID are assigned
 * by the lwIP maintainers (contact Christiaan Simons)!
 *
 * If you need to create your own private MIB you'll need
 * to apply for your own enterprise ID with IANA:
 * http://www.iana.org/numbers.html 
 */
#define SNMP_ENTERPRISE_ID 26381
#endif
#ifndef SNMP_SYSOBJID_LEN
#define SNMP_SYSOBJID_LEN 5
#endif
#ifndef SNMP_SYSOBJID
#define SNMP_SYSOBJID {6, 1, 4, 1, SNMP_ENTERPRISE_ID}
#endif

/** @todo MIB-tree will be inserted here */

/** .iso.org.dod.internet.mgmt.mib-2.sysObjectID  */
const struct snmp_obj_id sysobjid = {SNMP_SYSOBJID_LEN, SNMP_SYSOBJID};
/** enterprise ID for generic TRAPs, .iso.org.dod.internet.mgmt.mib-2.snmp */
const struct snmp_obj_id snmpgrp_id = {5,{6,1,2,1,11}};

/* mib-2.system counter(s) */
static u32_t sysuptime;
/* mib-2.interfaces counter(s) */
static u32_t ifinoctets,
             ifinucastpkts,
             ifinnucastpkts,
             ifindiscards,
             ifoutoctets,
             ifoutucastpkts,
             ifoutnucastpkts,
             ifoutdiscards;
/* mib-2.ip counter(s) */
static u32_t ipindelivers,
             ipinreceives,
             ipindiscards,
             ipoutdiscards,
             ipoutrequests,
             ipunknownprotos;
/* mib-2.icmp counter(s) */
static u32_t icmpinmsgs,
             icmpinerrors,
             icmpindestunreachs,
             icmpintimeexcds,
             icmpinparmprobs,
             icmpinsrcquenchs,
             icmpinredirects,
             icmpinechos,
             icmpinechoreps,
             icmpintimestamps,
             icmpintimestampreps,
             icmpinaddrmasks,
             icmpinaddrmaskreps,
             icmpoutmsgs,
             icmpouterrors,
             icmpoutdestunreachs,
             icmpouttimeexcds,
             icmpoutparmprobs,
             icmpoutsrcquenchs,
             icmpoutredirects,
             icmpoutechos,
             icmpoutechoreps,
             icmpouttimestamps,
             icmpouttimestampreps,
             icmpoutaddrmasks,
             icmpoutaddrmaskreps;
/* mib-2.tcp counter(s) */
static u32_t tcpactiveopens,
             tcppassiveopens,
             tcpattemptfails,
             tcpestabresets,
             tcpcurrestab,
             tcpinsegs,
             tcpoutsegs,
             tcpretranssegs,
             tcpinerrs,
             tcpoutrsts;
/* mib-2.udp counter(s) */
static u32_t udpindatagrams,
             udpnoports,
             udpinerrors,
             udpoutdatagrams;
/* mib-2.snmp counter(s) */             
static u32_t snmpinpkts,
             snmpoutpkts,
             snmpinbadversions,
             snmpinbadcommunitynames,
             snmpinbadcommunityuses,
             snmpinasnparseerrs,
             snmpintoobigs,
             snmpinnosuchnames,
             snmpinbadvalues,
             snmpinreadonlys,
             snmpingenerrs,
             snmpintotalreqvars,
             snmpintotalsetvars,
             snmpingetrequests,
             snmpingetnexts,
             snmpinsetrequests,
             snmpingetresponses,
             snmpintraps,
             snmpouttoobigs,
             snmpoutnosuchnames,
             snmpoutbadvalues,
             snmpoutgenerrs,
             snmpoutgetrequests,
             snmpoutgetnexts,
             snmpoutsetrequests,
             snmpoutgetresponses,
             snmpouttraps;

/* prototypes of the following functions are in lwip/src/include/lwip/snmp.h */

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

void snmp_get_sysobjid(const struct snmp_obj_id **oid)
{
  *oid = &sysobjid;
}

void snmp_add_ifinoctets(u32_t value)
{
  ifinoctets += value;  
}

void snmp_inc_ifinucastpkts(void)
{
  ifinucastpkts++;  
}

void snmp_inc_ifinnucastpkts(void)
{
  ifinnucastpkts++;  
}

void snmp_inc_ifindiscards(void)
{
  ifindiscards++;  
}

void snmp_add_ifoutoctets(u32_t value)
{
  ifoutoctets += value;  
}

void snmp_inc_ifoutucastpkts(void)
{
  ifoutucastpkts++;  
}

void snmp_inc_ifoutnucastpkts(void)
{
  ifoutnucastpkts++;  
}

void snmp_inc_ifoutdiscards(void)
{
  ifoutdiscards++;  
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

void snmp_get_snmpgrpid(const struct snmp_obj_id **oid)
{
  *oid = &snmpgrp_id;
}

#endif /* LWIP_SNMP */