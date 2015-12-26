/*
 * Copyright (c) 2001, 2002 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2001, 2002 Axon Digital Design B.V., The Netherlands.
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
 * Author: Leon Woestenberg <leon.woestenberg@axon.tv>
 *         Martin Hentschel <info@cl-soft.de>
 *
 */
#ifndef LWIP_HDR_APPS_SNMP_H
#define LWIP_HDR_APPS_SNMP_H

#include "lwip/apps/snmp_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/err.h"
#include "lwip/apps/snmp_core.h"

/** Agent setup, start listening to port 161. */
void snmp_init(void);
void snmp_set_mibs(const struct snmp_mib **mibs, u8_t num_mibs);

/**
* 'device enterprise oid' is used for 'device OID' field in trap PDU's (for identification of generating device)
* as well as for value returned by MIB-2 'sysObjectID' field (if internal MIB2 implementation is used).
* The 'device enterprise oid' shall point to an OID located under 'private-enterprises' branch (1.3.6.1.4.1.XXX). If a vendor
* wants to provide a custom object there, he has to get its own enterprise oid from IANA (http://www.iana.org). It
* is not allowed to use LWIP enterprise ID!
* In order to identify a specific device it is recommended to create a dedicated OID for each device type under its own 
* enterprise oid.
* e.g.
* device a > 1.3.6.1.4.1.XXX(ent-oid).1(devices).1(device a)
* device b > 1.3.6.1.4.1.XXX(ent-oid).1(devices).2(device b)
* for more details see description of 'sysObjectID' field in RFC1213-MIB
*/
void snmp_set_device_enterprise_oid(const struct snmp_obj_id* device_enterprise_oid);
const struct snmp_obj_id* snmp_get_device_enterprise_oid(void);

void snmp_trap_dst_enable(u8_t dst_idx, u8_t enable);
void snmp_trap_dst_ip_set(u8_t dst_idx, const ip_addr_t *dst);

#define SNMP_GENTRAP_COLDSTART 0
#define SNMP_GENTRAP_WARMSTART 1
#define SNMP_GENTRAP_LINKDOWN 2
#define SNMP_GENTRAP_LINKUP 3
#define SNMP_GENTRAP_AUTH_FAILURE 4
#define SNMP_GENTRAP_EGP_NEIGHBOR_LOSS 5
#define SNMP_GENTRAP_ENTERPRISE_SPECIFIC 6
err_t snmp_send_trap_generic(s32_t generic_trap);
err_t snmp_send_trap_specific(s32_t specific_trap);

#define SNMP_AUTH_TRAPS_DISABLED 0
#define SNMP_AUTH_TRAPS_ENABLED  1
void snmp_set_auth_traps_enabled(u8_t enable);
u8_t snmp_get_auth_traps_enabled(void);

const char * snmp_get_community(void);
const char * snmp_get_community_write(void);
const char * snmp_get_community_trap(void);
void snmp_set_community(const char * const community);
void snmp_set_community_write(const char * const community);
void snmp_set_community_trap(const char * const community);

void snmp_coldstart_trap(void);
void snmp_authfail_trap(void);

typedef void (*snmp_write_callback_fct)(const u32_t* oid, u8_t oid_len, void* callback_arg);
void snmp_set_write_callback(snmp_write_callback_fct write_callback, void* callback_arg);

#endif /* LWIP_SNMP */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_SNMP_H */
