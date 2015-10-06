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
 *
 */
#ifndef LWIP_HDR_SNMP_H
#define LWIP_HDR_SNMP_H

#include "lwip/opt.h"
#include "lwip/snmp_mib2.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

/** fixed maximum length for object identifier type */
#define LWIP_SNMP_OBJ_ID_LEN 32

/** internal object identifier representation */
struct snmp_obj_id
{
  u8_t len;
  s32_t id[LWIP_SNMP_OBJ_ID_LEN];
};

/** Agent setup, start listening to port 161. */
void snmp_init(void);
void snmp_trap_dst_enable(u8_t dst_idx, u8_t enable);
void snmp_trap_dst_ip_set(u8_t dst_idx, const ip_addr_t *dst);

const char * snmp_get_community(void);
void snmp_set_community(const char * const community);
#if SNMP_COMMUNITY_EXT
const char * snmp_get_community_write(void);
const char * snmp_get_community_trap(void);
void snmp_set_community_write(const char * const community);
void snmp_set_community_trap(const char * const community);
#endif /* SNMP_COMMUNITY_EXT */

/* system */
void snmp_set_sysdescr(const u8_t* str, const u8_t* len);
void snmp_set_sysobjid(const struct snmp_obj_id *oid);
void snmp_get_sysobjid_ptr(const struct snmp_obj_id **oid);
void snmp_set_syscontact(u8_t *ocstr, u8_t *ocstrlen, u8_t bufsize);
void snmp_set_sysname(u8_t *ocstr, u8_t *ocstrlen, u8_t bufsize);
void snmp_set_syslocation(u8_t *ocstr, u8_t *ocstrlen, u8_t bufsize);
void snmp_set_snmpenableauthentraps(u8_t *value);
#else
/* LWIP_SNMP support not available */
/* define everything to be empty */

/* system */
#define snmp_set_sysdescr(str, len)
#define snmp_set_sysobjid(oid)
#define snmp_get_sysobjid_ptr(oid)
#define snmp_set_syscontact(ocstr, ocstrlen, bufsize)
#define snmp_set_sysname(ocstr, ocstrlen, bufsize)
#define snmp_set_syslocation(ocstr, ocstrlen, bufsize)
#define snmp_set_snmpenableauthentraps(value)
#endif /* LWIP_SNMP */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_SNMP_H */
