/**
 * @file
 * Additional SNMPv3 functionality RFC3414 and RFC3826.
 */

/*
 * Copyright (c) 2016 Elias Oenal.
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
 * Author: Elias Oenal <lwip@eliasoenal.com>
 */

#ifndef LWIP_HDR_APPS_SNMP_V3_H
#define LWIP_HDR_APPS_SNMP_V3_H

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP && LWIP_SNMP_V3

#include "snmp_pbuf_stream.h"

#ifndef LWIP_SNMPV3_GET_ENGINE_BOOTS
/* #warning RFC3414 complicance requires a persistent boot count */
#define LWIP_SNMPV3_GET_ENGINE_BOOTS() 0
#endif

#ifndef LWIP_SNMPV3_SET_ENGINE_BOOTS
/* #warning RFC3414 complicance requires a method to set boot count */
#define LWIP_SNMPV3_SET_ENGINE_BOOTS(val)
#endif

#ifndef LWIP_SNMPV3_GET_ENGINE_TIME
/* #warning RFC3414 complicance requires the uptime to count until 2147483647 */
#define LWIP_SNMPV3_GET_ENGINE_TIME() (sys_now() / 10)
#endif

#ifndef LWIP_SNMPV3_RESET_ENGINE_TIME
/* #warning RFC3414 complicance requires a method to reset uptime */
#define LWIP_SNMPV3_RESET_ENGINE_TIME()
#endif

#ifndef LWIP_SNMPV3_GET_ENGINE_ID
/* #warning RFC3414 complicance requires an engine ID */
/* Using the one from the test vectors from RFC3414 */
#define LWIP_SNMPV3_GET_ENGINE_ID() "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
#endif

#ifndef LWIP_SNMPV3_GET_ENGINE_ID_LEN
/* #warning RFC3414 complicance requires an engine ID */
#define LWIP_SNMPV3_GET_ENGINE_ID_LEN() 12
#endif

#ifndef LWIP_SNMPV3_GET_USER
/* #warning Implement user handling */
/* @param username is a pointer to a string.
 * @param auth_algo is a pointer to u8_t. The implementation has to set this if user was found.
 * @param auth_key is a pointer to a pointer to a string. Implementation has to set this if user was found.
 * @param priv_algo is a pointer to u8_t. The implementation has to set this if user was found.
 * @param priv_key is a pointer to a pointer to a string. Implementation has to set this if user was found.
 */
/* Dummy implementation, pretend the user was found if cryptography isn't used */
#define LWIP_SNMPV3_GET_USER(username, auth_algo, auth_key, priv_algo, priv_key) ((auth_algo || auth_key \
                                          || priv_algo || priv_key)?1:0)
#endif

/* According to RFC 3411 */
#define SNMP_V3_MAX_ENGINE_ID_LENGTH  32
#define SNMP_V3_MAX_USER_LENGTH       32

#define SNMP_V3_MAX_AUTH_PARAM_LENGTH  12
#define SNMP_V3_MAX_PRIV_PARAM_LENGTH  8

#define SNMP_V3_AUTH_FLAG      0x01
#define SNMP_V3_PRIV_FLAG      0x02

#define SNMP_V3_MD5_LEN        16
#define SNMP_V3_SHA_LEN        20

#define SNMP_V3_AUTH_ALGO_INVAL  0
#define SNMP_V3_AUTH_ALGO_MD5    1
#define SNMP_V3_AUTH_ALGO_SHA    2

#define SNMP_V3_PRIV_ALGO_INVAL  0
#define SNMP_V3_PRIV_ALGO_DES    1
#define SNMP_V3_PRIV_ALGO_AES    2

#define SNMP_V3_PRIV_MODE_DECRYPT  0
#define SNMP_V3_PRIV_MODE_ENCRYPT  1

const char* snmpv3_get_engine_id(void);
void snmpv3_set_engine_id(const char* id);
u32_t snmpv3_get_engine_boots(void);
u32_t snmpv3_get_engine_time(void);
void snmpv3_engine_id_changed(void);
err_t snmpv3_auth(struct snmp_pbuf_stream* stream, u16_t length, const u8_t* key, u8_t algo, u8_t* hmac_out);
err_t snmpv3_crypt(struct snmp_pbuf_stream* stream, u16_t length, const u8_t* key,
    const u8_t* priv_param, const u32_t engine_boots, const u32_t engine_time, u8_t algo, u8_t mode);
err_t snmpv3_build_priv_param(u8_t* priv_param);

#endif

#endif /* LWIP_HDR_APPS_SNMP_V3_H */
