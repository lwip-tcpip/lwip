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

#include "snmpv3.h"
#include "arch/cc.h"
#include "snmp_msg.h"
#include "lwip/sys.h"
#include <string.h>

#if LWIP_SNMP && LWIP_SNMP_V3

#ifdef LWIP_SNMPV3_INCLUDE_ENGINE
#include LWIP_SNMPV3_INCLUDE_ENGINE
#endif

#ifdef LWIP_SNMP_V3_CRYPTO
#ifdef LWIP_INCLUDE_CRYPTO_LIB
#include LWIP_INCLUDE_CRYPTO_LIB
#endif
#ifdef LWIP_INCLUDE_CRYPTO_MD5
#include LWIP_INCLUDE_CRYPTO_MD5
#endif
#ifdef LWIP_INCLUDE_CRYPTO_SHA
#include LWIP_INCLUDE_CRYPTO_SHA
#endif
#ifdef LWIP_INCLUDE_CRYPTO_DES
#include LWIP_INCLUDE_CRYPTO_DES
#endif
#ifdef LWIP_INCLUDE_CRYPTO_AES
#include LWIP_INCLUDE_CRYPTO_AES
#endif
#endif

#ifdef LWIP_SNMP_V3_CRYPTO
#if !defined(LWIP_MD5_HMAC_HANDLE) || !defined(LWIP_MD5_HMAC_INIT) || \
    !defined(LWIP_MD5_HMAC_UPDATE) || !defined(LWIP_MD5_HMAC_FINAL)
#error LWIP_SNMP_V3_CRYPTO requires MD5 HMAC
#endif
#if !defined(LWIP_SHA_HMAC_HANDLE) || !defined(LWIP_SHA_HMAC_INIT) || \
    !defined(LWIP_SHA_HMAC_UPDATE) || !defined(LWIP_SHA_HMAC_FINAL)
#error LWIP_SNMP_V3_CRYPTO requires SHA HMAC
#endif
#if !defined(LWIP_DES_CBC_ENCRYPT_HANDLE) || !defined(LWIP_DES_CBC_ENCRYPT_INIT)  || \
  !defined(LWIP_DES_CBC_ENCRYPT_UPDATE)   || !defined(LWIP_DES_CBC_ENCRYPT_FINAL) || \
  !defined(LWIP_DES_CBC_DECRYPT_HANDLE)   || !defined(LWIP_DES_CBC_DECRYPT_INIT)  || \
  !defined(LWIP_DES_CBC_DECRYPT_UPDATE)   || !defined(LWIP_DES_CBC_DECRYPT_FINAL)
#error LWIP_SNMP_V3_CRYPTO requires DES CBC
#endif
#if !defined(LWIP_AES_CFB_ENCRYPT_HANDLE) || !defined(LWIP_AES_CFB_ENCRYPT_INIT)  || \
  !defined(LWIP_AES_CFB_ENCRYPT_UPDATE)   || !defined(LWIP_AES_CFB_ENCRYPT_FINAL) || \
  !defined(LWIP_AES_CFB_DECRYPT_HANDLE)   || !defined(LWIP_AES_CFB_DECRYPT_INIT)  || \
  !defined(LWIP_AES_CFB_DECRYPT_UPDATE)   || !defined(LWIP_AES_CFB_DECRYPT_FINAL)
#error LWIP_SNMP_V3_CRYPTO requires AES CFB
#endif
#endif

#define SNMP_MAX_TIME_BOOT 2147483647UL

/* Engine ID, as specified in RFC3411 */
const char*
snmpv3_get_engine_id(void)
{
  return LWIP_SNMPV3_GET_ENGINE_ID();
}

/* Has to reset boots, see below */
void
snmpv3_engine_id_changed(void)
{
  LWIP_SNMPV3_SET_ENGINE_BOOTS(0);
}

/* According to RFC3414 2.2.2.
 *
 * The number of times that the SNMP engine has
 * (re-)initialized itself since snmpEngineID
 * was last configured.
 */
u32_t
snmpv3_get_engine_boots(void)
{
  if (LWIP_SNMPV3_GET_ENGINE_BOOTS() == 0 ||
      LWIP_SNMPV3_GET_ENGINE_BOOTS() < SNMP_MAX_TIME_BOOT) {
    return LWIP_SNMPV3_GET_ENGINE_BOOTS();
  }

  LWIP_SNMPV3_SET_ENGINE_BOOTS(SNMP_MAX_TIME_BOOT);
  return LWIP_SNMPV3_GET_ENGINE_BOOTS();
}

/* RFC3414 2.2.2.
 *
 * Once the timer reaches 2147483647 it gets reset to zero and the
 * engine boot ups get incremented.
 */
u32_t
snmpv3_get_engine_time(void)
{
  if (LWIP_SNMPV3_GET_ENGINE_TIME() >= SNMP_MAX_TIME_BOOT) {
    LWIP_SNMPV3_RESET_ENGINE_TIME();

    if (LWIP_SNMPV3_GET_ENGINE_BOOTS() < SNMP_MAX_TIME_BOOT - 1) {
      LWIP_SNMPV3_SET_ENGINE_BOOTS(LWIP_SNMPV3_GET_ENGINE_BOOTS() + 1);
    } else {
      LWIP_SNMPV3_SET_ENGINE_BOOTS(SNMP_MAX_TIME_BOOT);
    }
  }

  return LWIP_SNMPV3_GET_ENGINE_TIME();
}

#ifdef LWIP_SNMP_V3_CRYPTO
err_t
snmpv3_auth(struct snmp_pbuf_stream* stream, u16_t length,
    const u8_t* key, u8_t algo, u8_t* hmac_out)
{
  u32_t i;
  u8_t byte;
  struct snmp_pbuf_stream read_stream;
  snmp_pbuf_stream_init(&read_stream, stream->pbuf, stream->offset,
      stream->length);

  if (algo == SNMP_V3_AUTH_ALGO_MD5) {
    LWIP_MD5_HMAC_HANDLE mh;
    if (LWIP_MD5_HMAC_INIT(&mh, key, SNMP_V3_MD5_LEN))
      return ERR_ARG;
    for (i = 0; i < length; i++) {
      if (snmp_pbuf_stream_read(&read_stream, &byte))
        return ERR_ARG;
      if (LWIP_MD5_HMAC_UPDATE(&mh, &byte, 1))
        return ERR_ARG;
    }
    if (LWIP_MD5_HMAC_FINAL(&mh, hmac_out))
      return ERR_ARG;

  } else if (algo == SNMP_V3_AUTH_ALGO_SHA) {
    LWIP_SHA_HMAC_HANDLE sh;
    if (LWIP_SHA_HMAC_INIT(&sh, key, SNMP_V3_SHA_LEN))
      return ERR_ARG;
    for (i = 0; i < length; i++) {
      if (snmp_pbuf_stream_read(&read_stream, &byte))
        return ERR_ARG;
      if (LWIP_SHA_HMAC_UPDATE(&sh, &byte, 1))
        return ERR_ARG;
    }
    if (LWIP_SHA_HMAC_FINAL(&sh, hmac_out))
      return ERR_ARG;
  } else
    return ERR_ARG;

  return ERR_OK;
}

err_t
snmpv3_crypt(struct snmp_pbuf_stream* stream, u16_t length,
    const u8_t* key, const u8_t* priv_param, const u32_t engine_boots,
    const u32_t engine_time, u8_t algo, u8_t mode)
{
  u8_t in_bytes[8];
  u8_t out_bytes[8];
  u8_t iv_local[16];

  u32_t i, j;
  /* RFC 3414 mandates padding for DES */
  if (algo == SNMP_V3_PRIV_ALGO_DES) {
    if (length % 8)
      return ERR_ARG;

    for (i = 0; i < 8; i++)
      iv_local[i] = priv_param[i] ^ key[i + 8];
  } else if (algo == SNMP_V3_PRIV_ALGO_AES) {
    /*
     * IV is the big endian concatenation of boots,
     * uptime and priv param - see RFC3826.
     */
    iv_local[0 + 0] = (engine_boots >> 24) & 0xFF;
    iv_local[0 + 1] = (engine_boots >> 16) & 0xFF;
    iv_local[0 + 2] = (engine_boots >> 8) & 0xFF;
    iv_local[0 + 3] = (engine_boots >> 0) & 0xFF;
    iv_local[4 + 0] = (engine_time >> 24) & 0xFF;
    iv_local[4 + 1] = (engine_time >> 16) & 0xFF;
    iv_local[4 + 2] = (engine_time >> 8) & 0xFF;
    iv_local[4 + 3] = (engine_time >> 0) & 0xFF;
    memcpy(iv_local + 8, priv_param, 8);
  }

  struct snmp_pbuf_stream read_stream;
  struct snmp_pbuf_stream write_stream;
  snmp_pbuf_stream_init(&read_stream, stream->pbuf, stream->offset,
      stream->length);
  snmp_pbuf_stream_init(&write_stream, stream->pbuf, stream->offset,
      stream->length);

  if (algo == SNMP_V3_PRIV_ALGO_DES && mode == SNMP_V3_PRIV_MODE_ENCRYPT) {
    LWIP_DES_CBC_ENCRYPT_HANDLE handle;
    LWIP_DES_CBC_ENCRYPT_INIT(&handle, key);

    for (i = 0; i < length; i += 8) {
      for (j = 0; j < 8; j++)
        snmp_pbuf_stream_read(&read_stream, &in_bytes[j]);

      LWIP_DES_CBC_ENCRYPT_UPDATE(&handle, 8, iv_local, in_bytes, out_bytes);

      for (j = 0; j < 8; j++)
        snmp_pbuf_stream_write(&write_stream, out_bytes[j]);
    }

    LWIP_DES_CBC_ENCRYPT_FINAL(&handle);
  } else if (algo == SNMP_V3_PRIV_ALGO_DES && mode == SNMP_V3_PRIV_MODE_DECRYPT) {
    LWIP_DES_CBC_DECRYPT_HANDLE handle;
    LWIP_DES_CBC_DECRYPT_INIT(&handle, key);

    for (i = 0; i < length; i += 8) {
      for (j = 0; j < 8; j++)
        snmp_pbuf_stream_read(&read_stream, &in_bytes[j]);

      LWIP_DES_CBC_DECRYPT_UPDATE(&handle, 8, iv_local, in_bytes, out_bytes);

      for (j = 0; j < 8; j++)
        snmp_pbuf_stream_write(&write_stream, out_bytes[j]);
    }

    LWIP_DES_CBC_DECRYPT_FINAL(&handle);
  } else if (algo == SNMP_V3_PRIV_ALGO_AES && mode == SNMP_V3_PRIV_MODE_ENCRYPT) {
    size_t iv_offset = 0;
    LWIP_AES_CFB_ENCRYPT_HANDLE handle;
    LWIP_AES_CFB_ENCRYPT_INIT(&handle, key);

    for (i = 0; i < length; i++) {
      snmp_pbuf_stream_read(&read_stream, &in_bytes[0]);
      LWIP_AES_CFB_ENCRYPT_UPDATE(&handle, 1, &iv_offset, iv_local, in_bytes,
          out_bytes);
      snmp_pbuf_stream_write(&write_stream, out_bytes[0]);
    }

    LWIP_AES_CFB_ENCRYPT_FINAL(&handle);
  } else if (algo == SNMP_V3_PRIV_ALGO_AES && mode == SNMP_V3_PRIV_MODE_DECRYPT) {
    size_t iv_off = 0;
    LWIP_AES_CFB_DECRYPT_HANDLE handle;
    LWIP_AES_CFB_DECRYPT_INIT(&handle, key);

    for (i = 0; i < length; i++) {
      snmp_pbuf_stream_read(&read_stream, &in_bytes[0]);
      LWIP_AES_CFB_DECRYPT_UPDATE(&handle, 1, &iv_off, iv_local, in_bytes,
          out_bytes);
      snmp_pbuf_stream_write(&write_stream, out_bytes[0]);
    }

    LWIP_AES_CFB_DECRYPT_FINAL(&handle);
  } else
    return ERR_ARG;

  return ERR_OK;
}

/* This function ignores the byte order suggestion in RFC3414
 * since it simply doesn't influence the effectiveness of an IV.
 *
 * Implementing RFC3826 priv param algorithm if LWIP_RAND is available.
 *
 * TODO: This is a potential thread safety issue.
 */
err_t
snmpv3_build_priv_param(u8_t* priv_param)
{
#ifdef LWIP_RAND /* Based on RFC3826 */
  static u8_t init;
  static u32_t priv1, priv2;

  /* Lazy initialisation */
  if (init == 0) {
    init = 1;
    priv1 = LWIP_RAND();
    priv2 = LWIP_RAND();
  }

  memcpy(&priv_param[0], &priv1, sizeof(priv1));
  memcpy(&priv_param[4], &priv2, sizeof(priv2));

  /* Emulate 64bit increment */
  priv1++;
  if (!priv1) /* Overflow */
    priv2++;
#else /* Based on RFC3414 */
  static u32_t ctr;
  u32_t boots = LWIP_SNMPV3_GET_ENGINE_BOOTS();
  memcpy(&priv_param[0], &boots, 4);
  memcpy(&priv_param[4], &ctr, 4);
  ctr++;
#endif
  return ERR_OK;
}
#endif /* LWIP_SNMP_V3_CRYPTO */

#endif
