/**
 * @file
 * ALTCP_TLS openHiTLS backend structure definitions
 */

/*
 * Copyright (c) 2026 openHiTLS
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
 * Author: Hui Zhang
 *
 */

#ifndef LWIP_HDR_ALTCP_TLS_HITLS_STRUCTS_H
#define LWIP_HDR_ALTCP_TLS_HITLS_STRUCTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_HITLS

#include "lwip/altcp.h"
#include "lwip/pbuf.h"
#include "lwip/apps/altcp_tls_hitls_opts.h"
#include "bsl_uio.h"
#include "hitls.h"
#include "hitls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALTCP_HITLS_FLAGS_HANDSHAKE_DONE    0x01
#define ALTCP_HITLS_FLAGS_UPPER_CALLED      0x02
#define ALTCP_HITLS_FLAGS_RX_CLOSE_QUEUED   0x04
#define ALTCP_HITLS_FLAGS_RX_CLOSED         0x08

typedef struct {
  u8_t *pass;
  size_t len;
} altcp_hitls_pass_userdata_t;

typedef struct altcp_tls_config {
  HITLS_Config *hitls_config;
  u8_t is_server;
  u8_t cert_count;
  u8_t cert_max;

  altcp_hitls_pass_userdata_t *userdata;

  u8_t *alpn_protos;
  u32_t alpn_protos_len;
} altcp_tls_config;

typedef struct altcp_hitls_state_s {
  void *conf;
  HITLS_Ctx *hitls_ctx;

  struct pbuf *rx;
  struct pbuf *rx_app;

  u8_t flags;

  s32_t rx_passed_unrecved;
  s32_t uio_bytes_read;
  s32_t uio_bytes_appl;
  s32_t overhead_bytes_adjust;
} altcp_hitls_state_t;

typedef struct altcp_hitls_uio_ctx_s {
  struct altcp_pcb *conn;
  altcp_hitls_state_t *state;
} altcp_hitls_uio_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_HITLS */
#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_TLS_HITLS_STRUCTS_H */
