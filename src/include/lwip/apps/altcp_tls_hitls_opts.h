/**
 * @file
 * ALTCP_TLS openHiTLS backend options
 *
 * This file contains options for an openHiTLS port of the TLS layer.
 * Set LWIP_ALTCP_TLS=1 and LWIP_ALTCP_TLS_HITLS=1 in lwipopts.h to use this
 * backend. openHiTLS headers and libraries must be provided by the application
 * build system.
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

#ifndef LWIP_HDR_ALTCP_TLS_HITLS_OPTS_H
#define LWIP_HDR_ALTCP_TLS_HITLS_OPTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_HITLS

/** ALTCP_HITLS_DEBUG: Enable debug output for HiTLS */
#ifndef ALTCP_HITLS_DEBUG
#define ALTCP_HITLS_DEBUG                   LWIP_DBG_ON
#endif

/** LWIP_ALTCP_HITLS_SESSION_RESUMPTION==1: Enable altcp_tls session resumption APIs.
 * This requires openHiTLS to be built with HITLS_TLS_FEATURE_SESSION support.
 */
#ifndef LWIP_ALTCP_HITLS_SESSION_RESUMPTION
#define LWIP_ALTCP_HITLS_SESSION_RESUMPTION 1
#endif

/** LWIP_ALTCP_HITLS_ALPN==1: Enable ALPN configuration APIs.
 * This requires openHiTLS to be built with HITLS_TLS_FEATURE_ALPN support.
 */
#ifndef LWIP_ALTCP_HITLS_ALPN
#define LWIP_ALTCP_HITLS_ALPN               1
#endif

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_HITLS */
#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_TLS_HITLS_OPTS_H */
