/**
 * @file
 * ALTCP_TLS backend selection options
 *
 * This file contains the top-level option for selecting which TLS backend
 * to use. Only one backend can be active at a time.
 */

/*
 * Copyright (c) 2017 Simon Goldschmidt
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
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 *
 */

#ifndef LWIP_HDR_ALTCP_TLS_OPTS_H
#define LWIP_HDR_ALTCP_TLS_OPTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

/** LWIP_ALTCP_TLS_MBEDTLS==1: use mbedTLS for TLS support for altcp API
 * mbedtls include directory must be reachable via include search path
 */
#ifndef LWIP_ALTCP_TLS_MBEDTLS
#define LWIP_ALTCP_TLS_MBEDTLS                        0
#endif

/** LWIP_ALTCP_TLS_HITLS==1: use openHiTLS for TLS support for altcp API
 * openhitls include directory must be reachable via include search path
 */
#ifndef LWIP_ALTCP_TLS_HITLS
#define LWIP_ALTCP_TLS_HITLS                          0
#endif

#if (LWIP_ALTCP_TLS_MBEDTLS + LWIP_ALTCP_TLS_HITLS) > 1
  #error "Only one ALTCP_TLS backend can be active at a time"
#endif

#if LWIP_ALTCP_TLS && !LWIP_ALTCP_TLS_MBEDTLS && !LWIP_ALTCP_TLS_HITLS
  #error "LWIP_ALTCP_TLS requires a backend (LWIP_ALTCP_TLS_MBEDTLS or LWIP_ALTCP_TLS_HITLS)"
#endif

#if LWIP_ALTCP_TLS_MBEDTLS
  #include "lwip/apps/altcp_tls_mbedtls_opts.h"
#endif

#if LWIP_ALTCP_TLS_HITLS
  #include "lwip/apps/altcp_tls_hitls_opts.h"
#endif

#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_TLS_OPTS_H */
