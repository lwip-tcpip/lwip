/**
 * @file
 * 6LowPAN over BLE for IPv6 (RFC7668). Config file
 */
 
/*
 * Copyright (c) 2017 Benjamin Aigner
 * Copyright (c) 2015 Inico Technologies Ltd. , Author: Ivan Delamer <delamer@inicotech.com>
 * 
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
 * Author: Benjamin Aigner <aignerb@technikum-wien.at>
 * 
 * Based on the original 6lowpan implementation of lwIP ( @see 6lowpan.c)
 */

#ifndef LWIP_HDR_RFC7668_OPTS_H
#define LWIP_HDR_RFC7668_OPTS_H

#include "lwip/opt.h"

/** LWIP_RFC7668==1: Enable the RFC7668 netif.*/
#ifndef LWIP_RFC7668
#define LWIP_RFC7668                          1
#endif

/** LWIP_RFC7668_NUM_CONTEXTS: define the number of compression
 * contexts.
 * CURRENTLY NOT SUPPORTED. */
#ifndef LWIP_RFC7668_NUM_CONTEXTS
#define LWIP_RFC7668_NUM_CONTEXTS             10
#endif

/** LWIP_RFC7668_DEBUG: Enable generic debugging in lowpan6_ble.c. */
#ifndef LWIP_RFC7668_DEBUG
#define LWIP_RFC7668_DEBUG                    LWIP_DBG_OFF
#endif

/** LWIP_RFC7668_IP_COMPRESSED_DEBUG: enable compressed IP frame
 * output debugging */
#ifndef LWIP_RFC7668_IP_COMPRESSED_DEBUG
#define LWIP_RFC7668_IP_COMPRESSED_DEBUG      LWIP_DBG_OFF
#endif

/** LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG: enable decompressed IP frame
 * output debugging */
#ifndef LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG
#define LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG    LWIP_DBG_OFF
#endif

/** LWIP_RFC7668_DECOMPRESSION_DEBUG: enable decompression debug output*/
#ifndef LWIP_RFC7668_DECOMPRESSION_DEBUG
#define LWIP_RFC7668_DECOMPRESSION_DEBUG      LWIP_DBG_OFF
#endif

/** LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS: 
 * Currently, the linux kernel driver for 6lowpan sets/clears a bit in
 * the address, depending on the BD address (either public or not).
 * Might not be RFC7668 conform, so you may select to do that (=1) or
 * not (=0) */
#ifndef LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS
#define LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS 1
#endif

#endif /* LWIP_HDR_RFC7668_OPTS_H */
