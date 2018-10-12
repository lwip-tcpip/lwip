/**
 * @file
 * MDNS responder - output related functionalities
 */

 /*
 * Copyright (c) 2015 Verisure Innovation AB
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
 * Author: Erik Ekman <erik@kryo.se>
 * Author: Jasper Verschueren <jasper.verschueren@apart-audio.com>
 *
 */

#ifndef LWIP_HDR_APPS_MDNS_OUT_H
#define LWIP_HDR_APPS_MDNS_OUT_H

#include "lwip/apps/mdns_opts.h"
#include "lwip/apps/mdns_priv.h"
#include "lwip/netif.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_MDNS_RESPONDER

/** Bitmasks outmsg generation */
/* Probe for ALL types with hostname */
#define QUESTION_PROBE_HOST_ANY          0x10
/* Probe for ALL types with service instance name */
#define QUESTION_PROBE_SERVICE_NAME_ANY  0x10

/* Lookup from hostname -> IPv4 */
#define REPLY_HOST_A            0x01
/* Lookup from IPv4/v6 -> hostname */
#define REPLY_HOST_PTR_V4       0x02
/* Lookup from hostname -> IPv6 */
#define REPLY_HOST_AAAA         0x04
/* Lookup from hostname -> IPv6 */
#define REPLY_HOST_PTR_V6       0x08

/* Lookup for service types */
#define REPLY_SERVICE_TYPE_PTR  0x10
/* Lookup for instances of service */
#define REPLY_SERVICE_NAME_PTR  0x20
/* Lookup for location of service instance */
#define REPLY_SERVICE_SRV       0x40
/* Lookup for text info on service instance */
#define REPLY_SERVICE_TXT       0x80

err_t mdns_send_outpacket(struct mdns_outmsg *msg, struct netif *netif);
void mdns_prepare_txtdata(struct mdns_service *service);

#endif /* LWIP_MDNS_RESPONDER */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_MDNS_OUT_H */
