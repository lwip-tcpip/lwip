/**
 * @file
 * Interface Identification APIs from:
 *              RFC 3493: Basic Socket Interface Extensions for IPv6
 *                  Section 4: Interface Identification
 */

/*
 * Copyright (c) 2017 Joel Cunningham, Garmin International, Inc. <joel.cunningham@garmin.com>
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
 * Author: Joel Cunningham <joel.cunningham@me.com>
 *
 */
#include "lwip/opt.h"

#if LWIP_SOCKET

#include "lwip/if_api.h"
#include "lwip/netifapi.h"

char *
lwip_if_indextoname(unsigned int ifindex, char *ifname)
{
#if LWIP_NETIF_API
  err_t err;
  if (ifindex > 0xff) {
    return NULL;
  }
  
  err = netifapi_netif_index_to_name((u8_t)ifindex, ifname);
  if (!err && ifname[0] != '\0') {
    return ifname;
  }
#else /* LWIP_NETIF_API */
  LWIP_UNUSED_ARG(ifindex);
  LWIP_UNUSED_ARG(ifname);
#endif /* LWIP_NETIF_API */
  return NULL;
}

unsigned int
lwip_if_nametoindex(const char *ifname)
{
#if LWIP_NETIF_API
  err_t err;
  u8_t idx;
  
  err = netifapi_netif_name_to_index(ifname, &idx);
  if (!err) {
    return idx;
  }
#else /* LWIP_NETIF_API */
  LWIP_UNUSED_ARG(ifname);
#endif /* LWIP_NETIF_API */
  return 0; /* invalid index */
}

#endif /* LWIP_SOCKET */
