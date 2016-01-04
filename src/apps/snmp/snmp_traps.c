/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Martin Hentschel
 *         Christiaan Simons <christiaan.simons@axon.tv>
 *
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/ip_addr.h"

#define snmp_community_trap snmp_community
/** Agent community string for sending traps */
extern const char *snmp_community_trap;

struct snmp_trap_dst
{
  /* destination IP address in network order */
  ip_addr_t dip;
  /* set to 0 when disabled, >0 when enabled */
  u8_t enable;
};
static struct snmp_trap_dst trap_dst[SNMP_TRAP_DESTINATIONS];

static u8_t snmp_auth_traps_enabled = 0;

/** TRAP message structure */
/*struct snmp_msg_trap trap_msg;*/

/**
 * Sets enable switch for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param enable switch if 0 destination is disabled >0 enabled.
 */
void
snmp_trap_dst_enable(u8_t dst_idx, u8_t enable)
{
  if (dst_idx < SNMP_TRAP_DESTINATIONS) {
    trap_dst[dst_idx].enable = enable;
  }
}

/**
 * Sets IPv4 address for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param dst IPv4 address in host order.
 */
void
snmp_trap_dst_ip_set(u8_t dst_idx, const ip_addr_t *dst)
{
  if (dst_idx < SNMP_TRAP_DESTINATIONS) {
    ip_addr_set(&trap_dst[dst_idx].dip, dst);
  }
}

void
snmp_set_auth_traps_enabled(u8_t enable)
{
  snmp_auth_traps_enabled = enable;
}

u8_t
snmp_get_auth_traps_enabled(void)
{
  return snmp_auth_traps_enabled;
}


/**
 * Sends an generic or enterprise specific trap message.
 *
 * @param generic_trap is the trap code
 * @param eoid points to enterprise object identifier
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the caller is responsible for filling in outvb in the trap_msg
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */
static err_t
snmp_send_trap(const struct snmp_obj_id *device_enterprise_oid, s32_t generic_trap, s32_t specific_trap)
{
  LWIP_UNUSED_ARG(device_enterprise_oid);
  LWIP_UNUSED_ARG(generic_trap);
  LWIP_UNUSED_ARG(specific_trap);
  return ERR_OK;
}

err_t 
snmp_send_trap_generic(s32_t generic_trap)
{
  return snmp_send_trap(NULL, generic_trap, 0);
}

err_t snmp_send_trap_specific(s32_t specific_trap)
{
  return snmp_send_trap(NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap);
}


void
snmp_coldstart_trap(void)
{
  snmp_send_trap_generic(SNMP_GENTRAP_COLDSTART);
}

void
snmp_authfail_trap(void)
{
  if (snmp_auth_traps_enabled != 0) {
    snmp_send_trap_generic(SNMP_GENTRAP_AUTH_FAILURE);
  }
}

#endif /* LWIP_SNMP */
