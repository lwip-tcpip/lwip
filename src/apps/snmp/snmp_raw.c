/**
 * @file
 * SNMP RAW API frontend.
 */

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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP && SNMP_USE_RAW

#include "lwip/udp.h"
#include "snmp_msg.h"

/* UDP Protocol Control Block */
static struct udp_pcb *snmp_pcb;

/* lwIP UDP receive callback function */
static void
snmp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  LWIP_UNUSED_ARG(arg);

  snmp_receive(pcb, p, addr, port);

  pbuf_free(p);
}

err_t 
snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port)
{
  err_t result = udp_sendto((struct udp_pcb*)handle, p, dst, port);
  return result;
}

/**
 * Starts SNMP Agent.
 * Allocates UDP pcb and binds it to IP_ADDR_ANY port 161.
 */
void
snmp_init(void)
{
  snmp_pcb = udp_new();

  if (snmp_pcb != NULL) {
    /*trap_msg.handle = snmp_pcb;*/
    /*trap_msg.lip = &snmp_pcb->local_ip;*/

    udp_recv(snmp_pcb, snmp_recv, (void *)SNMP_IN_PORT);
    udp_bind(snmp_pcb, IP_ADDR_ANY, SNMP_IN_PORT);
  }
}

#endif /* LWIP_SNMP && SNMP_USE_RAW */
