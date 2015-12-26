/**
 * @file
 * SNMP netconn frontend.
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

#if LWIP_SNMP && SNMP_USE_NETCONN

#include "lwip/api.h"
#include "lwip/udp.h"
#include "snmp_msg.h"
#include "lwip/sys.h"

/** SNMP netconn API worker thread */
static void
snmp_netconn_thread(void *arg)
{
  struct netconn *conn;
  struct netbuf *buf;
  err_t err;
  LWIP_UNUSED_ARG(arg);
  
  conn = netconn_new(NETCONN_UDP);
  LWIP_ERROR("snmp_netconn: invalid conn", (conn != NULL), return;);
  
  /*trap_msg.handle = conn;*/
  /*trap_msg.lip = &conn->pcb.udp->local_ip;*/
  
  /* Bind to SNMP port with default IP address */
  netconn_bind(conn, IP_ADDR_ANY, SNMP_IN_PORT);  

  do {
    err = netconn_recv(conn, &buf);

    if (err == ERR_OK) {
      snmp_receive(conn, buf->p, &buf->addr, buf->port);
    }

    if(buf != NULL) {
      netbuf_delete(buf);
    }
  } while(1);
}

err_t 
snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port)
{
  err_t result;
  struct netbuf buf;
  
  memset(&buf, 0, sizeof(buf));
  buf.p = p;
  result = netconn_sendto((struct netconn*)handle, &buf, dst, port);
  
  return result;
}

/**
 * Starts SNMP Agent.
 */
void
snmp_init(void)
{
  sys_thread_new("snmp_netconn", snmp_netconn_thread, NULL, SNMP_STACK_SIZE, SNMP_THREAD_PRIO);
}

#endif /* LWIP_SNMP && SNMP_USE_NETCONN */
