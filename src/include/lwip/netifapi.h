/*
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
 */
 
#ifndef __LWIP_NETIFAPI_H__
#define __LWIP_NETIFAPI_H__

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"

#if LWIP_NETIF_API

enum netifapi_msg_type {
  NETIFAPI_MSG_NETIF_ADD,
  NETIFAPI_MSG_NETIF_REMOVE,
#if LWIP_DHCP  
  NETIFAPI_MSG_DHCP_START,
  NETIFAPI_MSG_DHCP_STOP
#endif /* LWIP_DHCP */
};

struct netifapi_msg {
  enum netifapi_msg_type type;
  sys_sem_t sem;
  err_t err;
  struct netif *netif;
  union {
    struct {
      struct ip_addr *ipaddr;
      struct ip_addr *netmask;
      struct ip_addr *gw;
      void *state;
      err_t (* init)(struct netif *netif);
      err_t (* input)(struct pbuf *p, struct netif *netif);
    } add;
  } msg;
};


/* API for application */
err_t netifapi_netif_add   ( struct netif *netif,
                             struct ip_addr *ipaddr,
                             struct ip_addr *netmask,
                             struct ip_addr *gw,
                             void *state,
                             err_t (* init)(struct netif *netif),
                             err_t (* input)(struct pbuf *p, struct netif *netif) );

err_t netifapi_netif_remove( struct netif *netif);

err_t netifapi_dhcp_start  ( struct netif *netif);

err_t netifapi_dhcp_stop   ( struct netif *netif);


/* API for tcpip_thread */
void  netifapi_msg_input(struct netifapi_msg *msg);
err_t netifapi_msg_post (struct netifapi_msg *msg);

#endif /* LWIP_NETIF_API */

#endif /* __LWIP_NETIFAPI_H__ */
