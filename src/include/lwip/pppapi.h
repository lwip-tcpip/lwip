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

#ifndef __LWIP_PPPAPI_H__
#define __LWIP_PPPAPI_H__

#include "lwip/opt.h"

#if LWIP_PPP_API /* don't build if not configured for use in lwipopts.h */

#include "lwip/sys.h"
#include "netif/ppp/ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pppapi_msg_msg {
#if !LWIP_TCPIP_CORE_LOCKING
  sys_sem_t sem;
#endif /* !LWIP_TCPIP_CORE_LOCKING */
  int err;
  ppp_pcb *ppp;
  union {
    struct {
      u8_t authtype;
      char *user;
      char *passwd;
    } setauth;
#if PPPOS_SUPPORT
    struct {
      sio_fd_t fd;
      ppp_link_status_cb_fn link_status_cb;
      void *link_status_ctx;
    } serialopen;
#endif /* PPPOS_SUPPORT */
#if PPPOE_SUPPORT
    struct {
      struct netif *ethif;
      const char *service_name;
      const char *concentrator_name;
      ppp_link_status_cb_fn link_status_cb;
      void *link_status_ctx;
    } ethernetopen;
#endif /* PPPOE_SUPPORT */
#if PPPOL2TP_SUPPORT
    struct {
      struct netif *netif;
      ip_addr_t *ipaddr;
      u16_t port;
#if PPPOL2TP_AUTH_SUPPORT
      u8_t *secret;
      u8_t secret_len;
#endif /* PPPOL2TP_AUTH_SUPPORT */
      ppp_link_status_cb_fn link_status_cb;
      void *link_status_ctx;
    } l2tpopen;
#endif /* PPPOL2TP_SUPPORT */
    struct {
      u16_t holdoff;
    } reopen;
    struct {
      int cmd;
      void *arg;
    } ioctl;
#if PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD
    struct {
      u_char *data;
      int len;
    } ppposinput;
#endif /* PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD */
#if LWIP_NETIF_STATUS_CALLBACK
    struct {
      netif_status_callback_fn status_callback;
    } netifstatuscallback;
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
    struct {
      netif_status_callback_fn link_callback;
    } netiflinkcallback;
#endif /* LWIP_NETIF_LINK_CALLBACK */
  } msg;
};

struct pppapi_msg {
  void (* function)(struct pppapi_msg_msg *msg);
  struct pppapi_msg_msg msg;
};

/* API for application */
ppp_pcb *pppapi_new(void);
void pppapi_set_default(ppp_pcb *pcb);
void pppapi_set_auth(ppp_pcb *pcb, u8_t authtype, char *user, char *passwd);
#if PPPOS_SUPPORT
int pppapi_over_serial_open(ppp_pcb *pcb, sio_fd_t fd, ppp_link_status_cb_fn link_status_cb, void *link_status_ctx);
#endif /* PPPOS_SUPPORT */
#if PPPOE_SUPPORT
int pppapi_over_ethernet_open(ppp_pcb *pcb, struct netif *ethif, const char *service_name,
		const char *concentrator_name, ppp_link_status_cb_fn link_status_cb,
		void *link_status_ctx);
#endif /* PPPOE_SUPPORT */
#if PPPOL2TP_SUPPORT
int pppapi_over_l2tp_open(ppp_pcb *pcb, struct netif *netif, ip_addr_t *ipaddr, u16_t port,
		u8_t *secret, u8_t secret_len,
                ppp_link_status_cb_fn link_status_cb, void *link_status_ctx);
#endif /* PPPOL2TP_SUPPORT */
int pppapi_reopen(ppp_pcb *pcb, u16_t holdoff);
int pppapi_close(ppp_pcb *pcb);
void pppapi_sighup(ppp_pcb *pcb);
int pppapi_delete(ppp_pcb *pcb);
int pppapi_ioctl(ppp_pcb *pcb, int cmd, void *arg);
#if PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD
void ppposapi_input(ppp_pcb *pcb, u_char* data, int len);
#endif /* PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD */
#if LWIP_NETIF_STATUS_CALLBACK
void pppapi_set_netif_statuscallback(ppp_pcb *pcb, netif_status_callback_fn status_callback);
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
void pppapi_set_netif_linkcallback(ppp_pcb *pcb, netif_status_callback_fn link_callback);
#endif /* LWIP_NETIF_LINK_CALLBACK */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_PPP_API */

#endif /* __LWIP_PPPAPI_H__ */
