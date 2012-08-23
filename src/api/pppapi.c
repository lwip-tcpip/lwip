/**
 * @file
 * Point To Point Protocol Sequential API module
 *
 */

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

#include "lwip/opt.h"

#if LWIP_PPP_API /* don't build if not configured for use in lwipopts.h */

#include "lwip/pppapi.h"
#include "lwip/tcpip.h"

/**
 * Call ppp_new() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_new(struct pppapi_msg_msg *msg) {
  msg->ppp = ppp_new();
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_new() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
ppp_pcb *pppapi_new(void) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_new;
  TCPIP_PPPAPI(&msg);
  return msg.msg.ppp;
}


/**
 * Call ppp_set_default() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_set_default(struct pppapi_msg_msg *msg) {
  ppp_set_default(msg->ppp);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_set_default() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
void pppapi_set_default(ppp_pcb *pcb) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_set_default;
  msg.msg.ppp = pcb;
  TCPIP_PPPAPI(&msg);
}


/**
 * Call ppp_set_auth() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_set_auth(struct pppapi_msg_msg *msg) {
  ppp_set_auth(msg->ppp, msg->msg.setauth.authtype,
		  msg->msg.setauth.user, msg->msg.setauth.passwd);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_set_auth() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
void pppapi_set_auth(ppp_pcb *pcb, u8_t authtype, char *user, char *passwd) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_set_auth;
  msg.msg.ppp = pcb;
  msg.msg.msg.setauth.authtype = authtype;
  msg.msg.msg.setauth.user = user;
  msg.msg.msg.setauth.passwd = passwd;
  TCPIP_PPPAPI(&msg);
}


#if PPPOS_SUPPORT
/**
 * Call ppp_over_serial_open() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_over_serial_open(struct pppapi_msg_msg *msg) {
  msg->err = ppp_over_serial_open(msg->ppp, msg->msg.serialopen.fd,
		  msg->msg.serialopen.link_status_cb, msg->msg.serialopen.link_status_ctx);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_over_serial_open() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_over_serial_open(ppp_pcb *pcb, sio_fd_t fd, ppp_link_status_cb_fn link_status_cb, void *link_status_ctx) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_over_serial_open;
  msg.msg.ppp = pcb;
  msg.msg.msg.serialopen.fd = fd;
  msg.msg.msg.serialopen.link_status_cb = link_status_cb;
  msg.msg.msg.serialopen.link_status_ctx = link_status_ctx;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}
#endif /* PPPOS_SUPPORT */


#if PPPOE_SUPPORT
/**
 * Call ppp_over_ethernet_open() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_over_ethernet_open(struct pppapi_msg_msg *msg) {

  msg->err = ppp_over_ethernet_open(msg->ppp, msg->msg.ethernetopen.ethif,
		  msg->msg.ethernetopen.service_name, msg->msg.ethernetopen.concentrator_name,
		  msg->msg.ethernetopen.link_status_cb, msg->msg.ethernetopen.link_status_ctx);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_over_ethernet_open() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_over_ethernet_open(ppp_pcb *pcb, struct netif *ethif, const char *service_name,
		const char *concentrator_name, ppp_link_status_cb_fn link_status_cb,
		void *link_status_ctx) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_over_ethernet_open;
  msg.msg.ppp = pcb;
  msg.msg.msg.ethernetopen.ethif = ethif;
  msg.msg.msg.ethernetopen.service_name = service_name;
  msg.msg.msg.ethernetopen.concentrator_name = concentrator_name;
  msg.msg.msg.ethernetopen.link_status_cb = link_status_cb;
  msg.msg.msg.ethernetopen.link_status_ctx = link_status_ctx;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}
#endif /* PPPOE_SUPPORT */


#if PPPOL2TP_SUPPORT
/**
 * Call ppp_over_l2tp_open() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_over_l2tp_open(struct pppapi_msg_msg *msg) {

  msg->err = ppp_over_l2tp_open(msg->ppp,
		  msg->msg.l2tpopen.netif, msg->msg.l2tpopen.ipaddr, msg->msg.l2tpopen.port,
#if PPPOL2TP_AUTH_SUPPORT
		  msg->msg.l2tpopen.secret,
		  msg->msg.l2tpopen.secret_len,
#else /* PPPOL2TP_AUTH_SUPPORT */
		  NULL,
#endif /* PPPOL2TP_AUTH_SUPPORT */
		  msg->msg.l2tpopen.link_status_cb, msg->msg.l2tpopen.link_status_ctx);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_over_l2tp_open() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_over_l2tp_open(ppp_pcb *pcb, struct netif *netif, ip_addr_t *ipaddr, u16_t port,
		u8_t *secret, u8_t secret_len,
                ppp_link_status_cb_fn link_status_cb, void *link_status_ctx) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_over_l2tp_open;
  msg.msg.ppp = pcb;
  msg.msg.msg.l2tpopen.netif = netif;
  msg.msg.msg.l2tpopen.ipaddr = ipaddr;
  msg.msg.msg.l2tpopen.port = port;
#if PPPOL2TP_AUTH_SUPPORT
  msg.msg.msg.l2tpopen.secret = secret;
  msg.msg.msg.l2tpopen.secret_len = secret_len;
#endif /* PPPOL2TP_AUTH_SUPPORT */
  msg.msg.msg.l2tpopen.link_status_cb = link_status_cb;
  msg.msg.msg.l2tpopen.link_status_ctx = link_status_ctx;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}
#endif /* PPPOL2TP_SUPPORT */


/**
 * Call ppp_reopen() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_reopen(struct pppapi_msg_msg *msg) {
  msg->err = ppp_reopen(msg->ppp, msg->msg.reopen.holdoff);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_reopen() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_reopen(ppp_pcb *pcb, u16_t holdoff) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_reopen;
  msg.msg.ppp = pcb;
  msg.msg.msg.reopen.holdoff = holdoff;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}


/**
 * Call ppp_close() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_close(struct pppapi_msg_msg *msg) {
  msg->err = ppp_close(msg->ppp);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_close() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_close(ppp_pcb *pcb) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_close;
  msg.msg.ppp = pcb;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}


/**
 * Call ppp_sighup() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_sighup(struct pppapi_msg_msg *msg) {
  ppp_sighup(msg->ppp);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_sighup() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
void pppapi_sighup(ppp_pcb *pcb) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_sighup;
  msg.msg.ppp = pcb;
  TCPIP_PPPAPI(&msg);
}


/**
 * Call ppp_delete() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_delete(struct pppapi_msg_msg *msg) {
  msg->err = ppp_delete(msg->ppp);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_delete() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_delete(ppp_pcb *pcb) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_delete;
  msg.msg.ppp = pcb;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}


/**
 * Call ppp_ioctl() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_ioctl(struct pppapi_msg_msg *msg) {
  msg->err = ppp_ioctl(msg->ppp, msg->msg.ioctl.cmd, msg->msg.ioctl.arg);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_ioctl() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
int pppapi_ioctl(ppp_pcb *pcb, int cmd, void *arg) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_ioctl;
  msg.msg.ppp = pcb;
  msg.msg.msg.ioctl.cmd = cmd;
  msg.msg.msg.ioctl.arg = arg;
  TCPIP_PPPAPI(&msg);
  return msg.msg.err;
}


#if PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD
/**
 * Call pppos_input() inside the tcpip_thread context.
 */
static void pppapi_do_pppos_input(struct pppapi_msg_msg *msg) {
  pppos_input(msg->ppp, msg->msg.ppposinput.data, msg->msg.ppposinput.len);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call pppos_input() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
void ppposapi_input(ppp_pcb *pcb, u_char* data, int len) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_pppos_input;
  msg.msg.ppp = pcb;
  msg.msg.msg.ppposinput.data = data;
  msg.msg.msg.ppposinput.len = len;
  TCPIP_PPPAPI(&msg);
}
#endif /* PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD */


#if LWIP_NETIF_STATUS_CALLBACK
/**
 * Call ppp_set_netif_statuscallback() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_set_netif_statuscallback(struct pppapi_msg_msg *msg) {
  ppp_set_netif_statuscallback(msg->ppp, msg->msg.netifstatuscallback.status_callback);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_set_netif_statuscallback() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
void pppapi_set_netif_statuscallback(ppp_pcb *pcb, netif_status_callback_fn status_callback) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_set_netif_statuscallback;
  msg.msg.ppp = pcb;
  msg.msg.msg.netifstatuscallback.status_callback = status_callback;
  TCPIP_PPPAPI(&msg);
}
#endif /* LWIP_NETIF_STATUS_CALLBACK */


#if LWIP_NETIF_LINK_CALLBACK
/**
 * Call ppp_set_netif_linkcallback() inside the tcpip_thread context.
 */
static void pppapi_do_ppp_set_netif_linkcallback(struct pppapi_msg_msg *msg) {
  ppp_set_netif_linkcallback(msg->ppp, msg->msg.netiflinkcallback.link_callback);
  TCPIP_PPPAPI_ACK(msg);
}

/**
 * Call ppp_set_netif_linkcallback() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
void pppapi_set_netif_linkcallback(ppp_pcb *pcb, netif_status_callback_fn link_callback) {
  struct pppapi_msg msg;
  msg.function = pppapi_do_ppp_set_netif_linkcallback;
  msg.msg.ppp = pcb;
  msg.msg.msg.netiflinkcallback.link_callback = link_callback;
  TCPIP_PPPAPI(&msg);
}
#endif /* LWIP_NETIF_LINK_CALLBACK */

#endif /* LWIP_PPP_API */
