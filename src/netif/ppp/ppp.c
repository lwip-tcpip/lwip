/*****************************************************************************
* ppp.c - Network Point to Point Protocol program file.
*
* Copyright (c) 2003 by Marc Boucher, Services Informatiques (MBSI) inc.
* portions Copyright (c) 1997 by Global Election Systems Inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 03-01-01 Marc Boucher <marc@mbsi.ca>
*   Ported to lwIP.
* 97-11-05 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*   Original.
*****************************************************************************/

/*
 * ppp_defs.h - PPP definitions.
 *
 * if_pppvar.h - private structures and declarations for PPP.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */

/*
 * if_ppp.h - Point-to-Point Protocol definitions.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "lwip/opt.h"
#if PPP_SUPPORT /* don't build if not configured for use in lwipopts.h */

#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "lwip/api.h"
#include "lwip/snmp.h"
#include "lwip/sio.h"
#include "lwip/sys.h"
#include "lwip/ip.h" /* for ip_input() */

#include "ppp_impl.h"

#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#include "magic.h"

#if PAP_SUPPORT
#include "upap.h"
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
#include "chap-new.h"
#endif /* CHAP_SUPPORT */
#if EAP_SUPPORT
#include "eap.h"
#endif /* EAP_SUPPORT */
#if CCP_SUPPORT
#include "ccp.h"
#endif /* EAP_SUPPORT */
#if ECP_SUPPORT
#include "ecp.h"
#endif /* EAP_SUPPORT */
#if VJ_SUPPORT
#include "vj.h"
#endif /* VJ_SUPPORT */
#if PPP_IPV6_SUPPORT
#include "ipv6cp.h"
#endif /* PPP_IPV6_SUPPORT */

#if PPPOE_SUPPORT
#include "netif/ppp_oe.h"
#endif /* PPPOE_SUPPORT */

/* Global variables */

#if PPP_DEBUG
u8_t ppp_num;   /* PPP Interface counter, used for debugging messages */
#endif /* PPP_DEBUG */

/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/

/* FIXME: add stats per PPP session */
#if PPP_STATS_SUPPORT
static struct timeval start_time;	/* Time when link was started. */
static struct pppd_stats old_link_stats;
struct pppd_stats link_stats;
unsigned link_connect_time;
int link_stats_valid;
#endif /* PPP_STATS_SUPPORT */

/*
 * PPP Data Link Layer "protocol" table.
 * One entry per supported protocol.
 * The last entry must be NULL.
 */
struct protent *protocols[] = {
    &lcp_protent,
#if PAP_SUPPORT
    &pap_protent,
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
    &chap_protent,
#endif /* CHAP_SUPPORT */
#if CBCP_SUPPORT
    &cbcp_protent,
#endif
    &ipcp_protent,
#if PPP_IPV6_SUPPORT
    &ipv6cp_protent,
#endif
#if CCP_SUPPORT
    &ccp_protent,
#endif /* CCP_SUPPORT */
#if ECP_SUPPORT
    &ecp_protent,
#endif /* ECP_SUPPORT */
#ifdef AT_CHANGE
    &atcp_protent,
#endif
#if EAP_SUPPORT
    &eap_protent,
#endif /* EAP_SUPPORT */
    NULL
};

#if PPPOS_SUPPORT
#define ESCAPE_P(accm, c) ((accm)[(c) >> 3] & ppp_accm_mask[c & 0x07])
#endif /* PPPOS_SUPPORT */

/* Prototypes for procedures local to this file. */

static void ppp_start(ppp_pcb *pcb);	/** Initiate LCP open request */

#if PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD
static void ppp_receive_wakeup(ppp_pcb *pcb);
#endif /* #if PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD */

static void ppp_stop(ppp_pcb *pcb);
static void ppp_hup(ppp_pcb *pcb);

#if PPPOS_SUPPORT
#if PPP_INPROC_OWNTHREAD
static void ppp_input_thread(void *arg);
#endif /* PPP_INPROC_OWNTHREAD */
static void ppp_drop(ppp_pcb_rx *pcrx);
static void pppos_input_proc(ppp_pcb_rx *pcrx, u_char *s, int l);
#if PPP_INPROC_MULTITHREADED
static void pppos_input_callback(void *arg);
#endif /* PPP_INPROC_MULTITHREADED */
static void ppp_free_current_input_packet(ppp_pcb_rx *pcrx);
#endif /* PPPOS_SUPPORT */

static err_t ppp_netif_init_cb(struct netif *netif);
static err_t ppp_netif_output_ip4(struct netif *netif, struct pbuf *pb, ip_addr_t *ipaddr);
#if PPP_IPV6_SUPPORT
static err_t ppp_netif_output_ip6(struct netif *netif, struct pbuf *pb, ip6_addr_t *ipaddr);
#endif /* PPP_IPV6_SUPPORT */
static err_t ppp_netif_output(struct netif *netif, struct pbuf *pb, u_short protocol);

#if PPPOE_SUPPORT
static err_t ppp_netif_output_over_ethernet(ppp_pcb *pcb, struct pbuf *p, u_short protocol);
/* function called by ppp_write() */
static int ppp_write_over_ethernet(ppp_pcb *pcb, struct pbuf *p);
#endif /* PPPOE_SUPPORT */

static void ppp_destroy(ppp_pcb *pcb);

/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/

/* Initialize the PPP subsystem. */
int ppp_init(void) {

    /*
     * Initialize magic number generator now so that protocols may
     * use magic numbers in initialization.
     */
    magic_init();

    return 0;
}

/* Create a new PPP session. */
ppp_pcb *ppp_new(void) {
    int i;
    ppp_pcb *pcb;
    struct protent *protp;

    pcb = (ppp_pcb*)memp_malloc(MEMP_PPP_PCB);
    if (pcb == NULL)
      return NULL;

#if PPP_STATS_SUPPORT
    link_stats_valid = 0;
#endif /* PPP_STATS_SUPPORT */

    memset(pcb, 0, sizeof(ppp_pcb));
#if PPP_DEBUG
    pcb->num = ppp_num++;
#endif /* PPP_DEBUG */
    IP4_ADDR(&pcb->addrs.netmask, 255,255,255,255);
    pcb->lcp_loopbackfail = DEFLOOPBACKFAIL;

    /* default configuration */
    pcb->settings.usepeerdns = 1;
    pcb->settings.persist = 1;
#if CHAP_SUPPORT
    pcb->settings.chap_timeout_time = 3;
    pcb->settings.chap_max_transmits = 10;
#endif /* CHAP_SUPPPORT */
    pcb->settings.lcp_echo_interval = LCP_ECHOINTERVAL;
    pcb->settings.lcp_echo_fails = LCP_MAXECHOFAILS;

    /*
     * Initialize each protocol.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
        (*protp->init)(pcb);

    return pcb;
}

void ppp_set_auth(ppp_pcb *pcb, u8_t authtype, char *user, char *passwd) {

#if PAP_SUPPORT
  if(authtype & PPPAUTHTYPE_PAP)
    pcb->settings.refuse_pap = 0;
  else
    pcb->settings.refuse_pap = 1;
#endif /* PAP_SUPPORT */

#if CHAP_SUPPORT
  if(authtype & PPPAUTHTYPE_CHAP)
    pcb->settings.refuse_chap = 0;
  else
    pcb->settings.refuse_chap = 1;
#if MSCHAP_SUPPORT
  if(authtype & PPPAUTHTYPE_MSCHAP) {
    pcb->settings.refuse_mschap = 0;
    pcb->settings.refuse_mschap_v2 = 0;
  } else {
    pcb->settings.refuse_mschap = 1;
    pcb->settings.refuse_mschap_v2 = 1;
  }
#endif /* MSCHAP_SUPPORT */
#endif /* CHAP_SUPPORT */

#if EAP_SUPPORT
  if(authtype & PPPAUTHTYPE_EAP)
    pcb->settings.refuse_eap = 0;
  else
    pcb->settings.refuse_eap = 1;
#endif /* EAP_SUPPORT */

  if(user)
    pcb->settings.user = user;

  if(passwd)
    pcb->settings.passwd = passwd;
}

#if PPPOS_SUPPORT
/** Open a new PPP connection using the given I/O device.
 * This initializes the PPP control block but does not
 * attempt to negotiate the LCP session.  If this port
 * connects to a modem, the modem connection must be
 * established before calling this.
 * Return a new PPP connection descriptor on success or
 * an error code (negative) on failure.
 *
 * pppOpen() is directly defined to this function.
 */
int ppp_over_serial_open(ppp_pcb *pcb, sio_fd_t fd, ppp_link_status_cb_fn link_status_cb, void *link_status_ctx) {

  /* PPP is single-threaded: without a callback,
   * there is no way to know when the link is up. */
  if (link_status_cb == NULL)
    return PPPERR_PARAM;

  /* input pbuf left over from last session? */
  ppp_free_current_input_packet(&pcb->rx);

  pcb->fd = fd;

  pcb->rx.pcb = pcb;
  pcb->rx.fd = fd;

#if VJ_SUPPORT
  vj_compress_init(&pcb->vj_comp);
#endif /* VJ_SUPPORT */

  /*
   * Default the in and out accm so that escape and flag characters
   * are always escaped.
   */
  pcb->rx.in_accm[15] = 0x60; /* no need to protect since RX is not running */
  pcb->out_accm[15] = 0x60;

  pcb->link_status_cb = link_status_cb;
  pcb->link_status_ctx = link_status_ctx;

  /*
   * Start the connection and handle incoming events (packet or timeout).
   */
  PPPDEBUG(LOG_INFO, ("ppp_over_serial_open: unit %d: Connecting\n", pcb->num));
  new_phase(pcb, PHASE_INITIALIZE);
  ppp_start(pcb);
#if PPP_INPROC_OWNTHREAD
  sys_thread_new(PPP_THREAD_NAME, ppp_input_thread, (void*)&pcb->rx, PPP_THREAD_STACKSIZE, PPP_THREAD_PRIO);
#endif /* PPP_INPROC_OWNTHREAD */

  return PPPERR_NONE;
}

/*
 * ppp_set_xaccm - set the extended transmit ACCM for the interface.
 */
void ppp_set_xaccm(ppp_pcb *pcb, ext_accm *accm) {
  SMEMCPY(pcb->out_accm, accm, sizeof(ext_accm));
  PPPDEBUG(LOG_INFO, ("ppp_set_xaccm[%d]: out_accm=%X %X %X %X\n",
            pcb->num,
            pcb->out_accm[0],
            pcb->out_accm[1],
            pcb->out_accm[2],
            pcb->out_accm[3]));
}
#endif /* PPPOS_SUPPORT */

#if PPPOE_SUPPORT
static void ppp_over_ethernet_link_status_cb(ppp_pcb *pcb, int state);

int ppp_over_ethernet_open(ppp_pcb *pcb, struct netif *ethif, const char *service_name, const char *concentrator_name,
                        ppp_link_status_cb_fn link_status_cb, void *link_status_ctx) {

  lcp_options *wo = &pcb->lcp_wantoptions;
  lcp_options *ao = &pcb->lcp_allowoptions;

  LWIP_UNUSED_ARG(service_name);
  LWIP_UNUSED_ARG(concentrator_name);

  /* PPP is single-threaded: without a callback,
   * there is no way to know when the link is up. */
  if (link_status_cb == NULL)
    return PPPERR_PARAM;

  pcb->ethif = ethif;

  pcb->link_status_cb  = link_status_cb;
  pcb->link_status_ctx = link_status_ctx;

  wo->mru = ethif->mtu-PPPOE_HEADERLEN-2; /* two byte PPP protocol discriminator, then IP data */
  wo->neg_asyncmap = 0;
  wo->neg_pcompression = 0;
  wo->neg_accompression = 0;

  ao->mru = ethif->mtu-PPPOE_HEADERLEN-2; /* two byte PPP protocol discriminator, then IP data */
  ao->neg_asyncmap = 0;
  ao->neg_pcompression = 0;
  ao->neg_accompression = 0;

  if(pppoe_create(ethif, pcb, ppp_over_ethernet_link_status_cb, &pcb->pppoe_sc) != ERR_OK) {
    return PPPERR_OPEN;
  }

  new_phase(pcb, PHASE_INITIALIZE);
  pppoe_connect(pcb->pppoe_sc);
  return PPPERR_NONE;
}
#endif /* PPPOE_SUPPORT */


/* Close a PPP connection and release the descriptor.
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success, an error code on failure. */
int
ppp_close(ppp_pcb *pcb)
{
  int st = 0;

  PPPDEBUG(LOG_DEBUG, ("ppp_close() called\n"));
  pcb->settings.persist = 0;

  /* Disconnect */
#if PPPOE_SUPPORT
  if(pcb->ethif) {
    PPPDEBUG(LOG_DEBUG, ("ppp_close: unit %d kill_link -> ppp_stop\n", pcb->num));
    pcb->err_code = PPPERR_USER;
    /* This will leave us at PHASE_DEAD. */
    ppp_stop(pcb);
  } else
#endif /* PPPOE_SUPPORT */
  {
#if PPPOS_SUPPORT
    PPPDEBUG(LOG_DEBUG, ("ppp_close: unit %d kill_link -> ppp_stop\n", pcb->num));
    pcb->err_code = PPPERR_USER;
    /* This will leave us at PHASE_DEAD. */
    ppp_stop(pcb);
#if PPP_INPROC_OWNTHREAD
    ppp_receive_wakeup(pcb);
#endif /* PPP_INPROC_OWNTHREAD */
#endif /* PPPOS_SUPPORT */
  }

  return st;
}

/* This function is called when carrier is lost on the PPP channel. */
void
ppp_sighup(ppp_pcb *pcb)
{
  PPPDEBUG(LOG_DEBUG, ("ppp_sighup: unit %d sig_hup -> ppp_hup\n", pcb->num));
  ppp_hup(pcb);
}




/** Initiate LCP open request */
static void ppp_start(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_start: unit %d\n", pcb->num));
  lcp_open(pcb); /* Start protocol */
  lcp_lowerup(pcb);
  PPPDEBUG(LOG_DEBUG, ("ppp_start: finished\n"));
}

/** LCP close request */
static void ppp_stop(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_stop: unit %d\n", pcb->num));
  lcp_close(pcb, "User request");
}

/** Called when carrier/link is lost */
static void ppp_hup(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_hup: unit %d\n", pcb->num));
  lcp_lowerdown(pcb);
  link_terminated(pcb);
}

/*
 * Pass the processed input packet to the appropriate handler.
 * This function and all handlers run in the context of the tcpip_thread
 */
void ppp_input(ppp_pcb *pcb, struct pbuf *pb) {
  u16_t protocol;

  protocol = (((u8_t *)pb->payload)[0] << 8) | ((u8_t*)pb->payload)[1];

#if PRINTPKT_SUPPORT
  dump_packet("rcvd", pb->payload, pb->len);
#endif /* PRINTPKT_SUPPORT */

  if(pbuf_header(pb, -(s16_t)sizeof(protocol))) {
    LWIP_ASSERT("pbuf_header failed\n", 0);
    goto drop;
  }

  LINK_STATS_INC(link.recv);
  snmp_inc_ifinucastpkts(&pcb->netif);
  snmp_add_ifinoctets(&pcb->netif, pb->tot_len);

  /*
   * Toss all non-LCP packets unless LCP is OPEN.
   */
  if (protocol != PPP_LCP && pcb->lcp_fsm.state != OPENED) {
	dbglog("Discarded non-LCP packet when LCP not open");
	goto drop;
  }

  /*
   * Until we get past the authentication phase, toss all packets
   * except LCP, LQR and authentication packets.
   */
  if (pcb->phase <= PHASE_AUTHENTICATE
	&& !(protocol == PPP_LCP
#if LQR_SUPPORT
	     || protocol == PPP_LQR
#endif /* LQR_SUPPORT */
#if PAP_SUPPORT
	     || protocol == PPP_PAP
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
	     || protocol == PPP_CHAP
#endif /* CHAP_SUPPORT */
#if EAP_SUPPORT
	     || protocol == PPP_EAP
#endif /* EAP_SUPPORT */
	     )) {
	dbglog("discarding proto 0x%x in phase %d",
		   protocol, pcb->phase);
	goto drop;
  }

  /* FIXME: should we write protent to do that ? */

  switch(protocol) {

#if PPPOS_SUPPORT && VJ_SUPPORT
    case PPP_VJC_COMP:      /* VJ compressed TCP */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: vj_comp in pbuf len=%d\n", pcb->num, pb->len));
      /*
       * Clip off the VJ header and prepend the rebuilt TCP/IP header and
       * pass the result to IP.
       */
      if ((vj_uncompress_tcp(&pb, &pcb->vj_comp) >= 0) && (pcb->netif.input)) {
        pcb->netif.input(pb, &pcb->netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("ppp_input[%d]: Dropping VJ compressed\n", pcb->num));
      break;

    case PPP_VJC_UNCOMP:    /* VJ uncompressed TCP */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: vj_un in pbuf len=%d\n", pcb->num, pb->len));
      /*
       * Process the TCP/IP header for VJ header compression and then pass
       * the packet to IP.
       */
      if ((vj_uncompress_uncomp(pb, &pcb->vj_comp) >= 0) && pcb->netif.input) {
        pcb->netif.input(pb, &pcb->netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("ppp_input[%d]: Dropping VJ uncompressed\n", pcb->num));
      break;
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */

    case PPP_IP:            /* Internet Protocol */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: ip in pbuf len=%d\n", pcb->num, pb->len));
      ip_input(pb, &pcb->netif);
      return;

#if PPP_IPV6_SUPPORT
    case PPP_IPV6:          /* Internet Protocol Version 6 */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: ip6 in pbuf len=%d\n", pcb->num, pb->len));
      ip6_input(pb, &pcb->netif);
      return;
#endif /* PPP_IPV6_SUPPORT */

    default: {

	  int i;
	  struct protent *protp;
	  /*
	   * Upcall the proper protocol input routine.
	   */
	  for (i = 0; (protp = protocols[i]) != NULL; ++i) {
		if (protp->protocol == protocol && protp->enabled_flag) {
		    pb = ppp_singlebuf(pb);
		    (*protp->input)(pcb, pb->payload, pb->len);
		    goto out;
		}
#if 0 /* UNUSED
       *
       * This is actually a (hacked?) way for the PPP kernel implementation to pass a
       * data packet to the PPP daemon. The PPP daemon normally only do signaling
       * (LCP, PAP, CHAP, IPCP, ...) and does not handle any data packet at all.
       *
       * This is only used by CCP, which we cannot support until we have a CCP data
       * implementation.
       */
		if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag
		    && protp->datainput != NULL) {
		    (*protp->datainput)(pcb, pb->payload, pb->len);
		    goto out;
		}
#endif /* UNUSED */
	  }

#if PPP_DEBUG
#if PPP_PROTOCOLNAME
	const char *pname = protocol_name(protocol);
	if (pname != NULL)
	    warn("Unsupported protocol '%s' (0x%x) received", pname, protocol);
	else
#endif /* PPP_PROTOCOLNAME */
	    warn("Unsupported protocol 0x%x received", protocol);
#endif /* PPP_DEBUG */
	  if (pbuf_header(pb, (s16_t)sizeof(protocol))) {
	        LWIP_ASSERT("pbuf_header failed\n", 0);
	        goto drop;
	  }
	  lcp_sprotrej(pcb, pb->payload, pb->len);
    }
    break;
 }

drop:
  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(&pcb->netif);

out:
  pbuf_free(pb);
  magic_randomize();
  return;

#if 0
  /*
   * Toss all non-LCP packets unless LCP is OPEN.
   * Until we get past the authentication phase, toss all packets
   * except LCP, LQR and authentication packets.
   */
  if((lcp_phase[pcb->unit] <= PHASE_AUTHENTICATE) && (protocol != PPP_LCP)) {
    if(!((protocol == PPP_LQR) || (protocol == PPP_PAP) || (protocol == PPP_CHAP)) ||
        (lcp_phase[pcb->unit] != PHASE_AUTHENTICATE)) {
      PPPDEBUG(LOG_INFO, ("ppp_input: discarding proto 0x%"X16_F" in phase %d\n", protocol, lcp_phase[pcb->unit]));
      goto drop;
    }
  }

  switch(protocol) {
    case PPP_VJC_COMP:      /* VJ compressed TCP */
#if PPPOS_SUPPORT && VJ_SUPPORT
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: vj_comp in pbuf len=%d\n", pcb->unit, pb->len));
      /*
       * Clip off the VJ header and prepend the rebuilt TCP/IP header and
       * pass the result to IP.
       */
      if ((vj_uncompress_tcp(&pb, pcb->vj_comp) >= 0) && (pcb->netif.input)) {
        pcb->netif.input(pb, pcb->netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("ppp_input[%d]: Dropping VJ compressed\n", pcb->unit));
#else  /* PPPOS_SUPPORT && VJ_SUPPORT */
      /* No handler for this protocol so drop the packet. */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: drop VJ Comp in %d:%s\n", pcb->unit, pb->len, pb->payload));
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */
      break;

    case PPP_VJC_UNCOMP:    /* VJ uncompressed TCP */
#if PPPOS_SUPPORT && VJ_SUPPORT
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: vj_un in pbuf len=%d\n", pcb->unit, pb->len));
      /*
       * Process the TCP/IP header for VJ header compression and then pass
       * the packet to IP.
       */
      if ((vj_uncompress_uncomp(pb, pcb->vj_comp) >= 0) && pcb->netif.input) {
        pcb->netif.input(pb, pcb->netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("ppp_input[%d]: Dropping VJ uncompressed\n", pcb->unit));
#else  /* PPPOS_SUPPORT && VJ_SUPPORT */
      /* No handler for this protocol so drop the packet. */
      PPPDEBUG(LOG_INFO,
               ("ppp_input[%d]: drop VJ UnComp in %d:.*H\n",
                pcb->unit, pb->len, LWIP_MIN(pb->len * 2, 40), pb->payload));
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */
      break;

    case PPP_IP:            /* Internet Protocol */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: ip in pbuf len=%d\n", pcb->unit, pb->len));
      if (pcb->netif.input) {
        pcb->netif.input(pb, pcb->netif);
        return;
      }
      break;

    default: {
      struct protent *protp;
      int i;

      /*
       * Upcall the proper protocol input routine.
       */
      for (i = 0; (protp = ppp_protocols[i]) != NULL; ++i) {
        if (protp->protocol == protocol && protp->enabled_flag) {
          PPPDEBUG(LOG_INFO, ("ppp_input[%d]: %s len=%d\n", pcb->unit, protp->name, pb->len));
          pb = ppp_singlebuf(pb);
          (*protp->input)(pcb->unit, pb->payload, pb->len);
          PPPDEBUG(LOG_DETAIL, ("ppp_input[%d]: packet processed\n", pcb->unit));
          goto out;
        }
      }

      /* No handler for this protocol so reject the packet. */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: rejecting unsupported proto 0x%"X16_F" len=%d\n", pcb->unit, protocol, pb->len));
      if (pbuf_header(pb, sizeof(protocol))) {
        LWIP_ASSERT("pbuf_header failed\n", 0);
        goto drop;
      }
#if BYTE_ORDER == LITTLE_ENDIAN
      protocol = htons(protocol);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
      SMEMCPY(pb->payload, &protocol, sizeof(protocol));
      lcp_sprotrej(pcb->unit, pb->payload, pb->len);
    }
    break;
  }
#endif


}

#if PPPOS_SUPPORT
#if PPP_FCS_TABLE
/*
 * FCS lookup table as calculated by genfcstab.
 */
static const u_short fcstab[256] = {
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};
#else /* PPP_FCS_TABLE */
/* The HDLC polynomial: X**0 + X**5 + X**12 + X**16 (0x8408) */
#define PPP_FCS_POLYNOMIAL 0x8408
u16_t ppp_get_fcs(u8_t byte) {
  unsigned int octet;
  int bit;
  octet = byte;
  for (bit = 8; bit-- > 0; ) {
    octet = (octet & 0x01) ? ((octet >> 1) ^ PPP_FCS_POLYNOMIAL) : (octet >> 1);
  }
  return octet & 0xffff;
}
#endif /* PPP_FCS_TABLE */

/* PPP's Asynchronous-Control-Character-Map.  The mask array is used
 * to select the specific bit for a character. */
static u_char ppp_accm_mask[] = {
  0x01,
  0x02,
  0x04,
  0x08,
  0x10,
  0x20,
  0x40,
  0x80
};

#if PPP_INPROC_OWNTHREAD
/** Wake up the task blocked in reading from serial line (if any) */
static void
ppp_receive_wakeup(ppp_pcb *pcb)
{
  PPPDEBUG(LOG_DEBUG, ("ppp_receive_wakeup: unit %d\n", pcb->num));
  sio_read_abort(pcb->fd);
}
#endif /* PPP_INPROC_OWNTHREAD */
#endif /* PPPOS_SUPPORT */

/*
 * ppp_netif_init_cb - netif init callback
 */
static err_t ppp_netif_init_cb(struct netif *netif) {
  netif->name[0] = 'p';
  netif->name[1] = 'p';
  netif->output = ppp_netif_output_ip4;
#if PPP_IPV6_SUPPORT
  netif->output_ip6 = ppp_netif_output_ip6;
#endif /* PPP_IPV6_SUPPORT */
  netif->mtu = netif_get_mtu((ppp_pcb*)netif->state);
  netif->flags = NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_LINK_UP;
#if LWIP_NETIF_HOSTNAME
  /* @todo: Initialize interface hostname */
  /* netif_set_hostname(netif, "lwip"); */
#endif /* LWIP_NETIF_HOSTNAME */
  return ERR_OK;
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/

#if PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD
/* The main PPP process function.  This implements the state machine according
 * to section 4 of RFC 1661: The Point-To-Point Protocol. */
static void
ppp_input_thread(void *arg)
{
  int count;
  ppp_pcb_rx *pcrx = arg;
  ppp_pcb *pcb = pcrx->pcb;

  while (pcb->phase != PHASE_DEAD) {
    count = sio_read(pcrx->fd, pcrx->rxbuf, PPPOS_RX_BUFSIZE);
    if(count > 0) {
      pppos_input_proc(pcrx, pcrx->rxbuf, count);
    } else {
      /* nothing received, give other tasks a chance to run */
      sys_msleep(1);
    }
  }
}
#endif /* PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD */


#if PPPOS_SUPPORT
static void
pppos_put(ppp_pcb *pcb, struct pbuf *nb)
{
  struct pbuf *b;
  int c;

  for(b = nb; b != NULL; b = b->next) {
    if((c = sio_write(pcb->fd, b->payload, b->len)) != b->len) {
      PPPDEBUG(LOG_WARNING,
               ("PPP pppos_put: incomplete sio_write(fd:%"SZT_F", len:%d, c: 0x%"X8_F") c = %d\n", (size_t)pcb->fd, b->len, c, c));
      LINK_STATS_INC(link.err);
      pcb->last_xmit = 0; /* prepend PPP_FLAG to next packet */
      snmp_inc_ifoutdiscards(&pcb->netif);
      pbuf_free(nb);
      return;
    }
  }

  snmp_add_ifoutoctets(&pcb->netif, nb->tot_len);
  snmp_inc_ifoutucastpkts(&pcb->netif);
  pbuf_free(nb);
  LINK_STATS_INC(link.xmit);
}

/*
 * ppp_append - append given character to end of given pbuf.  If out_accm
 * is not NULL and the character needs to be escaped, do so.
 * If pbuf is full, append another.
 * Return the current pbuf.
 */
static struct pbuf *
ppp_append(u_char c, struct pbuf *nb, ext_accm *out_accm)
{
  struct pbuf *tb = nb;

  /* Make sure there is room for the character and an escape code.
   * Sure we don't quite fill the buffer if the character doesn't
   * get escaped but is one character worth complicating this? */
  /* Note: We assume no packet header. */
  if (nb && (PBUF_POOL_BUFSIZE - nb->len) < 2) {
    tb = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
    if (tb) {
      nb->next = tb;
    } else {
      LINK_STATS_INC(link.memerr);
    }
    nb = tb;
  }

  if (nb) {
    if (out_accm && ESCAPE_P(*out_accm, c)) {
      *((u_char*)nb->payload + nb->len++) = PPP_ESCAPE;
      *((u_char*)nb->payload + nb->len++) = c ^ PPP_TRANS;
    } else {
      *((u_char*)nb->payload + nb->len++) = c;
    }
  }

  return tb;
}
#endif /* PPPOS_SUPPORT */


/* Send a IPv4 packet on the given connection.
 */
static err_t ppp_netif_output_ip4(struct netif *netif, struct pbuf *pb, ip_addr_t *ipaddr) {
  LWIP_UNUSED_ARG(ipaddr);
  return ppp_netif_output(netif, pb, PPP_IP);
}

#if PPP_IPV6_SUPPORT
/* Send a IPv6 packet on the given connection.
 */
static err_t ppp_netif_output_ip6(struct netif *netif, struct pbuf *pb, ip6_addr_t *ipaddr) {
  LWIP_UNUSED_ARG(ipaddr);
  return ppp_netif_output(netif, pb, PPP_IPV6);
}
#endif /* PPP_IPV6_SUPPORT */

/* Send a packet on the given connection.
 *
 * This is the low level function that send the PPP packet,
 * only for IPv4 and IPv6 packets coming from lwIP.
 */
static err_t ppp_netif_output(struct netif *netif, struct pbuf *pb, u_short protocol) {
  ppp_pcb *pcb = (ppp_pcb*)netif->state;
#if PPPOS_SUPPORT
  u_int fcs_out = PPP_INITFCS;
  struct pbuf *head = NULL, *tail = NULL, *p;
  u_char c;
#endif /* PPPOS_SUPPORT */

  /* Validate parameters. */
  /* We let any protocol value go through - it can't hurt us
   * and the peer will just drop it if it's not accepting it. */
  if (!pcb || !pb) {
    PPPDEBUG(LOG_WARNING, ("ppp_netif_output[%d]: bad params prot=%d pb=%p\n",
              pcb->num, PPP_IP, (void*)pb));
    LINK_STATS_INC(link.opterr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_ARG;
  }

  /* Check that the link is up. */
  if (pcb->phase == PHASE_DEAD) {
    PPPDEBUG(LOG_ERR, ("ppp_netif_output[%d]: link not up\n", pcb->num));
    LINK_STATS_INC(link.rterr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_RTE;
  }

#if PPPOE_SUPPORT
  if(pcb->ethif) {
    return ppp_netif_output_over_ethernet(pcb, pb, protocol);
  }
#endif /* PPPOE_SUPPORT */

#if PPPOS_SUPPORT
  /* Grab an output buffer. */
  head = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  if (head == NULL) {
    PPPDEBUG(LOG_WARNING, ("ppp_netif_output[%d]: first alloc fail\n", pcb->num));
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_MEM;
  }

#if VJ_SUPPORT
  /*
   * Attempt Van Jacobson header compression if VJ is configured and
   * this is an IP packet.
   */
  if (protocol == PPP_IP && pcb->vj_enabled) {
    switch (vj_compress_tcp(&pcb->vj_comp, pb)) {
      case TYPE_IP:
        /* No change...
           protocol = PPP_IP_PROTOCOL; */
        break;
      case TYPE_COMPRESSED_TCP:
        protocol = PPP_VJC_COMP;
        break;
      case TYPE_UNCOMPRESSED_TCP:
        protocol = PPP_VJC_UNCOMP;
        break;
      default:
        PPPDEBUG(LOG_WARNING, ("ppp_netif_output[%d]: bad IP packet\n", pcb->num));
        LINK_STATS_INC(link.proterr);
        LINK_STATS_INC(link.drop);
        snmp_inc_ifoutdiscards(netif);
        pbuf_free(head);
        return ERR_VAL;
    }
  }
#endif /* VJ_SUPPORT */

  tail = head;

  /* Build the PPP header. */
  if ((sys_jiffies() - pcb->last_xmit) >= PPP_MAXIDLEFLAG) {
    tail = ppp_append(PPP_FLAG, tail, NULL);
  }

  pcb->last_xmit = sys_jiffies();
  if (!pcb->accomp) {
    fcs_out = PPP_FCS(fcs_out, PPP_ALLSTATIONS);
    tail = ppp_append(PPP_ALLSTATIONS, tail, &pcb->out_accm);
    fcs_out = PPP_FCS(fcs_out, PPP_UI);
    tail = ppp_append(PPP_UI, tail, &pcb->out_accm);
  }
  if (!pcb->pcomp || protocol > 0xFF) {
    c = (protocol >> 8) & 0xFF;
    fcs_out = PPP_FCS(fcs_out, c);
    tail = ppp_append(c, tail, &pcb->out_accm);
  }
  c = protocol & 0xFF;
  fcs_out = PPP_FCS(fcs_out, c);
  tail = ppp_append(c, tail, &pcb->out_accm);

  /* Load packet. */
  for(p = pb; p; p = p->next) {
    int n;
    u_char *sPtr;

    sPtr = (u_char*)p->payload;
    n = p->len;
    while (n-- > 0) {
      c = *sPtr++;

      /* Update FCS before checking for special characters. */
      fcs_out = PPP_FCS(fcs_out, c);

      /* Copy to output buffer escaping special characters. */
      tail = ppp_append(c, tail, &pcb->out_accm);
    }
  }

  /* Add FCS and trailing flag. */
  c = ~fcs_out & 0xFF;
  tail = ppp_append(c, tail, &pcb->out_accm);
  c = (~fcs_out >> 8) & 0xFF;
  tail = ppp_append(c, tail, &pcb->out_accm);
  tail = ppp_append(PPP_FLAG, tail, NULL);

  /* If we failed to complete the packet, throw it away. */
  if (!tail) {
    PPPDEBUG(LOG_WARNING,
             ("ppp_netif_output[%d]: Alloc err - dropping proto=%d\n",
              pcb->num, protocol));
    pbuf_free(head);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_MEM;
  }

  /* Send it. */
  PPPDEBUG(LOG_INFO, ("ppp_netif_output[%d]: proto=0x%"X16_F"\n", pcb->num, protocol));

  pppos_put(pcb, head);
#endif /* PPPOS_SUPPORT */

  return ERR_OK;
}


#if PPPOE_SUPPORT
static err_t ppp_netif_output_over_ethernet(ppp_pcb *pcb, struct pbuf *p, u_short protocol) {
  struct pbuf *pb;
  int i=0;
  u16_t tot_len;

  /* @todo: try to use pbuf_header() here! */
  pb = pbuf_alloc(PBUF_LINK, PPPOE_HDRLEN + sizeof(protocol), PBUF_RAM);
  if(!pb) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pcb->netif);
    return ERR_MEM;
  }

  pbuf_header(pb, -(s16_t)PPPOE_HDRLEN);

  pcb->last_xmit = sys_jiffies();

  if (!pcb->pcomp || protocol > 0xFF) {
    *((u_char*)pb->payload + i++) = (protocol >> 8) & 0xFF;
  }
  *((u_char*)pb->payload + i) = protocol & 0xFF;

  pbuf_chain(pb, p);
  tot_len = pb->tot_len;

  if(pppoe_xmit(pcb->pppoe_sc, pb) != ERR_OK) {
    LINK_STATS_INC(link.err);
    snmp_inc_ifoutdiscards(&pcb->netif);
    return PPPERR_DEVICE;
  }

  snmp_add_ifoutoctets(&pcb->netif, tot_len);
  snmp_inc_ifoutucastpkts(&pcb->netif);
  LINK_STATS_INC(link.xmit);
  return ERR_OK;
}
#endif /* PPPOE_SUPPORT */


/* Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. */
int
ppp_ioctl(ppp_pcb *pcb, int cmd, void *arg)
{
  if(NULL == pcb)
    return PPPERR_PARAM;

  switch(cmd) {
    case PPPCTLG_UPSTATUS:      /* Get the PPP up status. */
      if (arg) {
        *(int *)arg = (int)(pcb->if_up);
        return PPPERR_NONE;
      }
      return PPPERR_PARAM;
      break;

    case PPPCTLS_ERRCODE:       /* Set the PPP error code. */
      if (arg) {
        pcb->err_code = *(u8_t *)arg;
        return PPPERR_NONE;
      }
      return PPPERR_PARAM;
      break;

    case PPPCTLG_ERRCODE:       /* Get the PPP error code. */
      if (arg) {
        *(int *)arg = (int)(pcb->err_code);
        return PPPERR_NONE;
      }
      return PPPERR_PARAM;
      break;

#if PPPOS_SUPPORT
    case PPPCTLG_FD:            /* Get the fd associated with the ppp */
      if (arg) {
        *(sio_fd_t *)arg = pcb->fd;
        return PPPERR_NONE;
      }
      return PPPERR_PARAM;
      break;
#endif /* PPPOS_SUPPORT */

    default:
      return PPPERR_PARAM;
      break;
  }

  return PPPERR_PARAM;
}

/*
 * Write a pbuf to a ppp link, only used from PPP functions
 * to send PPP packets.
 *
 * IPv4 and IPv6 packets from lwIP are sent, respectively,
 * with ppp_netif_output_ip4() and ppp_netif_output_ip6()
 * functions (which are callbacks of the netif PPP interface).
 *
 *  RETURN: >= 0 Number of characters written
 *           -1 Failed to write to device
 */
int ppp_write(ppp_pcb *pcb, struct pbuf *p) {
#if PPPOS_SUPPORT
  u_char *s = p->payload;
  int n = p->len;
  u_char c;
  u_int fcs_out;
  struct pbuf *head, *tail;
#endif /* PPPOS_SUPPORT */

#if PRINTPKT_SUPPORT
  dump_packet("sent", (unsigned char *)p->payload+2, p->len-2);
#endif /* PRINTPKT_SUPPORT */

#if PPPOE_SUPPORT
  if(pcb->ethif) {
    return ppp_write_over_ethernet(pcb, p);
  }
#endif /* PPPOE_SUPPORT */

#if PPPOS_SUPPORT
  head = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  if (head == NULL) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pcb->netif);
    pbuf_free(p);
    return PPPERR_ALLOC;
  }

  tail = head;

  /* If the link has been idle, we'll send a fresh flag character to
   * flush any noise. */
  if ((sys_jiffies() - pcb->last_xmit) >= PPP_MAXIDLEFLAG) {
    tail = ppp_append(PPP_FLAG, tail, NULL);
  }
  pcb->last_xmit = sys_jiffies();

  fcs_out = PPP_INITFCS;
  /* Load output buffer. */
  while (n-- > 0) {
    c = *s++;

    /* Update FCS before checking for special characters. */
    fcs_out = PPP_FCS(fcs_out, c);

    /* Copy to output buffer escaping special characters. */
    tail = ppp_append(c, tail, &pcb->out_accm);
  }

  /* Add FCS and trailing flag. */
  c = ~fcs_out & 0xFF;
  tail = ppp_append(c, tail, &pcb->out_accm);
  c = (~fcs_out >> 8) & 0xFF;
  tail = ppp_append(c, tail, &pcb->out_accm);
  tail = ppp_append(PPP_FLAG, tail, NULL);

  /* If we failed to complete the packet, throw it away.
   * Otherwise send it. */
  if (!tail) {
    PPPDEBUG(LOG_WARNING,
             ("ppp_write[%d]: Alloc err - dropping pbuf len=%d\n", pcb->num, head->len));
           /*"ppp_write[%d]: Alloc err - dropping %d:%.*H", pd, head->len, LWIP_MIN(head->len * 2, 40), head->payload)); */
    pbuf_free(head);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pcb->netif);
    pbuf_free(p);
    return PPPERR_ALLOC;
  }

  PPPDEBUG(LOG_INFO, ("ppp_write[%d]: len=%d\n", pcb->num, head->len));
                   /* "ppp_write[%d]: %d:%.*H", pd, head->len, LWIP_MIN(head->len * 2, 40), head->payload)); */
  pppos_put(pcb, head);
#endif /* PPPOS_SUPPORT */

  pbuf_free(p);
  return PPPERR_NONE;
}

#if PPPOE_SUPPORT
static int ppp_write_over_ethernet(ppp_pcb *pcb, struct pbuf *p) {
  struct pbuf *ph; /* Ethernet + PPPoE header */
  u16_t tot_len;

  /* skip address & flags */
  pbuf_header(p, -(s16_t)2);

  ph = pbuf_alloc(PBUF_LINK, (u16_t)(PPPOE_HDRLEN), PBUF_RAM);
  if(!ph) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pcb->netif);
    pbuf_free(p);
    return PPPERR_ALLOC;
  }

  pbuf_header(ph, -(s16_t)PPPOE_HDRLEN); /* hide PPPoE header */
  pbuf_cat(ph, p);
  tot_len = ph->tot_len;

  pcb->last_xmit = sys_jiffies();

  if(pppoe_xmit(pcb->pppoe_sc, ph) != ERR_OK) {
    LINK_STATS_INC(link.err);
    snmp_inc_ifoutdiscards(&pcb->netif);
    return PPPERR_DEVICE;
  }

  snmp_add_ifoutoctets(&pcb->netif, (u16_t)tot_len);
  snmp_inc_ifoutucastpkts(&pcb->netif);
  LINK_STATS_INC(link.xmit);
  return PPPERR_NONE;
}
#endif /* PPPOE_SUPPORT */


#if PPPOS_SUPPORT
/*
 * Drop the input packet.
 */
static void
ppp_free_current_input_packet(ppp_pcb_rx *pcrx)
{
  if (pcrx->in_head != NULL) {
    if (pcrx->in_tail && (pcrx->in_tail != pcrx->in_head)) {
      pbuf_free(pcrx->in_tail);
    }
    pbuf_free(pcrx->in_head);
    pcrx->in_head = NULL;
  }
  pcrx->in_tail = NULL;
}

/*
 * Drop the input packet and increase error counters.
 */
static void
ppp_drop(ppp_pcb_rx *pcrx)
{
  ppp_pcb *pcb = (ppp_pcb*)pcrx->pcb;
  if (pcrx->in_head != NULL) {
#if 0
    PPPDEBUG(LOG_INFO, ("ppp_drop: %d:%.*H\n", pcrx->in_head->len, min(60, pcrx->in_head->len * 2), pcrx->in_head->payload));
#endif
    PPPDEBUG(LOG_INFO, ("ppp_drop: pbuf len=%d, addr %p\n", pcrx->in_head->len, (void*)pcrx->in_head));
  }
  ppp_free_current_input_packet(pcrx);
#if VJ_SUPPORT
  vj_uncompress_err(&pcb->vj_comp);
#endif /* VJ_SUPPORT */

  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(&pcb->netif);
}

#if !PPP_INPROC_OWNTHREAD
/** Pass received raw characters to PPPoS to be decoded. This function is
 * thread-safe and can be called from a dedicated RX-thread or from a main-loop.
 *
 * @param pd PPP descriptor index, returned by pppOpen()
 * @param data received data
 * @param len length of received data
 */
void
pppos_input(ppp_pcb *pcb, u_char* data, int len)
{
  pppos_input_proc(&pcb->rx, data, len);
}
#endif

#if PPP_INPROC_MULTITHREADED
struct ppp_tcpip_callback_header {
  ppp_pcb *pcb;
};
#endif /* PPP_INPROC_MULTITHREADED */

/**
 * Process a received octet string.
 */
static void
pppos_input_proc(ppp_pcb_rx *pcrx, u_char *s, int l)
{
  ppp_pcb *pcb = (ppp_pcb*)pcrx->pcb;
  struct pbuf *next_pbuf;
  u_char cur_char;
  u_char escaped;
  SYS_ARCH_DECL_PROTECT(lev);

  PPPDEBUG(LOG_DEBUG, ("pppos_input_proc[%d]: got %d bytes\n", pcb->num, l));
  while (l-- > 0) {
    cur_char = *s++;

    SYS_ARCH_PROTECT(lev);
    escaped = ESCAPE_P(pcrx->in_accm, cur_char);
    SYS_ARCH_UNPROTECT(lev);
    /* Handle special characters. */
    if (escaped) {
      /* Check for escape sequences. */
      /* XXX Note that this does not handle an escaped 0x5d character which
       * would appear as an escape character.  Since this is an ASCII ']'
       * and there is no reason that I know of to escape it, I won't complicate
       * the code to handle this case. GLL */
      if (cur_char == PPP_ESCAPE) {
        pcrx->in_escaped = 1;
      /* Check for the flag character. */
      } else if (cur_char == PPP_FLAG) {
        /* If this is just an extra flag character, ignore it. */
        if (pcrx->in_state <= PDADDRESS) {
          /* ignore it */;
        /* If we haven't received the packet header, drop what has come in. */
        } else if (pcrx->in_state < PDDATA) {
          PPPDEBUG(LOG_WARNING,
                   ("pppos_input_proc[%d]: Dropping incomplete packet %d\n",
                    pcb->num, pcrx->in_state));
          LINK_STATS_INC(link.lenerr);
          ppp_drop(pcrx);
        /* If the fcs is invalid, drop the packet. */
        } else if (pcrx->in_fcs != PPP_GOODFCS) {
          PPPDEBUG(LOG_INFO,
                   ("pppos_input_proc[%d]: Dropping bad fcs 0x%"X16_F" proto=0x%"X16_F"\n",
                    pcb->num, pcrx->in_fcs, pcrx->in_protocol));
          /* Note: If you get lots of these, check for UART frame errors or try different baud rate */
          LINK_STATS_INC(link.chkerr);
          ppp_drop(pcrx);
        /* Otherwise it's a good packet so pass it on. */
        } else {
          struct pbuf *inp;
#if PPP_INPROC_MULTITHREADED
          struct pbuf *head;
          struct ppp_tcpip_callback_header *cbhead;
#endif /* PPP_INPROC_MULTITHREADED */
          /* Trim off the checksum. */
          if(pcrx->in_tail->len > 2) {
            pcrx->in_tail->len -= 2;

            pcrx->in_tail->tot_len = pcrx->in_tail->len;
            if (pcrx->in_tail != pcrx->in_head) {
              pbuf_cat(pcrx->in_head, pcrx->in_tail);
            }
          } else {
            pcrx->in_tail->tot_len = pcrx->in_tail->len;
            if (pcrx->in_tail != pcrx->in_head) {
              pbuf_cat(pcrx->in_head, pcrx->in_tail);
            }

            pbuf_realloc(pcrx->in_head, pcrx->in_head->tot_len - 2);
          }

          /* Dispatch the packet thereby consuming it. */
          inp = pcrx->in_head;
          /* Packet consumed, release our references. */
          pcrx->in_head = NULL;
          pcrx->in_tail = NULL;
#if PPP_INPROC_MULTITHREADED
          head = pbuf_alloc(PBUF_RAW, sizeof(struct ppp_tcpip_callback_header), PBUF_POOL);
          if(NULL != head) {
            cbhead = (struct ppp_tcpip_callback_header*)head->payload;
            cbhead->pcb = pcb;
            pbuf_chain(head, inp);
            if(tcpip_callback_with_block(pppos_input_callback, head, 0) != ERR_OK) {
              PPPDEBUG(LOG_ERR, ("pppos_input_proc[%d]: tcpip_callback() failed, dropping packet\n", pcb->num));
              pbuf_free(head);
              pbuf_free(inp);
              LINK_STATS_INC(link.drop);
              snmp_inc_ifindiscards(&pcb->netif);
            }
          }
#else /* PPP_INPROC_MULTITHREADED */
          ppp_input(pcrx->pcb, inp);
#endif /* PPP_INPROC_MULTITHREADED */
        }

        /* Prepare for a new packet. */
        pcrx->in_fcs = PPP_INITFCS;
        pcrx->in_state = PDADDRESS;
        pcrx->in_escaped = 0;
      /* Other characters are usually control characters that may have
       * been inserted by the physical layer so here we just drop them. */
      } else {
        PPPDEBUG(LOG_WARNING,
                 ("pppos_input_proc[%d]: Dropping ACCM char <%d>\n", pcb->num, cur_char));
      }
    /* Process other characters. */
    } else {
      /* Unencode escaped characters. */
      if (pcrx->in_escaped) {
        pcrx->in_escaped = 0;
        cur_char ^= PPP_TRANS;
      }

      /* Process character relative to current state. */
      switch(pcrx->in_state) {
        case PDIDLE:                    /* Idle state - waiting. */
          /* Drop the character if it's not 0xff
           * we would have processed a flag character above. */
          if (cur_char != PPP_ALLSTATIONS) {
            break;
          }
          /* no break */
          /* Fall through */

        case PDSTART:                   /* Process start flag. */
          /* Prepare for a new packet. */
          pcrx->in_fcs = PPP_INITFCS;
          /* no break */
          /* Fall through */

        case PDADDRESS:                 /* Process address field. */
          if (cur_char == PPP_ALLSTATIONS) {
            pcrx->in_state = PDCONTROL;
            break;
          }
          /* no break */

          /* Else assume compressed address and control fields so
           * fall through to get the protocol... */
        case PDCONTROL:                 /* Process control field. */
          /* If we don't get a valid control code, restart. */
          if (cur_char == PPP_UI) {
            pcrx->in_state = PDPROTOCOL1;
            break;
          }
          /* no break */

#if 0
          else {
            PPPDEBUG(LOG_WARNING,
                     ("pppos_input_proc[%d]: Invalid control <%d>\n", pcb->num, cur_char));
            pcrx->in_state = PDSTART;
          }
#endif
        case PDPROTOCOL1:               /* Process protocol field 1. */
          /* If the lower bit is set, this is the end of the protocol
           * field. */
          if (cur_char & 1) {
            pcrx->in_protocol = cur_char;
            pcrx->in_state = PDDATA;
          } else {
            pcrx->in_protocol = (u_int)cur_char << 8;
            pcrx->in_state = PDPROTOCOL2;
          }
          break;
        case PDPROTOCOL2:               /* Process protocol field 2. */
          pcrx->in_protocol |= cur_char;
          pcrx->in_state = PDDATA;
          break;
        case PDDATA:                    /* Process data byte. */
          /* Make space to receive processed data. */
          if (pcrx->in_tail == NULL || pcrx->in_tail->len == PBUF_POOL_BUFSIZE) {
            if (pcrx->in_tail != NULL) {
              pcrx->in_tail->tot_len = pcrx->in_tail->len;
              if (pcrx->in_tail != pcrx->in_head) {
                pbuf_cat(pcrx->in_head, pcrx->in_tail);
                /* give up the in_tail reference now */
                pcrx->in_tail = NULL;
              }
            }
            /* If we haven't started a packet, we need a packet header. */
            next_pbuf = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
            if (next_pbuf == NULL) {
              /* No free buffers.  Drop the input packet and let the
               * higher layers deal with it.  Continue processing
               * the received pbuf chain in case a new packet starts. */
              PPPDEBUG(LOG_ERR, ("pppos_input_proc[%d]: NO FREE MBUFS!\n", pcb->num));
              LINK_STATS_INC(link.memerr);
              ppp_drop(pcrx);
              pcrx->in_state = PDSTART;  /* Wait for flag sequence. */
              break;
            }
            if (pcrx->in_head == NULL) {
              ((u8_t*)next_pbuf->payload)[0] = pcrx->in_protocol >> 8;
              ((u8_t*)next_pbuf->payload)[1] = pcrx->in_protocol & 0xFF;
              next_pbuf->len += sizeof(pcrx->in_protocol);

              pcrx->in_head = next_pbuf;
            }
            pcrx->in_tail = next_pbuf;
          }
          /* Load character into buffer. */
          ((u_char*)pcrx->in_tail->payload)[pcrx->in_tail->len++] = cur_char;
          break;
      }

      /* update the frame check sequence number. */
      pcrx->in_fcs = PPP_FCS(pcrx->in_fcs, cur_char);
    }
  } /* while (l-- > 0), all bytes processed */

  magic_randomize();
}

#if PPP_INPROC_MULTITHREADED
/* PPPoS input callback using one input pointer
 *   *arg is a pbuf chain of two chained pbuf, the first contains
 *   a pointer to the PPP PCB structure, the second contains the
 *   PPP payload
 */
static void pppos_input_callback(void *arg) {
  struct pbuf *hd, *pl;
  struct ppp_tcpip_callback_header *cbhead;
  ppp_pcb *pcb;

  hd = (struct pbuf *)arg;
  cbhead = (struct ppp_tcpip_callback_header *)hd->payload;
  pcb = cbhead->pcb;

  pl = hd->next;
  pbuf_free(hd);
  if(NULL == pl)
    goto drop;

  /* Dispatch the packet thereby consuming it. */
  ppp_input(pcb, pl);
  return;

drop:
  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(&pcb->netif);
  pbuf_free(pl);
  return;
}
#endif /* PPP_INPROC_MULTITHREADED */
#endif /* PPPOS_SUPPORT */

/* merge a pbuf chain into one pbuf */
struct pbuf * ppp_singlebuf(struct pbuf *p) {
  struct pbuf *q, *b;
  u_char *pl;

  if(p->tot_len == p->len) {
    return p;
  }

  q = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
  if(!q) {
    PPPDEBUG(LOG_ERR,
             ("ppp_singlebuf: unable to alloc new buf (%d)\n", p->tot_len));
    return p; /* live dangerously */
  }

  for(b = p, pl = q->payload; b != NULL; b = b->next) {
    MEMCPY(pl, b->payload, b->len);
    pl += b->len;
  }

  pbuf_free(p);

  return q;
}

#if PPPOE_SUPPORT
static void ppp_over_ethernet_link_status_cb(ppp_pcb *pcb, int state) {
  int pppoe_err_code = PPPERR_NONE;

  switch(state) {

    /* PPPoE link is established, starting PPP negotiation */
    case PPPOE_CB_STATE_UP:
      PPPDEBUG(LOG_INFO, ("ppp_over_ethernet_link_status_cb: unit %d: UP, connecting\n", pcb->num));
      ppp_start(pcb);
      return;

    /* PPPoE link normally down (i.e. asked to do so) */
    case PPPOE_CB_STATE_DOWN:
      PPPDEBUG(LOG_INFO, ("ppp_over_ethernet_link_status_cb: unit %d: DOWN, disconnected\n", pcb->num));
      pppoe_err_code = PPPERR_CONNECT;
      break;

    /* PPPoE link failed to setup (i.e. PADI/PADO timeout) */
    case PPPOE_CB_STATE_FAILED:
      PPPDEBUG(LOG_INFO, ("ppp_over_ethernet_link_status_cb: unit %d: FAILED, aborting\n", pcb->num));
      pppoe_err_code = PPPERR_OPEN;
      break;
  }

  /* Reconnect if persist mode is enabled */
  if(pcb->settings.persist) {
    if(pcb->link_status_cb)
      pcb->link_status_cb(pcb, pcb->err_code ? pcb->err_code : pppoe_err_code, pcb->link_status_ctx);
    new_phase(pcb, PHASE_INITIALIZE);
    pppoe_connect(pcb->pppoe_sc);
    return;
  }

  ppp_hup(pcb);
  ppp_stop(pcb);
  pppoe_destroy(&pcb->netif);
  if(pcb->link_status_cb)
    pcb->link_status_cb(pcb, pcb->err_code ? pcb->err_code : pppoe_err_code, pcb->link_status_ctx);
  ppp_destroy(pcb);
}
#endif /* PPPOE_SUPPORT */

void ppp_link_down(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_link_down: unit %d\n", pcb->num));

#if PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD
  ppp_receive_wakeup(pcb);
#endif /* PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD*/
}

void ppp_link_terminated(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated: unit %d\n", pcb->num));

#if PPPOE_SUPPORT
  if (pcb->ethif) {
    pppoe_disconnect(pcb->pppoe_sc);
  } else
#endif /* PPPOE_SUPPORT */
  {
#if PPPOS_SUPPORT
#if PPP_INPROC_OWNTHREAD
    ppp_receive_wakeup(pcb);
#endif /* PPP_INPROC_OWNTHREAD */

    PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated: unit %d: link_status_cb=%p err_code=%d\n", pcb->num, pcb->link_status_cb, pcb->err_code));
    if (pcb->link_status_cb) {
      pcb->link_status_cb(pcb, pcb->err_code ? pcb->err_code : PPPERR_PROTOCOL, pcb->link_status_ctx);
    }
    ppp_destroy(pcb);
#endif /* PPPOS_SUPPORT */
  }
  PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated: finished.\n"));
}

static void ppp_destroy(ppp_pcb *pcb) {

  PPPDEBUG(LOG_DEBUG, ("ppp_destroy: unit %d\n", pcb->num));
  memp_free(MEMP_PPP_PCB, pcb);
}

#if LWIP_NETIF_STATUS_CALLBACK
/** Set the status callback of a PPP's netif
 *
 * @param pd The PPP descriptor returned by pppOpen()
 * @param status_callback pointer to the status callback function
 *
 * @see netif_set_status_callback
 */
void
ppp_set_netif_statuscallback(ppp_pcb *pcb, netif_status_callback_fn status_callback)
{
  netif_set_status_callback(pcb->netif, status_callback);
}
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_LINK_CALLBACK
/** Set the link callback of a PPP's netif
 *
 * @param pd The PPP descriptor returned by pppOpen()
 * @param link_callback pointer to the link callback function
 *
 * @see netif_set_link_callback
 */
void
ppp_set_netif_linkcallback(ppp_pcb *pcb, netif_status_callback_fn link_callback)
{
  netif_set_link_callback(pcb->netif, link_callback);
}
#endif /* LWIP_NETIF_LINK_CALLBACK */

/************************************************************************
 * Functions called by various PPP subsystems to configure
 * the PPP interface or change the PPP phase.
 */

/*
 * new_phase - signal the start of a new phase of pppd's operation.
 */
void new_phase(ppp_pcb *pcb, int p) {
    pcb->phase = p;
#if PPP_NOTIFY
    /* The one willing notify support should add here the code to be notified of phase changes */
#endif /* PPP_NOTIFY */
}

/*
 * ppp_send_config - configure the transmit-side characteristics of
 * the ppp interface.
 */
int ppp_send_config(ppp_pcb *pcb, int mtu, u_int32_t accm, int pcomp, int accomp) {
#if PPPOS_SUPPORT
  int i;
#endif /* PPPOS_SUPPORT */

  /* pcb->mtu = mtu; -- set correctly with netif_set_mtu */
  pcb->pcomp = pcomp;
  pcb->accomp = accomp;

#if PPPOS_SUPPORT
  /* Load the ACCM bits for the 32 control codes. */
  for (i = 0; i < 32/8; i++) {
    pcb->out_accm[i] = (u_char)((accm >> (8 * i)) & 0xFF);
  }
#else
  LWIP_UNUSED_ARG(accm);
#endif /* PPPOS_SUPPORT */

#if PPPOS_SUPPORT
  PPPDEBUG(LOG_INFO, ("ppp_send_config[%d]: out_accm=%X %X %X %X\n",
            pcb->num,
            pcb->out_accm[0], pcb->out_accm[1], pcb->out_accm[2], pcb->out_accm[3]));
#else
  PPPDEBUG(LOG_INFO, ("ppp_send_config[%d]\n", pcb->num) );
#endif /* PPPOS_SUPPORT */
  return 0;
}

/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */
int ppp_recv_config(ppp_pcb *pcb, int mru, u_int32_t accm, int pcomp, int accomp) {
#if PPPOS_SUPPORT
  int i;
  SYS_ARCH_DECL_PROTECT(lev);
#endif /* PPPOS_SUPPORT */

  LWIP_UNUSED_ARG(accomp);
  LWIP_UNUSED_ARG(pcomp);
  LWIP_UNUSED_ARG(mru);

  /* Load the ACCM bits for the 32 control codes. */
#if PPPOS_SUPPORT
  SYS_ARCH_PROTECT(lev);
  for (i = 0; i < 32 / 8; i++) {
    /* @todo: does this work? ext_accm has been modified from pppd! */
    pcb->rx.in_accm[i] = (u_char)(accm >> (i * 8));
  }
  SYS_ARCH_UNPROTECT(lev);
#else
  LWIP_UNUSED_ARG(accm);
#endif /* PPPOS_SUPPORT */

#if PPPOS_SUPPORT
  PPPDEBUG(LOG_INFO, ("ppp_recv_config[%d]: in_accm=%X %X %X %X\n",
            pcb->num,
            pcb->rx.in_accm[0], pcb->rx.in_accm[1], pcb->rx.in_accm[2], pcb->rx.in_accm[3]));
#else
  PPPDEBUG(LOG_INFO, ("ppp_recv_config[%d]\n", pcb->num) );
#endif /* PPPOS_SUPPORT */
  return 0;
}


/*
 * sifaddr - Config the interface IP addresses and netmask.
 */
int sifaddr(ppp_pcb *pcb, u_int32_t our_adr, u_int32_t his_adr,
	     u_int32_t net_mask) {

  SMEMCPY(&pcb->addrs.our_ipaddr, &our_adr, sizeof(our_adr));
  SMEMCPY(&pcb->addrs.his_ipaddr, &his_adr, sizeof(his_adr));
  SMEMCPY(&pcb->addrs.netmask, &net_mask, sizeof(net_mask));
  return 1;
}


/********************************************************************
 *
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */
int cifaddr(ppp_pcb *pcb, u_int32_t our_adr, u_int32_t his_adr) {

  LWIP_UNUSED_ARG(our_adr);
  LWIP_UNUSED_ARG(his_adr);

  IP4_ADDR(&pcb->addrs.our_ipaddr, 0,0,0,0);
  IP4_ADDR(&pcb->addrs.his_ipaddr, 0,0,0,0);
  IP4_ADDR(&pcb->addrs.netmask, 255,255,255,255);
  return 1;
}


#if PPP_IPV6_SUPPORT
#define IN6_LLADDR_FROM_EUI64(ip6, eui64) do {			\
  memset(&ip6.addr, 0, sizeof(ip6_addr_t));	\
  ip6.addr[0] = PP_HTONL(0xfe800000);			\
  eui64_copy(eui64, ip6.addr[2]);			\
  } while (0)

/********************************************************************
 *
 * sif6addr - Config the interface with an IPv6 link-local address
 */
int sif6addr(ppp_pcb *pcb, eui64_t our_eui64, eui64_t his_eui64) {

  IN6_LLADDR_FROM_EUI64(pcb->addrs.our6_ipaddr, our_eui64);
  IN6_LLADDR_FROM_EUI64(pcb->addrs.his6_ipaddr, his_eui64);
  return 1;
}

/********************************************************************
 *
 * cif6addr - Remove IPv6 address from interface
 */
int cif6addr(ppp_pcb *pcb, eui64_t our_eui64, eui64_t his_eui64) {

  LWIP_UNUSED_ARG(our_eui64);
  LWIP_UNUSED_ARG(his_eui64);

  IP6_ADDR(&pcb->addrs.our6_ipaddr, 0, 0,0,0,0);
  IP6_ADDR(&pcb->addrs.his6_ipaddr, 0, 0,0,0,0);
  return 1;
}
#endif /* PPP_IPV6_SUPPORT */


/*
 * sdns - Config the DNS servers
 */
int sdns(ppp_pcb *pcb, u_int32_t ns1, u_int32_t ns2) {

  SMEMCPY(&pcb->addrs.dns1, &ns1, sizeof(ns1));
  SMEMCPY(&pcb->addrs.dns2, &ns2, sizeof(ns2));
  return 1;
}


/********************************************************************
 *
 * cdns - Clear the DNS servers
 */
int cdns(ppp_pcb *pcb, u_int32_t ns1, u_int32_t ns2) {

  LWIP_UNUSED_ARG(ns1);
  LWIP_UNUSED_ARG(ns2);

  IP4_ADDR(&pcb->addrs.dns1, 0,0,0,0);
  IP4_ADDR(&pcb->addrs.dns2, 0,0,0,0);
  return 1;
}


/*
 * sifup - Config the interface up and enable IP packets to pass.
 */
int sifup(ppp_pcb *pcb) {

  if(!pcb->if_up) {
    if(!netif_add(&pcb->netif, &pcb->addrs.our_ipaddr, &pcb->addrs.netmask,
                  &pcb->addrs.his_ipaddr, (void *)pcb, ppp_netif_init_cb, NULL)) {
      PPPDEBUG(LOG_ERR, ("sifup[%d]: netif_add failed\n", pcb->num));
      return 0;
    }
  } else {
    netif_set_addr(&pcb->netif, &pcb->addrs.our_ipaddr, &pcb->addrs.netmask,
                   &pcb->addrs.his_ipaddr);
  }

#if PPP_IPV6_SUPPORT
  ip6_addr_copy(pcb->netif.ip6_addr[0], pcb->addrs.our6_ipaddr);
  netif_ip6_addr_set_state(&pcb->netif, 0, IP6_ADDR_PREFERRED);
#endif /* PPP_IPV6_SUPPORT */

  netif_set_up(&pcb->netif);
  pcb->if_up = 1;
  pcb->err_code = PPPERR_NONE;

  PPPDEBUG(LOG_DEBUG, ("sifup: unit %d: err_code=%d\n", pcb->num, pcb->err_code));
  if (pcb->link_status_cb)
    pcb->link_status_cb(pcb, pcb->err_code, pcb->link_status_ctx);

  return 1;
}

/********************************************************************
 *
 * sifdown - Disable the indicated protocol and config the interface
 *	     down if there are no remaining protocols.
 */
int sifdown(ppp_pcb *pcb) {

  if(!pcb->if_up)
    return 1;

  pcb->if_up = 0;
  /* make sure the netif status callback is called */
  netif_set_down(&pcb->netif);
  netif_remove(&pcb->netif);
  PPPDEBUG(LOG_DEBUG, ("sifdown: unit %d: err_code=%d\n", pcb->num, pcb->err_code));
  if (pcb->link_status_cb)
    pcb->link_status_cb(pcb, PPPERR_CONNECT, pcb->link_status_ctx);

  return 1;
}

/*
 * sifnpmode - Set the mode for handling packets for a given NP.
 */
int sifnpmode(ppp_pcb *pcb, int proto, enum NPmode mode) {
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(proto);
  LWIP_UNUSED_ARG(mode);
  return 0;
}

/*
 * netif_set_mtu - set the MTU on the PPP network interface.
 */
void netif_set_mtu(ppp_pcb *pcb, int mtu) {

  pcb->mtu = mtu;
}

/*
 * netif_get_mtu - get PPP interface MTU
 */
int netif_get_mtu(ppp_pcb *pcb) {

  return pcb->mtu;
}

/********************************************************************
 *
 * sifdefaultroute - assign a default route through the address given.
 *
 * If the global default_rt_repl_rest flag is set, then this function
 * already replaced the original system defaultroute with some other
 * route and it should just replace the current defaultroute with
 * another one, without saving the current route. Use: demand mode,
 * when pppd sets first a defaultroute it it's temporary ppp0 addresses
 * and then changes the temporary addresses to the addresses for the real
 * ppp connection when it has come up.
 */
int sifdefaultroute(ppp_pcb *pcb, u_int32_t ouraddr, u_int32_t gateway, u8_t replace) {

  LWIP_UNUSED_ARG(ouraddr);
  LWIP_UNUSED_ARG(gateway);
  LWIP_UNUSED_ARG(replace);

  netif_set_default(&pcb->netif);
  return 1;
}

/********************************************************************
 *
 * cifdefaultroute - delete a default route through the address given.
 */
int cifdefaultroute(ppp_pcb *pcb, u_int32_t ouraddr, u_int32_t gateway) {

  LWIP_UNUSED_ARG(ouraddr);
  LWIP_UNUSED_ARG(gateway);

  netif_set_default(NULL);
  return 1;
}

/********************************************************************
 *
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int sifproxyarp(ppp_pcb *pcb, u_int32_t his_adr) {
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(his_adr);
  /* FIXME: do we really need that in IPCP ? */
  return 0;
}

/********************************************************************
 *
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */

int cifproxyarp(ppp_pcb *pcb, u_int32_t his_adr) {
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(his_adr);
  /* FIXME: do we really need that in IPCP ? */
  return 0;
}

/********************************************************************
 *
 * sifvjcomp - config tcp header compression
 */
int sifvjcomp(ppp_pcb *pcb, int vjcomp, int cidcomp, int maxcid) {

#if PPPOS_SUPPORT && VJ_SUPPORT
  pcb->vj_enabled = vjcomp;
  pcb->vj_comp.compressSlot = cidcomp;
  pcb->vj_comp.maxSlotIndex = maxcid;
  PPPDEBUG(LOG_INFO, ("sifvjcomp: VJ compress enable=%d slot=%d max slot=%d\n",
            vjcomp, cidcomp, maxcid));
#else /* PPPOS_SUPPORT && VJ_SUPPORT */
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(vjcomp);
  LWIP_UNUSED_ARG(cidcomp);
  LWIP_UNUSED_ARG(maxcid);
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */

  return 0;
}

#if PPP_IDLETIMELIMIT
/********************************************************************
 *
 * get_idle_time - return how long the link has been idle.
 */
int get_idle_time(ppp_pcb *pcb, struct ppp_idle *ip) {
    /* FIXME: add idle time support and make it optional */
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(ip);
    return 1;
}
#endif /* PPP_IDLETIMELIMIT */

/********************************************************************
 *
 * get_loop_output - get outgoing packets from the ppp device,
 * and detect when we want to bring the real link up.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 */
int get_loop_output(void) {
    /* FIXME: necessary for "demand", do we really need to support on-demand ? */
    return 0;
}

/********************************************************************
 *
 * Return user specified netmask, modified by any mask we might determine
 * for address `addr' (in network byte order).
 * Here we scan through the system's list of interfaces, looking for
 * any non-point-to-point interfaces which might appear to be on the same
 * network as `addr'.  If we find any, we OR in their netmask to the
 * user-specified netmask.
 */
u_int32_t get_mask(u_int32_t addr) {
#if 0
	u32_t mask, nmask;

  addr = htonl(addr);
  if (IP_CLASSA(addr)) { /* determine network mask for address class */
    nmask = IP_CLASSA_NET;
  } else if (IP_CLASSB(addr)) {
    nmask = IP_CLASSB_NET;
  } else {
    nmask = IP_CLASSC_NET;
  }

  /* class D nets are disallowed by bad_ip_adrs */
  mask = PP_HTONL(0xffffff00UL) | htonl(nmask);

  /* XXX
   * Scan through the system's network interfaces.
   * Get each netmask and OR them into our mask.
   */
  /* return mask; */
  return mask;
#endif
  LWIP_UNUSED_ARG(addr);
  return 0xFFFFFFFF;
}


#if PPP_PROTOCOLNAME
/* List of protocol names, to make our messages a little more informative. */
struct protocol_list {
    u_short	proto;
    const char	*name;
} protocol_list[] = {
    { 0x21,	"IP" },
    { 0x23,	"OSI Network Layer" },
    { 0x25,	"Xerox NS IDP" },
    { 0x27,	"DECnet Phase IV" },
    { 0x29,	"Appletalk" },
    { 0x2b,	"Novell IPX" },
    { 0x2d,	"VJ compressed TCP/IP" },
    { 0x2f,	"VJ uncompressed TCP/IP" },
    { 0x31,	"Bridging PDU" },
    { 0x33,	"Stream Protocol ST-II" },
    { 0x35,	"Banyan Vines" },
    { 0x39,	"AppleTalk EDDP" },
    { 0x3b,	"AppleTalk SmartBuffered" },
    { 0x3d,	"Multi-Link" },
    { 0x3f,	"NETBIOS Framing" },
    { 0x41,	"Cisco Systems" },
    { 0x43,	"Ascom Timeplex" },
    { 0x45,	"Fujitsu Link Backup and Load Balancing (LBLB)" },
    { 0x47,	"DCA Remote Lan" },
    { 0x49,	"Serial Data Transport Protocol (PPP-SDTP)" },
    { 0x4b,	"SNA over 802.2" },
    { 0x4d,	"SNA" },
    { 0x4f,	"IP6 Header Compression" },
    { 0x51,	"KNX Bridging Data" },
    { 0x53,	"Encryption" },
    { 0x55,	"Individual Link Encryption" },
    { 0x57,	"IPv6" },
    { 0x59,	"PPP Muxing" },
    { 0x5b,	"Vendor-Specific Network Protocol" },
    { 0x61,	"RTP IPHC Full Header" },
    { 0x63,	"RTP IPHC Compressed TCP" },
    { 0x65,	"RTP IPHC Compressed non-TCP" },
    { 0x67,	"RTP IPHC Compressed UDP 8" },
    { 0x69,	"RTP IPHC Compressed RTP 8" },
    { 0x6f,	"Stampede Bridging" },
    { 0x73,	"MP+" },
    { 0xc1,	"NTCITS IPI" },
    { 0xfb,	"single-link compression" },
    { 0xfd,	"Compressed Datagram" },
    { 0x0201,	"802.1d Hello Packets" },
    { 0x0203,	"IBM Source Routing BPDU" },
    { 0x0205,	"DEC LANBridge100 Spanning Tree" },
    { 0x0207,	"Cisco Discovery Protocol" },
    { 0x0209,	"Netcs Twin Routing" },
    { 0x020b,	"STP - Scheduled Transfer Protocol" },
    { 0x020d,	"EDP - Extreme Discovery Protocol" },
    { 0x0211,	"Optical Supervisory Channel Protocol" },
    { 0x0213,	"Optical Supervisory Channel Protocol" },
    { 0x0231,	"Luxcom" },
    { 0x0233,	"Sigma Network Systems" },
    { 0x0235,	"Apple Client Server Protocol" },
    { 0x0281,	"MPLS Unicast" },
    { 0x0283,	"MPLS Multicast" },
    { 0x0285,	"IEEE p1284.4 standard - data packets" },
    { 0x0287,	"ETSI TETRA Network Protocol Type 1" },
    { 0x0289,	"Multichannel Flow Treatment Protocol" },
    { 0x2063,	"RTP IPHC Compressed TCP No Delta" },
    { 0x2065,	"RTP IPHC Context State" },
    { 0x2067,	"RTP IPHC Compressed UDP 16" },
    { 0x2069,	"RTP IPHC Compressed RTP 16" },
    { 0x4001,	"Cray Communications Control Protocol" },
    { 0x4003,	"CDPD Mobile Network Registration Protocol" },
    { 0x4005,	"Expand accelerator protocol" },
    { 0x4007,	"ODSICP NCP" },
    { 0x4009,	"DOCSIS DLL" },
    { 0x400B,	"Cetacean Network Detection Protocol" },
    { 0x4021,	"Stacker LZS" },
    { 0x4023,	"RefTek Protocol" },
    { 0x4025,	"Fibre Channel" },
    { 0x4027,	"EMIT Protocols" },
    { 0x405b,	"Vendor-Specific Protocol (VSP)" },
    { 0x8021,	"Internet Protocol Control Protocol" },
    { 0x8023,	"OSI Network Layer Control Protocol" },
    { 0x8025,	"Xerox NS IDP Control Protocol" },
    { 0x8027,	"DECnet Phase IV Control Protocol" },
    { 0x8029,	"Appletalk Control Protocol" },
    { 0x802b,	"Novell IPX Control Protocol" },
    { 0x8031,	"Bridging NCP" },
    { 0x8033,	"Stream Protocol Control Protocol" },
    { 0x8035,	"Banyan Vines Control Protocol" },
    { 0x803d,	"Multi-Link Control Protocol" },
    { 0x803f,	"NETBIOS Framing Control Protocol" },
    { 0x8041,	"Cisco Systems Control Protocol" },
    { 0x8043,	"Ascom Timeplex" },
    { 0x8045,	"Fujitsu LBLB Control Protocol" },
    { 0x8047,	"DCA Remote Lan Network Control Protocol (RLNCP)" },
    { 0x8049,	"Serial Data Control Protocol (PPP-SDCP)" },
    { 0x804b,	"SNA over 802.2 Control Protocol" },
    { 0x804d,	"SNA Control Protocol" },
    { 0x804f,	"IP6 Header Compression Control Protocol" },
    { 0x8051,	"KNX Bridging Control Protocol" },
    { 0x8053,	"Encryption Control Protocol" },
    { 0x8055,	"Individual Link Encryption Control Protocol" },
    { 0x8057,	"IPv6 Control Protocol" },
    { 0x8059,	"PPP Muxing Control Protocol" },
    { 0x805b,	"Vendor-Specific Network Control Protocol (VSNCP)" },
    { 0x806f,	"Stampede Bridging Control Protocol" },
    { 0x8073,	"MP+ Control Protocol" },
    { 0x80c1,	"NTCITS IPI Control Protocol" },
    { 0x80fb,	"Single Link Compression Control Protocol" },
    { 0x80fd,	"Compression Control Protocol" },
    { 0x8207,	"Cisco Discovery Protocol Control" },
    { 0x8209,	"Netcs Twin Routing" },
    { 0x820b,	"STP - Control Protocol" },
    { 0x820d,	"EDPCP - Extreme Discovery Protocol Ctrl Prtcl" },
    { 0x8235,	"Apple Client Server Protocol Control" },
    { 0x8281,	"MPLSCP" },
    { 0x8285,	"IEEE p1284.4 standard - Protocol Control" },
    { 0x8287,	"ETSI TETRA TNP1 Control Protocol" },
    { 0x8289,	"Multichannel Flow Treatment Protocol" },
    { 0xc021,	"Link Control Protocol" },
    { 0xc023,	"Password Authentication Protocol" },
    { 0xc025,	"Link Quality Report" },
    { 0xc027,	"Shiva Password Authentication Protocol" },
    { 0xc029,	"CallBack Control Protocol (CBCP)" },
    { 0xc02b,	"BACP Bandwidth Allocation Control Protocol" },
    { 0xc02d,	"BAP" },
    { 0xc05b,	"Vendor-Specific Authentication Protocol (VSAP)" },
    { 0xc081,	"Container Control Protocol" },
    { 0xc223,	"Challenge Handshake Authentication Protocol" },
    { 0xc225,	"RSA Authentication Protocol" },
    { 0xc227,	"Extensible Authentication Protocol" },
    { 0xc229,	"Mitsubishi Security Info Exch Ptcl (SIEP)" },
    { 0xc26f,	"Stampede Bridging Authorization Protocol" },
    { 0xc281,	"Proprietary Authentication Protocol" },
    { 0xc283,	"Proprietary Authentication Protocol" },
    { 0xc481,	"Proprietary Node ID Authentication Protocol" },
    { 0,	NULL },
};

/*
 * protocol_name - find a name for a PPP protocol.
 */
const char * protocol_name(int proto) {
    struct protocol_list *lp;

    for (lp = protocol_list; lp->proto != 0; ++lp)
	if (proto == lp->proto)
	    return lp->name;
    return NULL;
}
#endif /* PPP_PROTOCOLNAME */

#if PPP_STATS_SUPPORT

/* ---- Note on PPP Stats support ----
 *
 * The one willing link stats support should add the get_ppp_stats()
 * to fetch statistics from lwIP.
 */

/*
 * reset_link_stats - "reset" stats when link goes up.
 */
void reset_link_stats(int u) {
    if (!get_ppp_stats(u, &old_link_stats))
	return;
    gettimeofday(&start_time, NULL);
}

/*
 * update_link_stats - get stats at link termination.
 */
void update_link_stats(int u) {

    struct timeval now;
    char numbuf[32];

    if (!get_ppp_stats(u, &link_stats)
	|| gettimeofday(&now, NULL) < 0)
	return;
    link_connect_time = now.tv_sec - start_time.tv_sec;
    link_stats_valid = 1;

    link_stats.bytes_in  -= old_link_stats.bytes_in;
    link_stats.bytes_out -= old_link_stats.bytes_out;
    link_stats.pkts_in   -= old_link_stats.pkts_in;
    link_stats.pkts_out  -= old_link_stats.pkts_out;
}

void print_link_stats() {
    /*
     * Print connect time and statistics.
     */
    if (link_stats_valid) {
       int t = (link_connect_time + 5) / 6;    /* 1/10ths of minutes */
       info("Connect time %d.%d minutes.", t/10, t%10);
       info("Sent %u bytes, received %u bytes.",
	    link_stats.bytes_out, link_stats.bytes_in);
       link_stats_valid = 0;
    }
}
#endif /* PPP_STATS_SUPPORT */

#endif /* PPP_SUPPORT */
