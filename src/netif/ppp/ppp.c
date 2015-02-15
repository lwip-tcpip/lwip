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

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/pppos.h"

#include "netif/ppp/fsm.h"
#include "netif/ppp/lcp.h"
#include "netif/ppp/ipcp.h"
#include "netif/ppp/magic.h"

#if PAP_SUPPORT
#include "netif/ppp/upap.h"
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
#include "netif/ppp/chap-new.h"
#endif /* CHAP_SUPPORT */
#if EAP_SUPPORT
#include "netif/ppp/eap.h"
#endif /* EAP_SUPPORT */
#if CCP_SUPPORT
#include "netif/ppp/ccp.h"
#endif /* EAP_SUPPORT */
#if ECP_SUPPORT
#include "netif/ppp/ecp.h"
#endif /* EAP_SUPPORT */
#if VJ_SUPPORT
#include "netif/ppp/vj.h"
#endif /* VJ_SUPPORT */
#if PPP_IPV6_SUPPORT
#include "netif/ppp/ipv6cp.h"
#endif /* PPP_IPV6_SUPPORT */

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
const struct protent* const protocols[] = {
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

/* Prototypes for procedures local to this file. */
static void ppp_do_open(void *arg);
static void ppp_stop(ppp_pcb *pcb);
static void ppp_hup(ppp_pcb *pcb);

static err_t ppp_netif_init_cb(struct netif *netif);
static err_t ppp_netif_output_ip4(struct netif *netif, struct pbuf *pb, ip_addr_t *ipaddr);
#if PPP_IPV6_SUPPORT
static err_t ppp_netif_output_ip6(struct netif *netif, struct pbuf *pb, ip6_addr_t *ipaddr);
#endif /* PPP_IPV6_SUPPORT */
static err_t ppp_netif_output(struct netif *netif, struct pbuf *pb, u_short protocol);

/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/

#if PPPOS_SUPPORT
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

void ppp_set_auth(ppp_pcb *pcb, u8_t authtype, const char *user, const char *passwd) {

#if PAP_SUPPORT
  if (authtype & PPPAUTHTYPE_PAP) {
    pcb->settings.refuse_pap = 0;
  } else {
    pcb->settings.refuse_pap = 1;
  }
#endif /* PAP_SUPPORT */

#if CHAP_SUPPORT
  if (authtype & PPPAUTHTYPE_CHAP) {
    pcb->settings.refuse_chap = 0;
  } else {
    pcb->settings.refuse_chap = 1;
  }
#if MSCHAP_SUPPORT
  if (authtype & PPPAUTHTYPE_MSCHAP) {
    pcb->settings.refuse_mschap = 0;
    pcb->settings.refuse_mschap_v2 = 0;
  } else {
    pcb->settings.refuse_mschap = 1;
    pcb->settings.refuse_mschap_v2 = 1;
  }
#endif /* MSCHAP_SUPPORT */
#endif /* CHAP_SUPPORT */

#if EAP_SUPPORT
  if (authtype & PPPAUTHTYPE_EAP) {
    pcb->settings.refuse_eap = 0;
  } else {
    pcb->settings.refuse_eap = 1;
  }
#endif /* EAP_SUPPORT */

  if (user) {
    pcb->settings.user = user;
  }

  if (passwd) {
    pcb->settings.passwd = passwd;
  }
}

#if PPP_NOTIFY_PHASE
void ppp_set_notify_phase_callback(ppp_pcb *pcb, ppp_notify_phase_cb_fn notify_phase_cb) {
	pcb->notify_phase_cb = notify_phase_cb;
	notify_phase_cb(pcb, pcb->phase, pcb->ctx_cb);
}
#endif /* PPP_NOTIFY_PHASE */

/*
 * Open a PPP connection.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * Holdoff is the time to wait (in seconds) before initiating
 * the connection.
 */
int ppp_open(ppp_pcb *pcb, u16_t holdoff) {
  if (pcb->phase != PPP_PHASE_DEAD) {
    return PPPERR_PARAM;
  }

  PPPDEBUG(LOG_DEBUG, ("ppp_open() called, holdoff=%d\n", holdoff));

  if (holdoff == 0) {
    ppp_do_open(pcb);
    return PPPERR_NONE;
  }

  new_phase(pcb, PPP_PHASE_HOLDOFF);
  sys_timeout((u32_t)(holdoff*1000), ppp_do_open, pcb);
  return PPPERR_NONE;
}

/*
 * Initiate the end of a PPP connection.
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success, an error code on failure.
 */
int
ppp_close(ppp_pcb *pcb)
{
  int st = 0;

  pcb->err_code = PPPERR_USER;

  /* dead phase, nothing to do, call the status callback to be consistent */
  if (pcb->phase == PPP_PHASE_DEAD) {
    pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
    return PPPERR_NONE;
  }

  /* holdoff phase, cancel the reconnection and call the status callback */
  if (pcb->phase == PPP_PHASE_HOLDOFF) {
    sys_untimeout(ppp_do_open, pcb);
    pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
    return PPPERR_NONE;
  }

  PPPDEBUG(LOG_DEBUG, ("ppp_close() called\n"));

  /* Disconnect */
  PPPDEBUG(LOG_DEBUG, ("ppp_close: unit %d kill_link -> ppp_stop\n", pcb->num));
  /* This will leave us at PPP_PHASE_DEAD. */
  ppp_stop(pcb);

  return st;
}

/* This function is called when carrier is lost on the PPP channel. */
void
ppp_sighup(ppp_pcb *pcb)
{
  PPPDEBUG(LOG_DEBUG, ("ppp_sighup: unit %d sig_hup -> ppp_hup\n", pcb->num));
  ppp_hup(pcb);
}

/*
 * Release the control block.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * You must use ppp_close() before if you wish to terminate
 * an established PPP session.
 *
 * Return 0 on success, an error code on failure.
 */
int ppp_free(ppp_pcb *pcb) {
  if (pcb->phase != PPP_PHASE_DEAD) {
    return PPPERR_PARAM;
  }

  PPPDEBUG(LOG_DEBUG, ("ppp_free: unit %d\n", pcb->num));

  netif_remove(pcb->netif);

  pcb->link_command_cb(pcb->link_ctx_cb, PPP_LINK_COMMAND_FREE);

  memp_free(MEMP_PPP_PCB, pcb);
  return 0;
}




/************************************/
/*** PRIVATE FUNCTION DEFINITIONS ***/
/************************************/

/* Initialize the PPP subsystem. */
int ppp_init(void) {

    /*
     * Initialize magic number generator now so that protocols may
     * use magic numbers in initialization.
     */
    magic_init();

    return 0;
}

/*
 * Create a new PPP control block.
 *
 * This initializes the PPP control block but does not
 * attempt to negotiate the LCP session.
 *
 * Return a new PPP connection control block pointer
 * on success or a null pointer on failure.
 */
ppp_pcb *ppp_new(struct netif *pppif, ppp_link_status_cb_fn link_status_cb, void *ctx_cb) {
  ppp_pcb *pcb;

  /* PPP is single-threaded: without a callback,
   * there is no way to know when the link is up. */
  if (link_status_cb == NULL) {
    return NULL;
  }

  pcb = (ppp_pcb*)memp_malloc(MEMP_PPP_PCB);
  if (pcb == NULL) {
    return NULL;
  }

  memset(pcb, 0, sizeof(ppp_pcb));
#if PPP_DEBUG
  pcb->num = ppp_num++;
#endif /* PPP_DEBUG */

  /* default configuration */
  pcb->settings.usepeerdns = 1;

#if PAP_SUPPORT
  pcb->settings.pap_timeout_time = UPAP_DEFTIMEOUT;
  pcb->settings.pap_max_transmits = UPAP_DEFTRANSMITS;
#if PPP_SERVER
  pcb->settings.pap_req_timeout = UPAP_DEFREQTIME;
#endif /* PPP_SERVER */
#endif /* PAP_SUPPORT */

#if CHAP_SUPPORT
  pcb->settings.chap_timeout_time = CHAP_DEFTIMEOUT;
  pcb->settings.chap_max_transmits = CHAP_DEFTRANSMITS;
#if PPP_SERVER
  pcb->settings.chap_rechallenge_time = CHAP_DEFREQTIME;
#endif /* PPP_SERVER */
#endif /* CHAP_SUPPPORT */

#if EAP_SUPPORT
  pcb->settings.eap_req_time = EAP_DEFREQTIME;
  pcb->settings.eap_allow_req = EAP_DEFALLOWREQ;
#if PPP_SERVER
  pcb->settings.eap_timeout_time = EAP_DEFTIMEOUT;
  pcb->settings.eap_max_transmits = EAP_DEFTRANSMITS;
#endif /* PPP_SERVER */
#endif /* EAP_SUPPORT */

  pcb->settings.lcp_loopbackfail = LCP_DEFLOOPBACKFAIL;
  pcb->settings.lcp_echo_interval = LCP_ECHOINTERVAL;
  pcb->settings.lcp_echo_fails = LCP_MAXECHOFAILS;

  pcb->settings.fsm_timeout_time = FSM_DEFTIMEOUT;
  pcb->settings.fsm_max_conf_req_transmits = FSM_DEFMAXCONFREQS;
  pcb->settings.fsm_max_term_transmits = FSM_DEFMAXTERMREQS;
  pcb->settings.fsm_max_nak_loops = FSM_DEFMAXNAKLOOPS;

  pcb->netif = pppif;
  if (!netif_add(pcb->netif, &pcb->addrs.our_ipaddr, &pcb->addrs.netmask,
                 &pcb->addrs.his_ipaddr, (void *)pcb, ppp_netif_init_cb, NULL)) {
    memp_free(MEMP_PPP_PCB, pcb);
    PPPDEBUG(LOG_ERR, ("ppp_new[%d]: netif_add failed\n", pcb->num));
    return NULL;
  }

  pcb->link_status_cb = link_status_cb;
  pcb->ctx_cb = ctx_cb;
  new_phase(pcb, PPP_PHASE_DEAD);
  return pcb;
}

/* Set a PPP PCB to its initial state */
void ppp_clear(ppp_pcb *pcb) {
  const struct protent *protp;
  int i;

  LWIP_ASSERT("pcb->phase == PPP_PHASE_DEAD || pcb->phase == PPP_PHASE_HOLDOFF", pcb->phase == PPP_PHASE_DEAD || pcb->phase == PPP_PHASE_HOLDOFF);

#if PPP_STATS_SUPPORT
  link_stats_valid = 0;
#endif /* PPP_STATS_SUPPORT */

  memset(&pcb->phase, 0, sizeof(ppp_pcb) - ( (char*)&((ppp_pcb*)0)->phase - (char*)0 ) );
  IP4_ADDR(&pcb->addrs.netmask, 255,255,255,255);

  /*
   * Initialize each protocol.
   */
  for (i = 0; (protp = protocols[i]) != NULL; ++i) {
      (*protp->init)(pcb);
  }

  new_phase(pcb, PPP_PHASE_INITIALIZE);
}

void ppp_link_set_callbacks(ppp_pcb *pcb, link_command_cb_fn command, link_write_cb_fn write, link_netif_output_cb_fn netif_output, void *ctx) {
  pcb->link_command_cb = command;
  pcb->link_write_cb = write;
  pcb->link_netif_output_cb = netif_output;
  pcb->link_ctx_cb = ctx;
}

static void ppp_do_open(void *arg) {
  ppp_pcb *pcb = (ppp_pcb*)arg;

  LWIP_ASSERT("pcb->phase == PPP_PHASE_DEAD || pcb->phase == PPP_PHASE_HOLDOFF", pcb->phase == PPP_PHASE_DEAD || pcb->phase == PPP_PHASE_HOLDOFF);

  pcb->link_command_cb(pcb->link_ctx_cb, PPP_LINK_COMMAND_CONNECT);
}

/** Initiate LCP open request */
void ppp_start(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_start: unit %d\n", pcb->num));
  lcp_open(pcb); /* Start protocol */
  lcp_lowerup(pcb);
  PPPDEBUG(LOG_DEBUG, ("ppp_start: finished\n"));
}

/** Called when link failed to setup */
void ppp_link_failed(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_failed: unit %d\n", pcb->num));
  new_phase(pcb, PPP_PHASE_DEAD);
  pcb->link_status_cb(pcb, PPPERR_OPEN, pcb->ctx_cb);
}

/** Called when link is normally down (i.e. it was asked to end) */
void ppp_link_end(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_end: unit %d\n", pcb->num));
  pcb->link_status_cb(pcb, PPPERR_CONNECT, pcb->ctx_cb);
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
  ppp_dump_packet("rcvd", (unsigned char *)pb->payload, pb->len);
#endif /* PRINTPKT_SUPPORT */

  if(pbuf_header(pb, -(s16_t)sizeof(protocol))) {
    LWIP_ASSERT("pbuf_header failed\n", 0);
    goto drop;
  }

  LINK_STATS_INC(link.recv);
  snmp_inc_ifinucastpkts(pcb->netif);
  snmp_add_ifinoctets(pcb->netif, pb->tot_len);

  /*
   * Toss all non-LCP packets unless LCP is OPEN.
   */
  if (protocol != PPP_LCP && pcb->lcp_fsm.state != PPP_FSM_OPENED) {
	ppp_dbglog("Discarded non-LCP packet when LCP not open");
	goto drop;
  }

  /*
   * Until we get past the authentication phase, toss all packets
   * except LCP, LQR and authentication packets.
   */
  if (pcb->phase <= PPP_PHASE_AUTHENTICATE
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
	ppp_dbglog("discarding proto 0x%x in phase %d",
		   protocol, pcb->phase);
	goto drop;
  }

  /* FIXME: should we write protent to do that ? */

  switch(protocol) {

#if VJ_SUPPORT
    case PPP_VJC_COMP:      /* VJ compressed TCP */
      if (pppos_vjc_comp(pcb, pb) >= 0) {
        return;
      }
      break;

    case PPP_VJC_UNCOMP:    /* VJ uncompressed TCP */
      if (pppos_vjc_uncomp(pcb, pb) >= 0) {
        return;
      }
      break;
#endif /* VJ_SUPPORT */

    case PPP_IP:            /* Internet Protocol */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: ip in pbuf len=%d\n", pcb->num, pb->len));
      ip_input(pb, pcb->netif);
      return;

#if PPP_IPV6_SUPPORT
    case PPP_IPV6:          /* Internet Protocol Version 6 */
      PPPDEBUG(LOG_INFO, ("ppp_input[%d]: ip6 in pbuf len=%d\n", pcb->num, pb->len));
      ip6_input(pb, pcb->netif);
      return;
#endif /* PPP_IPV6_SUPPORT */

    default: {

      int i;
      const struct protent *protp;
      /*
       * Upcall the proper protocol input routine.
       */
      for (i = 0; (protp = protocols[i]) != NULL; ++i) {
        if (protp->protocol == protocol && protp->enabled_flag) {
          pb = ppp_singlebuf(pb);
          (*protp->input)(pcb, (u_char*)pb->payload, pb->len);
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
    if (pname != NULL) {
      ppp_warn("Unsupported protocol '%s' (0x%x) received", pname, protocol);
    } else
#endif /* PPP_PROTOCOLNAME */
      ppp_warn("Unsupported protocol 0x%x received", protocol);
#endif /* PPP_DEBUG */
      if (pbuf_header(pb, (s16_t)sizeof(protocol))) {
        LWIP_ASSERT("pbuf_header failed\n", 0);
        goto drop;
      }
      lcp_sprotrej(pcb, (u_char*)pb->payload, pb->len);
    }
    break;
  }

drop:
  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(pcb->netif);

out:
  pbuf_free(pb);
  magic_randomize();
  return;
}

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
  if (!pcb->if_up) {
    PPPDEBUG(LOG_ERR, ("ppp_netif_output[%d]: link not up\n", pcb->num));
    LINK_STATS_INC(link.rterr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_RTE;
  }

  return pcb->link_netif_output_cb(pcb->link_ctx_cb, pb, protocol);
}

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
        pcb->err_code = (u8_t)(*(int *)arg);
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

#if 0/*PPPOS_SUPPORT*/
    case PPPCTLG_FD:            /* Get the fd associated with the ppp */
      if (arg) {
        *(sio_fd_t *)arg = pcb->fd;
        return PPPERR_NONE;
      }
      return PPPERR_PARAM;
      break;
#endif /* PPPOS_SUPPORT */

    default:
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
#if PRINTPKT_SUPPORT
  ppp_dump_packet("sent", (unsigned char *)p->payload+2, p->len-2);
#endif /* PRINTPKT_SUPPORT */
  return pcb->link_write_cb(pcb->link_ctx_cb, p);
}

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

  for(b = p, pl = (u_char*)q->payload; b != NULL; b = b->next) {
    MEMCPY(pl, b->payload, b->len);
    pl += b->len;
  }

  pbuf_free(p);

  return q;
}

void ppp_link_down(ppp_pcb *pcb) {
  LWIP_UNUSED_ARG(pcb); /* necessary if PPPDEBUG is defined to an empty function */
  PPPDEBUG(LOG_DEBUG, ("ppp_link_down: unit %d\n", pcb->num));
}

void ppp_link_terminated(ppp_pcb *pcb) {
  PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated: unit %d\n", pcb->num));
  pcb->link_command_cb(pcb->link_ctx_cb, PPP_LINK_COMMAND_DISCONNECT);
  PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated: finished.\n"));
}

#if LWIP_NETIF_STATUS_CALLBACK
/** Set the status callback of a PPP's netif
 *
 * @param pcb The PPP descriptor returned by ppp_new()
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
 * @param pcb The PPP descriptor returned by ppp_new()
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
  PPPDEBUG(LOG_DEBUG, ("ppp phase changed: unit %d: phase=%d\n", pcb->num, pcb->phase));
#if PPP_NOTIFY_PHASE
  if(NULL != pcb->notify_phase_cb) {
	pcb->notify_phase_cb(pcb, p, pcb->ctx_cb);
  }
#endif /* PPP_NOTIFY_PHASE */
}

/*
 * ppp_send_config - configure the transmit-side characteristics of
 * the ppp interface.
 */
int ppp_send_config(ppp_pcb *pcb, int mtu, u32_t accm, int pcomp, int accomp) {
#if PPPOS_SUPPORT
  int i;
#endif /* PPPOS_SUPPORT */
  LWIP_UNUSED_ARG(mtu);

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
int ppp_recv_config(ppp_pcb *pcb, int mru, u32_t accm, int pcomp, int accomp) {
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
int sifaddr(ppp_pcb *pcb, u32_t our_adr, u32_t his_adr,
	     u32_t net_mask) {

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
int cifaddr(ppp_pcb *pcb, u32_t our_adr, u32_t his_adr) {

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
int sdns(ppp_pcb *pcb, u32_t ns1, u32_t ns2) {

  SMEMCPY(&pcb->addrs.dns1, &ns1, sizeof(ns1));
  SMEMCPY(&pcb->addrs.dns2, &ns2, sizeof(ns2));
  return 1;
}


/********************************************************************
 *
 * cdns - Clear the DNS servers
 */
int cdns(ppp_pcb *pcb, u32_t ns1, u32_t ns2) {

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

  netif_set_addr(pcb->netif, &pcb->addrs.our_ipaddr, &pcb->addrs.netmask,
                 &pcb->addrs.his_ipaddr);

  netif_set_up(pcb->netif);
  pcb->if_up = 1;
  pcb->err_code = PPPERR_NONE;

  PPPDEBUG(LOG_DEBUG, ("sifup: unit %d: err_code=%d\n", pcb->num, pcb->err_code));
  pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
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

  if (1
#if PPP_IPV6_SUPPORT
   /* set the interface down if IPv6 is down as well */
   && !pcb->if6_up
#endif /* PPP_IPV6_SUPPORT */
  ) {
    /* make sure the netif status callback is called */
    netif_set_down(pcb->netif);
  }
  PPPDEBUG(LOG_DEBUG, ("sifdown: unit %d: err_code=%d\n", pcb->num, pcb->err_code));
  return 1;
}

#if PPP_IPV6_SUPPORT
/*
 * sif6up - Config the interface up and enable IPv6 packets to pass.
 */
int sif6up(ppp_pcb *pcb) {

  ip6_addr_copy(pcb->netif->ip6_addr[0], pcb->addrs.our6_ipaddr);
  netif_ip6_addr_set_state(pcb->netif, 0, IP6_ADDR_PREFERRED);

  netif_set_up(pcb->netif);
  pcb->if6_up = 1;
  pcb->err_code = PPPERR_NONE;

  PPPDEBUG(LOG_DEBUG, ("sif6up: unit %d: err_code=%d\n", pcb->num, pcb->err_code));
  pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
  return 1;
}

/********************************************************************
 *
 * sif6down - Disable the indicated protocol and config the interface
 *	      down if there are no remaining protocols.
 */
int sif6down(ppp_pcb *pcb) {

  if(!pcb->if6_up)
    return 1;

  pcb->if6_up = 0;
  /* set the interface down if IPv4 is down as well */
  if (!pcb->if_up) {
    /* make sure the netif status callback is called */
    netif_set_down(pcb->netif);
  }
  PPPDEBUG(LOG_DEBUG, ("sif6down: unit %d: err_code=%d\n", pcb->num, pcb->err_code));
  return 1;
}
#endif /* PPP_IPV6_SUPPORT */

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

  pcb->netif->mtu = mtu;
}

/*
 * netif_get_mtu - get PPP interface MTU
 */
int netif_get_mtu(ppp_pcb *pcb) {

  return pcb->netif->mtu;
}

/********************************************************************
 *
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int sifproxyarp(ppp_pcb *pcb, u32_t his_adr) {
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(his_adr);
  /* FIXME: do we really need that in IPCP ? */
  return 0;
}

/********************************************************************
 *
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */

int cifproxyarp(ppp_pcb *pcb, u32_t his_adr) {
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
#if VJ_SUPPORT
  pppos_vjc_config(pcb, vjcomp, cidcomp, maxcid);
#else /* VJ_SUPPORT */
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(vjcomp);
  LWIP_UNUSED_ARG(cidcomp);
  LWIP_UNUSED_ARG(maxcid);
#endif /* VJ_SUPPORT */
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
u32_t get_mask(u32_t addr) {
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
