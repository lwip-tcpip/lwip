/*
 * pppmy.c
 *
 *  Created on: May 12, 2012
 *      Author: gradator
 */

#include "lwip/opt.h"

#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/sys.h"

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"

#include "pppdebug.h"
#include "pppmy.h"

#if PPPOE_SUPPORT
#include "netif/ppp_oe.h"
#endif /* PPPOE_SUPPORT */

/* PPP packet parser states.  Current state indicates operation yet to be
 * completed. */
typedef enum {
  PDIDLE = 0,  /* Idle state - waiting. */
  PDSTART,     /* Process start flag. */
  PDADDRESS,   /* Process address field. */
  PDCONTROL,   /* Process control field. */
  PDPROTOCOL1, /* Process protocol field 1. */
  PDPROTOCOL2, /* Process protocol field 2. */
  PDDATA       /* Process data byte. */
} PPPDevStates;

typedef struct PPPControlRx_s {
  /** unit number / ppp descriptor */
  int pd;
  /** the rx file descriptor */
#if PPPOS_SUPPORT		/* FIXME: enable sio_fd_t back */
  sio_fd_t fd;
#endif
#if PPPOE_SUPPORT
  int fd;
#endif
  /** receive buffer - encoded data is stored here */
#if PPP_INPROC_OWNTHREAD
  u_char rxbuf[PPPOS_RX_BUFSIZE];
#endif /* PPP_INPROC_OWNTHREAD */

  /* The input packet. */
  struct pbuf *inHead, *inTail;

#if PPPOS_SUPPORT
  u16_t inProtocol;             /* The input protocol code. */
  u16_t inFCS;                  /* Input Frame Check Sequence value. */
#endif /* PPPOS_SUPPORT */
  PPPDevStates inState;         /* The input process state. */
  char inEscaped;               /* Escape next character. */
  ext_accm inACCM;              /* Async-Ctl-Char-Map for input. */
} PPPControlRx;

/*
 * PPP interface control block.
 */
typedef struct PPPControl_s {
  PPPControlRx rx;
  char openFlag;                /* True when in use. */
#if PPPOE_SUPPORT
  struct netif *ethif;
  struct pppoe_softc *pppoe_sc;
#endif /* PPPOE_SUPPORT */
  int  if_up;                   /* True when the interface is up. */
  int  errCode;                 /* Code indicating why interface is down. */
#if PPPOS_SUPPORT
  sio_fd_t fd;                  /* File device ID of port. */
#endif /* PPPOS_SUPPORT */
  u16_t mtu;                    /* Peer's mru */
  int  pcomp;                   /* Does peer accept protocol compression? */
  int  accomp;                  /* Does peer accept addr/ctl compression? */
  u_long lastXMit;              /* Time of last transmission. */
  ext_accm outACCM;             /* Async-Ctl-Char-Map for output. */
#if PPPOS_SUPPORT && VJ_SUPPORT
  int  vjEnabled;               /* Flag indicating VJ compression enabled. */
  struct vjcompress vjComp;     /* Van Jacobson compression header. */
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */

  struct netif netif;

  struct ppp_addrs addrs;

  void (*linkStatusCB)(void *ctx, int errCode, void *arg);
  void *linkStatusCtx;

} PPPControl;

/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
static PPPControl pppControl[NUM_PPP]; /* The PPP interface control blocks. */


struct pbuf * pppSingleBuf(struct pbuf *p) {
  struct pbuf *q, *b;
  u_char *pl;

  if(p->tot_len == p->len) {
    return p;
  }

  q = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
  if(!q) {
    PPPDEBUG(LOG_ERR,
             ("pppSingleBuf: unable to alloc new buf (%d)\n", p->tot_len));
    return p; /* live dangerously */
  }

  for(b = p, pl = q->payload; b != NULL; b = b->next) {
    MEMCPY(pl, b->payload, b->len);
    pl += b->len;
  }

  pbuf_free(p);

  return q;
}

/** Input helper struct, must be packed since it is stored to pbuf->payload,
 * which might be unaligned.
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct pppInputHeader {
  PACK_STRUCT_FIELD(int unit);
  PACK_STRUCT_FIELD(u16_t proto);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/** Initiate LCP open request */
static void pppStart(int pd)
{
  PPPDEBUG(LOG_DEBUG, ("pppStart: unit %d\n", pd));
  lcp_open(pd); /* Start protocol */
  lcp_lowerup(pd);
  PPPDEBUG(LOG_DEBUG, ("pppStart: finished\n"));
}


/*
 * Pass the processed input packet to the appropriate handler.
 * This function and all handlers run in the context of the tcpip_thread
 */

/* FIXME: maybe we should pass in two arguments pppInputHeader and payload
 * this is totally stupid to make room for it and then modify the packet directly
 * or it is used in output ?  have to find out...
 */
static void ppp_input(void *arg) {
  struct pbuf *nb = (struct pbuf *)arg;
  u16_t protocol;
  int pd;

  pd = ((struct pppInputHeader *)nb->payload)->unit;
  protocol = ((struct pppInputHeader *)nb->payload)->proto;
  printf("ppp_input() called, pd = %d, protocol = 0x%x\n", pd, protocol);

  if(pbuf_header(nb, -(int)sizeof(struct pppInputHeader))) {
    LWIP_ASSERT("pbuf_header failed\n", 0);
    goto drop;
  }

  LINK_STATS_INC(link.recv);
  snmp_inc_ifinucastpkts(&pppControl[pd].netif);
  snmp_add_ifinoctets(&pppControl[pd].netif, nb->tot_len);

  /*
   * Toss all non-LCP packets unless LCP is OPEN.
   */
  if (protocol != PPP_LCP && lcp_fsm[0].state != OPENED) {
	dbglog("Discarded non-LCP packet when LCP not open");
	return;
  }

  /* FIXME: add a phase per connection */

  /*
   * Until we get past the authentication phase, toss all packets
   * except LCP, LQR and authentication packets.
   */
  if (phase <= PHASE_AUTHENTICATE
	&& !(protocol == PPP_LCP || protocol == PPP_LQR
	     || protocol == PPP_PAP || protocol == PPP_CHAP ||
		protocol == PPP_EAP)) {
	dbglog("discarding proto 0x%x in phase %d",
		   protocol, phase);
	return;
  }

  /* FIXME: should we write protent to do that ? */

  switch(protocol) {
    case PPP_VJC_COMP:      /* VJ compressed TCP */
#if PPPOS_SUPPORT && VJ_SUPPORT
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: vj_comp in pbuf len=%d\n", pd, nb->len));
      /*
       * Clip off the VJ header and prepend the rebuilt TCP/IP header and
       * pass the result to IP.
       */
      if ((vj_uncompress_tcp(&nb, &pppControl[pd].vjComp) >= 0) && (pppControl[pd].netif.input)) {
        pppControl[pd].netif.input(nb, &pppControl[pd].netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("pppInput[%d]: Dropping VJ compressed\n", pd));
#else  /* PPPOS_SUPPORT && VJ_SUPPORT */
      /* No handler for this protocol so drop the packet. */
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: drop VJ Comp in %d:%s\n", pd, nb->len, nb->payload));
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */
      break;

    case PPP_VJC_UNCOMP:    /* VJ uncompressed TCP */
#if PPPOS_SUPPORT && VJ_SUPPORT
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: vj_un in pbuf len=%d\n", pd, nb->len));
      /*
       * Process the TCP/IP header for VJ header compression and then pass
       * the packet to IP.
       */
      if ((vj_uncompress_uncomp(nb, &pppControl[pd].vjComp) >= 0) && pppControl[pd].netif.input) {
        pppControl[pd].netif.input(nb, &pppControl[pd].netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("pppInput[%d]: Dropping VJ uncompressed\n", pd));
#else  /* PPPOS_SUPPORT && VJ_SUPPORT */
      /* No handler for this protocol so drop the packet. */
      PPPDEBUG(LOG_INFO,
               ("pppInput[%d]: drop VJ UnComp in %d:.*H\n",
                pd, nb->len, LWIP_MIN(nb->len * 2, 40), nb->payload));
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */
      break;

    case PPP_IP:            /* Internet Protocol */
	    printf("IP packet received\n");
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: ip in pbuf len=%d\n", pd, nb->len));
      if (pppControl[pd].netif.input) {
        pppControl[pd].netif.input(nb, &pppControl[pd].netif);
        return;
      }
      break;

    default: {

	  int i;
	  struct protent *protp;
	  /*
	   * Upcall the proper protocol input routine.
	   */
	  for (i = 0; (protp = protocols[i]) != NULL; ++i) {
		if (protp->protocol == protocol && protp->enabled_flag) {
		    (*protp->input)(pd, nb->payload, nb->len);
		    goto out;
		}
#if 0 /* Unused ? */
		if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag
		    && protp->datainput != NULL) {
		    (*protp->datainput)(pd, nb->payload, nb->len);
		    goto out;
		}
#endif /* Unused */
	  }

	  if (debug) {
		const char *pname = protocol_name(protocol);
		if (pname != NULL)
		    warn("Unsupported protocol '%s' (0x%x) received", pname, protocol);
		else
		    warn("Unsupported protocol 0x%x received", protocol);
	  }
	  if (pbuf_header(nb, sizeof(protocol))) {
	        LWIP_ASSERT("pbuf_header failed\n", 0);
	        goto drop;
	  }
	  lcp_sprotrej(pd, nb->payload, nb->len);
    }
    break;
 }

drop:
  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(&pppControl[pd].netif);

out:
  pbuf_free(nb);
  return;

 #if 0
  /*
   * Toss all non-LCP packets unless LCP is OPEN.
   * Until we get past the authentication phase, toss all packets
   * except LCP, LQR and authentication packets.
   */
  if((lcp_phase[pd] <= PHASE_AUTHENTICATE) && (protocol != PPP_LCP)) {
    if(!((protocol == PPP_LQR) || (protocol == PPP_PAP) || (protocol == PPP_CHAP)) ||
        (lcp_phase[pd] != PHASE_AUTHENTICATE)) {
      PPPDEBUG(LOG_INFO, ("pppInput: discarding proto 0x%"X16_F" in phase %d\n", protocol, lcp_phase[pd]));
      goto drop;
    }
  }

  switch(protocol) {
    case PPP_VJC_COMP:      /* VJ compressed TCP */
#if PPPOS_SUPPORT && VJ_SUPPORT
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: vj_comp in pbuf len=%d\n", pd, nb->len));
      /*
       * Clip off the VJ header and prepend the rebuilt TCP/IP header and
       * pass the result to IP.
       */
      if ((vj_uncompress_tcp(&nb, &pppControl[pd].vjComp) >= 0) && (pppControl[pd].netif.input)) {
        pppControl[pd].netif.input(nb, &pppControl[pd].netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("pppInput[%d]: Dropping VJ compressed\n", pd));
#else  /* PPPOS_SUPPORT && VJ_SUPPORT */
      /* No handler for this protocol so drop the packet. */
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: drop VJ Comp in %d:%s\n", pd, nb->len, nb->payload));
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */
      break;

    case PPP_VJC_UNCOMP:    /* VJ uncompressed TCP */
#if PPPOS_SUPPORT && VJ_SUPPORT
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: vj_un in pbuf len=%d\n", pd, nb->len));
      /*
       * Process the TCP/IP header for VJ header compression and then pass
       * the packet to IP.
       */
      if ((vj_uncompress_uncomp(nb, &pppControl[pd].vjComp) >= 0) && pppControl[pd].netif.input) {
        pppControl[pd].netif.input(nb, &pppControl[pd].netif);
        return;
      }
      /* Something's wrong so drop it. */
      PPPDEBUG(LOG_WARNING, ("pppInput[%d]: Dropping VJ uncompressed\n", pd));
#else  /* PPPOS_SUPPORT && VJ_SUPPORT */
      /* No handler for this protocol so drop the packet. */
      PPPDEBUG(LOG_INFO,
               ("pppInput[%d]: drop VJ UnComp in %d:.*H\n",
                pd, nb->len, LWIP_MIN(nb->len * 2, 40), nb->payload));
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */
      break;

    case PPP_IP:            /* Internet Protocol */
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: ip in pbuf len=%d\n", pd, nb->len));
      if (pppControl[pd].netif.input) {
        pppControl[pd].netif.input(nb, &pppControl[pd].netif);
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
          PPPDEBUG(LOG_INFO, ("pppInput[%d]: %s len=%d\n", pd, protp->name, nb->len));
          nb = pppSingleBuf(nb);
          (*protp->input)(pd, nb->payload, nb->len);
          PPPDEBUG(LOG_DETAIL, ("pppInput[%d]: packet processed\n", pd));
          goto out;
        }
      }

      /* No handler for this protocol so reject the packet. */
      PPPDEBUG(LOG_INFO, ("pppInput[%d]: rejecting unsupported proto 0x%"X16_F" len=%d\n", pd, protocol, nb->len));
      if (pbuf_header(nb, sizeof(protocol))) {
        LWIP_ASSERT("pbuf_header failed\n", 0);
        goto drop;
      }
#if BYTE_ORDER == LITTLE_ENDIAN
      protocol = htons(protocol);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
      SMEMCPY(nb->payload, &protocol, sizeof(protocol));
      lcp_sprotrej(pd, nb->payload, nb->len);
    }
    break;
  }
#endif


}

/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/* Initialize the PPP subsystem. */

int ppp_init(void) {
    int i;
    struct protent *protp;

    debug = 1;

    openlog("LWIP-PPP", LOG_PID | LOG_NDELAY, LOG_PPP);
    setlogmask(LOG_UPTO(LOG_DEBUG));
    syslog(LOG_DEBUG, "hello, this is gradator lwIP PPP!");

    memset(&ppp_settings, 0, sizeof(ppp_settings));
    ppp_settings.usepeerdns = 1;
    pppSetAuth(PPPAUTHTYPE_NONE, NULL, NULL);

    /*
     * Initialize magic number generator now so that protocols may
     * use magic numbers in initialization.
     */
    magic_init();

    /*
     * Initialize each protocol.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
        (*protp->init)(0);
}

void
pppSetAuth(enum pppAuthType authType, const char *user, const char *passwd)
{
  /* FIXME: the following may look stupid, but this is just an easy way
   * to check different auth by changing compile time option
   */
  ppp_settings.refuse_pap = 0;

#if CHAP_SUPPORT
  ppp_settings.refuse_pap = 1;
  ppp_settings.refuse_chap = 0;
#endif /* CHAP_SUPPORT */

#if MSCHAP_SUPPORT
  ppp_settings.refuse_pap = 1;
  ppp_settings.refuse_chap = 1;
  ppp_settings.refuse_mschap = 1;
  ppp_settings.refuse_mschap_v2 = 0;
#endif /* MSCHAP_SUPPORT */

#if EAP_SUPPORT
  ppp_settings.refuse_pap = 1;
#if CHAP_SUPPORT
  ppp_settings.refuse_chap = 1;
#if MSCHAP_SUPPORT
  ppp_settings.refuse_mschap = 1;
  ppp_settings.refuse_mschap_v2 = 1;
#endif /* MSCHAP_SUPPORT */
#endif /* CHAP_SUPPORT */
  ppp_settings.refuse_eap = 0;
#endif /* EAP_SUPPORT */

/* FIXME: re-enable that */
#if 0
  switch(authType) {
    case PPPAUTHTYPE_NONE:
    default:
#ifdef LWIP_PPP_STRICT_PAP_REJECT
      ppp_settings.refuse_pap = 1;
#else  /* LWIP_PPP_STRICT_PAP_REJECT */
      /* some providers request pap and accept an empty login/pw */
      ppp_settings.refuse_pap = 0;
#endif /* LWIP_PPP_STRICT_PAP_REJECT */
      ppp_settings.refuse_chap = 1;
      break;

    case PPPAUTHTYPE_ANY:
      /* Warning: Using PPPAUTHTYPE_ANY might have security consequences.
       * RFC 1994 says:
       *
       * In practice, within or associated with each PPP server, there is a
       * database which associates "user" names with authentication
       * information ("secrets").  It is not anticipated that a particular
       * named user would be authenticated by multiple methods.  This would
       * make the user vulnerable to attacks which negotiate the least secure
       * method from among a set (such as PAP rather than CHAP).  If the same
       * secret was used, PAP would reveal the secret to be used later with
       * CHAP.
       *
       * Instead, for each user name there should be an indication of exactly
       * one method used to authenticate that user name.  If a user needs to
       * make use of different authentication methods under different
       * circumstances, then distinct user names SHOULD be employed, each of
       * which identifies exactly one authentication method.
       *
       */
      ppp_settings.refuse_pap = 0;
      ppp_settings.refuse_chap = 0;
      break;

    case PPPAUTHTYPE_PAP:
      ppp_settings.refuse_pap = 0;
      ppp_settings.refuse_chap = 1;
      break;

    case PPPAUTHTYPE_CHAP:
      ppp_settings.refuse_pap = 1;
      ppp_settings.refuse_chap = 0;
      break;
  }
#endif

  if(user) {
    strncpy(ppp_settings.user, user, sizeof(ppp_settings.user)-1);
    ppp_settings.user[sizeof(ppp_settings.user)-1] = '\0';
  } else {
    ppp_settings.user[0] = '\0';
  }

  if(passwd) {
    strncpy(ppp_settings.passwd, passwd, sizeof(ppp_settings.passwd)-1);
    ppp_settings.passwd[sizeof(ppp_settings.passwd)-1] = '\0';
  } else {
    ppp_settings.passwd[0] = '\0';
  }
}

#if PPPOE_SUPPORT
static void pppOverEthernetLinkStatusCB(int pd, int up);

int pppOverEthernetOpen(struct netif *ethif, const char *service_name, const char *concentrator_name,
                        pppLinkStatusCB_fn linkStatusCB, void *linkStatusCtx)
{
  PPPControl *pc;
  int pd;

  LWIP_UNUSED_ARG(service_name);
  LWIP_UNUSED_ARG(concentrator_name);

  if (linkStatusCB == NULL) {
    /* PPP is single-threaded: without a callback,
     * there is no way to know when the link is up. */
    return PPPERR_PARAM;
  }

  /* Find a free PPP session descriptor. Critical region? */
  for (pd = 0; pd < NUM_PPP && pppControl[pd].openFlag != 0; pd++);
  if (pd >= NUM_PPP) {
    pd = PPPERR_OPEN;
  } else {
    pc = &pppControl[pd];
    memset(pc, 0, sizeof(PPPControl));
    pc->openFlag = 1;
    pc->ethif = ethif;

    pc->linkStatusCB  = linkStatusCB;
    pc->linkStatusCtx = linkStatusCtx;

    lcp_wantoptions[pd].mru = PPPOE_MAXMTU;
    lcp_wantoptions[pd].neg_asyncmap = 0;
    lcp_wantoptions[pd].neg_pcompression = 0;
    lcp_wantoptions[pd].neg_accompression = 0;

    lcp_allowoptions[pd].mru = PPPOE_MAXMTU;
    lcp_allowoptions[pd].neg_asyncmap = 0;
    lcp_allowoptions[pd].neg_pcompression = 0;
    lcp_allowoptions[pd].neg_accompression = 0;

    if(pppoe_create(ethif, pd, pppOverEthernetLinkStatusCB, &pc->pppoe_sc) != ERR_OK) {
      pc->openFlag = 0;
      return PPPERR_OPEN;
    }

    pppoe_connect(pc->pppoe_sc);
  }

  return pd;
}

/* FIXME: maybe we should pass in two arguments pppInputHeader and payload
 * this is totally stupid to make room for it and then modify the packet directly
 * or it is used in output ?  have to find out...
 */
void pppInProcOverEthernet(int pd, struct pbuf *pb) {
  struct pppInputHeader *pih;
  u16_t inProtocol;

  if(pb->len < sizeof(inProtocol)) {
    PPPDEBUG(LOG_ERR, ("pppInProcOverEthernet: too small for protocol field\n"));
    goto drop;
  }

  inProtocol = (((u8_t *)pb->payload)[0] << 8) | ((u8_t*)pb->payload)[1];
  printf("pppInProcOverEthernet() called, pd = %d, inprotocol = 0x%x\n", pd, inProtocol);

  /* make room for pppInputHeader - should not fail */
  if (pbuf_header(pb, sizeof(*pih) - sizeof(inProtocol)) != 0) {
    PPPDEBUG(LOG_ERR, ("pppInProcOverEthernet: could not allocate room for header\n"));
    goto drop;
  }

  pih = pb->payload;

  pih->unit = pd;
  pih->proto = inProtocol;

  /* Dispatch the packet thereby consuming it. */
  ppp_input(pb);
  return;

drop:
  LINK_STATS_INC(link.drop);
//  snmp_inc_ifindiscards(&pppControl[pd].netif);
  pbuf_free(pb);
  return;
}

void
pppOverEthernetInitFailed(int pd)
{
  PPPControl* pc;

  //pppHup(pd);
  //pppStop(pd);

  pc = &pppControl[pd];
  pppoe_destroy(&pc->netif);
  pc->openFlag = 0;

  if(pc->linkStatusCB) {
    pc->linkStatusCB(pc->linkStatusCtx, pc->errCode ? pc->errCode : PPPERR_PROTOCOL, NULL);
  }
}

static void
pppOverEthernetLinkStatusCB(int pd, int up)
{
  printf("pppOverEthernetLinkStatusCB: called, pd = %d, up = %d\n", pd, up);
  if(up) {
    PPPDEBUG(LOG_INFO, ("pppOverEthernetLinkStatusCB: unit %d: Connecting\n", pd));
    pppStart(pd);
  } else {
    pppOverEthernetInitFailed(pd);
  }
}
#endif

#if PPPOE_SUPPORT
static err_t
pppifOutputOverEthernet(int pd, struct pbuf *p)
{
  PPPControl *pc = &pppControl[pd];
  struct pbuf *pb;
  u_short protocol = PPP_IP;
  int i=0;
  u16_t tot_len;

  /* @todo: try to use pbuf_header() here! */
  pb = pbuf_alloc(PBUF_LINK, PPPOE_HDRLEN + sizeof(protocol), PBUF_RAM);
  if(!pb) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pc->netif);
    return ERR_MEM;
  }

  pbuf_header(pb, -(s16_t)PPPOE_HDRLEN);

  pc->lastXMit = sys_jiffies();

  if (!pc->pcomp || protocol > 0xFF) {
    *((u_char*)pb->payload + i++) = (protocol >> 8) & 0xFF;
  }
  *((u_char*)pb->payload + i) = protocol & 0xFF;

  pbuf_chain(pb, p);
  tot_len = pb->tot_len;

  if(pppoe_xmit(pc->pppoe_sc, pb) != ERR_OK) {
    LINK_STATS_INC(link.err);
    snmp_inc_ifoutdiscards(&pc->netif);
    return PPPERR_DEVICE;
  }

  snmp_add_ifoutoctets(&pc->netif, tot_len);
  snmp_inc_ifoutucastpkts(&pc->netif);
  LINK_STATS_INC(link.xmit);
  return ERR_OK;
}
#endif /* PPPOE_SUPPORT */

/* Send a packet on the given connection. */
static err_t
pppifOutput(struct netif *netif, struct pbuf *pb, ip_addr_t *ipaddr)
{
  int pd = (int)(size_t)netif->state;
  PPPControl *pc = &pppControl[pd];
#if PPPOS_SUPPORT
  u_short protocol = PPP_IP;
  u_int fcsOut = PPP_INITFCS;
  struct pbuf *headMB = NULL, *tailMB = NULL, *p;
  u_char c;
#endif /* PPPOS_SUPPORT */

  LWIP_UNUSED_ARG(ipaddr);

  /* Validate parameters. */
  /* We let any protocol value go through - it can't hurt us
   * and the peer will just drop it if it's not accepting it. */
  if (pd < 0 || pd >= NUM_PPP || !pc->openFlag || !pb) {
    PPPDEBUG(LOG_WARNING, ("pppifOutput[%d]: bad parms prot=%d pb=%p\n",
              pd, PPP_IP, pb));
    LINK_STATS_INC(link.opterr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_ARG;
  }

  /* Check that the link is up. */
  if (phase == PHASE_DEAD) {
    PPPDEBUG(LOG_ERR, ("pppifOutput[%d]: link not up\n", pd));
    LINK_STATS_INC(link.rterr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_RTE;
  }

#if PPPOE_SUPPORT
  if(pc->ethif) {
    return pppifOutputOverEthernet(pd, pb);
  }
#endif /* PPPOE_SUPPORT */

#if PPPOS_SUPPORT
  /* Grab an output buffer. */
  headMB = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  if (headMB == NULL) {
    PPPDEBUG(LOG_WARNING, ("pppifOutput[%d]: first alloc fail\n", pd));
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
  if (protocol == PPP_IP && pc->vjEnabled) {
    switch (vj_compress_tcp(&pc->vjComp, pb)) {
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
        PPPDEBUG(LOG_WARNING, ("pppifOutput[%d]: bad IP packet\n", pd));
        LINK_STATS_INC(link.proterr);
        LINK_STATS_INC(link.drop);
        snmp_inc_ifoutdiscards(netif);
        pbuf_free(headMB);
        return ERR_VAL;
    }
  }
#endif /* VJ_SUPPORT */

  tailMB = headMB;

  /* Build the PPP header. */
  if ((sys_jiffies() - pc->lastXMit) >= PPP_MAXIDLEFLAG) {
    tailMB = pppAppend(PPP_FLAG, tailMB, NULL);
  }

  pc->lastXMit = sys_jiffies();
  if (!pc->accomp) {
    fcsOut = PPP_FCS(fcsOut, PPP_ALLSTATIONS);
    tailMB = pppAppend(PPP_ALLSTATIONS, tailMB, &pc->outACCM);
    fcsOut = PPP_FCS(fcsOut, PPP_UI);
    tailMB = pppAppend(PPP_UI, tailMB, &pc->outACCM);
  }
  if (!pc->pcomp || protocol > 0xFF) {
    c = (protocol >> 8) & 0xFF;
    fcsOut = PPP_FCS(fcsOut, c);
    tailMB = pppAppend(c, tailMB, &pc->outACCM);
  }
  c = protocol & 0xFF;
  fcsOut = PPP_FCS(fcsOut, c);
  tailMB = pppAppend(c, tailMB, &pc->outACCM);

  /* Load packet. */
  for(p = pb; p; p = p->next) {
    int n;
    u_char *sPtr;

    sPtr = (u_char*)p->payload;
    n = p->len;
    while (n-- > 0) {
      c = *sPtr++;

      /* Update FCS before checking for special characters. */
      fcsOut = PPP_FCS(fcsOut, c);

      /* Copy to output buffer escaping special characters. */
      tailMB = pppAppend(c, tailMB, &pc->outACCM);
    }
  }

  /* Add FCS and trailing flag. */
  c = ~fcsOut & 0xFF;
  tailMB = pppAppend(c, tailMB, &pc->outACCM);
  c = (~fcsOut >> 8) & 0xFF;
  tailMB = pppAppend(c, tailMB, &pc->outACCM);
  tailMB = pppAppend(PPP_FLAG, tailMB, NULL);

  /* If we failed to complete the packet, throw it away. */
  if (!tailMB) {
    PPPDEBUG(LOG_WARNING,
             ("pppifOutput[%d]: Alloc err - dropping proto=%d\n",
              pd, protocol));
    pbuf_free(headMB);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(netif);
    return ERR_MEM;
  }

  /* Send it. */
  PPPDEBUG(LOG_INFO, ("pppifOutput[%d]: proto=0x%"X16_F"\n", pd, protocol));

  nPut(pc, headMB);
#endif /* PPPOS_SUPPORT */

  return ERR_OK;
}


/*
 * Return the Maximum Transmission Unit for the given PPP connection.
 */
u_short
pppMTU(int pd)
{
  PPPControl *pc = &pppControl[pd];
  u_short st;

  /* Validate parameters. */
  if (pd < 0 || pd >= NUM_PPP || !pc->openFlag) {
    st = 0;
  } else {
    st = pc->mtu;
  }

  return st;
}

#if PPPOE_SUPPORT
int
pppWriteOverEthernet(int pd, const u_char *s, int n)
{
  PPPControl *pc = &pppControl[pd];
  struct pbuf *pb;

  printf("pppWriteOverEthernet() called\n");

  /* skip address & flags */
  s += 2;
  n -= 2;

  LWIP_ASSERT("PPPOE_HDRLEN + n <= 0xffff", PPPOE_HDRLEN + n <= 0xffff);
  pb = pbuf_alloc(PBUF_LINK, (u16_t)(PPPOE_HDRLEN + n), PBUF_RAM);
  if(!pb) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pc->netif);
    return PPPERR_ALLOC;
  }

  pbuf_header(pb, -(s16_t)PPPOE_HDRLEN);

  pc->lastXMit = sys_jiffies();

  MEMCPY(pb->payload, s, n);

  if(pppoe_xmit(pc->pppoe_sc, pb) != ERR_OK) {
    LINK_STATS_INC(link.err);
    snmp_inc_ifoutdiscards(&pc->netif);
    return PPPERR_DEVICE;
  }

  snmp_add_ifoutoctets(&pc->netif, (u16_t)n);
  snmp_inc_ifoutucastpkts(&pc->netif);
  LINK_STATS_INC(link.xmit);
  return PPPERR_NONE;
}
#endif /* PPPOE_SUPPORT */

/*
 * Write n characters to a ppp link.
 *  RETURN: >= 0 Number of characters written
 *           -1 Failed to write to device
 */
int
pppWrite(int pd, const u_char *s, int n)
{
  PPPControl *pc = &pppControl[pd];
#if PPPOS_SUPPORT
  u_char c;
  u_int fcsOut;
  struct pbuf *headMB, *tailMB;
#endif /* PPPOS_SUPPORT */

#if PPPOE_SUPPORT
  if(pc->ethif) {
    return pppWriteOverEthernet(pd, s, n);
  }
#endif /* PPPOE_SUPPORT */

#if PPPOS_SUPPORT
  headMB = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  if (headMB == NULL) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pc->netif);
    return PPPERR_ALLOC;
  }

  tailMB = headMB;

  /* If the link has been idle, we'll send a fresh flag character to
   * flush any noise. */
  if ((sys_jiffies() - pc->lastXMit) >= PPP_MAXIDLEFLAG) {
    tailMB = pppAppend(PPP_FLAG, tailMB, NULL);
  }
  pc->lastXMit = sys_jiffies();

  fcsOut = PPP_INITFCS;
  /* Load output buffer. */
  while (n-- > 0) {
    c = *s++;

    /* Update FCS before checking for special characters. */
    fcsOut = PPP_FCS(fcsOut, c);

    /* Copy to output buffer escaping special characters. */
    tailMB = pppAppend(c, tailMB, &pc->outACCM);
  }

  /* Add FCS and trailing flag. */
  c = ~fcsOut & 0xFF;
  tailMB = pppAppend(c, tailMB, &pc->outACCM);
  c = (~fcsOut >> 8) & 0xFF;
  tailMB = pppAppend(c, tailMB, &pc->outACCM);
  tailMB = pppAppend(PPP_FLAG, tailMB, NULL);

  /* If we failed to complete the packet, throw it away.
   * Otherwise send it. */
  if (!tailMB) {
    PPPDEBUG(LOG_WARNING,
             ("pppWrite[%d]: Alloc err - dropping pbuf len=%d\n", pd, headMB->len));
           /*"pppWrite[%d]: Alloc err - dropping %d:%.*H", pd, headMB->len, LWIP_MIN(headMB->len * 2, 40), headMB->payload)); */
    pbuf_free(headMB);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(&pc->netif);
    return PPPERR_ALLOC;
  }

  PPPDEBUG(LOG_INFO, ("pppWrite[%d]: len=%d\n", pd, headMB->len));
                   /* "pppWrite[%d]: %d:%.*H", pd, headMB->len, LWIP_MIN(headMB->len * 2, 40), headMB->payload)); */
  nPut(pc, headMB);
#endif /* PPPOS_SUPPORT */

  return PPPERR_NONE;
}


/* FIXME: rename all output() to pppWrite() */
/********************************************************************
 *
 * output - Output PPP packet.
 */

void output (int unit, unsigned char *p, int len)
{
	pppWrite(unit, p, len);
}


/*
 * ppp_send_config - configure the transmit-side characteristics of
 * the ppp interface.
 */
int
ppp_send_config(unit, mtu, accm, pcomp, accomp)
    int unit, mtu;
    u_int32_t accm;
    int pcomp, accomp;
{
  PPPControl *pc = &pppControl[unit];
  int i;

  pc->mtu = mtu;
  pc->pcomp = pcomp;
  pc->accomp = accomp;

  /* Load the ACCM bits for the 32 control codes. */
  for (i = 0; i < 32/8; i++) {
    pc->outACCM[i] = (u_char)((accm >> (8 * i)) & 0xFF);
  }
  PPPDEBUG(LOG_INFO, ("ppp_send_config[%d]: outACCM=%X %X %X %X\n",
            unit,
            pc->outACCM[0], pc->outACCM[1], pc->outACCM[2], pc->outACCM[3]));
}

/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */
int
ppp_recv_config(unit, mru, accm, pcomp, accomp)
    int unit, mru;
    u_int32_t accm;
    int pcomp, accomp;
{
  PPPControl *pc = &pppControl[unit];
  int i;
  SYS_ARCH_DECL_PROTECT(lev);

  LWIP_UNUSED_ARG(accomp);
  LWIP_UNUSED_ARG(pcomp);
  LWIP_UNUSED_ARG(mru);

  /* Load the ACCM bits for the 32 control codes. */
  SYS_ARCH_PROTECT(lev);
  for (i = 0; i < 32 / 8; i++) {
    /* @todo: does this work? ext_accm has been modified from pppd! */
    pc->rx.inACCM[i] = (u_char)(accm >> (i * 8));
  }
  SYS_ARCH_UNPROTECT(lev);
  PPPDEBUG(LOG_INFO, ("ppp_recv_config[%d]: inACCM=%X %X %X %X\n",
            unit,
            pc->rx.inACCM[0], pc->rx.inACCM[1], pc->rx.inACCM[2], pc->rx.inACCM[3]));
}




/*
 * sifaddr - Config the interface IP addresses and netmask.
 */
int sifaddr (int unit, u_int32_t our_adr, u_int32_t his_adr,
	     u_int32_t net_mask)
{
  PPPControl *pc = &pppControl[unit];
  int st = 1;

  if (unit < 0 || unit >= NUM_PPP || !pc->openFlag) {
    st = 0;
    PPPDEBUG(LOG_WARNING, ("sifup[%d]: bad parms\n", unit));
  } else {
    SMEMCPY(&pc->addrs.our_ipaddr, &our_adr, sizeof(our_adr));
    SMEMCPY(&pc->addrs.his_ipaddr, &his_adr, sizeof(his_adr));
    SMEMCPY(&pc->addrs.netmask, &net_mask, sizeof(net_mask));
//    SMEMCPY(&pc->addrs.dns1, &ns1, sizeof(ns1));
//    SMEMCPY(&pc->addrs.dns2, &ns2, sizeof(ns2));
  }
  return st;
}

/*
 * pppifNetifInit - netif init callback
 */
static err_t
pppifNetifInit(struct netif *netif)
{
  netif->name[0] = 'p';
  netif->name[1] = 'p';
  netif->output = pppifOutput;
  netif->mtu = pppMTU((int)(size_t)netif->state);
  netif->flags = NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_LINK_UP;
#if LWIP_NETIF_HOSTNAME
  /* @todo: Initialize interface hostname */
  /* netif_set_hostname(netif, "lwip"); */
#endif /* LWIP_NETIF_HOSTNAME */
  return ERR_OK;
}

/*
 * sifup - Config the interface up and enable IP packets to pass.
 */
int sifup(int u)
{
  PPPControl *pc = &pppControl[u];
  int st = 1;

  if (u < 0 || u >= NUM_PPP || !pc->openFlag) {
    st = 0;
    PPPDEBUG(LOG_WARNING, ("sifup[%d]: bad parms\n", u));
  } else {
    netif_remove(&pc->netif);
    if (netif_add(&pc->netif, &pc->addrs.our_ipaddr, &pc->addrs.netmask,
                  &pc->addrs.his_ipaddr, (void *)(size_t)u, pppifNetifInit, ip_input)) {
      netif_set_up(&pc->netif);
      pc->if_up = 1;
      pc->errCode = PPPERR_NONE;

      PPPDEBUG(LOG_DEBUG, ("sifup: unit %d: linkStatusCB=%p errCode=%d\n", u, pc->linkStatusCB, pc->errCode));
      if (pc->linkStatusCB) {
        pc->linkStatusCB(pc->linkStatusCtx, pc->errCode, &pc->addrs);
      }
    } else {
      st = 0;
      PPPDEBUG(LOG_ERR, ("sifup[%d]: netif_add failed\n", u));
    }
  }

  return st;
}


/*
 * sifnpmode - Set the mode for handling packets for a given NP.
 */
int
sifnpmode(int u, int proto, enum NPmode mode)
{
  LWIP_UNUSED_ARG(u);
  LWIP_UNUSED_ARG(proto);
  LWIP_UNUSED_ARG(mode);
  return 0;
}

