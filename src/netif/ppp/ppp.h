/*****************************************************************************
* ppp.h - Network Point to Point Protocol header file.
*
* Copyright (c) 2003 by Marc Boucher, Services Informatiques (MBSI) inc.
* portions Copyright (c) 1997 Global Election Systems Inc.
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
* 97-11-05 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*   Original derived from BSD codes.
*****************************************************************************/

#include "lwip/opt.h"
#if PPP_SUPPORT /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_H
#define PPP_H

#include "lwip/def.h"
#include "lwip/sio.h"
#include "lwip/stats.h"
#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/timers.h"
#if PPP_IPV6_SUPPORT
#include "lwip/ip6_addr.h"
#endif /* PPP_IPV6_SUPPORT */

#include "vj.h"

/** PPP_INPROC_MULTITHREADED==1 call ppp_input using tcpip_callback().
 * Set this to 0 if pppos_input_proc is called inside tcpip_thread or with NO_SYS==1.
 * Default is 1 for NO_SYS==0 (multithreaded) and 0 for NO_SYS==1 (single-threaded).
 */
#ifndef PPP_INPROC_MULTITHREADED
#define PPP_INPROC_MULTITHREADED (NO_SYS==0)
#endif

/** PPP_INPROC_OWNTHREAD==1: start a dedicated RX thread per PPP session.
 * Default is 1 if PPP_INPROC_MULTITHREADED is enabled.
 * If set to 0, call pppos_input() for received raw characters, character
 * reception is up to the port.
 */
#ifndef PPP_INPROC_OWNTHREAD
#define PPP_INPROC_OWNTHREAD      PPP_INPROC_MULTITHREADED
#endif

#if PPP_INPROC_OWNTHREAD && !PPP_INPROC_MULTITHREADED
  #error "PPP_INPROC_OWNTHREAD needs PPP_INPROC_MULTITHREADED==1"
#endif

#if PPPOS_SUPPORT
/** RX buffer size: this may be configured smaller! */
#ifndef PPPOS_RX_BUFSIZE
#define PPPOS_RX_BUFSIZE    (PPP_MRU + PPP_HDRLEN)
#endif
#endif /* PPPOS_SUPPORT */


#ifndef __u_char_defined

/* Type definitions for BSD code. */
typedef unsigned long  u_long;
typedef unsigned int   u_int;
typedef unsigned short u_short;
typedef unsigned char  u_char;

#endif

#ifndef bool
typedef unsigned char	bool;
#endif

/*************************
*** PUBLIC DEFINITIONS ***
*************************/

/*
 * The basic PPP frame.
 */
#define PPP_HDRLEN	4	/* octets for standard ppp header */
#define PPP_FCSLEN	2	/* octets for FCS */

/* Error codes. */
#define PPPERR_NONE         0  /* No error. */
#define PPPERR_PARAM        1  /* Invalid parameter. */
#define PPPERR_OPEN         2  /* Unable to open PPP session. */
#define PPPERR_DEVICE       3  /* Invalid I/O device for PPP. */
#define PPPERR_ALLOC        4  /* Unable to allocate resources. */
#define PPPERR_USER         5  /* User interrupt. */
#define PPPERR_CONNECT      6  /* Connection lost. */
#define PPPERR_AUTHFAIL     7  /* Failed authentication challenge. */
#define PPPERR_PROTOCOL     8  /* Failed to meet protocol. */
#define PPPERR_PEERDEAD     9  /* Connection timeout */
#define PPPERR_IDLETIMEOUT  10 /* Idle Timeout */
#define PPPERR_CONNECTTIME  11 /* Max connect time reached */
#define PPPERR_LOOPBACK     12 /* Loopback detected */

/*
 * PPP IOCTL commands.
 */
/*
 * Get the up status - 0 for down, non-zero for up.  The argument must
 * point to an int.
 */
#define PPPCTLG_UPSTATUS 100 /* Get the up status - 0 down else up */
#define PPPCTLS_ERRCODE  101 /* Set the error code */
#define PPPCTLG_ERRCODE  102 /* Get the error code */
#define PPPCTLG_FD       103 /* Get the fd associated with the ppp */

/************************
*** PUBLIC DATA TYPES ***
************************/

/*
 * Other headers require ppp_pcb definition for prototypes, but ppp_pcb
 * require some structure definition from other headers as well, we are
 * fixing the dependency loop here by declaring the ppp_pcb type then
 * by including headers containing necessary struct definition for ppp_pcb
 */
typedef struct ppp_pcb_s ppp_pcb;

#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#if PPP_IPV6_SUPPORT
#include "ipv6cp.h"
#endif /* PPP_IPV6_SUPPORT */
#if PAP_SUPPORT
#include "upap.h"
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
#include "chap-new.h"
#endif /* CHAP_SUPPORT */
#if EAP_SUPPORT
#include "eap.h"
#endif /* EAP_SUPPORT */

/*
 * PPP configuration.
 */
typedef struct ppp_settings_s {

#if PPP_SERVER
  u_int  auth_required     : 1;       /* Peer is required to authenticate */
#endif /* PPP_SERVER */
#if PPP_REMOTENAME
  u_int  explicit_remote   : 1;       /* remote_name specified with remotename opt */
#endif /* PPP_REMOTENAME */
#if PAP_SUPPORT
  u_int  refuse_pap        : 1;       /* Don't wanna auth. ourselves with PAP */
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
  u_int  refuse_chap       : 1;       /* Don't wanna auth. ourselves with CHAP */
#endif /* CHAP_SUPPORT */
#if MSCHAP_SUPPORT
  u_int  refuse_mschap     : 1;       /* Don't wanna auth. ourselves with MS-CHAP */
  u_int  refuse_mschap_v2  : 1;       /* Don't wanna auth. ourselves with MS-CHAPv2 */
#endif /* MSCHAP_SUPPORT */
#if EAP_SUPPORT
  u_int  refuse_eap        : 1;       /* Don't wanna auth. ourselves with EAP */
#endif /* EAP_SUPPORT */
  u_int  usepeerdns        : 1;       /* Ask peer for DNS adds */
  u_int  persist           : 1;       /* Persist mode, always try to reopen the connection */
#if PRINTPKT_SUPPORT
  u_int  hide_password     : 1;       /* Hide password in dumped packets */
#endif /* PRINTPKT_SUPPORT */
  u_int  noremoteip        : 1;       /* Let him have no IP address */
  u_int  lax_recv          : 1;       /* accept control chars in asyncmap */
  u_int  noendpoint        : 1;       /* don't send/accept endpoint discriminator */
#if PPP_LCP_ADAPTIVE
  u_int lcp_echo_adaptive  : 1;       /* request echo only if the link was idle */
#endif


  u16_t  listen_time;                 /* time to listen first (ms), waiting for peer to send LCP packet */

#if PPP_IDLETIMELIMIT
  u16_t  idle_time_limit;             /* Disconnect if idle for this many seconds */
#endif /* PPP_IDLETIMELIMIT */
#if PPP_MAXCONNECT
  u32_t  maxconnect;                  /* Maximum connect time (seconds) */
#endif /* PPP_MAXCONNECT */

  /* auth data */
  char  *user;                         /* Username for PAP */
  char  *passwd;                       /* Password for PAP, secret for CHAP */
#if PPP_SERVER
  char  our_name   [MAXNAMELEN   + 1]; /* Our name for authentication purposes */
#endif /* PPP_SERVER */
#if PPP_REMOTENAME
  char  remote_name[MAXNAMELEN   + 1]; /* Peer's name for authentication */
#endif /* PPP_REMOTENAME */

#if CHAP_SUPPORT
  u8_t  chap_timeout_time;
  u8_t  chap_max_transmits;
  u8_t  chap_rechallenge_time;
#endif /* CHAP_SUPPPORT */

  u8_t  lcp_echo_interval;    /* Interval between LCP echo-requests */
  u8_t  lcp_echo_fails;       /* Tolerance to unanswered echo-requests */

} ppp_settings;

struct ppp_addrs {
  ip_addr_t our_ipaddr, his_ipaddr, netmask;
  ip_addr_t dns1, dns2;
#if PPP_IPV6_SUPPORT
  ip6_addr_t our6_ipaddr, his6_ipaddr;
#endif /* PPP_IPV6_SUPPORT */
};

/* FIXME: find a way to move ppp_dev_states and ppp_pcb_rx_s to ppp_impl.h */
#if PPPOS_SUPPORT
/*
 * Extended asyncmap - allows any character to be escaped.
 */
typedef u_char  ext_accm[32];

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
} ppp_dev_states;

/*
 * PPP interface RX control block.
 */
typedef struct ppp_pcb_rx_s {
  /** ppp descriptor */
  ppp_pcb *pcb;
  /** the rx file descriptor */
  sio_fd_t fd;
  /** receive buffer - encoded data is stored here */
#if PPP_INPROC_OWNTHREAD
  u_char rxbuf[PPPOS_RX_BUFSIZE];
#endif /* PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD */

  /* The input packet. */
  struct pbuf *in_head, *in_tail;

  u16_t in_protocol;             /* The input protocol code. */
  u16_t in_fcs;                  /* Input Frame Check Sequence value. */
  ppp_dev_states in_state;         /* The input process state. */
  char in_escaped;               /* Escape next character. */
  ext_accm in_accm;              /* Async-Ctl-Char-Map for input. */
} ppp_pcb_rx;
#endif /* PPPOS_SUPPORT */

/*
 * PPP interface control block.
 */
struct ppp_pcb_s {
  u_int if_up                   :1; /* True when the interface is up. */
  u_int pcomp                   :1; /* Does peer accept protocol compression? */
  u_int accomp                  :1; /* Does peer accept addr/ctl compression? */
  u_int default_route_set       :1; /* Have set up a default route */
  u_int proxy_arp_set           :1; /* Have created proxy arp entry */
  u_int ipcp_is_open            :1; /* haven't called np_finished() */
  u_int ipcp_is_up              :1; /* have called ipcp_up() */
#if PPP_IPV6_SUPPORT
  u_int ipv6cp_is_up            :1; /* have called ip6cp_up() */
#endif /* PPP_IPV6_SUPPORT */
  u_int ask_for_local           :1; /* request our address from peer */
  u_int lcp_echo_timer_running  :1; /* set if a timer is running */
#if PPPOS_SUPPORT && VJ_SUPPORT
  u_int vj_enabled              :1; /* Flag indicating VJ compression enabled. */
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */

  ppp_settings settings;

#if PPP_DEBUG
  u8_t num;                      /* Interface number - only useful for debugging */
#endif /* PPP_DEBUG */

#if PPPOS_SUPPORT
  sio_fd_t fd;                   /* File device ID of port. */
/* FIXME: there is probably one superfluous */
  ext_accm out_accm;             /* Async-Ctl-Char-Map for output. */
  ext_accm xmit_accm;            /* extended transmit ACCM */
  ppp_pcb_rx rx;
#if VJ_SUPPORT
  struct vjcompress vj_comp;     /* Van Jacobson compression header. */
#endif /* VJ_SUPPORT */
#endif /* PPPOS_SUPPORT */

#if PPPOE_SUPPORT
  struct netif *ethif;
  struct pppoe_softc *pppoe_sc;
#endif /* PPPOE_SUPPORT */

  u8_t phase;                    /* where the link is at */
  u8_t err_code;                 /* Code indicating why interface is down. */

  /* FIXME: maybe we should cleanup one of those MTU variables */
  u16_t mtu;                     /* Peer's mru */
  u16_t peer_mru;                /* currently negotiated peer MRU */

  u32_t last_xmit;               /* Time of last transmission. */

  struct ppp_addrs addrs;        /* PPP addresses */
  struct netif netif;            /* PPP interface */

  void (*link_status_cb)(ppp_pcb *pcb, int err_code, void *ctx);  /* Status change callback */
  void *link_status_ctx;                                       /* Status change callback optional pointer */

  /* auth data */
#if PPP_SERVER
  char peer_authname[MAXNAMELEN + 1]; /* The name by which the peer authenticated itself to us. */
#endif /* PPP_SERVER */
  u16_t auth_pending;        /* Records which authentication operations haven't completed yet. */
  u16_t auth_done;           /* Records which authentication operations have been completed. */
  u8_t num_np_open;         /* Number of network protocols which we have opened. */
  u8_t num_np_up;           /* Number of network protocols which have come up. */

#if PAP_SUPPORT
  upap_state upap;          /* PAP data */
#endif /* PAP_SUPPORT */

#if CHAP_SUPPORT
  chap_client_state chap_client;  /* CHAP client data */
#if PPP_SERVER
  chap_server_state chap_server;  /* CHAP server data */
#endif /* PPP_SERVER */
#endif /* CHAP_SUPPORT */

#if EAP_SUPPORT
  eap_state eap;            /* EAP data */
#endif /* EAP_SUPPORT */

  fsm lcp_fsm;                   /* LCP fsm structure */
  lcp_options lcp_wantoptions;   /* Options that we want to request */
  lcp_options lcp_gotoptions;    /* Options that peer ack'd */
  lcp_options lcp_allowoptions;  /* Options we allow peer to request */
  lcp_options lcp_hisoptions;    /* Options that we ack'd */
  u8_t lcp_echos_pending;        /* Number of outstanding echo msgs */
  u8_t lcp_echo_number;          /* ID number of next echo frame */
  u8_t lcp_loopbackfail;

  fsm ipcp_fsm;                   /* IPCP fsm structure */
  ipcp_options ipcp_wantoptions;  /* Options that we want to request */
  ipcp_options ipcp_gotoptions;   /* Options that peer ack'd */
  ipcp_options ipcp_allowoptions; /* Options we allow peer to request */
  ipcp_options ipcp_hisoptions;   /* Options that we ack'd */

#if PPP_IPV6_SUPPORT
  fsm ipv6cp_fsm;                     /* IPV6CP fsm structure */
  ipv6cp_options ipv6cp_wantoptions;  /* Options that we want to request */
  ipv6cp_options ipv6cp_gotoptions;   /* Options that peer ack'd */
  ipv6cp_options ipv6cp_allowoptions; /* Options we allow peer to request */
  ipv6cp_options ipv6cp_hisoptions;   /* Options that we ack'd */
#endif /* PPP_IPV6_SUPPORT */
};

/************************
 *** PUBLIC FUNCTIONS ***
 ************************/

/* Initialize the PPP subsystem. */
int ppp_init(void);

/* Create a new PPP session, returns a PPP PCB structure. */
ppp_pcb *ppp_new(void);

/* Set auth helper, optional, you can either fill ppp_pcb->settings. */

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
#define PPPAUTHTYPE_NONE   0x00
#define PPPAUTHTYPE_PAP    0x01
#define PPPAUTHTYPE_CHAP   0x02
#define PPPAUTHTYPE_MSCHAP 0x04
#define PPPAUTHTYPE_EAP    0x08
#define PPPAUTHTYPE_ANY    0xff

void ppp_set_auth(ppp_pcb *pcb, u8_t authtype, char *user, char *passwd);

/* Link status callback function prototype */
typedef void (*ppp_link_status_cb_fn)(ppp_pcb *pcb, int err_code, void *ctx);

#if PPPOS_SUPPORT
/*
 * Open a new PPP connection using the given serial I/O device.
 * This initializes the PPP control block but does not
 * attempt to negotiate the LCP session.
 *
 * If this port connects to a modem, the modem connection must be
 * established before calling this.
 *
 * Return a new PPP connection descriptor on success or
 * an error code (negative) on failure.
 */
int ppp_over_serial_open(ppp_pcb *pcb, sio_fd_t fd, ppp_link_status_cb_fn link_status_cb, void *link_status_ctx);
#endif /* PPPOS_SUPPORT */

#if PPPOE_SUPPORT
/*
 * Open a new PPP Over Ethernet (PPPoE) connection.
 */
int ppp_over_ethernet_open(ppp_pcb *pcb, struct netif *ethif, const char *service_name, const char *concentrator_name,
                        ppp_link_status_cb_fn link_status_cb, void *link_status_ctx);
#endif /* PPPOE_SUPPORT */

/*
 * Close a PPP connection and release the descriptor. 
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success, an error code on failure. 
 */
int ppp_close(ppp_pcb *pcb);

/*
 * Indicate to the PPP process that the line has disconnected.
 */
void ppp_sighup(ppp_pcb *pcb);

/*
 * Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. 
 */
int ppp_ioctl(ppp_pcb *pcb, int cmd, void *arg);

#if PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD
/*
 * PPP over Serial: this is the input function to be called for received data.
 * If PPP_INPROC_OWNTHREAD==1, a separate input thread using the blocking
 * sio_read() is used, so this is deactivated.
 */
void pppos_input(ppp_pcb *pcb, u_char* data, int len);
#endif /* PPPOS_SUPPORT && !PPP_INPROC_OWNTHREAD */


#if LWIP_NETIF_STATUS_CALLBACK
/* Set an lwIP-style status-callback for the selected PPP device */
void ppp_set_netif_statuscallback(ppp_pcb *pcb, netif_status_callback_fn status_callback);
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
/* Set an lwIP-style link-callback for the selected PPP device */
void ppp_set_netif_linkcallback(ppp_pcb *pcb, netif_status_callback_fn link_callback);
#endif /* LWIP_NETIF_LINK_CALLBACK */


/* Source code compatibility */
#if 0
#define pppAuthType ppp_auth_type
#define pppInit() ppp_init()
#define pppSetAuth(authtype,user,passwd) ppp_set_auth(authtype,user,passwd)
#define pppOpen(fd,cb,ls) ppp_over_serial_open(fd,cb,ls)
#define pppOverSerialOpen(fd,cb,ls) ppp_over_serial_open(fd,cb,ls)
#define pppOverEthernetOpen(ethif,sn,cn,lscb,lsctx) ppp_over_ethernet_open(ethif,sn,cn,lscb,lsctx)
#define pppClose(unit) ppp_close(unit)
#define pppSigHUP(unit) ppp_sigup(unit)
#define pppIOCtl(pd,cmd,arg) ppp_ioctl(pd,cmd,arg)
#define pppMTU(unit) ppp_mtu(unit)
#endif

#endif /* PPP_H */

#endif /* PPP_SUPPORT */
