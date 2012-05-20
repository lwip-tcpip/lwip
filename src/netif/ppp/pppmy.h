/*
 * pppmy.h
 *
 *  Created on: May 12, 2012
 *      Author: gradator
 */

#ifndef PPPMY_H_
#define PPPMY_H_

#include <syslog.h> /* FIXME: temporary */

#include "lwip/netif.h"
#include "lwip/def.h"

/*************************
*** PUBLIC DEFINITIONS ***
*************************/

/* Error codes. */
#define PPPERR_NONE      0 /* No error. */
#define PPPERR_PARAM    -1 /* Invalid parameter. */
#define PPPERR_OPEN     -2 /* Unable to open PPP session. */
#define PPPERR_DEVICE   -3 /* Invalid I/O device for PPP. */
#define PPPERR_ALLOC    -4 /* Unable to allocate resources. */
#define PPPERR_USER     -5 /* User interrupt. */
#define PPPERR_CONNECT  -6 /* Connection lost. */
#define PPPERR_AUTHFAIL -7 /* Failed authentication challenge. */
#define PPPERR_PROTOCOL -8 /* Failed to meet protocol. */

/************************
*** PUBLIC DATA TYPES ***
************************/

struct ppp_addrs {
  ip_addr_t our_ipaddr, his_ipaddr, netmask, dns1, dns2;
};


/* FIXME: use PPP option instead ? */

struct ppp_settings {

  u_int  disable_defaultip : 1;       /* Don't use hostname for default IP addrs */
  u_int  auth_required     : 1;       /* Peer is required to authenticate */
  u_int  explicit_remote   : 1;       /* remote_name specified with remotename opt */
  u_int  refuse_pap        : 1;       /* Don't wanna auth. ourselves with PAP */
  u_int  refuse_chap       : 1;       /* Don't wanna auth. ourselves with CHAP */
#if EAP_SUPPORT
  u_int  refuse_eap        : 1;       /* Don't wanna auth. ourselves with EAP */
#endif /* EAP_SUPPORT */
  u_int  usehostname       : 1;       /* Use hostname for our_name */
  u_int  usepeerdns        : 1;       /* Ask peer for DNS adds */

  u_short idle_time_limit;            /* Shut down link if idle for this long */
  int  maxconnect;                    /* Maximum connect time (seconds) */

  char user       [MAXNAMELEN   + 1]; /* Username for PAP */
  char passwd     [MAXSECRETLEN + 1]; /* Password for PAP, secret for CHAP */
  char our_name   [MAXNAMELEN   + 1]; /* Our name for authentication purposes */
  // FIXME: re-enable that
  //  char remote_name[MAXNAMELEN   + 1]; /* Peer's name for authentication */
};

struct ppp_settings ppp_settings;

/* FIXME: move all private stuff into a new include */

/*************************
 *** PRIVATE FUNCTIONS ***
 *************************/

/** Initiate LCP open request */
static void pppStart(int pd);

struct pbuf *pppSingleBuf(struct pbuf *p);


/************************
 *** PUBLIC FUNCTIONS ***
 ************************/

/* Initialize the PPP subsystem. */
int ppp_init(void);

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
enum pppAuthType {
    PPPAUTHTYPE_NONE,
    PPPAUTHTYPE_ANY,
    PPPAUTHTYPE_PAP,
    PPPAUTHTYPE_CHAP
};

void pppSetAuth(enum pppAuthType authType, const char *user, const char *passwd);

/* Link status callback function prototype */
typedef void (*pppLinkStatusCB_fn)(void *ctx, int errCode, void *arg);

/*
 * Open a new PPP Over Ethernet (PPPOE) connection.
 */
int pppOverEthernetOpen(struct netif *ethif, const char *service_name, const char *concentrator_name,
                        pppLinkStatusCB_fn linkStatusCB, void *linkStatusCtx);

void pppInProcOverEthernet(int pd, struct pbuf *pb);


#endif /* PPPMY_H_ */
