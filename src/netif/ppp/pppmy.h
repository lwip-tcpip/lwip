/*
 * pppmy.h
 *
 *  Created on: May 12, 2012
 *      Author: gradator
 */

#include "lwip/opt.h"

#ifndef PPPMY_H_
#define PPPMY_H_

#include <syslog.h> /* FIXME: temporary */

#include <net/ppp_defs.h> /* FIXME: merge linux/ppp_defs.h content here */

#include "lwip/netif.h"
#include "lwip/def.h"

#ifndef bool
typedef unsigned char	bool;
#endif

/*
 * The following struct gives the addresses of procedures to call
 * for a particular protocol.
 */
struct protent {
    u_short protocol;		/* PPP protocol number */
    /* Initialization procedure */
    void (*init) __P((int unit));
    /* Process a received packet */
    void (*input) __P((int unit, u_char *pkt, int len));
    /* Process a received protocol-reject */
    void (*protrej) __P((int unit));
    /* Lower layer has come up */
    void (*lowerup) __P((int unit));
    /* Lower layer has gone down */
    void (*lowerdown) __P((int unit));
    /* Open the protocol */
    void (*open) __P((int unit));
    /* Close the protocol */
    void (*close) __P((int unit, char *reason));
#if PRINTPKT_SUPPORT
    /* Print a packet in readable form */
    int  (*printpkt) __P((u_char *pkt, int len,
			  void (*printer) __P((void *, char *, ...)),
			  void *arg));
#endif /* PRINTPKT_SUPPORT */
    /* FIXME: data input is only used by CCP, which is not supported at this time,
     *        should we remove this entry and save some flash ?
     */
    /* Process a received data packet */
    void (*datainput) __P((int unit, u_char *pkt, int len));
    bool enabled_flag;		/* 0 iff protocol is disabled */
#if PRINTPKT_SUPPORT
    char *name;			/* Text name of protocol */
    char *data_name;		/* Text name of corresponding data protocol */
#endif /* PRINTPKT_SUPPORT */
#if PPP_OPTIONS
    option_t *options;		/* List of command-line options */
    /* Check requested options, assign defaults */
    void (*check_options) __P((void));
#endif /* PPP_OPTIONS */
#if DEMAND_SUPPORT
    /* Configure interface for demand-dial */
    int  (*demand_conf) __P((int unit));
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt) __P((u_char *pkt, int len));
#endif /* DEMAND_SUPPORT */
};

/* Table of pointers to supported protocols */
extern struct protent *protocols[];


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

#if PPP_STATS_SUPPORT
/*
 * PPP statistics structure
 */
struct pppd_stats {
    unsigned int	bytes_in;
    unsigned int	bytes_out;
    unsigned int	pkts_in;
    unsigned int	pkts_out;
};
#endif /* PPP_STATS_SUPPORT */

/* FIXME: use PPP option instead ? */

struct ppp_settings {

  u_int  disable_defaultip : 1;       /* Don't use hostname for default IP addrs */
  u_int  auth_required     : 1;       /* Peer is required to authenticate */
  u_int  explicit_remote   : 1;       /* remote_name specified with remotename opt */
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
#if CHAP_SUPPORT
    PPPAUTHTYPE_CHAP,
#endif /* CHAP_SUPPORT */
};

struct pbuf * pppSingleBuf(struct pbuf *p);

static void pppStart(int pd);

static void ppp_input(void *arg);

int ppp_init(void);

void pppSetAuth(enum pppAuthType authType, const char *user, const char *passwd);

/* Link status callback function prototype */
typedef void (*pppLinkStatusCB_fn)(void *ctx, int errCode, void *arg);

/*
 * Open a new PPP Over Ethernet (PPPOE) connection.
 */
int pppOverEthernetOpen(struct netif *ethif, const char *service_name, const char *concentrator_name,
                        pppLinkStatusCB_fn linkStatusCB, void *linkStatusCtx);


void pppInProcOverEthernet(int pd, struct pbuf *pb);

void pppOverEthernetInitFailed(int pd);

static void pppOverEthernetLinkStatusCB(int pd, int up);

static err_t pppifOutputOverEthernet(int pd, struct pbuf *p);

static err_t pppifOutput(struct netif *netif, struct pbuf *pb, ip_addr_t *ipaddr);

u_short pppMTU(int pd);

int pppWriteOverEthernet(int pd, const u_char *s, int n);

int pppWrite(int pd, const u_char *s, int n);

void pppInProcOverEthernet(int pd, struct pbuf *pb);

void output (int unit, unsigned char *p, int len);

int ppp_send_config(int unit, int mtu, u_int32_t accm, int pcomp, int accomp);
int ppp_recv_config(int unit, int mru, u_int32_t accm, int pcomp, int accomp);

int sifaddr(int unit, u_int32_t our_adr, u_int32_t his_adr, u_int32_t net_mask);
int cifaddr(int unit, u_int32_t our_adr, u_int32_t his_adr);

static err_t pppifNetifInit(struct netif *netif);

int sifup(int u);
int sifdown (int u);

int sifnpmode(int u, int proto, enum NPmode mode);

void netif_set_mtu(int unit, int mtu);
int netif_get_mtu(int mtu);

int sifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway, bool replace);
int cifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway);

int sifproxyarp (int unit, u_int32_t his_adr);
int cifproxyarp (int unit, u_int32_t his_adr);

int sifvjcomp (int u, int vjcomp, int cidcomp, int maxcid);

int get_idle_time(int u, struct ppp_idle *ip);

int get_loop_output(void);

u_int32_t GetMask (u_int32_t addr);

#if PPP_PROTOCOLNAME
const char * protocol_name(int proto);
#endif /* PPP_PROTOCOLNAME  */

void new_phase(int p);

#if PPP_STATS_SUPPORT
void print_link_stats(void); /* Print stats, if available */
void reset_link_stats(int u); /* Reset (init) stats when link goes up */
void update_link_stats(int u); /* Get stats at link termination */
#endif /* PPP_STATS_SUPPORT */

#endif /* PPPMY_H_ */
