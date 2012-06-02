/*
 * pppmy.h
 *
 *  Created on: May 12, 2012
 *      Author: gradator
 */

#include "lwip/opt.h"

#ifndef PPPMY_H_
#define PPPMY_H_

#include "lwip/netif.h"
#include "lwip/def.h"

#include "pppdebug.h"

#include <net/ppp_defs.h> /* FIXME: merge linux/ppp_defs.h content here */

#ifdef INET6
#include "eui64.h"
#endif

#if defined(__STDC__)
#include <stdarg.h>
#define __V(x)	x
#else
#include <varargs.h>
#define __V(x)	(va_alist) va_dcl
#define const
#define volatile
#endif

/*
 * Limits.
 */

#define NUM_PPP		1	/* One PPP interface supported (per process) */
#define MAXWORDLEN	1024	/* max length of word in file (incl null) */
#define MAXARGS		1	/* max # args to a command */
#define MAXNAMELEN	256	/* max length of hostname or name for auth */
#define MAXSECRETLEN	256	/* max length of password or secret */

#ifndef bool
typedef unsigned char	bool;
#endif

/* FIXME: make endpoint discriminator optional */

/* An endpoint discriminator, used with multilink. */
#define MAX_ENDP_LEN	20	/* maximum length of discriminator value */
struct epdisc {
    unsigned char	class;
    unsigned char	length;
    unsigned char	value[MAX_ENDP_LEN];
};

/* values for epdisc.class */
#define EPD_NULL	0	/* null discriminator, no data */
#define EPD_LOCAL	1
#define EPD_IP		2
#define EPD_MAC		3
#define EPD_MAGIC	4
#define EPD_PHONENUM	5

/* FIXME: global variables per PPP session */

/*
 * Global variables.
 */
/* FIXME: improve debug flag */
extern int	debug;		/* Debug flag */

/* FIXME: is our_name really necessary ? */
extern char	our_name[MAXNAMELEN];/* Our name for authentication purposes */
extern char	remote_name[MAXNAMELEN]; /* Peer's name for authentication */
extern bool	explicit_remote;/* remote_name specified with remotename opt */

/* FIXME: make it a compile time option */
extern int	idle_time_limit;/* Shut down link if idle for this long */

extern int	phase;		/* Current state of link - see values below */
extern int	error_count;	/* # of times error() has been called */
extern int	unsuccess;	/* # unsuccessful connection attempts */
extern int	listen_time;	/* time to listen first (ms) */
extern int	status;		/* exit status for pppd */
extern int	need_holdoff;	/* Need holdoff period after link terminates */
/* FIXME: remove ifunit */
extern int	ifunit;		/* Interface unit number */
extern u_char	outpacket_buf[]; /* Buffer for outgoing packets */

/* FIXME: add more HAVE_MULTILINK */
extern bool	multilink;	/* enable multilink operation */

/* FIXME: it is really necessary ? */
extern int	maxconnect;	/* Maximum connect time (seconds) */

#ifdef HAVE_MULTILINK
extern bool	doing_multilink;
extern bool	multilink_master;
extern bool	bundle_eof;
extern bool	bundle_terminating;
#endif

#ifdef MAXOCTETS
extern unsigned int maxoctets;	     /* Maximum octetes per session (in bytes) */
extern int       maxoctets_dir;      /* Direction :
				      0 - in+out (default)
				      1 - in
				      2 - out
				      3 - max(in,out) */
extern int       maxoctets_timeout;  /* Timeout for check of octets limit */
#define PPP_OCTETS_DIRECTION_SUM        0
#define PPP_OCTETS_DIRECTION_IN         1
#define PPP_OCTETS_DIRECTION_OUT        2
#define PPP_OCTETS_DIRECTION_MAXOVERAL  3
/* same as previos, but little different on RADIUS side */
#define PPP_OCTETS_DIRECTION_MAXSESSION 4
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


/* Values for auth_pending, auth_done */
#if PAP_SUPPORT
#define PAP_WITHPEER	0x1
#define PAP_PEER	0x2
#endif /* PAP_SUPPORT */
#if CHAP_SUPPORT
#define CHAP_WITHPEER	0x4
#define CHAP_PEER	0x8
#endif /* CHAP_SUPPORT */
#if EAP_SUPPORT
#define EAP_WITHPEER	0x10
#define EAP_PEER	0x20
#endif /* EAP_SUPPORT */

/* Values for auth_done only */
#if CHAP_SUPPORT
#define CHAP_MD5_WITHPEER	0x40
#define CHAP_MD5_PEER		0x80
#if MSCHAP_SUPPORT
#define CHAP_MS_SHIFT		8	/* LSB position for MS auths */
#define CHAP_MS_WITHPEER	0x100
#define CHAP_MS_PEER		0x200
#define CHAP_MS2_WITHPEER	0x400
#define CHAP_MS2_PEER		0x800
#endif /* MSCHAP_SUPPORT */
#endif /* CHAP_SUPPORT */

/*
 * Values for phase.
 */
#define PHASE_DEAD		0
#define PHASE_INITIALIZE	1
#define PHASE_SERIALCONN	2
#define PHASE_DORMANT		3
#define PHASE_ESTABLISH		4
#define PHASE_AUTHENTICATE	5
#define PHASE_CALLBACK		6
#define PHASE_NETWORK		7
#define PHASE_RUNNING		8
#define PHASE_TERMINATE		9
#define PHASE_DISCONNECT	10
#define PHASE_HOLDOFF		11
#define PHASE_MASTER		12


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



/*
 * Inline versions of get/put char/short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */
#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}
#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}


#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}
#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}
#define PUTLONG(l, cp) { \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8); \
	*(cp)++ = (u_char) (l); \
}

#define INCPTR(n, cp)	((cp) += (n))
#define DECPTR(n, cp)	((cp) -= (n))

/*
 * System dependent definitions for user-level 4.3BSD UNIX implementation.
 */
#define TIMEOUT(f, a, t)    do { sys_untimeout((f), (a)); sys_timeout((t)*1000, (f), (a)); } while(0)
#define TIMEOUTMS(f, a, t)    do { sys_untimeout((f), (a)); sys_timeout((t), (f), (a)); } while(0)
#define UNTIMEOUT(f, a)     sys_untimeout((f), (a))

#define BZERO(s, n)		memset(s, 0, n)
#define	BCMP(s1, s2, l)		memcmp(s1, s2, l)

#define PRINTMSG(m, l)		{ info("Remote message: %0.*v", l, m); }

/*
 * MAKEHEADER - Add Header fields to a packet.
 */
#define MAKEHEADER(p, t) { \
    PUTCHAR(PPP_ALLSTATIONS, p); \
    PUTCHAR(PPP_UI, p); \
    PUTSHORT(t, p); }

/*
 * Exit status values.
 */
#define EXIT_OK			0
#define EXIT_FATAL_ERROR	1
#define EXIT_OPTION_ERROR	2
#define EXIT_NOT_ROOT		3
#define EXIT_NO_KERNEL_SUPPORT	4
#define EXIT_USER_REQUEST	5
#define EXIT_LOCK_FAILED	6
#define EXIT_OPEN_FAILED	7
#define EXIT_CONNECT_FAILED	8
#define EXIT_PTYCMD_FAILED	9
#define EXIT_NEGOTIATION_FAILED	10
#define EXIT_PEER_AUTH_FAILED	11
#define EXIT_IDLE_TIMEOUT	12
#define EXIT_CONNECT_TIME	13
#define EXIT_CALLBACK		14
#define EXIT_PEER_DEAD		15
#define EXIT_HANGUP		16
#define EXIT_LOOPBACK		17
#define EXIT_INIT_FAILED	18
#define EXIT_AUTH_TOPEER_FAILED	19
#ifdef MAXOCTETS
#define EXIT_TRAFFIC_LIMIT	20
#endif
#define EXIT_CNID_AUTH_FAILED	21

/* Procedures exported from auth.c */
void link_required __P((int));	  /* we are starting to use the link */
void link_terminated __P((int));  /* we are finished with the link */
void link_down __P((int));	  /* the LCP layer has left the Opened state */
void upper_layers_down __P((int));/* take all NCPs down */
void link_established __P((int)); /* the link is up; authenticate now */
void start_networks __P((int));   /* start all the network control protos */
void continue_networks __P((int)); /* start network [ip, etc] control protos */

void auth_peer_fail __P((int, int));
				/* peer failed to authenticate itself */
void auth_peer_success __P((int, int, int, char *, int));
				/* peer successfully authenticated itself */
void auth_withpeer_fail __P((int, int));
				/* we failed to authenticate ourselves */
void auth_withpeer_success __P((int, int, int));
				/* we successfully authenticated ourselves */
void np_up __P((int, int));	  /* a network protocol has come up */
void np_down __P((int, int));	  /* a network protocol has gone down */
void np_finished __P((int, int)); /* a network protocol no longer needs link */
void auth_reset __P((int));	/* check what secrets we have */
int  get_secret __P((int, char *, char *, char *, int *, int));
				/* get "secret" for chap */

/* Procedures exported from ipcp.c */
int parse_dotted_ip __P((char *, u_int32_t *));

/* Procedures exported from demand.c */
#if DEMAND_SUPPORT
void demand_conf __P((void));	/* config interface(s) for demand-dial */
void demand_block __P((void));	/* set all NPs to queue up packets */
void demand_unblock __P((void)); /* set all NPs to pass packets */
void demand_discard __P((void)); /* set all NPs to discard packets */
void demand_rexmit __P((int, u_int32_t)); /* retransmit saved frames for an NP*/
int  loop_chars __P((unsigned char *, int)); /* process chars from loopback */
int  loop_frame __P((unsigned char *, int)); /* should we bring link up? */
#endif /* DEMAND_SUPPORT */

/* Procedures exported from multilink.c */
#ifdef HAVE_MULTILINK
void mp_check_options __P((void)); /* Check multilink-related options */
int  mp_join_bundle __P((void));  /* join our link to an appropriate bundle */
void mp_exit_bundle __P((void));  /* have disconnected our link from bundle */
void mp_bundle_terminated __P((void));
char *epdisc_to_str __P((struct epdisc *)); /* string from endpoint discrim. */
int  str_to_epdisc __P((struct epdisc *, char *)); /* endpt disc. from str */
#else
#define mp_bundle_terminated()	/* nothing */
#define mp_exit_bundle()	/* nothing */
#define doing_multilink		0
#define multilink_master	0
#endif

/* Procedures exported from utils.c. */
void print_string __P((char *, int,  void (*) (void *, char *, ...),
		void *));	/* Format a string for output */
int slprintf __P((char *, int, char *, ...));		/* sprintf++ */
int vslprintf __P((char *, int, char *, va_list));	/* vsprintf++ */
size_t strlcpy __P((char *, const char *, size_t));	/* safe strcpy */
size_t strlcat __P((char *, const char *, size_t));	/* safe strncpy */
void dbglog __P((char *, ...));	/* log a debug message */
void info __P((char *, ...));	/* log an informational message */
void notice __P((char *, ...));	/* log a notice-level message */
void warn __P((char *, ...));	/* log a warning message */
void error __P((char *, ...));	/* log an error message */
void fatal __P((char *, ...));	/* log an error message and die(1) */
void init_pr_log __P((const char *, int)); /* initialize for using pr_log */
void pr_log __P((void *, char *, ...));	/* printer fn, output to syslog */
void end_pr_log __P((void));	/* finish up after using pr_log */
#if PRINTPKT_SUPPORT
void dump_packet __P((const char *, u_char *, int));
				/* dump packet to debug log if interesting */
#endif /* PRINTPKT_SUPPORT */
