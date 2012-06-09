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

#ifndef PPP_IMP_H_
#define PPP_IMP_H_

#include <stdio.h> /* formats */
#include <stdarg.h>

#ifndef bool
typedef unsigned char	bool;
#endif

#include "lwip/netif.h"
#include "lwip/def.h"
#include "lwip/timers.h"
#include "lwip/sio.h"

#include "ppp.h"
#include "pppdebug.h"

#ifdef INET6
#include "eui64.h"
#endif

/*
 * Limits.
 */
#define NUM_PPP		1	/* One PPP interface supported (per process) */
#define MAXWORDLEN	1024	/* max length of word in file (incl null) */
#define MAXARGS		1	/* max # args to a command */
#define MAXNAMELEN	256	/* max length of hostname or name for auth */
#define MAXSECRETLEN	256	/* max length of password or secret */


/*
 * The basic PPP frame.
 */
#define PPP_HDRLEN	4	/* octets for standard ppp header */
#define PPP_FCSLEN	2	/* octets for FCS */

#define PPP_ADDRESS(p)	(((u_char *)(p))[0])
#define PPP_CONTROL(p)	(((u_char *)(p))[1])
#define PPP_PROTOCOL(p)	((((u_char *)(p))[2] << 8) + ((u_char *)(p))[3])

/*
 * Significant octet values.
 */
#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI		0x03	/* Unnumbered Information */
#define	PPP_FLAG	0x7e	/* Flag Sequence */
#define	PPP_ESCAPE	0x7d	/* Asynchronous Control Escape */
#define	PPP_TRANS	0x20	/* Asynchronous transparency modifier */

/*
 * Protocol field values.
 */
#define PPP_IP		0x21	/* Internet Protocol */
#if 0 /* UNUSED */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#endif /* UNUSED */
#if VJ_SUPPORT
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#endif /* VJ_SUPPORT */
#ifdef INET6
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#endif /* INET6 */
#if CCP_SUPPORT
#define PPP_COMP	0xfd	/* compressed packet */
#endif /* CCP_SUPPORT */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#if 0 /* UNUSED */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#endif /* UNUSED */
#ifdef INET6
#define PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#endif /* INET6 */
#if CCP_SUPPORT
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#endif /* CCP_SUPPORT */
#if ECP_SUPPORT
#define PPP_ECP		0x8053	/* Encryption Control Protocol */
#endif /* ECP_SUPPORT */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#if PAP_SUPPORT
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#endif /* PAP_SUPPORT */
#if LQR_SUPPORT
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#endif /* LQR_SUPPORT */
#if CHAP_SUPPORT
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#endif /* CHAP_SUPPORT */
#if CBCP_SUPPORT
#define PPP_CBCP	0xc029	/* Callback Control Protocol */
#endif /* CBCP_SUPPORT */
#if EAP_SUPPORT
#define PPP_EAP		0xc227	/* Extensible Authentication Protocol */
#endif /* EAP_SUPPORT */

/*
 * Values for FCS calculations.
 */
#define PPP_INITFCS	0xffff	/* Initial FCS value */
#define PPP_GOODFCS	0xf0b8	/* Good final FCS value */
#define PPP_FCS(fcs, c)	(((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])

/*
 * A 32-bit unsigned integral type.
 */

#if !defined(__BIT_TYPES_DEFINED__) && !defined(_BITYPES) \
 && !defined(__FreeBSD__) && (NS_TARGET < 40)
#ifdef	UINT32_T
typedef UINT32_T	u_int32_t;
#else
typedef unsigned int	u_int32_t;
typedef unsigned short  u_int16_t;
#endif
#endif

/*
 * Extended asyncmap - allows any character to be escaped.
 */
typedef u_char  ext_accm[32];

/*
 * What to do with network protocol (NP) packets.
 */
enum NPmode {
    NPMODE_PASS,		/* pass the packet through */
    NPMODE_DROP,		/* silently drop the packet */
    NPMODE_ERROR,		/* return an error */
    NPMODE_QUEUE		/* save it up for later. */
};

/*
 * Statistics.
 */
#if PPP_STATS_SUPPORT
struct pppstat	{
    unsigned int ppp_ibytes;	/* bytes received */
    unsigned int ppp_ipackets;	/* packets received */
    unsigned int ppp_ierrors;	/* receive errors */
    unsigned int ppp_obytes;	/* bytes sent */
    unsigned int ppp_opackets;	/* packets sent */
    unsigned int ppp_oerrors;	/* transmit errors */
};

#if VJ_SUPPORT
struct vjstat {
    unsigned int vjs_packets;	/* outbound packets */
    unsigned int vjs_compressed; /* outbound compressed packets */
    unsigned int vjs_searches;	/* searches for connection state */
    unsigned int vjs_misses;	/* times couldn't find conn. state */
    unsigned int vjs_uncompressedin; /* inbound uncompressed packets */
    unsigned int vjs_compressedin; /* inbound compressed packets */
    unsigned int vjs_errorin;	/* inbound unknown type packets */
    unsigned int vjs_tossed;	/* inbound packets tossed because of error */
};
#endif /* VJ_SUPPORT */

struct ppp_stats {
    struct pppstat p;		/* basic PPP statistics */
#if VJ_SUPPORT
    struct vjstat vj;		/* VJ header compression statistics */
#endif /* VJ_SUPPORT */
};

#if CCP_SUPPORT
struct compstat {
    unsigned int unc_bytes;	/* total uncompressed bytes */
    unsigned int unc_packets;	/* total uncompressed packets */
    unsigned int comp_bytes;	/* compressed bytes */
    unsigned int comp_packets;	/* compressed packets */
    unsigned int inc_bytes;	/* incompressible bytes */
    unsigned int inc_packets;	/* incompressible packets */
    unsigned int ratio;		/* recent compression ratio << 8 */
};

struct ppp_comp_stats {
    struct compstat c;		/* packet compression statistics */
    struct compstat d;		/* packet decompression statistics */
};
#endif /* CCP_SUPPORT */

#endif /* PPP_STATS_SUPPORT */

/*
 * The following structure records the time in seconds since
 * the last NP packet was sent or received.
 */
/* FIXME: add idle time support and make it optional */
struct ppp_idle {
    time_t xmit_idle;		/* time since last NP packet sent */
    time_t recv_idle;		/* time since last NP packet received */
};

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

extern int	unsuccess;	/* # unsuccessful connection attempts */
extern int	listen_time;	/* time to listen first (ms) */
extern int	status;		/* exit status for pppd */
extern int	need_holdoff;	/* Need holdoff period after link terminates */
extern u_char	outpacket_buf[]; /* Buffer for outgoing packets */

#ifdef HAVE_MULTILINK
extern bool	multilink;	/* enable multilink operation */
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
    void (*init) (int unit);
    /* Process a received packet */
    void (*input) (int unit, u_char *pkt, int len);
    /* Process a received protocol-reject */
    void (*protrej) (int unit);
    /* Lower layer has come up */
    void (*lowerup) (int unit);
    /* Lower layer has gone down */
    void (*lowerdown) (int unit);
    /* Open the protocol */
    void (*open) (int unit);
    /* Close the protocol */
    void (*close) (int unit, char *reason);
#if PRINTPKT_SUPPORT
    /* Print a packet in readable form */
    int  (*printpkt) (u_char *pkt, int len,
			  void (*printer) (void *, char *, ...),
			  void *arg);
#endif /* PRINTPKT_SUPPORT */
    /* FIXME: data input is only used by CCP, which is not supported at this time,
     *        should we remove this entry and save some flash ?
     */
    /* Process a received data packet */
    void (*datainput) (int unit, u_char *pkt, int len);
    bool enabled_flag;		/* 0 iff protocol is disabled */
#if PRINTPKT_SUPPORT
    char *name;			/* Text name of protocol */
    char *data_name;		/* Text name of corresponding data protocol */
#endif /* PRINTPKT_SUPPORT */
#if PPP_OPTIONS
    option_t *options;		/* List of command-line options */
    /* Check requested options, assign defaults */
    void (*check_options) (void);
#endif /* PPP_OPTIONS */
#if DEMAND_SUPPORT
    /* Configure interface for demand-dial */
    int  (*demand_conf) (int unit);
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt) (u_char *pkt, int len);
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

/* FIXME: fill the struct below with option.c global variables */

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
  u_int  persist           : 1;       /* Persist mode, always try to reopen the connection */

  u_short idle_time_limit;	      /* Disconnect if idle for this many seconds */
  int  maxconnect;                    /* Maximum connect time (seconds) */

  char user       [MAXNAMELEN   + 1]; /* Username for PAP */
  char passwd     [MAXSECRETLEN + 1]; /* Password for PAP, secret for CHAP */
#if PPP_SERVER
  char our_name   [MAXNAMELEN   + 1]; /* Our name for authentication purposes */
#endif /* PPP_SERVER */
  /* FIXME: re-enable that */
  /*  char remote_name[MAXNAMELEN   + 1]; */ /* Peer's name for authentication */
};

struct ppp_settings ppp_settings;

/*
 * PPP interface RX control block.
 */
typedef struct ppp_control_rx_s {
  /** unit number / ppp descriptor */
  int pd;
  /** the rx file descriptor */
  sio_fd_t fd;
  /** receive buffer - encoded data is stored here */
#if PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD
  u_char rxbuf[PPPOS_RX_BUFSIZE];
#endif /* PPPOS_SUPPORT && PPP_INPROC_OWNTHREAD */

#if PPPOS_SUPPORT
  /* The input packet. */
  struct pbuf *in_head, *in_tail;

  u16_t in_protocol;             /* The input protocol code. */
  u16_t in_fcs;                  /* Input Frame Check Sequence value. */
  ppp_dev_states in_state;         /* The input process state. */
  char in_escaped;               /* Escape next character. */
  ext_accm in_accm;              /* Async-Ctl-Char-Map for input. */
#endif /* PPPOS_SUPPORT */
} ppp_control_rx;

/*
 * PPP interface control block.
 */
typedef struct ppp_control_s {
  ppp_control_rx rx;
  char open_flag;                /* True when in use. */
  u8_t phase;                    /* where the link is at */
#if PPPOE_SUPPORT
  struct netif *ethif;
  struct pppoe_softc *pppoe_sc;
#endif /* PPPOE_SUPPORT */
  int  if_up;                    /* True when the interface is up. */
  int  err_code;                 /* Code indicating why interface is down. */
#if PPPOS_SUPPORT
  sio_fd_t fd;                   /* File device ID of port. */
#endif /* PPPOS_SUPPORT */
  u16_t mtu;                     /* Peer's mru */
  int  pcomp;                    /* Does peer accept protocol compression? */
  int  accomp;                   /* Does peer accept addr/ctl compression? */
  u_long last_xmit;              /* Time of last transmission. */
#if PPPOS_SUPPORT
  ext_accm out_accm;             /* Async-Ctl-Char-Map for output. */
#endif /* PPPOS_SUPPORT */
#if PPPOS_SUPPORT && VJ_SUPPORT
  int  vj_enabled;               /* Flag indicating VJ compression enabled. */
  struct vjcompress vj_comp;     /* Van Jacobson compression header. */
#endif /* PPPOS_SUPPORT && VJ_SUPPORT */

  struct netif netif;

  struct ppp_addrs addrs;

  void (*link_status_cb)(void *ctx, int err_code, void *arg);
  void *link_status_ctx;

} ppp_control;

ppp_control ppp_control_list[NUM_PPP]; /* The PPP interface control blocks. */

/* PPP flow functions
 */
#if PPPOE_SUPPORT
void ppp_over_ethernet_init_failed(int pd);
/* function called by pppoe.c */
void ppp_input_over_ethernet(int pd, struct pbuf *pb);
#endif /* PPPOE_SUPPORT */

/* function called by all PPP subsystems to send packets */
int ppp_write(int pd, const u_char *s, int n);

/* functions called by auth.c link_terminated() */
void ppp_link_down(int pd);
void ppp_link_terminated(int pd);

/* merge a pbuf chain into one pbuf */
struct pbuf * ppp_singlebuf(struct pbuf *p);


/* Functions called by various PPP subsystems to configure
 * the PPP interface or change the PPP phase.
 */
void new_phase(int unit, int p);

#if PPPOS_SUPPORT
void ppp_set_xaccm(int unit, ext_accm *accm);
#endif /* PPPOS_SUPPORT */
int ppp_send_config(int unit, int mtu, u_int32_t accm, int pcomp, int accomp);
int ppp_recv_config(int unit, int mru, u_int32_t accm, int pcomp, int accomp);

int sifaddr(int unit, u_int32_t our_adr, u_int32_t his_adr, u_int32_t net_mask);
int cifaddr(int unit, u_int32_t our_adr, u_int32_t his_adr);

int sdns(int unit, u_int32_t ns1, u_int32_t ns2);
int cdns(int unit, u_int32_t ns1, u_int32_t ns2);

int sifup(int u);
int sifdown (int u);

int sifnpmode(int u, int proto, enum NPmode mode);

void netif_set_mtu(int unit, int mtu);
int netif_get_mtu(int unit);

int sifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway, bool replace);
int cifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway);

int sifproxyarp (int unit, u_int32_t his_adr);
int cifproxyarp (int unit, u_int32_t his_adr);

int sifvjcomp (int u, int vjcomp, int cidcomp, int maxcid);

int get_idle_time(int u, struct ppp_idle *ip);

int get_loop_output(void);

u_int32_t get_mask (u_int32_t addr);


/* Optional protocol names list, to make our messages a little more informative. */
#if PPP_PROTOCOLNAME
const char * protocol_name(int proto);
#endif /* PPP_PROTOCOLNAME  */


/* Optional stats support, to get some statistics on the PPP interface */
#if PPP_STATS_SUPPORT
void print_link_stats(void); /* Print stats, if available */
void reset_link_stats(int u); /* Reset (init) stats when link goes up */
void update_link_stats(int u); /* Get stats at link termination */
#endif /* PPP_STATS_SUPPORT */



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
void link_required (int);	  /* we are starting to use the link */
void link_terminated (int);  /* we are finished with the link */
void link_down (int);	  /* the LCP layer has left the Opened state */
void upper_layers_down (int);/* take all NCPs down */
void link_established (int); /* the link is up; authenticate now */
void start_networks (int);   /* start all the network control protos */
void continue_networks (int); /* start network [ip, etc] control protos */

void auth_peer_fail (int, int);
				/* peer failed to authenticate itself */
void auth_peer_success (int, int, int, char *, int);
				/* peer successfully authenticated itself */
void auth_withpeer_fail (int, int);
				/* we failed to authenticate ourselves */
void auth_withpeer_success (int, int, int);
				/* we successfully authenticated ourselves */
void np_up (int, int);	  /* a network protocol has come up */
void np_down (int, int);	  /* a network protocol has gone down */
void np_finished (int, int); /* a network protocol no longer needs link */
void auth_reset (int);	/* check what secrets we have */
int  get_secret (int, char *, char *, char *, int *, int);
				/* get "secret" for chap */

/* Procedures exported from ipcp.c */
/* int parse_dotted_ip (char *, u_int32_t *); */

/* Procedures exported from demand.c */
#if DEMAND_SUPPORT
void demand_conf (void);	/* config interface(s) for demand-dial */
void demand_block (void);	/* set all NPs to queue up packets */
void demand_unblock (void); /* set all NPs to pass packets */
void demand_discard (void); /* set all NPs to discard packets */
void demand_rexmit (int, u_int32_t); /* retransmit saved frames for an NP*/
int  loop_chars (unsigned char *, int); /* process chars from loopback */
int  loop_frame (unsigned char *, int); /* should we bring link up? */
#endif /* DEMAND_SUPPORT */

/* Procedures exported from multilink.c */
#ifdef HAVE_MULTILINK
void mp_check_options (void); /* Check multilink-related options */
int  mp_join_bundle (void);  /* join our link to an appropriate bundle */
void mp_exit_bundle (void);  /* have disconnected our link from bundle */
void mp_bundle_terminated (void);
char *epdisc_to_str (struct epdisc *); /* string from endpoint discrim. */
int  str_to_epdisc (struct epdisc *, char *); /* endpt disc. from str */
#else
#define mp_bundle_terminated()	/* nothing */
#define mp_exit_bundle()	/* nothing */
#define doing_multilink		0
#define multilink_master	0
#endif

/* Procedures exported from utils.c. */
void print_string (char *, int,  void (*) (void *, char *, ...),
		void *);	/* Format a string for output */
int slprintf (char *, int, char *, ...);		/* sprintf++ */
int vslprintf (char *, int, char *, va_list);	/* vsprintf++ */
size_t strlcpy (char *, const char *, size_t);	/* safe strcpy */
size_t strlcat (char *, const char *, size_t);	/* safe strncpy */
void dbglog (char *, ...);	/* log a debug message */
void info (char *, ...);	/* log an informational message */
void notice (char *, ...);	/* log a notice-level message */
void warn (char *, ...);	/* log a warning message */
void error (char *, ...);	/* log an error message */
void fatal (char *, ...);	/* log an error message and die(1) */
void init_pr_log (const char *, int); /* initialize for using pr_log */
void pr_log (void *, char *, ...);	/* printer fn, output to syslog */
void end_pr_log (void);	/* finish up after using pr_log */
#if PRINTPKT_SUPPORT
void dump_packet (const char *, u_char *, int);
				/* dump packet to debug log if interesting */
#endif /* PRINTPKT_SUPPORT */


#endif /* PPP_IMP_H_ */

#endif /* PPP_SUPPORT */
