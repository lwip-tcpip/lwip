/**
 * @file
 * Network Point to Point Protocol over Serial file.
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
#if PPP_SUPPORT && PPPOS_SUPPORT /* don't build if not configured for use in lwipopts.h */

#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/memp.h"
#include "lwip/netif.h"
#include "lwip/snmp.h"
#include "lwip/tcpip.h"
#include "lwip/api.h"
#include "lwip/sio.h"
#include "lwip/ip.h" /* for ip_input() */

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/pppos.h"
#include "netif/ppp/magic.h"
#include "netif/ppp/vj.h"

/*
 * Linked list of created PPPoS interfaces
 *
 * We only need to keep track of existing PPPoS interfaces if PPPoS
 * is not the only enabled protocol.
 *
 * PPP CORE does not have callbacks pointers for all PPPoS callbacks
 * which should actually be required for PPPoS (VJ config, asyncmap, ...),
 * there is too much callbacks to create and PPPoS must be kept light,
 * especially for users who are only using PPPoS.
 *
 * But there is a drawback, PPP CORE does not know which
 * lower protocols it is talking to thanks to the abstraction,
 * therefore if PPPoS is enabled as well as PPPoE or PPPoL2TP there
 * might be situation where PPP CORE calls pppos_ config functions
 * on interfaces which are NOT PPPoS one. This is very unlikely to
 * happen because protocols not supported by PPPoE or PPPoL2TP are
 * disabled at LCP/IPCP negotiation but we are better safe than sorry.
 *
 * So we check if passed PPP pointer to PPPoS configuration functions
 * is a PPPoS interface by checking against a linked list of existing
 * PPPoS interfaces.
 */
#define PPPOS_PCB_LIST (PPP_LINK_ENABLED_NUMBER > 1)
#if PPPOS_PCB_LIST
static pppos_pcb *pppos_pcb_list;
static u8_t pppos_exist(pppos_pcb *pppos);
#else /* PPPOS_PCB_LIST */
#define pppos_exist(pppos)     1
#endif /* PPPOS_PCB_LIST */

/* callbacks called from PPP core */
static int pppos_link_command_callback(void *pcb, u8_t command);
static int pppos_link_write_callback(void *pcb, struct pbuf *p);
static err_t pppos_link_netif_output_callback(void *pcb, struct pbuf *pb, u_short protocol);

/* Prototypes for procedures local to this file. */
static void pppos_connect(pppos_pcb *pppos);
static void pppos_disconnect(pppos_pcb *pppos);
static err_t pppos_destroy(pppos_pcb *pppos);
#if PPP_INPROC_MULTITHREADED
static void pppos_input_callback(void *arg);
#endif /* PPP_INPROC_MULTITHREADED */
static void pppos_xmit(pppos_pcb *pppos, struct pbuf *nb);
static void pppos_free_current_input_packet(pppos_pcb *pppos);
static struct pbuf *pppos_append(u_char c, struct pbuf *nb, ext_accm *out_accm);
static void pppos_drop(pppos_pcb *pppos);

/* PPP's Asynchronous-Control-Character-Map.  The mask array is used
 * to select the specific bit for a character. */
static const u_char ppp_accm_mask[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
#define ESCAPE_P(accm, c) ((accm)[(c) >> 3] & ppp_accm_mask[c & 0x07])

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
#define PPP_FCS(fcs, c) (((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])
#else /* PPP_FCS_TABLE */
/* The HDLC polynomial: X**0 + X**5 + X**12 + X**16 (0x8408) */
#define PPP_FCS_POLYNOMIAL 0x8408
static u16_t
ppp_get_fcs(u8_t byte)
{
  unsigned int octet;
  int bit;
  octet = byte;
  for (bit = 8; bit-- > 0; ) {
    octet = (octet & 0x01) ? ((octet >> 1) ^ PPP_FCS_POLYNOMIAL) : (octet >> 1);
  }
  return octet & 0xffff;
}
#define PPP_FCS(fcs, c) (((fcs) >> 8) ^ ppp_get_fcs(((fcs) ^ (c)) & 0xff))
#endif /* PPP_FCS_TABLE */

/*
 * Values for FCS calculations.
 */
#define PPP_INITFCS     0xffff  /* Initial FCS value */
#define PPP_GOODFCS     0xf0b8  /* Good final FCS value */



/*
 * Create a new PPP connection using the given serial I/O device.
 *
 * If this port connects to a modem, the modem connection must be
 * established before calling this.
 *
 * Return 0 on success, an error code on failure.
 */
ppp_pcb *pppos_create(struct netif *pppif, sio_fd_t fd,
       ppp_link_status_cb_fn link_status_cb, void *ctx_cb)
{
  pppos_pcb *pppos;
  ppp_pcb *ppp;

  ppp = ppp_new(pppif, link_status_cb, ctx_cb);
  if (ppp == NULL) {
    return NULL;
  }

  pppos = (pppos_pcb *)memp_malloc(MEMP_PPPOS_PCB);
  if (pppos == NULL) {
    ppp_free(ppp);
    return NULL;
  }

#if PPPOS_PCB_LIST
  /* put the new interface at the head of the list */
  pppos->next = pppos_pcb_list;
  pppos_pcb_list = pppos;
#endif /* PPPOS_PCB_LIST */

  pppos->ppp = ppp;
  pppos->fd = fd;
  ppp_link_set_callbacks(ppp, pppos_link_command_callback, pppos_link_write_callback, pppos_link_netif_output_callback, pppos);
  return ppp;
}

/* Called by PPP core */
static int
pppos_link_command_callback(void *pcb, u8_t command)
{
  pppos_pcb *pppos = (pppos_pcb *)pcb;

  switch(command) {
  case PPP_LINK_COMMAND_CONNECT:
    pppos_connect(pppos);
    break;

  case PPP_LINK_COMMAND_DISCONNECT:
    pppos_disconnect(pppos);
    break;

  case PPP_LINK_COMMAND_FREE:
    return pppos_destroy(pppos);

  default: ;
  }

  return PPPERR_NONE;
}

/* Called by PPP core */
static int
pppos_link_write_callback(void *pcb, struct pbuf *p)
{
  pppos_pcb *pppos = (pppos_pcb *)pcb;
  ppp_pcb *ppp = pppos->ppp;
  u_char *s = (u_char*)p->payload;
  int n = p->len;
  u_char c;
  u_int fcs_out;
  struct pbuf *head, *tail;

  head = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  if (head == NULL) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(ppp->netif);
    pbuf_free(p);
    return PPPERR_ALLOC;
  }

  tail = head;

  /* If the link has been idle, we'll send a fresh flag character to
   * flush any noise. */
  if ((sys_jiffies() - ppp->last_xmit) >= PPP_MAXIDLEFLAG) {
    tail = pppos_append(PPP_FLAG, tail, NULL);
  }
  ppp->last_xmit = sys_jiffies();

  fcs_out = PPP_INITFCS;
  /* Load output buffer. */
  while (n-- > 0) {
    c = *s++;

    /* Update FCS before checking for special characters. */
    fcs_out = PPP_FCS(fcs_out, c);

    /* Copy to output buffer escaping special characters. */
    tail = pppos_append(c, tail, &pppos->out_accm);
  }

  /* Add FCS and trailing flag. */
  c = ~fcs_out & 0xFF;
  tail = pppos_append(c, tail, &pppos->out_accm);
  c = (~fcs_out >> 8) & 0xFF;
  tail = pppos_append(c, tail, &pppos->out_accm);
  tail = pppos_append(PPP_FLAG, tail, NULL);

  /* If we failed to complete the packet, throw it away.
   * Otherwise send it. */
  if (!tail) {
    PPPDEBUG(LOG_WARNING,
             ("ppp_write[%d]: Alloc err - dropping pbuf len=%d\n", ppp->num, head->len));
           /*"ppp_write[%d]: Alloc err - dropping %d:%.*H", pd, head->len, LWIP_MIN(head->len * 2, 40), head->payload)); */
    pbuf_free(head);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.proterr);
    snmp_inc_ifoutdiscards(ppp->netif);
    pbuf_free(p);
    return PPPERR_ALLOC;
  }

  PPPDEBUG(LOG_INFO, ("ppp_write[%d]: len=%d\n", ppp->num, head->len));
                   /* "ppp_write[%d]: %d:%.*H", pd, head->len, LWIP_MIN(head->len * 2, 40), head->payload)); */
  pppos_xmit(pppos, head);
  pbuf_free(p);
  return PPPERR_NONE;
}

/* Called by PPP core */
static err_t
pppos_link_netif_output_callback(void *pcb, struct pbuf *pb, u_short protocol)
{
  pppos_pcb *pppos = (pppos_pcb *)pcb;
  ppp_pcb *ppp = pppos->ppp;
  u_int fcs_out = PPP_INITFCS;
  struct pbuf *head = NULL, *tail = NULL, *p;
  u_char c;

  /* Grab an output buffer. */
  head = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  if (head == NULL) {
    PPPDEBUG(LOG_WARNING, ("ppp_netif_output[%d]: first alloc fail\n", ppp->num));
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(ppp->netif);
    return ERR_MEM;
  }

#if VJ_SUPPORT
  /*
   * Attempt Van Jacobson header compression if VJ is configured and
   * this is an IP packet.
   */
  if (protocol == PPP_IP && ppp->vj_enabled) {
    switch (vj_compress_tcp(&pppos->vj_comp, pb)) {
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
        PPPDEBUG(LOG_WARNING, ("ppp_netif_output[%d]: bad IP packet\n", ppp->num));
        LINK_STATS_INC(link.proterr);
        LINK_STATS_INC(link.drop);
        snmp_inc_ifoutdiscards(ppp->netif);
        pbuf_free(head);
        return ERR_VAL;
    }
  }
#endif /* VJ_SUPPORT */

  tail = head;

  /* Build the PPP header. */
  if ((sys_jiffies() - ppp->last_xmit) >= PPP_MAXIDLEFLAG) {
    tail = pppos_append(PPP_FLAG, tail, NULL);
  }

  ppp->last_xmit = sys_jiffies();
  if (!ppp->accomp) {
    fcs_out = PPP_FCS(fcs_out, PPP_ALLSTATIONS);
    tail = pppos_append(PPP_ALLSTATIONS, tail, &pppos->out_accm);
    fcs_out = PPP_FCS(fcs_out, PPP_UI);
    tail = pppos_append(PPP_UI, tail, &pppos->out_accm);
  }
  if (!ppp->pcomp || protocol > 0xFF) {
    c = (protocol >> 8) & 0xFF;
    fcs_out = PPP_FCS(fcs_out, c);
    tail = pppos_append(c, tail, &pppos->out_accm);
  }
  c = protocol & 0xFF;
  fcs_out = PPP_FCS(fcs_out, c);
  tail = pppos_append(c, tail, &pppos->out_accm);

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
      tail = pppos_append(c, tail, &pppos->out_accm);
    }
  }

  /* Add FCS and trailing flag. */
  c = ~fcs_out & 0xFF;
  tail = pppos_append(c, tail, &pppos->out_accm);
  c = (~fcs_out >> 8) & 0xFF;
  tail = pppos_append(c, tail, &pppos->out_accm);
  tail = pppos_append(PPP_FLAG, tail, NULL);

  /* If we failed to complete the packet, throw it away. */
  if (!tail) {
    PPPDEBUG(LOG_WARNING,
             ("ppp_netif_output[%d]: Alloc err - dropping proto=%d\n",
              ppp->num, protocol));
    pbuf_free(head);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    snmp_inc_ifoutdiscards(ppp->netif);
    return ERR_MEM;
  }

  /* Send it. */
  PPPDEBUG(LOG_INFO, ("ppp_netif_output[%d]: proto=0x%"X16_F"\n", ppp->num, protocol));

  pppos_xmit(pppos, head);
  return ERR_OK;
}

#if PPPOS_PCB_LIST
static u8_t
pppos_exist(pppos_pcb *pppos)
{
  pppos_pcb *test;
  for (test = pppos_pcb_list; test != NULL; test = test->next) {
    if (test == pppos) {
      return 1;
    }
  }
  return 0;
}
#endif /* PPPOS_PCB_LIST */

static void
pppos_connect(pppos_pcb *pppos)
{
  ppp_pcb *ppp = pppos->ppp;
#if !VJ_SUPPORT
  ipcp_options *ipcp_wo;
  ipcp_options *ipcp_ao;
#endif /* !VJ_SUPPORT */

  /* input pbuf left over from last session? */
  pppos_free_current_input_packet(pppos);

  ppp_clear(ppp);
  /* reset PPPoS control block to its initial state */
  memset(&pppos->out_accm, 0, sizeof(pppos_pcb) - ( (char*)&((pppos_pcb*)0)->out_accm - (char*)0 ) );

#if VJ_SUPPORT
  vj_compress_init(&pppos->vj_comp);
#else /* VJ_SUPPORT */
  /* Don't even try to negotiate VJ if VJ is disabled */
  ipcp_wo = &ppp->ipcp_wantoptions;
  ipcp_wo->neg_vj = 0;
  ipcp_wo->old_vj = 0;

  ipcp_ao = &ppp->ipcp_allowoptions;
  ipcp_ao->neg_vj = 0;
  ipcp_ao->old_vj = 0;
#endif /* VJ_SUPPORT */

  /*
   * Default the in and out accm so that escape and flag characters
   * are always escaped.
   */
  pppos->in_accm[15] = 0x60; /* no need to protect since RX is not running */
  pppos->out_accm[15] = 0x60;

  /*
   * Start the connection and handle incoming events (packet or timeout).
   */
  PPPDEBUG(LOG_INFO, ("pppos_connect: unit %d: connecting\n", ppp->num));
  ppp_start(ppp); /* notify upper layers */
}

static void
pppos_disconnect(pppos_pcb *pppos)
{
  ppp_pcb *ppp = pppos->ppp;

  /* We cannot call ppp_free_current_input_packet() here because
   * rx thread might still call pppos_input()
   */
  ppp_link_end(ppp); /* notify upper layers */
}

static err_t
pppos_destroy(pppos_pcb *pppos)
{
#if PPPOS_PCB_LIST
  pppos_pcb **copp, *freep;

  /* remove interface from list */
  for (copp = &pppos_pcb_list; (freep = *copp); copp = &freep->next) {
    if (freep == pppos) {
       *copp = freep->next;
       break;
    }
  }
#endif /* PPPOS_PCB_LIST */

  /* input pbuf left ? */
  pppos_free_current_input_packet(pppos);

  memp_free(MEMP_PPPOS_PCB, pppos);
  return ERR_OK;
}

/** PPPoS input helper struct, must be packed since it is stored
 * to pbuf->payload, which might be unaligned. */
#if PPP_INPROC_MULTITHREADED
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct pppos_input_header {
  PACK_STRUCT_FIELD(ppp_pcb *ppp);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif
#endif /* PPP_INPROC_MULTITHREADED */

/** Pass received raw characters to PPPoS to be decoded. This function is
 * thread-safe and can be called from a dedicated RX-thread or from a main-loop.
 *
 * @param pcb PPP descriptor index, returned by ppp_new()
 * @param data received data
 * @param len length of received data
 */
void
pppos_input(ppp_pcb *ppp, u_char *s, int l)
{
  pppos_pcb *pppos = (pppos_pcb *)ppp->link_ctx_cb;
  struct pbuf *next_pbuf;
  u_char cur_char;
  u_char escaped;
  SYS_ARCH_DECL_PROTECT(lev);

  PPPDEBUG(LOG_DEBUG, ("pppos_input[%d]: got %d bytes\n", ppp->num, l));
  while (l-- > 0) {
    cur_char = *s++;

    SYS_ARCH_PROTECT(lev);
    escaped = ESCAPE_P(pppos->in_accm, cur_char);
    SYS_ARCH_UNPROTECT(lev);
    /* Handle special characters. */
    if (escaped) {
      /* Check for escape sequences. */
      /* XXX Note that this does not handle an escaped 0x5d character which
       * would appear as an escape character.  Since this is an ASCII ']'
       * and there is no reason that I know of to escape it, I won't complicate
       * the code to handle this case. GLL */
      if (cur_char == PPP_ESCAPE) {
        pppos->in_escaped = 1;
      /* Check for the flag character. */
      } else if (cur_char == PPP_FLAG) {
        /* If this is just an extra flag character, ignore it. */
        if (pppos->in_state <= PDADDRESS) {
          /* ignore it */;
        /* If we haven't received the packet header, drop what has come in. */
        } else if (pppos->in_state < PDDATA) {
          PPPDEBUG(LOG_WARNING,
                   ("pppos_input[%d]: Dropping incomplete packet %d\n",
                    ppp->num, pppos->in_state));
          LINK_STATS_INC(link.lenerr);
          pppos_drop(pppos);
        /* If the fcs is invalid, drop the packet. */
        } else if (pppos->in_fcs != PPP_GOODFCS) {
          PPPDEBUG(LOG_INFO,
                   ("pppos_input[%d]: Dropping bad fcs 0x%"X16_F" proto=0x%"X16_F"\n",
                    ppp->num, pppos->in_fcs, pppos->in_protocol));
          /* Note: If you get lots of these, check for UART frame errors or try different baud rate */
          LINK_STATS_INC(link.chkerr);
          pppos_drop(pppos);
        /* Otherwise it's a good packet so pass it on. */
        } else {
          struct pbuf *inp;
          /* Trim off the checksum. */
          if(pppos->in_tail->len > 2) {
            pppos->in_tail->len -= 2;

            pppos->in_tail->tot_len = pppos->in_tail->len;
            if (pppos->in_tail != pppos->in_head) {
              pbuf_cat(pppos->in_head, pppos->in_tail);
            }
          } else {
            pppos->in_tail->tot_len = pppos->in_tail->len;
            if (pppos->in_tail != pppos->in_head) {
              pbuf_cat(pppos->in_head, pppos->in_tail);
            }

            pbuf_realloc(pppos->in_head, pppos->in_head->tot_len - 2);
          }

          /* Dispatch the packet thereby consuming it. */
          inp = pppos->in_head;
          /* Packet consumed, release our references. */
          pppos->in_head = NULL;
          pppos->in_tail = NULL;
#if IP_FORWARD || LWIP_IPV6_FORWARD
          /* hide the room for Ethernet forwarding header */
          pbuf_header(inp, -(s16_t)PBUF_LINK_HLEN);
#endif /* IP_FORWARD || LWIP_IPV6_FORWARD */
#if PPP_INPROC_MULTITHREADED
          if(tcpip_callback_with_block(pppos_input_callback, inp, 0) != ERR_OK) {
            PPPDEBUG(LOG_ERR, ("pppos_input[%d]: tcpip_callback() failed, dropping packet\n", ppp->num));
            pbuf_free(inp);
            LINK_STATS_INC(link.drop);
            snmp_inc_ifindiscards(ppp->netif);
          }
#else /* PPP_INPROC_MULTITHREADED */
          ppp_input(pcb, inp);
#endif /* PPP_INPROC_MULTITHREADED */
        }

        /* Prepare for a new packet. */
        pppos->in_fcs = PPP_INITFCS;
        pppos->in_state = PDADDRESS;
        pppos->in_escaped = 0;
      /* Other characters are usually control characters that may have
       * been inserted by the physical layer so here we just drop them. */
      } else {
        PPPDEBUG(LOG_WARNING,
                 ("pppos_input[%d]: Dropping ACCM char <%d>\n", ppp->num, cur_char));
      }
    /* Process other characters. */
    } else {
      /* Unencode escaped characters. */
      if (pppos->in_escaped) {
        pppos->in_escaped = 0;
        cur_char ^= PPP_TRANS;
      }

      /* Process character relative to current state. */
      switch(pppos->in_state) {
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
          pppos->in_fcs = PPP_INITFCS;
          /* no break */
          /* Fall through */

        case PDADDRESS:                 /* Process address field. */
          if (cur_char == PPP_ALLSTATIONS) {
            pppos->in_state = PDCONTROL;
            break;
          }
          /* no break */

          /* Else assume compressed address and control fields so
           * fall through to get the protocol... */
        case PDCONTROL:                 /* Process control field. */
          /* If we don't get a valid control code, restart. */
          if (cur_char == PPP_UI) {
            pppos->in_state = PDPROTOCOL1;
            break;
          }
          /* no break */

#if 0
          else {
            PPPDEBUG(LOG_WARNING,
                     ("pppos_input[%d]: Invalid control <%d>\n", ppp->num, cur_char));
            pppos->in_state = PDSTART;
          }
#endif
        case PDPROTOCOL1:               /* Process protocol field 1. */
          /* If the lower bit is set, this is the end of the protocol
           * field. */
          if (cur_char & 1) {
            pppos->in_protocol = cur_char;
            pppos->in_state = PDDATA;
          } else {
            pppos->in_protocol = (u_int)cur_char << 8;
            pppos->in_state = PDPROTOCOL2;
          }
          break;
        case PDPROTOCOL2:               /* Process protocol field 2. */
          pppos->in_protocol |= cur_char;
          pppos->in_state = PDDATA;
          break;
        case PDDATA:                    /* Process data byte. */
          /* Make space to receive processed data. */
          if (pppos->in_tail == NULL || pppos->in_tail->len == PBUF_POOL_BUFSIZE) {
            u16_t pbuf_alloc_len;
            if (pppos->in_tail != NULL) {
              pppos->in_tail->tot_len = pppos->in_tail->len;
              if (pppos->in_tail != pppos->in_head) {
                pbuf_cat(pppos->in_head, pppos->in_tail);
                /* give up the in_tail reference now */
                pppos->in_tail = NULL;
              }
            }
            /* If we haven't started a packet, we need a packet header. */
            pbuf_alloc_len = 0;
#if IP_FORWARD || LWIP_IPV6_FORWARD
            /* If IP forwarding is enabled we are reserving PBUF_LINK_HLEN bytes so
             * the packet is being allocated with enough header space to be
             * forwarded (to Ethernet for example).
             */
            if (pppos->in_head == NULL) {
              pbuf_alloc_len = PBUF_LINK_HLEN;
            }
#endif /* IP_FORWARD || LWIP_IPV6_FORWARD */
            next_pbuf = pbuf_alloc(PBUF_RAW, pbuf_alloc_len, PBUF_POOL);
            if (next_pbuf == NULL) {
              /* No free buffers.  Drop the input packet and let the
               * higher layers deal with it.  Continue processing
               * the received pbuf chain in case a new packet starts. */
              PPPDEBUG(LOG_ERR, ("pppos_input[%d]: NO FREE PBUFS!\n", ppp->num));
              LINK_STATS_INC(link.memerr);
              pppos_drop(pppos);
              pppos->in_state = PDSTART;  /* Wait for flag sequence. */
              break;
            }
            if (pppos->in_head == NULL) {
              u8_t *payload = ((u8_t*)next_pbuf->payload) + pbuf_alloc_len;
#if PPP_INPROC_MULTITHREADED
              ((struct pppos_input_header*)payload)->ppp = ppp;
              payload += sizeof(struct pppos_input_header);
              next_pbuf->len += sizeof(struct pppos_input_header);
#endif /* PPP_INPROC_MULTITHREADED */
              next_pbuf->len += sizeof(pppos->in_protocol);
              *(payload++) = pppos->in_protocol >> 8;
              *(payload) = pppos->in_protocol & 0xFF;
              pppos->in_head = next_pbuf;
            }
            pppos->in_tail = next_pbuf;
          }
          /* Load character into buffer. */
          ((u_char*)pppos->in_tail->payload)[pppos->in_tail->len++] = cur_char;
          break;
        default:
          break;
      }

      /* update the frame check sequence number. */
      pppos->in_fcs = PPP_FCS(pppos->in_fcs, cur_char);
    }
  } /* while (l-- > 0), all bytes processed */

  magic_randomize();
}

#if PPP_INPROC_MULTITHREADED
/* PPPoS input callback using one input pointer
 */
static void pppos_input_callback(void *arg) {
  struct pbuf *pb = (struct pbuf*)arg;
  ppp_pcb *ppp;

  ppp = ((struct pppos_input_header*)pb->payload)->ppp;
  if(pbuf_header(pb, -(s16_t)sizeof(struct pppos_input_header))) {
    LWIP_ASSERT("pbuf_header failed\n", 0);
    goto drop;
  }

  /* Dispatch the packet thereby consuming it. */
  ppp_input(ppp, pb);
  return;

drop:
  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(ppp->netif);
  pbuf_free(pb);
}
#endif /* PPP_INPROC_MULTITHREADED */

void
pppos_accm_out_config(pppos_pcb *pppos, u32_t accm)
{
  int i;

  if (!pppos_exist(pppos)) {
    return;
  }

  /* Load the ACCM bits for the 32 control codes. */
  for (i = 0; i < 32/8; i++) {
    pppos->out_accm[i] = (u_char)((accm >> (8 * i)) & 0xFF);
  }

  PPPDEBUG(LOG_INFO, ("pppos_accm_out_config[%d]: in_accm=%X %X %X %X\n",
            pppos->ppp->num,
            pppos->out_accm[0], pppos->out_accm[1], pppos->out_accm[2], pppos->out_accm[3]));
}

void
pppos_accm_in_config(pppos_pcb *pppos, u32_t accm)
{
  int i;
  SYS_ARCH_DECL_PROTECT(lev);

  if (!pppos_exist(pppos)) {
    return;
  }

  /* Load the ACCM bits for the 32 control codes. */
  SYS_ARCH_PROTECT(lev);
  for (i = 0; i < 32 / 8; i++) {
    pppos->in_accm[i] = (u_char)(accm >> (i * 8));
  }
  SYS_ARCH_UNPROTECT(lev);

  PPPDEBUG(LOG_INFO, ("pppos_accm_in_config[%d]: in_accm=%X %X %X %X\n",
            pppos->ppp->num,
            pppos->in_accm[0], pppos->in_accm[1], pppos->in_accm[2], pppos->in_accm[3]));
}

sio_fd_t
pppos_get_fd(pppos_pcb *pppos)
{
  if (!pppos_exist(pppos)) {
    return 0;
  }
  return pppos->fd;
}

#if VJ_SUPPORT
void
pppos_vjc_config(pppos_pcb *pppos, int vjcomp, int cidcomp, int maxcid)
{
  ppp_pcb *ppp;

  if (!pppos_exist(pppos)) {
    return;
  }

  ppp = pppos->ppp;
  ppp->vj_enabled = vjcomp;
  pppos->vj_comp.compressSlot = cidcomp;
  pppos->vj_comp.maxSlotIndex = maxcid;
  PPPDEBUG(LOG_INFO, ("pppos_vjc_config[%d]: VJ compress enable=%d slot=%d max slot=%d\n",
            ppp->num, vjcomp, cidcomp, maxcid));
}

int
pppos_vjc_comp(pppos_pcb *pppos, struct pbuf *pb)
{
  ppp_pcb *ppp = pppos->ppp;
  int ret;
  PPPDEBUG(LOG_INFO, ("pppos_vjc_comp[%d]: vj_comp in pbuf len=%d\n", ppp->num, pb->len));

  /*
   * Clip off the VJ header and prepend the rebuilt TCP/IP header and
   * pass the result to IP.
   */
  ret = vj_uncompress_tcp(&pb, &pppos->vj_comp);
  if (ret >= 0) {
    ip_input(pb, ppp->netif);
    return ret;
  }

  /* Something's wrong so drop it. */
  PPPDEBUG(LOG_WARNING, ("pppos_vjc_comp[%d]: Dropping VJ compressed\n", ppp->num));
  return -1;
}

int
pppos_vjc_uncomp(pppos_pcb *pppos, struct pbuf *pb)
{
  ppp_pcb *ppp = pppos->ppp;
  int ret;
  PPPDEBUG(LOG_INFO, ("pppos_vjc_uncomp[%d]: vj_un in pbuf len=%d\n", ppp->num, pb->len));

  /*
   * Process the TCP/IP header for VJ header compression and then pass
   * the packet to IP.
   */
  ret = vj_uncompress_uncomp(pb, &pppos->vj_comp);
  if (ret >= 0) {
    ip_input(pb, ppp->netif);
    return ret;
  }

  /* Something's wrong so drop it. */
  PPPDEBUG(LOG_WARNING, ("pppos_vjc_uncomp[%d]: Dropping VJ uncompressed\n", ppp->num));
  return -1;
}
#endif /* VJ_SUPPORT */

static void
pppos_xmit(pppos_pcb *pppos, struct pbuf *nb)
{
  ppp_pcb *ppp = pppos->ppp;
  struct pbuf *b;
  int c;

  for(b = nb; b != NULL; b = b->next) {
    c = sio_write(pppos->fd, (u8_t*)b->payload, b->len);
    if(c != b->len) {
      PPPDEBUG(LOG_WARNING,
               ("PPP pppos_xmit: incomplete sio_write(fd:%"SZT_F", len:%d, c: 0x%"X8_F") c = %d\n", (size_t)pppos->fd, b->len, c, c));
      LINK_STATS_INC(link.err);
      ppp->last_xmit = 0; /* prepend PPP_FLAG to next packet */
      snmp_inc_ifoutdiscards(ppp->netif);
      pbuf_free(nb);
      return;
    }
  }

  snmp_add_ifoutoctets(ppp->netif, nb->tot_len);
  snmp_inc_ifoutucastpkts(ppp->netif);
  pbuf_free(nb);
  LINK_STATS_INC(link.xmit);
}

/*
 * Drop the input packet.
 */
static void
pppos_free_current_input_packet(pppos_pcb *pppos)
{
  if (pppos->in_head != NULL) {
    if (pppos->in_tail && (pppos->in_tail != pppos->in_head)) {
      pbuf_free(pppos->in_tail);
    }
    pbuf_free(pppos->in_head);
    pppos->in_head = NULL;
  }
  pppos->in_tail = NULL;
}

/*
 * pppos_append - append given character to end of given pbuf.  If out_accm
 * is not NULL and the character needs to be escaped, do so.
 * If pbuf is full, append another.
 * Return the current pbuf.
 */
static struct pbuf *
pppos_append(u_char c, struct pbuf *nb, ext_accm *out_accm)
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

/*
 * Drop the input packet and increase error counters.
 */
static void
pppos_drop(pppos_pcb *pppos)
{
#if LWIP_SNMP
  ppp_pcb *ppp = pppos->ppp;
#endif /* LWIP_SNMP || VJ_SUPPORT */
  if (pppos->in_head != NULL) {
#if 0
    PPPDEBUG(LOG_INFO, ("pppos_drop: %d:%.*H\n", pppos->in_head->len, min(60, pppos->in_head->len * 2), pppos->in_head->payload));
#endif
    PPPDEBUG(LOG_INFO, ("pppos_drop: pbuf len=%d, addr %p\n", pppos->in_head->len, (void*)pppos->in_head));
  }
  pppos_free_current_input_packet(pppos);
#if VJ_SUPPORT
  vj_uncompress_err(&pppos->vj_comp);
#endif /* VJ_SUPPORT */

  LINK_STATS_INC(link.drop);
  snmp_inc_ifindiscards(ppp->netif);
}
#endif /* PPP_SUPPORT && PPPOS_SUPPORT */
