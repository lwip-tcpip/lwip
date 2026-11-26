#include "test_pppos.h"

#include "lwip/netif.h"
#include "lwip/stats.h"
#include "netif/ppp/pppos.h"
#include "netif/ppp/ppp.h"

#if PPP_SUPPORT && PPPOS_SUPPORT
#ifdef PPP_INCLUDE_SETTINGS_HEADER
#undef PPP_INCLUDE_SETTINGS_HEADER /* including ppp_settings.h does not work at least for win32 port */
#endif
#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/fsm.h"
#include <string.h>

static struct netif pppos_netif;
static ppp_pcb *ppp;

/* Raw (HDLC encoded) bytes sent by the PPP stack */
static u8_t ppp_out[8192];
static u32_t ppp_out_len;

static u32_t ppp_output_cb(ppp_pcb *pcb, const void *data, u32_t len, void *ctx)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);

  if (ppp_out_len + len <= sizeof(ppp_out)) {
    memcpy(&ppp_out[ppp_out_len], data, len);
    ppp_out_len += len;
  }
  return len;
}

static void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(err_code);
  LWIP_UNUSED_ARG(ctx);
}

static u16_t pppos_test_fcs(const u8_t *p, u16_t len)
{
  u16_t fcs = 0xffff;
  int i;
  while (len--) {
    fcs ^= *p++;
    for (i = 0; i < 8; i++) {
      fcs = (fcs & 1) ? (u16_t)((fcs >> 1) ^ 0x8408) : (u16_t)(fcs >> 1);
    }
  }
  return (u16_t)~fcs;
}

/* Feed one PPP packet to pppos_input() as an HDLC frame, escaping all
 * control characters. */
static void pppos_test_send(u16_t protocol, const u8_t *data, u16_t len)
{
  static u8_t body[2048];
  static u8_t frame[4100];
  u16_t n = 0, i, fcs;
  int f = 0;

  fail_unless(len + 6 <= (int)sizeof(body));
  body[n++] = PPP_ALLSTATIONS;
  body[n++] = PPP_UI;
  body[n++] = (u8_t)(protocol >> 8);
  body[n++] = (u8_t)protocol;
  memcpy(&body[n], data, len);
  n += len;
  fcs = pppos_test_fcs(body, n);
  body[n++] = (u8_t)fcs;
  body[n++] = (u8_t)(fcs >> 8);

  frame[f++] = PPP_FLAG;
  for (i = 0; i < n; i++) {
    if (body[i] < 0x20 || body[i] == PPP_FLAG || body[i] == PPP_ESCAPE) {
      frame[f++] = PPP_ESCAPE;
      frame[f++] = (u8_t)(body[i] ^ PPP_TRANS);
    } else {
      frame[f++] = body[i];
    }
  }
  frame[f++] = PPP_FLAG;
  pppos_input(ppp, frame, f);
}

/* Search the frames sent so far for a control packet with the given
 * protocol, code and id (-1: any). Returns its length and copies it to
 * out, or -1. */
static int pppos_test_find(u16_t protocol, u8_t code, int id, u8_t *out, int size)
{
  static u8_t pkt[2048];
  u32_t pos = 0;

  while (pos < ppp_out_len) {
    int n = 0, escaped = 0, hdr;
    while (pos < ppp_out_len && ppp_out[pos] == PPP_FLAG) {
      pos++;
    }
    while (pos < ppp_out_len && ppp_out[pos] != PPP_FLAG) {
      u8_t c = ppp_out[pos++];
      if (c == PPP_ESCAPE) {
        escaped = 1;
        continue;
      }
      if (escaped) {
        c ^= PPP_TRANS;
        escaped = 0;
      }
      if (n < (int)sizeof(pkt)) {
        pkt[n++] = c;
      }
    }
    n -= 2; /* FCS */
    hdr = (n >= 2 && pkt[0] == PPP_ALLSTATIONS && pkt[1] == PPP_UI) ? 2 : 0;
    if (n - hdr >= 2 + HEADERLEN &&
        pkt[hdr] == (u8_t)(protocol >> 8) && pkt[hdr + 1] == (u8_t)protocol &&
        pkt[hdr + 2] == code && (id < 0 || pkt[hdr + 3] == id)) {
      n -= hdr + 2;
      fail_unless(n <= size);
      memcpy(out, &pkt[hdr + 2], n);
      return n;
    }
  }
  return -1;
}

static void pppos_setup(void)
{
  fail_if(ppp != NULL);
  ppp_out_len = 0;
  ppp = pppos_create(&pppos_netif, ppp_output_cb, ppp_link_status_cb, NULL);
  fail_if(ppp == NULL);
  ppp_connect(ppp, 0);
}

static void pppos_teardown(void)
{
  if (ppp != NULL) {
    err_t err;
    /* hack to ensure the ppp_pcb gets freed: */
    ppp->phase = PPP_PHASE_DEAD;
    err = ppp_free(ppp);
    fail_unless(err == ERR_OK);
    ppp = NULL;
  }
}

START_TEST(test_pppos_empty_packet_with_valid_fcs)
{
  u8_t two_breaks[] = { 0x7e, 0, 0, 0x7e };
  u8_t other_packet[] = { 0x7e, 0x7d, 0x20, 0x00, 0x7e };
  /* Set internal states of the underlying pcb */
  pppos_pcb *pppos = (pppos_pcb *)ppp->link_ctx_cb;

  LWIP_UNUSED_ARG(_i);

  pppos->open = 1;  /* Pretend the connection is open already */
  pppos->in_accm[0] = 0xf0;  /* Make sure 0x0's are not escaped chars */

  pppos_input(ppp, two_breaks, sizeof(two_breaks));
  pppos_input(ppp, other_packet, sizeof(other_packet));

}
END_TEST

/* An LCP Configure-Request with more Nak'd options than fit in the
 * Configure-Nak buffer of lcp_reqci() must not overflow that buffer. */
START_TEST(test_pppos_lcp_many_naked_options)
{
  static u8_t req[HEADERLEN + 370 * 4];
  static u8_t rsp[sizeof(req)];
  STAT_COUNTER illegal = lwip_stats.mem.illegal;
  u16_t len, i;
  int n;
  LWIP_UNUSED_ARG(_i);

  /* One MRU below PPP_MINMRU: Nak'd with PPP_MINMRU */
  len = HEADERLEN + 4;
  req[0] = CONFREQ; req[1] = 1; req[2] = 0; req[3] = (u8_t)len;
  req[4] = 1; req[5] = 4; req[6] = 0; req[7] = 64;
  pppos_test_send(PPP_LCP, req, len);
  n = pppos_test_find(PPP_LCP, CONFNAK, 1, rsp, sizeof(rsp));
  fail_unless(n == HEADERLEN + 4);
  fail_unless(rsp[4] == 1 && rsp[5] == 4 && rsp[6] == (PPP_MINMRU >> 8) && rsp[7] == (PPP_MINMRU & 0xff));

  /* The same option 370 times: the Naks would need 1480 bytes */
  len = HEADERLEN;
  for (i = 0; i < 370; i++) {
    req[len++] = 1; req[len++] = 4; req[len++] = 0; req[len++] = 64;
  }
  req[0] = CONFREQ; req[1] = 2; req[2] = (u8_t)(len >> 8); req[3] = (u8_t)len;
  pppos_test_send(PPP_LCP, req, len);
  fail_unless(lwip_stats.mem.illegal == illegal);
  n = pppos_test_find(PPP_LCP, CONFNAK, 2, rsp, sizeof(rsp));
  fail_unless(n > HEADERLEN && n <= HEADERLEN + PPP_CTRL_PBUF_UNKNOWN_SIZE);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
pppos_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_pppos_empty_packet_with_valid_fcs),
    TESTFUNC(test_pppos_lcp_many_naked_options)
  };
  return create_suite("PPPOS", tests, sizeof(tests)/sizeof(testfunc), pppos_setup, pppos_teardown);
}

#endif /* PPP_SUPPORT && PPPOS_SUPPORT */
