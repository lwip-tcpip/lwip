#include "test_pppos.h"

#include "lwip/netif.h"
#include "netif/ppp/pppos.h"
#include "netif/ppp/ppp.h"
#include "netif/ppp/lcp.h"
#include "lwip/timeouts.h"
#include "arch/sys_arch.h"

#include <string.h>

#if PPP_SUPPORT && PPPOS_SUPPORT
static struct netif pppos_netif;
static ppp_pcb *ppp;

static u32_t ppp_output_cb(ppp_pcb *pcb, const void *data, u32_t len, void *ctx)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(data);
  LWIP_UNUSED_ARG(len);
  LWIP_UNUSED_ARG(ctx);

  return  0;
}

static void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(err_code);
  LWIP_UNUSED_ARG(ctx);
}

static void pppos_setup(void)
{
  ppp = pppos_create(&pppos_netif, ppp_output_cb, ppp_link_status_cb, NULL);
  fail_if(ppp == NULL);
  ppp_connect(ppp, 0);
}

static void
pppos_stop(void)
{
  int i;
  ppp_close(ppp, 0);
  for (i = 0; i < 20 && ppp->phase != PPP_PHASE_DEAD; i++) {
    lwip_sys_now += 1000;
    sys_check_timeouts();
  }
  fail_unless(ppp->phase == PPP_PHASE_DEAD);
}

static void pppos_teardown(void)
{
  if (ppp != NULL) {
    pppos_stop();
    fail_unless(ppp_free(ppp) == ERR_OK);
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

#if PPP_SERVER
static u8_t clientserver_output[64];
static u32_t clientserver_output_len;
static u32_t clientserver_write_limit;

static u32_t
clientserver_output_cb(ppp_pcb *pcb, const void *data, u32_t len, void *ctx)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);
  len = LWIP_MIN(len, clientserver_write_limit);
  fail_unless(clientserver_output_len + len <= sizeof(clientserver_output));
  MEMCPY(clientserver_output + clientserver_output_len, data, len);
  clientserver_output_len += len;
  return len;
}

static void
clientserver_listen(void)
{
  /* Stop the fixture's outbound connection before exercising a listener. */
  pppos_stop();
  ppp_set_silent(ppp, 1);
  ((pppos_pcb *)ppp->link_ctx_cb)->output_cb = clientserver_output_cb;
  clientserver_output_len = 0;
  clientserver_write_limit = sizeof(clientserver_output);
  fail_unless(ppp_listen(ppp) == ERR_OK);
}

#if PPPOS_CLIENTSERVER_SUPPORT
static void
clientserver_expect_reply(void)
{
  fail_unless(clientserver_output_len == 12);
  fail_unless(memcmp(clientserver_output, "CLIENTSERVER", 12) == 0);
}

START_TEST(test_pppos_clientserver_fragmented)
{
  int split;
  LWIP_UNUSED_ARG(_i);
  for (split = 0; split <= 6; split++) {
    clientserver_listen();
    pppos_input(ppp, "CLIENT", split);
    pppos_input(ppp, "CLIENT" + split, 6 - split);
    clientserver_expect_reply();
  }
}
END_TEST

START_TEST(test_pppos_clientserver_noise_and_repeated_request)
{
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  pppos_input(ppp, "noiseCLICCLIENT", sizeof("noiseCLICCLIENT") - 1);
  clientserver_expect_reply();
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(clientserver_output_len == 24);
  fail_unless(memcmp(clientserver_output + 12, "CLIENTSERVER", 12) == 0);
}
END_TEST

START_TEST(test_pppos_clientserver_partial_write)
{
  int i;
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  clientserver_write_limit = 0;
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(clientserver_output_len == 0);
  /* Receive while the reply is pending, without scheduling duplicate retries. */
  pppos_input(ppp, "CLIENT", 6);
  lwip_sys_now += 25;
  sys_check_timeouts();
  fail_unless(clientserver_output_len == 0);
  clientserver_write_limit = 3;
  for (i = 0; i < 4; i++) {
    lwip_sys_now += 25;
    sys_check_timeouts();
    fail_unless(clientserver_output_len == (u32_t)((i + 1) * 3));
  }
  clientserver_expect_reply();
  lwip_sys_now += 25;
  sys_check_timeouts();
  clientserver_expect_reply();
}
END_TEST

START_TEST(test_pppos_clientserver_plain_ppp)
{
  const u8_t flag = 0x7e;
  pppos_pcb *pppos = (pppos_pcb *)ppp->link_ctx_cb;
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  pppos_input(ppp, &flag, 1);
  fail_unless(pppos->in_state == PDADDRESS);
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(clientserver_output_len == 0);
}
END_TEST

START_TEST(test_pppos_clientserver_ppp_after_reply)
{
  const u8_t flag = 0x7e;
  pppos_pcb *pppos = (pppos_pcb *)ppp->link_ctx_cb;
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  pppos_input(ppp, "CLIENT", 6);
  clientserver_expect_reply();
  pppos_input(ppp, &flag, 1);
  fail_unless(pppos->in_state == PDADDRESS);
  pppos_input(ppp, "CLIENT", 6);
  clientserver_expect_reply();
}
END_TEST

START_TEST(test_pppos_clientserver_outbound)
{
  LWIP_UNUSED_ARG(_i);
  /* The fixture starts an outbound connection, which must ignore the preamble. */
  clientserver_output_len = 0;
  clientserver_write_limit = sizeof(clientserver_output);
  ((pppos_pcb *)ppp->link_ctx_cb)->output_cb = clientserver_output_cb;
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(clientserver_output_len == 0);
}
END_TEST

START_TEST(test_pppos_clientserver_close_and_restart)
{
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  clientserver_write_limit = 3;
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(clientserver_output_len == 3);
  ppp_close(ppp, 0);
  fail_unless(ppp->phase == PPP_PHASE_DEAD);
  clientserver_write_limit = sizeof(clientserver_output);
  lwip_sys_now += 25;
  sys_check_timeouts();
  fail_unless(clientserver_output_len == 3);
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(ppp->phase == PPP_PHASE_DEAD);
  fail_unless(clientserver_output_len == 3);
  clientserver_output_len = 0;
  fail_unless(ppp_listen(ppp) == ERR_OK);
  pppos_input(ppp, "CLIENT", 6);
  clientserver_expect_reply();
}
END_TEST

START_TEST(test_pppos_clientserver_failure_relisten)
{
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  pppos_input(ppp, "CLIENT", 6);
  clientserver_expect_reply();
  ppp->err_code = PPPERR_PROTOCOL;
  lcp_close(ppp, "test failure");
  fail_unless(ppp->phase == PPP_PHASE_DEAD);
  clientserver_output_len = 0;
  pppos_input(ppp, "CLI", 3);
  fail_unless(ppp->phase == PPP_PHASE_ESTABLISH);
  pppos_input(ppp, "ENT", 3);
  clientserver_expect_reply();
}
END_TEST

START_TEST(test_pppos_clientserver_free_cancels_retry)
{
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  clientserver_write_limit = 0;
  pppos_input(ppp, "CLIENT", 6);
  ppp_close(ppp, 0);
  fail_unless(ppp_free(ppp) == ERR_OK);
  ppp = NULL;
  clientserver_write_limit = sizeof(clientserver_output);
  lwip_sys_now += 25;
  sys_check_timeouts();
  fail_unless(clientserver_output_len == 0);
}
END_TEST
#else /* PPPOS_CLIENTSERVER_SUPPORT */
START_TEST(test_pppos_clientserver_disabled)
{
  LWIP_UNUSED_ARG(_i);
  clientserver_listen();
  pppos_input(ppp, "CLIENT", 6);
  fail_unless(clientserver_output_len == 0);
}
END_TEST
#endif /* PPPOS_CLIENTSERVER_SUPPORT */
#endif /* PPP_SERVER */

/** Create the suite including all tests for this module */
Suite *
pppos_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_pppos_empty_packet_with_valid_fcs)
#if PPP_SERVER
#if PPPOS_CLIENTSERVER_SUPPORT
    , TESTFUNC(test_pppos_clientserver_fragmented)
    , TESTFUNC(test_pppos_clientserver_noise_and_repeated_request)
    , TESTFUNC(test_pppos_clientserver_partial_write)
    , TESTFUNC(test_pppos_clientserver_plain_ppp)
    , TESTFUNC(test_pppos_clientserver_ppp_after_reply)
    , TESTFUNC(test_pppos_clientserver_outbound)
    , TESTFUNC(test_pppos_clientserver_close_and_restart)
    , TESTFUNC(test_pppos_clientserver_failure_relisten)
    , TESTFUNC(test_pppos_clientserver_free_cancels_retry)
#else
    , TESTFUNC(test_pppos_clientserver_disabled)
#endif
#endif
  };
  return create_suite("PPPOS", tests, sizeof(tests)/sizeof(testfunc), pppos_setup, pppos_teardown);
}

#endif /* PPP_SUPPORT && PPPOS_SUPPORT */
