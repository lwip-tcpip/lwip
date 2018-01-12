#include "test_netif.h"

#include "lwip/netif.h"
#include "lwip/stats.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"

#if !LWIP_NETIF_EXT_STATUS_CALLBACK
#error "This tests needs LWIP_NETIF_EXT_STATUS_CALLBACK enabled"
#endif

struct netif net_test;


/* Setups/teardown functions */

static void
netif_setup(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
netif_teardown(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

/* test helper functions */

static err_t
testif_tx_func(struct netif *netif, struct pbuf *p)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static err_t
testif_init(struct netif *netif)
{
  netif->name[0] = 'c';
  netif->name[1] = 'h';
  netif->output = etharp_output;
  netif->linkoutput = testif_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = 6;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;

  netif->hwaddr[0] = 0x02;
  netif->hwaddr[1] = 0x03;
  netif->hwaddr[2] = 0x04;
  netif->hwaddr[3] = 0x05;
  netif->hwaddr[4] = 0x06;
  netif->hwaddr[5] = 0x07;

  return ERR_OK;
}

#define MAX_NSC_REASON_IDX 10
static int ext_cb_counters[MAX_NSC_REASON_IDX];
static netif_nsc_reason_t reasons;

static netif_ext_callback_args_t *expected_args;

static int dummy_active;

static void
test_netif_ext_callback_dummy(struct netif* netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t* args)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(reason);
  LWIP_UNUSED_ARG(args);

  fail_unless(dummy_active);
}

static void
test_netif_ext_callback(struct netif* netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t* args)
{
  int i;
  u32_t reason_flags = (u32_t)reason;
  u32_t mask;

  reasons = reasons | reason;

  fail_unless(netif == &net_test);
  fail_unless(reason != 0);
  fail_unless((((u32_t)reason) & ~((1U << MAX_NSC_REASON_IDX) - 1U)) == 0);

  LWIP_UNUSED_ARG(args);

  for (i = 0, mask = 1U; i < MAX_NSC_REASON_IDX; i++, mask <<= 1) {
    if (reason_flags & mask) {
      ext_cb_counters[i]++;
    }
  }
  if (expected_args != NULL) {
    fail_unless(memcmp(expected_args, args, sizeof(netif_ext_callback_args_t)) == 0);
  }
}

static void
test_netif_ext_callback_assert_flag_count(netif_nsc_reason_t reason, int expected_count)
{
  int i;
  u32_t reason_flags = (u32_t)reason;
  u32_t mask;
  for (i = 0, mask = 1U; i < MAX_NSC_REASON_IDX; i++, mask <<= 1) {
    if (reason_flags & mask) {
      fail_unless(ext_cb_counters[i] == expected_count);
    }
  }
}

static void
test_netif_ext_callback_reset(void)
{
  memset(ext_cb_counters, 0, sizeof(ext_cb_counters));
  reasons = 0;
}

/* Test functions */

NETIF_DECLARE_EXT_CALLBACK(netif_callback_1)
NETIF_DECLARE_EXT_CALLBACK(netif_callback_2)
NETIF_DECLARE_EXT_CALLBACK(netif_callback_3)

START_TEST(test_netif_extcallbacks)
{
  ip4_addr_t addr;
  ip4_addr_t netmask;
  ip4_addr_t gw;
  LWIP_UNUSED_ARG(_i);

  IP4_ADDR(&addr, 0, 0, 0, 0);
  IP4_ADDR(&netmask, 0, 0, 0, 0);
  IP4_ADDR(&gw, 0, 0, 0, 0);

  netif_add_ext_callback(&netif_callback_3, test_netif_ext_callback_dummy);
  netif_add_ext_callback(&netif_callback_2, test_netif_ext_callback);
  netif_add_ext_callback(&netif_callback_1, test_netif_ext_callback_dummy);

  dummy_active = 1;

  reasons = 0;
  netif_add(&net_test, &addr, &netmask, &gw, &net_test, testif_init, ethernet_input);
  fail_unless(reasons == LWIP_NSC_NETIF_ADDED);
  test_netif_ext_callback_assert_flag_count(LWIP_NSC_NETIF_ADDED, 1);
  test_netif_ext_callback_reset();

  netif_set_link_up(&net_test);
  fail_unless(reasons == LWIP_NSC_LINK_CHANGED);
  test_netif_ext_callback_assert_flag_count(LWIP_NSC_LINK_CHANGED, 1);
  test_netif_ext_callback_reset();
  netif_set_up(&net_test);
  fail_unless(reasons == LWIP_NSC_STATUS_CHANGED);
  test_netif_ext_callback_assert_flag_count(LWIP_NSC_STATUS_CHANGED, 1);
  test_netif_ext_callback_reset();

  IP4_ADDR(&addr, 1, 2, 3, 4);
  netif_set_ipaddr(&net_test, &addr);
  fail_unless(reasons == LWIP_NSC_IPV4_ADDRESS_CHANGED);
  test_netif_ext_callback_assert_flag_count(LWIP_NSC_IPV4_ADDRESS_CHANGED, 1);
  test_netif_ext_callback_reset();

  netif_remove(&net_test);
  fail_unless(reasons == (LWIP_NSC_NETIF_REMOVED | LWIP_NSC_STATUS_CHANGED));
  test_netif_ext_callback_assert_flag_count(LWIP_NSC_NETIF_REMOVED, 1);
  test_netif_ext_callback_assert_flag_count(LWIP_NSC_STATUS_CHANGED, 1);
  test_netif_ext_callback_reset();

  netif_remove_ext_callback(&netif_callback_2);
  netif_remove_ext_callback(&netif_callback_3);
  netif_remove_ext_callback(&netif_callback_1);
  dummy_active = 0;
}
END_TEST


/** Create the suite including all tests for this module */
Suite *
netif_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_netif_extcallbacks)
  };
  return create_suite("NETIF", tests, sizeof(tests)/sizeof(testfunc), netif_setup, netif_teardown);
}
