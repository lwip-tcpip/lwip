#include "test_ip6.h"

#include "lwip/ethip6.h"
#include "lwip/ip6.h"
#include "lwip/inet_chksum.h"
#include "lwip/nd6.h"
#include "lwip/stats.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip6.h"

#include "lwip/tcpip.h"

#if LWIP_IPV6 /* allow to build the unit tests without IPv6 support */

static struct netif test_netif6;
static int linkoutput_ctr;

static err_t
dummy_input_function(struct pbuf *p, struct netif *inp)
{
  LWIP_UNUSED_ARG(p);
  LWIP_UNUSED_ARG(inp);
  fail("this netif should have no input");
  return ERR_VAL;
}

static err_t
default_netif_linkoutput(struct netif *netif, struct pbuf *p)
{
  fail_unless(netif == &test_netif6);
  fail_unless(p != NULL);
  linkoutput_ctr++;
  return ERR_OK;
}

static err_t
default_netif_init(struct netif *netif)
{
  fail_unless(netif != NULL);
  netif->linkoutput = default_netif_linkoutput;
  netif->output_ip6 = ethip6_output;
  netif->mtu = 1500;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  return ERR_OK;
}

static void
default_netif_add(void)
{
  struct netif *n;
  fail_unless(netif_default == NULL);
  n = netif_add_noaddr(&test_netif6, NULL, default_netif_init, dummy_input_function);
  fail_unless(n == &test_netif6);
  netif_set_default(&test_netif6);
}

static void
default_netif_remove(void)
{
  fail_unless(netif_default == &test_netif6);
  netif_remove(&test_netif6);
}

static void
ip6_test_handle_timers(int count)
{
  int i;
  for (i = 0; i < count; i++) {
    nd6_tmr();
  }
}

/* Setups/teardown functions */

static void
ip6_setup(void)
{
  default_netif_add();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
ip6_teardown(void)
{
  if (netif_list->loop_first != NULL) {
    pbuf_free(netif_list->loop_first);
    netif_list->loop_first = NULL;
  }
  netif_list->loop_last = NULL;
  /* poll until all memory is released... */
  tcpip_thread_poll_one();
  default_netif_remove();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}


/* Test functions */

static void
test_ip6_ll_addr_iter(int expected_ctr1, int expected_ctr2)
{
  fail_unless(linkoutput_ctr == 0);

  /* test that nothing is sent with link uo but netif down */
  netif_set_link_up(&test_netif6);
  ip6_test_handle_timers(500);
  fail_unless(linkoutput_ctr == 0);
  netif_set_link_down(&test_netif6);
  fail_unless(linkoutput_ctr == 0);

  /* test that nothing is sent with link down but netif up */
  netif_set_up(&test_netif6);
  ip6_test_handle_timers(500);
  fail_unless(linkoutput_ctr == 0);
  netif_set_down(&test_netif6);
  fail_unless(linkoutput_ctr == 0);

  /* test what is sent with link up + netif up */
  netif_set_link_up(&test_netif6);
  netif_set_up(&test_netif6);
  ip6_test_handle_timers(500);
  fail_unless(linkoutput_ctr == expected_ctr1);
  netif_set_down(&test_netif6);
  netif_set_link_down(&test_netif6);
  fail_unless(linkoutput_ctr == expected_ctr1);
  linkoutput_ctr = 0;

  netif_set_up(&test_netif6);
  netif_set_link_up(&test_netif6);
  ip6_test_handle_timers(500);
  fail_unless(linkoutput_ctr == expected_ctr2);
  netif_set_link_down(&test_netif6);
  netif_set_down(&test_netif6);
  fail_unless(linkoutput_ctr == expected_ctr2);
  linkoutput_ctr = 0;
}

START_TEST(test_ip6_ll_addr)
{
  LWIP_UNUSED_ARG(_i);

  /* test without link-local address */
  test_ip6_ll_addr_iter(0, 0);

  /* test with link-local address */
  netif_create_ip6_linklocal_address(&test_netif6, 1);
  test_ip6_ll_addr_iter(3 + LWIP_IPV6_DUP_DETECT_ATTEMPTS + LWIP_IPV6_MLD, 3);
}
END_TEST

START_TEST(test_ip6_aton_ipv4mapped)
{
  int ret;
  ip_addr_t addr;
  ip6_addr_t addr6;
  const ip_addr_t addr_expected = IPADDR6_INIT_HOST(0, 0, 0xFFFF, 0xD4CC65D2);
  LWIP_UNUSED_ARG(_i);

  /* check IPv6 representation */
  memset(&addr6, 0, sizeof(addr6));
  ret = ip6addr_aton("0:0:0:0:0:FFFF:D4CC:65D2", &addr6);
  fail_unless(ret == 1);
  fail_unless(memcmp(&addr6, &addr_expected, 16) == 0);
  memset(&addr, 0, sizeof(addr));
  ret = ipaddr_aton("0:0:0:0:0:FFFF:D4CC:65D2", &addr);
  fail_unless(ret == 1);
  fail_unless(memcmp(&addr, &addr_expected, 16) == 0);

  /* check shortened IPv6 representation */
  memset(&addr6, 0, sizeof(addr6));
  ret = ip6addr_aton("::FFFF:D4CC:65D2", &addr6);
  fail_unless(ret == 1);
  fail_unless(memcmp(&addr6, &addr_expected, 16) == 0);
  memset(&addr, 0, sizeof(addr));
  ret = ipaddr_aton("::FFFF:D4CC:65D2", &addr);
  fail_unless(ret == 1);
  fail_unless(memcmp(&addr, &addr_expected, 16) == 0);

  /* checked mixed representation */
  memset(&addr6, 0, sizeof(addr6));
  ret = ip6addr_aton("::FFFF:212.204.101.210", &addr6);
  fail_unless(ret == 1);
  fail_unless(memcmp(&addr6, &addr_expected, 16) == 0);
  memset(&addr, 0, sizeof(addr));
  ret = ipaddr_aton("::FFFF:212.204.101.210", &addr);
  fail_unless(ret == 1);
  fail_unless(memcmp(&addr, &addr_expected, 16) == 0);

  /* checked bogus mixed representation */
  memset(&addr6, 0, sizeof(addr6));
  ret = ip6addr_aton("::FFFF:212.204.101.2101", &addr6);
  fail_unless(ret == 0);
  memset(&addr, 0, sizeof(addr));
  ret = ipaddr_aton("::FFFF:212.204.101.2101", &addr);
  fail_unless(ret == 0);

}
END_TEST

/** Create the suite including all tests for this module */
Suite *
ip6_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_ip6_ll_addr),
    TESTFUNC(test_ip6_aton_ipv4mapped),
  };
  return create_suite("IPv6", tests, sizeof(tests)/sizeof(testfunc), ip6_setup, ip6_teardown);
}

#else /* LWIP_IPV6 */

/* allow to build the unit tests without IPv6 support */
START_TEST(test_ip6_dummy)
{
  LWIP_UNUSED_ARG(_i);
}
END_TEST

Suite *
ip6_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_ip6_dummy),
  };
  return create_suite("IPv6", tests, sizeof(tests)/sizeof(testfunc), NULL, NULL);
}
#endif /* LWIP_IPV6 */
