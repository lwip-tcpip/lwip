#include "test_lowpan6.h"

#include "netif/lowpan6.h"

#include "lwip/tcpip.h"

#if LWIP_IPV6 /* allow to build the unit tests without IPv6 support */

static struct netif test_netif_lowpan6;
static int linkoutput_ctr;
static int linkoutput_byte_ctr;

/* Helper functions */
static err_t
default_netif_linkoutput(struct netif *netif, struct pbuf *p)
{
  fail_unless(netif == &test_netif_lowpan6);
  fail_unless(p != NULL);
  linkoutput_ctr++;
  linkoutput_byte_ctr += p->tot_len;
  return ERR_OK;
}

static err_t
default_netif_init(struct netif *netif)
{
  fail_unless(netif == &test_netif_lowpan6);
  netif->name[0] = 'L';
  netif->name[1] = '6';
  netif->output_ip6 = lowpan6_output;
  netif->linkoutput = default_netif_linkoutput;
  netif->mtu = IP6_MIN_MTU_LENGTH;
  netif->hwaddr_len = 8;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_MLD6;
  netif->hwaddr[0] = 0x00;
  netif->hwaddr[1] = 0x23;
  netif->hwaddr[2] = 0xC1;
  netif->hwaddr[3] = 0xDE;
  netif->hwaddr[4] = 0xD0;
  netif->hwaddr[5] = 0x0D;
#if NETIF_MAX_HWADDR_LEN < 8
#error "6LowPAN needs NETIF_MAX_HWADDR_LEN == 8"
#endif
  netif->hwaddr[6] = 0x00;
  netif->hwaddr[7] = 0x01;
  netif_create_ip6_linklocal_address(netif, 1);
  return ERR_OK;
}

static void
default_netif_add(void)
{
  struct netif *n;
  fail_unless(netif_default == NULL);
  n = netif_add_noaddr(&test_netif_lowpan6, NULL, default_netif_init, lowpan6_input);
  fail_unless(n == &test_netif_lowpan6);
  netif_set_default(&test_netif_lowpan6);
}

static void
default_netif_remove(void)
{
  fail_unless(netif_default == &test_netif_lowpan6);
  netif_remove(&test_netif_lowpan6);
}

/* Setups/teardown functions */

static void
lowpan6_setup(void)
{
  default_netif_add();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
lowpan6_teardown(void)
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

START_TEST(test_6low_frag1_short)
{
  unsigned char frame[] = {
     0x61, 0xC8,                                     /* Frame Control */
     0x01,                                           /* Sequence Number */
     0xCD, 0xAB,                                     /* Dst PAN ID (LE) */
     0xFF, 0xFF,                                     /* Dst Short Addr (LE) */
     0x01, 0x00, 0x0D, 0xD0, 0xDE, 0xC1, 0x23, 0x00, /* Src Ext Addr */
     /* 6LoWPAN FRAG1 dispatch: b & 0xf8 == 0xc0 */
     0xC0, 0x08, /* datagram_size=8, high bits */
     0x00, 0x00, /* datagram_tag=0 */
     /* IPHC dispatch byte (0x60) - triggers lowpan6_decompress which will
      * fail because there's not enough data for the IPHC header */
     0x60 };

  struct pbuf* p;
  err_t err;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, sizeof(frame), PBUF_POOL);
  fail_unless(p != NULL);
  if (p == NULL) {
    return;
  }
  pbuf_take(p, frame, sizeof(frame));

  err = lowpan6_input(p, &test_netif_lowpan6);
  fail_unless(err == ERR_OK);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
lowpan6_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_6low_frag1_short)
  };
  return create_suite("6LoWPAN", tests, sizeof(tests)/sizeof(testfunc), lowpan6_setup, lowpan6_teardown);
}

#else /* LWIP_IPV6 */

/* allow to build the unit tests without IPv6 support */
START_TEST(test_lowpan6_dummy)
{
  LWIP_UNUSED_ARG(_i);
}
END_TEST

Suite *
lowpan6_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_lowpan6_dummy),
  };
  return create_suite("6LoWPAN", tests, sizeof(tests)/sizeof(testfunc), NULL, NULL);
}
#endif /* LWIP_IPV6 */
