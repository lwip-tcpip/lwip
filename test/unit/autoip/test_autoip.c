/**
 * AutoIP + ACD tests for DHCP/AutoIP cooperation (LWIP_DHCP_AUTOIP_COOP).
 *
 * Before the ACD split (lwIP 2.1.3), rate limiting lived in autoip.c and was
 * re-applied from tried_llipaddr on every autoip_start_probing(). With ACD,
 * the wait is ACD_STATE_RATE_LIMIT, while dhcp_discover() may call
 * autoip_start() on every discover after LWIP_DHCP_AUTOIP_COOP_TRIES.
 */

#include "test_autoip.h"

#include "lwip/netif.h"
#include "lwip/autoip.h"
#include "lwip/acd.h"
#include "lwip/etharp.h"
#include "lwip/prot/acd.h"
#include "lwip/prot/autoip.h"
#include "netif/ethernet.h"

#include <string.h>

#if LWIP_IPV4 && LWIP_AUTOIP && LWIP_ACD

static struct netif net_test;
static struct autoip autoip_client;
static int txpacket;

static err_t lwip_tx_func(struct netif *netif, struct pbuf *p)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  txpacket++;
  return ERR_OK;
}

static err_t testif_init(struct netif *netif)
{
  netif->name[0] = 'a';
  netif->name[1] = 'i';
  netif->output = etharp_output;
  netif->linkoutput = lwip_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = 6;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
  netif->hwaddr[0] = 0x00;
  netif->hwaddr[1] = 0x23;
  netif->hwaddr[2] = 0xC1;
  netif->hwaddr[3] = 0xDE;
  netif->hwaddr[4] = 0xD0;
  netif->hwaddr[5] = 0x0D;
  return ERR_OK;
}

static void autoip_setup(void)
{
  ip4_addr_t addr, netmask, gw;
  txpacket = 0;
  IP4_ADDR(&addr, 0, 0, 0, 0);
  IP4_ADDR(&netmask, 0, 0, 0, 0);
  IP4_ADDR(&gw, 0, 0, 0, 0);
  memset(&autoip_client, 0, sizeof(autoip_client));
  netif_add(&net_test, &addr, &netmask, &gw, &net_test, testif_init, ethernet_input);
  autoip_set_struct(&net_test, &autoip_client);
  netif_set_link_up(&net_test);
  netif_set_up(&net_test);
}

static void autoip_teardown(void)
{
  autoip_stop(&net_test);
  autoip_remove_struct(&net_test);
  netif_remove(&net_test);
  memset(&net_test, 0, sizeof(net_test));
}

/** Inject an ARP reply claiming @a claim_ip from a foreign MAC (ACD conflict). */
static void send_arp_conflict(const ip4_addr_t *claim_ip)
{
  u8_t frame[42];
  struct pbuf *p;
  const u8_t foreign_mac[6] = { 0x00, 0x32, 0x44, 0x20, 0x01, 0x02 };
  u32_t sip = ip4_addr_get_u32(claim_ip);

  memset(frame, 0, sizeof(frame));
  /* eth dst = broadcast */
  memset(&frame[0], 0xff, 6);
  memcpy(&frame[6], foreign_mac, 6);
  frame[12] = 0x08;
  frame[13] = 0x06; /* ARP */
  frame[14] = 0x00;
  frame[15] = 0x01; /* hw eth */
  frame[16] = 0x08;
  frame[17] = 0x00; /* proto ip */
  frame[18] = 0x06;
  frame[19] = 0x04;
  frame[20] = 0x00;
  frame[21] = 0x02; /* reply */
  memcpy(&frame[22], foreign_mac, 6);
  memcpy(&frame[28], &sip, 4);
  memcpy(&frame[32], net_test.hwaddr, 6);
  /* target ip any */
  memset(&frame[38], 0, 4);

  p = pbuf_alloc(PBUF_RAW, sizeof(frame), PBUF_RAM);
  fail_unless(p != NULL);
  memcpy(p->payload, frame, sizeof(frame));
  net_test.input(p, &net_test);
}

/**
 * After ACD rate-limit decline, AutoIP is OFF but ACD stays in
 * ACD_STATE_RATE_LIMIT. A later autoip_start() (as from DHCP coop) must not
 * call acd_start() and wipe the rate-limit timer (RFC 3927 rate limiting).
 */
START_TEST(test_autoip_rate_limit_survives_coop_start)
{
  struct autoip *autoip;
  u16_t ttw_before;
  LWIP_UNUSED_ARG(_i);

  autoip_setup();
  fail_unless(autoip_start(&net_test) == ERR_OK);
  autoip = netif_autoip_data(&net_test);
  fail_unless(autoip != NULL);
  fail_unless(autoip->acd.state == ACD_STATE_PROBE_WAIT ||
              autoip->acd.state == ACD_STATE_PROBING);

  /* Drive conflicts until ACD enters RATE_LIMIT (MAX_CONFLICTS == 2 in lwipopts). */
  {
    int safety = 0;
    while (autoip->acd.state != ACD_STATE_RATE_LIMIT && safety < 20) {
      ip4_addr_t claim;
      if (autoip->acd.state == ACD_STATE_OFF ||
          autoip->acd.state == ACD_STATE_PROBE_WAIT ||
          autoip->acd.state == ACD_STATE_PROBING ||
          autoip->acd.state == ACD_STATE_ANNOUNCE_WAIT) {
        ip4_addr_copy(claim, autoip->acd.ipaddr);
        if (!ip4_addr_isany_val(claim)) {
          send_arp_conflict(&claim);
        }
      }
      acd_tmr();
      safety++;
    }
  }
  fail_unless(autoip->acd.state == ACD_STATE_RATE_LIMIT,
              "expected RATE_LIMIT after MAX_CONFLICTS, got %d",
              (int)autoip->acd.state);
  fail_unless(autoip->state == AUTOIP_STATE_OFF,
              "ACD_DECLINE should leave AutoIP OFF during rate limit");
  ttw_before = autoip->acd.ttw;
  fail_unless(ttw_before > 0);

  /* Simulate DHCP coop re-entry (dhcp_discover may call this every discover). */
  fail_unless(autoip_start(&net_test) == ERR_OK);

  fail_unless(autoip->acd.state == ACD_STATE_RATE_LIMIT,
              "autoip_start must not wipe ACD_STATE_RATE_LIMIT (got %d)",
              (int)autoip->acd.state);
  fail_unless(autoip->acd.ttw == ttw_before,
              "rate-limit ttw must be preserved across coop autoip_start");
  fail_unless(autoip->state == AUTOIP_STATE_OFF);

  autoip_teardown();
}
END_TEST

/**
 * After LL→routable, AutoIP ACD goes PASSIVE_ONGOING. A conflict on the
 * background LL address must restart AutoIP (ACD_RESTART_CLIENT), not only
 * ACD_DECLINE, so a new link-local address is selected and probed.
 */
START_TEST(test_autoip_passive_conflict_restarts)
{
  struct autoip *autoip;
  ip4_addr_t ll, routable, rmask, rgw;
  LWIP_UNUSED_ARG(_i);

  autoip_setup();
  fail_unless(autoip_start(&net_test) == ERR_OK);
  autoip = netif_autoip_data(&net_test);

  /* Complete probing/announcing into ONGOING + AutoIP BOUND. */
  {
    int ticks = 0;
    while (autoip->acd.state != ACD_STATE_ONGOING && ticks < 200) {
      acd_tmr();
      ticks++;
    }
  }
  fail_unless(autoip->acd.state == ACD_STATE_ONGOING,
              "ACD did not reach ONGOING (state=%d)", (int)autoip->acd.state);
  fail_unless(autoip->state == AUTOIP_STATE_BOUND);
  ip4_addr_copy(ll, autoip->llipaddr);

  /* LL → routable puts AutoIP ACD into PASSIVE_ONGOING. */
  IP4_ADDR(&routable, 192, 168, 1, 50);
  IP4_ADDR(&rmask, 255, 255, 255, 0);
  IP4_ADDR(&rgw, 192, 168, 1, 1);
  netif_set_addr(&net_test, &routable, &rmask, &rgw);
  fail_unless(autoip->acd.state == ACD_STATE_PASSIVE_ONGOING,
              "expected PASSIVE_ONGOING after LL->routable, got %d",
              (int)autoip->acd.state);

  send_arp_conflict(&ll);

  fail_unless(autoip->acd.state == ACD_STATE_PROBE_WAIT ||
              autoip->acd.state == ACD_STATE_PROBING,
              "passive conflict must ACD_RESTART_CLIENT (state=%d)",
              (int)autoip->acd.state);
  fail_unless(autoip->state == AUTOIP_STATE_CHECKING,
              "AutoIP should be CHECKING after passive restart");
  fail_if(ip4_addr_eq(&autoip->llipaddr, &ll),
          "should select a new LL address after passive decline");

  autoip_teardown();
}
END_TEST

Suite *
autoip_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_autoip_rate_limit_survives_coop_start),
    TESTFUNC(test_autoip_passive_conflict_restarts),
  };
  return create_suite("AUTOIP_ACD_COOP", tests, sizeof(tests) / sizeof(testfunc), NULL, NULL);
}

#else /* LWIP_IPV4 && LWIP_AUTOIP && LWIP_ACD */

Suite *
autoip_suite(void)
{
  return create_suite("AUTOIP_ACD_COOP", NULL, 0, NULL, NULL);
}

#endif /* LWIP_IPV4 && LWIP_AUTOIP && LWIP_ACD */
