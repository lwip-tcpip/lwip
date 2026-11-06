#include "test_mqtt.h"

#include "lwip/pbuf.h"
#include "lwip/apps/mqtt.h"
#include "lwip/apps/mqtt_priv.h"
#include "lwip/netif.h"

const ip_addr_t test_mqtt_local_ip = IPADDR4_INIT_BYTES(192, 168, 1, 1);
const ip_addr_t test_mqtt_remote_ip = IPADDR4_INIT_BYTES(192, 168, 1, 2);
const ip_addr_t test_mqtt_netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);

static err_t test_mqtt_netif_output(struct netif *netif, struct pbuf *p,
       const ip4_addr_t *ipaddr)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(ipaddr);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static void
test_mqtt_init_netif(struct netif *netif, const ip_addr_t *ip_addr, const ip_addr_t *netmask)
{
  struct netif *n;
  memset(netif, 0, sizeof(struct netif));
  netif->output = test_mqtt_netif_output;
  netif->flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
  ip_addr_copy_from_ip4(netif->netmask, *ip_2_ip4(netmask));
  ip_addr_copy_from_ip4(netif->ip_addr, *ip_2_ip4(ip_addr));
  for (n = netif_list; n != NULL; n = n->next) {
    if (n == netif) {
      return;
    }
  }
  netif->next = NULL;
  netif_list = netif;
}

/* Setups/teardown functions */
static struct netif *old_netif_list;
static struct netif *old_netif_default;

static void
mqtt_setup(void)
{
  old_netif_list = netif_list;
  old_netif_default = netif_default;
  netif_list = NULL;
  netif_default = NULL;
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
mqtt_teardown(void)
{
  netif_list = NULL;
  netif_default = NULL;
  /* restore netif_list for next tests (e.g. loopif) */
  netif_list = old_netif_list;
  netif_default = old_netif_default;
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void test_mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status)
{
  LWIP_UNUSED_ARG(client);
  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(status);
}

START_TEST(basic_connect)
{
  mqtt_client_t* client;
  struct netif netif;
  err_t err;
  struct mqtt_connect_client_info_t client_info = {
    "dumm",
    NULL, NULL,
    10,
    NULL, NULL, 0, 0, 0
  };
  struct pbuf *p;
  unsigned char rxbuf[] = {0x20, 0x02, 0x00, 0x00};
  LWIP_UNUSED_ARG(_i);

  test_mqtt_init_netif(&netif, &test_mqtt_local_ip, &test_mqtt_netmask);

  client = mqtt_client_new();
  fail_unless(client != NULL);
  err = mqtt_client_connect(client, &test_mqtt_remote_ip, 1234, test_mqtt_connection_cb, NULL, &client_info);
  fail_unless(err == ERR_OK);

  client->conn->connected(client->conn->callback_arg, client->conn, ERR_OK);
  p = pbuf_alloc(PBUF_RAW, sizeof(rxbuf), PBUF_REF);
  fail_unless(p != NULL);
  p->payload = rxbuf;
  /* since we hack the rx path, we have to hack the rx window, too: */
  client->conn->rcv_wnd -= p->tot_len;
  if (client->conn->recv(client->conn->callback_arg, client->conn, p, ERR_OK) != ERR_OK) {
    pbuf_free(p);
  }

  mqtt_disconnect(client);
  /* fixme: mqtt_client_fre() is missing... */
  mem_free(client);
}
END_TEST

START_TEST(rx_overflow)
{
  mqtt_client_t* client;
  struct netif netif;
  err_t err;
  struct mqtt_connect_client_info_t client_info = {
    "dumm",
    NULL, NULL,
    10,
    NULL, NULL, 0, 0, 0
  };
  struct pbuf* p;
  unsigned char rxbuf[400];
  LWIP_UNUSED_ARG(_i);

  test_mqtt_init_netif(&netif, &test_mqtt_local_ip, &test_mqtt_netmask);

  client = mqtt_client_new();
  fail_unless(client != NULL);
  err = mqtt_client_connect(client, &test_mqtt_remote_ip, 1234, test_mqtt_connection_cb, NULL, &client_info);
  fail_unless(err == ERR_OK);

  client->conn->connected(client->conn->callback_arg, client->conn, ERR_OK);
  memset(rxbuf, 0xff, sizeof(rxbuf));
  p = pbuf_alloc(PBUF_RAW, sizeof(rxbuf), PBUF_REF);
  fail_unless(p != NULL);
  p->payload = rxbuf;
  /* since we hack the rx path, we have to hack the rx window, too: */
  client->conn->rcv_wnd -= p->tot_len;
  if (client->conn->recv(client->conn->callback_arg, client->conn, p, ERR_OK) != ERR_OK) {
    pbuf_free(p);
  }

  mqtt_disconnect(client);
  /* fixme: mqtt_client_fre() is missing... */
  mem_free(client);
}
END_TEST

struct remaining_length_state {
  unsigned int accepted;
  unsigned int disconnected;
};

static void
test_mqtt_remaining_length_cb(mqtt_client_t *client, void *arg,
                              mqtt_connection_status_t status)
{
  struct remaining_length_state *state = (struct remaining_length_state *)arg;
  LWIP_UNUSED_ARG(client);
  if (status == MQTT_CONNECT_ACCEPTED) {
    state->accepted++;
  } else {
    fail_unless(status == MQTT_CONNECT_DISCONNECTED);
    state->disconnected++;
  }
}

static void
test_mqtt_feed(mqtt_client_t *client, const u8_t *data, u16_t len)
{
  struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
  fail_unless(client->conn != NULL);
  fail_unless(p != NULL);
  fail_unless(pbuf_take(p, data, len) == ERR_OK);
  client->conn->rcv_wnd -= len;
  fail_unless(client->conn->recv(client->conn->callback_arg, client->conn, p, ERR_OK) == ERR_OK);
}

static void
test_mqtt_remaining_length(const u8_t *packet, u16_t len, u16_t chunk, int valid)
{
  static const u8_t connack[] = {0x20, 0x02, 0x00, 0x00};
  struct mqtt_connect_client_info_t info = {
    "length-test", NULL, NULL, 10, NULL, NULL, 0, 0, 0
  };
  struct remaining_length_state state = {0, 0};
  struct netif netif;
  struct netif *saved_netif_list = netif_list;
  mqtt_client_t *client;
  u16_t offset;

  test_mqtt_init_netif(&netif, &test_mqtt_local_ip, &test_mqtt_netmask);
  client = mqtt_client_new();
  fail_unless(client != NULL);
  fail_unless(mqtt_client_connect(client, &test_mqtt_remote_ip, 1234,
                                  test_mqtt_remaining_length_cb, &state, &info) == ERR_OK);
  fail_unless(client->conn->connected(client->conn->callback_arg, client->conn, ERR_OK) == ERR_OK);
  test_mqtt_feed(client, connack, sizeof(connack));
  fail_unless(state.accepted == 1 && mqtt_client_is_connected(client));

  for (offset = 0; offset < len && client->conn != NULL;) {
    u16_t amount = LWIP_MIN(chunk, (u16_t)(len - offset));
    test_mqtt_feed(client, packet + offset, amount);
    offset = (u16_t)(offset + amount);
    if (!valid && offset >= 5) {
      /* Reject the fourth continuation immediately, without a fifth byte. */
      fail_unless(state.disconnected == 1 && client->conn == NULL);
    } else {
      fail_unless(state.disconnected == 0 && client->conn != NULL);
    }
  }
  if (valid) {
    fail_unless(mqtt_client_is_connected(client));
    /* Legal PUBLISH headers await payload; zero-length PINGRESP is complete. */
    fail_unless(client->msg_idx == (packet[1] == 0 ? 0 : len));
  } else {
    fail_unless(!mqtt_client_is_connected(client) && state.disconnected == 1);
  }
  mqtt_disconnect(client);
  mqtt_client_free(client);
  netif_list = saved_netif_list;
}

START_TEST(remaining_length_valid)
{
  static const u8_t packets[][5] = {
    {0xd0, 0x00},
    {0x30, 0x03},
    {0x30, 0x80, 0x01},
    {0x30, 0x80, 0x80, 0x01},
    {0x30, 0x80, 0x80, 0x80, 0x01},
    {0x30, 0xff, 0xff, 0xff, 0x7f}
  };
  static const u16_t lengths[] = {2, 2, 3, 4, 5, 5};
  size_t i;
  u16_t chunk;
  LWIP_UNUSED_ARG(_i);
  for (i = 0; i < LWIP_ARRAYSIZE(packets); i++) {
    for (chunk = 1; chunk <= lengths[i]; chunk++) {
      test_mqtt_remaining_length(packets[i], lengths[i], chunk, 1);
    }
  }
}
END_TEST

START_TEST(remaining_length_invalid)
{
  static const u8_t packets[][7] = {
    {0x30, 0x80, 0x80, 0x80, 0x80},
    {0x30, 0x80, 0x80, 0x80, 0x80, 0x00},
    {0x30, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}
  };
  static const u16_t lengths[] = {5, 6, 6, 7};
  size_t i;
  u16_t chunk;
  LWIP_UNUSED_ARG(_i);
  for (i = 0; i < LWIP_ARRAYSIZE(packets); i++) {
    for (chunk = 1; chunk <= lengths[i]; chunk++) {
      test_mqtt_remaining_length(packets[i], lengths[i], chunk, 0);
    }
  }
}
END_TEST

Suite* mqtt_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(basic_connect),
    TESTFUNC(rx_overflow),
    TESTFUNC(remaining_length_valid),
    TESTFUNC(remaining_length_invalid),
  };
  return create_suite("MQTT", tests, sizeof(tests)/sizeof(testfunc), mqtt_setup, mqtt_teardown);
}
