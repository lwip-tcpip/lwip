#include "test_sockets.h"

#include "lwip/sockets.h"
#include "lwip/stats.h"

#include "lwip/tcpip.h"


/* Setups/teardown functions */
static int tcpip_init_called;

static void
sockets_setup(void)
{
  if (!tcpip_init_called) {
    tcpip_init_called = 1;
    tcpip_init(NULL, NULL);
  }
}

static void
sockets_teardown(void)
{
}

#ifndef NUM_SOCKETS
#define NUM_SOCKETS MEMP_NUM_NETCONN
#endif

static int
test_sockets_alloc_socket_nonblocking(int domain, int type)
{
  int s = lwip_socket(domain, type, 0);
  if (s >= 0) {
    int ret = lwip_fcntl(s, F_SETFL, O_NONBLOCK);
    fail_unless(ret == 0);
  }
  return s;
}

/* Verify basic sockets functionality
 */
START_TEST(test_sockets_basics)
{
  int s, i, ret;
  int s2[NUM_SOCKETS];
  LWIP_UNUSED_ARG(_i);

  s = lwip_socket(AF_INET, SOCK_STREAM, 0);
  fail_unless(s >= 0);
  lwip_close(s);

  for (i = 0; i < NUM_SOCKETS; i++) {
    s2[i] = lwip_socket(AF_INET, SOCK_STREAM, 0);
    fail_unless(s2[i] >= 0);
  }

  /* all sockets used, now it should fail */
  s = lwip_socket(AF_INET, SOCK_STREAM, 0);
  fail_unless(s == -1);
  /* close one socket */
  ret = lwip_close(s2[0]);
  fail_unless(ret == 0);
  /* now it should succeed */
  s2[0] = lwip_socket(AF_INET, SOCK_STREAM, 0);
  fail_unless(s2[0] >= 0);

  /* close all sockets */
  for (i = 0; i < NUM_SOCKETS; i++) {
    ret = lwip_close(s2[i]);
    fail_unless(ret == 0);
  }
}
END_TEST

static void test_sockets_allfunctions_basic_domain(int domain)
{
  int s, s2, s3, ret;
  struct sockaddr_storage addr, addr2;
  socklen_t addrlen, addr2len;
  /* listen socket */
  s = lwip_socket(domain, SOCK_STREAM, 0);
  fail_unless(s >= 0);

  ret = lwip_listen(s, 0);
  fail_unless(ret == 0);

  addrlen = sizeof(addr);
  ret = lwip_getsockname(s, (struct sockaddr*)&addr, &addrlen);
  fail_unless(ret == 0);

  s2 = test_sockets_alloc_socket_nonblocking(domain, SOCK_STREAM);
  fail_unless(s2 >= 0);
  /* nonblocking connect s2 to s (but use loopback address) */
  if (domain == AF_INET) {
#if LWIP_IPV4
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
    addr4->sin_addr.s_addr = inet_addr("127.0.0.1");
#endif
  } else {
#if LWIP_IPV6
#endif
  }
  ret = lwip_connect(s2, (struct sockaddr*)&addr, addrlen);
  fail_unless(ret == -1);
  fail_unless(errno == EINPROGRESS);
  ret = lwip_connect(s2, (struct sockaddr*)&addr, addrlen);
  fail_unless(ret == -1);
  fail_unless(errno == EALREADY);

  while(tcpip_thread_poll_one());

  s3 = lwip_accept(s, (struct sockaddr*)&addr2, &addr2len);
  fail_unless(s3 >= 0);

  ret = lwip_connect(s2, (struct sockaddr*)&addr, addrlen);
  fail_unless(ret == -1);
  fail_unless(errno == EISCONN);

  ret = lwip_close(s);
  fail_unless(ret == 0);
  ret = lwip_close(s2);
  fail_unless(ret == 0);
  ret = lwip_close(s3);
  fail_unless(ret == 0);
}

/* Try to step through all sockets functions once...
 */
START_TEST(test_sockets_allfunctions_basic)
{
  LWIP_UNUSED_ARG(_i);
#if LWIP_IPV4
  test_sockets_allfunctions_basic_domain(AF_INET);
#endif
#if LWIP_IPV6
  test_sockets_allfunctions_basic_domain(AF_INET6);
#endif
}
END_TEST

static void test_sockets_sendmsg_udp_send_recv_loop(int s, struct msghdr *msg)
{
  int i, ret;
  u8_t buf[4];

  /* send/receive our datagram of IO vectors 10 times */
  for (i = 0; i < 10; i++) {
    ret = lwip_sendmsg(s, msg, 0);
    fail_unless(ret == 4);

    while (tcpip_thread_poll_one());

    ret = lwip_recv(s, buf, sizeof(buf), 0);
    fail_unless(ret == 4);

    /* verify data */
    fail_unless(buf[0] == 0xDE);
    fail_unless(buf[1] == 0xAD);
    fail_unless(buf[2] == 0xBE);
    fail_unless(buf[3] == 0xEF);
  }
}

static void test_sockets_sendmsg_udp(int domain)
{
  int s, i, ret;
  struct sockaddr_storage addr_storage;
  socklen_t addr_size;

  struct iovec iovs[4];
  struct msghdr msg;
  u8_t bytes[4];

  /* each datagram should be 0xDEADBEEF */
  bytes[0] = 0xDE;
  bytes[1] = 0xAD;
  bytes[2] = 0xBE;
  bytes[3] = 0xEF;

  /* initialize IO vectors with data */
  for (i = 0; i < 4; i++) {
    iovs[i].iov_base = &bytes[i];
    iovs[i].iov_len = sizeof(char);
  }

  /* set up address to send to */
  memset(&addr_storage, 0, sizeof(addr_storage));
  switch(domain) {
#if LWIP_IPV6
    case AF_INET6: {
      struct sockaddr_in6 *addr = (struct sockaddr_in6*)&addr_storage;
      struct in6_addr lo6 = IN6ADDR_LOOPBACK_INIT;
      addr->sin6_family = AF_INET6;
      addr->sin6_port = 0; /* use ephemeral port */
      addr->sin6_addr = lo6;
      addr_size = sizeof(*addr);
   }
      break;
#endif /* LWIP_IPV6 */
#if LWIP_IPV4
    case AF_INET: {
      struct sockaddr_in *addr = (struct sockaddr_in*)&addr_storage;
      addr->sin_family = AF_INET;
      addr->sin_port = 0; /* use ephemeral port */
      addr->sin_addr.s_addr = PP_HTONL(INADDR_LOOPBACK);
      addr_size = sizeof(*addr);
    }
      break;
#endif /* LWIP_IPV4 */
  }

  s = test_sockets_alloc_socket_nonblocking(domain, SOCK_DGRAM);
  fail_unless(s >= 0);

  ret = lwip_bind(s, (struct sockaddr*)&addr_storage, addr_size);
  fail_unless(ret == 0);

  /* Update addr with epehermal port */
  ret = lwip_getsockname(s, (struct sockaddr*)&addr_storage, &addr_size);
  fail_unless(ret == 0);
  switch(domain) {
#if LWIP_IPV6
    case AF_INET6:
      fail_unless(addr_size == sizeof(struct sockaddr_in6));
      break;
#endif /* LWIP_IPV6 */
#if LWIP_IPV4
    case AF_INET:
        fail_unless(addr_size == sizeof(struct sockaddr_in));
        break;
#endif /* LWIP_IPV6 */
  }

  msg.msg_iov = iovs;
  msg.msg_iovlen = 4;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  /* perform a sendmsg with remote host (self) */
  msg.msg_name = &addr_storage;
  msg.msg_namelen = addr_size;

  test_sockets_sendmsg_udp_send_recv_loop(s, &msg);

  /* Connect to self, allowing us to not pass message name */
  ret = lwip_connect(s, (struct sockaddr*)&addr_storage, addr_size);
  fail_unless(ret == 0);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;

  test_sockets_sendmsg_udp_send_recv_loop(s, &msg);

  ret = lwip_close(s);
  fail_unless(ret == 0);
}

START_TEST(test_sockets_sendmsg)
{
  LWIP_UNUSED_ARG(_i);
#if LWIP_IPV4
  test_sockets_sendmsg_udp(AF_INET);
#endif
#if LWIP_IPV6
  test_sockets_sendmsg_udp(AF_INET6);
#endif
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
sockets_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_sockets_basics),
    TESTFUNC(test_sockets_allfunctions_basic),
    TESTFUNC(test_sockets_sendmsg),
  };
  return create_suite("SOCKETS", tests, sizeof(tests)/sizeof(testfunc), sockets_setup, sockets_teardown);
}
