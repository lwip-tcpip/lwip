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

/** Create the suite including all tests for this module */
Suite *
sockets_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_sockets_basics),
    TESTFUNC(test_sockets_allfunctions_basic)
  };
  return create_suite("SOCKETS", tests, sizeof(tests)/sizeof(testfunc), sockets_setup, sockets_teardown);
}
