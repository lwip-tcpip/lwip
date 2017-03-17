#include "test_sockets.h"

#include "lwip/sockets.h"
#include "lwip/stats.h"

#include "lwip/tcpip.h"


/* Setups/teardown functions */

static void
sockets_setup(void)
{
}

static void
sockets_teardown(void)
{
}

#ifndef NUM_SOCKETS
#define NUM_SOCKETS MEMP_NUM_NETCONN
#endif

#if LWIP_SOCKET
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
    addr4->sin_addr.s_addr = PP_HTONL(INADDR_LOOPBACK);
#endif
  } else {
#if LWIP_IPV6
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
    struct in6_addr lo6 = IN6ADDR_LOOPBACK_INIT;
    addr6->sin6_addr = lo6;
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

static void test_sockets_msgapi_udp_send_recv_loop(int s, struct msghdr *smsg, struct msghdr *rmsg)
{
  int i, ret;

  /* send/receive our datagram of IO vectors 10 times */
  for (i = 0; i < 10; i++) {
    ret = lwip_sendmsg(s, smsg, 0);
    fail_unless(ret == 4);

    while (tcpip_thread_poll_one());

    /* receive the datagram split across 4 buffers */
    ret = lwip_recvmsg(s, rmsg, 0);
    fail_unless(ret == 4);

    /* verify data */
    fail_unless(*((u8_t*)rmsg->msg_iov[0].iov_base) == 0xDE);
    fail_unless(*((u8_t*)rmsg->msg_iov[1].iov_base) == 0xAD);
    fail_unless(*((u8_t*)rmsg->msg_iov[2].iov_base) == 0xBE);
    fail_unless(*((u8_t*)rmsg->msg_iov[3].iov_base) == 0xEF);
  }
}

static void test_sockets_msgapi_udp(int domain)
{
  int s, i, ret;
  struct sockaddr_storage addr_storage;
  socklen_t addr_size;
  struct iovec riovs[4];
  struct msghdr rmsg;
  u8_t rcv_buf[4];
  struct iovec siovs[4];
  struct msghdr smsg;
  u8_t snd_buf[4] = {0xDE, 0xAD, 0xBE, 0xEF};

  /* initialize IO vectors with data */
  for (i = 0; i < 4; i++) {
    siovs[i].iov_base = &snd_buf[i];
    siovs[i].iov_len = sizeof(u8_t);
    riovs[i].iov_base = &rcv_buf[i];
    riovs[i].iov_len = sizeof(u8_t);
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
    default:
      addr_size = 0;
      fail();
      break;
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
    default:
      fail();
      break;
  }

  /* send and receive the datagram in 4 pieces */
  memset(&smsg, 0, sizeof(smsg));
  smsg.msg_iov = siovs;
  smsg.msg_iovlen = 4;
  memset(&rmsg, 0, sizeof(rmsg));
  rmsg.msg_iov = riovs;
  rmsg.msg_iovlen = 4;

  /* perform a sendmsg with remote host (self) */
  smsg.msg_name = &addr_storage;
  smsg.msg_namelen = addr_size;

  test_sockets_msgapi_udp_send_recv_loop(s, &smsg, &rmsg);

  /* Connect to self, allowing us to not pass message name */
  ret = lwip_connect(s, (struct sockaddr*)&addr_storage, addr_size);
  fail_unless(ret == 0);

  smsg.msg_name = NULL;
  smsg.msg_namelen = 0;

  test_sockets_msgapi_udp_send_recv_loop(s, &smsg, &rmsg);

  ret = lwip_close(s);
  fail_unless(ret == 0);
}

START_TEST(test_sockets_msgapis)
{
  LWIP_UNUSED_ARG(_i);
#if LWIP_IPV4
  test_sockets_msgapi_udp(AF_INET);
#endif
#if LWIP_IPV6
  test_sockets_msgapi_udp(AF_INET6);
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
    TESTFUNC(test_sockets_msgapis),
  };
  return create_suite("SOCKETS", tests, sizeof(tests)/sizeof(testfunc), sockets_setup, sockets_teardown);
}

#else /* LWIP_SOCKET */

Suite *
sockets_suite(void)
{
  return create_suite("SOCKETS", NULL, 0, NULL, NULL);
}
#endif /* LWIP_SOCKET */
