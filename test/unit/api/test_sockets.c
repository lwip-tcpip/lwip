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

/** Create the suite including all tests for this module */
Suite *
sockets_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_sockets_basics)
  };
  return create_suite("SOCKETS", tests, sizeof(tests)/sizeof(testfunc), sockets_setup, sockets_teardown);
}
