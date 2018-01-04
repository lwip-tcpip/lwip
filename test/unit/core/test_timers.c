#include "test_timers.h"

#include "lwip/def.h"
#include "lwip/timeouts.h"
#include "arch/sys_arch.h"

/* Setups/teardown functions */

static struct sys_timeo* old_list_head;

static void
timers_setup(void)
{
  struct sys_timeo** list_head = lwip_sys_timers_get_next_timout();
  old_list_head = *list_head;
  *list_head = NULL;
}

static void
timers_teardown(void)
{
  struct sys_timeo** list_head = lwip_sys_timers_get_next_timout();
  *list_head = old_list_head;
  lwip_sys_now = 0;
}

static void dummy_handler(void* arg)
{
  LWIP_UNUSED_ARG(arg);
}

static void test_timers(void)
{
  struct sys_timeo** list_head = lwip_sys_timers_get_next_timout();

  lwip_sys_now = 100;

  sys_timeout(10, dummy_handler, NULL);
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout(20, dummy_handler, NULL);
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout( 5, dummy_handler, NULL);
  fail_unless(sys_timeouts_sleeptime() == 5);

  sys_untimeout(dummy_handler, NULL);
  sys_untimeout(dummy_handler, NULL);
  sys_untimeout(dummy_handler, NULL);

  lwip_sys_now = 0xfffffff0;

  sys_timeout(10, dummy_handler, NULL);
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout(20, dummy_handler, NULL);
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout( 5, dummy_handler, NULL);
  fail_unless(sys_timeouts_sleeptime() == 5);

  sys_untimeout(dummy_handler, NULL);
  sys_untimeout(dummy_handler, NULL);
  sys_untimeout(dummy_handler, NULL);
}

START_TEST(test_lwip_timers)
{
  LWIP_UNUSED_ARG(_i);

  test_timers();
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
timers_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_lwip_timers)
  };
  return create_suite("TIMERS", tests, LWIP_ARRAYSIZE(tests), timers_setup, timers_teardown);
}
