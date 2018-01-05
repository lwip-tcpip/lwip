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

static int fired[3];
static void dummy_handler(void* arg)
{
  int index = LWIP_PTR_NUMERIC_CAST(int, arg);
  fired[index] = 1;
}

/* reproduce bug bug #52748: the bug in timeouts.c */
START_TEST(test_bug52748)
{
  LWIP_UNUSED_ARG(_i);

  memset(&fired, 0, sizeof(fired));

  lwip_sys_now = 50;
  sys_timeout(20, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 0));
  sys_timeout( 5, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 2));

  lwip_sys_now = 55;
  sys_check_timeouts();
  fail_unless(fired[0] == 0);
  fail_unless(fired[1] == 0);
  fail_unless(fired[2] == 1);

  lwip_sys_now = 60;
  sys_timeout(10, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 1));
  sys_check_timeouts();
  fail_unless(fired[0] == 0);
  fail_unless(fired[1] == 0);
  fail_unless(fired[2] == 1);

  lwip_sys_now = 70;
  sys_check_timeouts();
  fail_unless(fired[0] == 1);
  fail_unless(fired[1] == 1);
  fail_unless(fired[2] == 1);
}
END_TEST

START_TEST(test_timers)
{
  LWIP_UNUSED_ARG(_i);

  /* struct sys_timeo** list_head = lwip_sys_timers_get_next_timout(); */

  /* check without u32_t wraparound */

  lwip_sys_now = 100;

  sys_timeout(10, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 0));
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout(20, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 1));
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout( 5, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 2));
  fail_unless(sys_timeouts_sleeptime() == 5);

  /* linked list correctly sorted? */
  /*
  fail_unless((*list_head)->time             == (u32_t)(lwip_sys_now + 5));
  fail_unless((*list_head)->next->time       == (u32_t)(lwip_sys_now + 10));
  fail_unless((*list_head)->next->next->time == (u32_t)(lwip_sys_now + 20));
  */
  
  /* check timers expire in correct order */
  memset(&fired, 0, sizeof(fired));

  lwip_sys_now += 4;
  sys_check_timeouts();
  fail_unless(fired[2] == 0);

  lwip_sys_now += 1;
  sys_check_timeouts();
  fail_unless(fired[2] == 1);

  lwip_sys_now += 4;
  sys_check_timeouts();
  fail_unless(fired[0] == 0);

  lwip_sys_now += 1;
  sys_check_timeouts();
  fail_unless(fired[0] == 1);

  lwip_sys_now += 9;
  sys_check_timeouts();
  fail_unless(fired[1] == 0);

  lwip_sys_now += 1;
  sys_check_timeouts();
  fail_unless(fired[1] == 1);

  sys_untimeout(dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 0));
  sys_untimeout(dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 1));
  sys_untimeout(dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 2));

  /* check u32_t wraparound */

  lwip_sys_now = 0xfffffff5;

  sys_timeout(10, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 0));
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout(20, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 1));
  fail_unless(sys_timeouts_sleeptime() == 10);
  sys_timeout( 5, dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 2));
  fail_unless(sys_timeouts_sleeptime() == 5);

  /* linked list correctly sorted? */
  /*
  fail_unless((*list_head)->time             == (u32_t)(lwip_sys_now + 5));
  fail_unless((*list_head)->next->time       == (u32_t)(lwip_sys_now + 10));
  fail_unless((*list_head)->next->next->time == (u32_t)(lwip_sys_now + 20));
  */

  /* check timers expire in correct order */
  memset(&fired, 0, sizeof(fired));

  lwip_sys_now += 4;
  sys_check_timeouts();
  fail_unless(fired[2] == 0);

  lwip_sys_now += 1;
  sys_check_timeouts();
  fail_unless(fired[2] == 1);

  lwip_sys_now += 4;
  sys_check_timeouts();
  fail_unless(fired[0] == 0);

  lwip_sys_now += 1;
  sys_check_timeouts();
  fail_unless(fired[0] == 1);

  lwip_sys_now += 9;
  sys_check_timeouts();
  fail_unless(fired[1] == 0);

  lwip_sys_now += 1;
  sys_check_timeouts();
  fail_unless(fired[1] == 1);

  sys_untimeout(dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 0));
  sys_untimeout(dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 1));
  sys_untimeout(dummy_handler, LWIP_PTR_NUMERIC_CAST(void*, 2));
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
timers_suite(void)
{
  testfunc tests[] = {
    /* TESTFUNC(test_bug52748), */
    TESTFUNC(test_timers)
  };
  return create_suite("TIMERS", tests, LWIP_ARRAYSIZE(tests), timers_setup, timers_teardown);
}
