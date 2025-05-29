#include "test_def.h"

#include "lwip/def.h"

#define MAGIC_UNTOUCHED_BYTE  0x7a
#define TEST_BUFSIZE          32
#define GUARD_SIZE            4

/* Setups/teardown functions */

static void
def_setup(void)
{
}

static void
def_teardown(void)
{
}

static void
def_check_range_untouched(const char *buf, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++) {
    fail_unless(buf[i] == (char)MAGIC_UNTOUCHED_BYTE);
  }
}

START_TEST(test_def_lwip_strnstr)
{
  const char *buffer = "abc";

  LWIP_UNUSED_ARG(_i);

  fail_unless(lwip_strnstr(buffer, "", 3) == buffer);
  fail_unless(lwip_strnstr(buffer, "bc", 3) == buffer + 1);
  fail_unless(lwip_strnstr(buffer, "bx", 3) == NULL);
  fail_unless(lwip_strnstr(buffer, "x", 3) == NULL);
}
END_TEST

START_TEST(test_def_lwip_strnistr)
{
  const char *buffer = "aBC";

  LWIP_UNUSED_ARG(_i);

  fail_unless(lwip_strnistr(buffer, "", 3) == buffer);
  fail_unless(lwip_strnistr(buffer, "bc", 3) == buffer + 1);
  fail_unless(lwip_strnistr(buffer, "bx", 3) == NULL);
  fail_unless(lwip_strnistr(buffer, "x", 3) == NULL);
}
END_TEST

START_TEST(test_def_lwip_stricmp)
{
  LWIP_UNUSED_ARG(_i);

  fail_unless(lwip_stricmp("", "") == 0);
  fail_unless(lwip_stricmp("!", "!") == 0);
  fail_unless(lwip_stricmp("!", "{") != 0);
  fail_unless(lwip_stricmp("{", "!") != 0);
  fail_unless(lwip_stricmp("{", "{") == 0);
  fail_unless(lwip_stricmp("1", "1") == 0);
  fail_unless(lwip_stricmp("1", "2") != 0);
  fail_unless(lwip_stricmp("a", "a") == 0);
  fail_unless(lwip_stricmp("a", "b") != 0);
  fail_unless(lwip_stricmp("a", "A") == 0);
  fail_unless(lwip_stricmp("a", "b") != 0);
}
END_TEST

START_TEST(test_def_lwip_strincmp)
{
  int i;

  LWIP_UNUSED_ARG(_i);

  for (i = 2; i < 3; ++i) {
    fail_unless(lwip_strnicmp("", "", i) == 0);
    fail_unless(lwip_strnicmp("0!", "0!", i) == 0);
    fail_unless(lwip_strnicmp("0!", "0{", i) != 0);
    fail_unless(lwip_strnicmp("0{", "0!", i) != 0);
    fail_unless(lwip_strnicmp("0{", "0{", i) == 0);
    fail_unless(lwip_strnicmp("01", "01", i) == 0);
    fail_unless(lwip_strnicmp("01", "02", i) != 0);
    fail_unless(lwip_strnicmp("0a", "0a", i) == 0);
    fail_unless(lwip_strnicmp("0a", "0b", i) != 0);
    fail_unless(lwip_strnicmp("0a", "0A", i) == 0);
    fail_unless(lwip_strnicmp("0a", "0b", i) != 0);
  }
}

static void test_def_itoa(int number, const char *expected)
{
  char buf[TEST_BUFSIZE];
  char *test_buf = &buf[GUARD_SIZE];

  size_t exp_len = strlen(expected);
  fail_unless(exp_len + 4 < (TEST_BUFSIZE - (2 * GUARD_SIZE)));

  memset(buf, MAGIC_UNTOUCHED_BYTE, sizeof(buf));
  lwip_itoa(test_buf, exp_len + 1, number);
  def_check_range_untouched(buf, GUARD_SIZE);
  fail_unless(test_buf[exp_len] == 0);
  fail_unless(!memcmp(test_buf, expected, exp_len));
  def_check_range_untouched(&test_buf[exp_len + 1], TEST_BUFSIZE - GUARD_SIZE - exp_len - 1);

  /* check with too small buffer */
  memset(buf, MAGIC_UNTOUCHED_BYTE, sizeof(buf));
  lwip_itoa(test_buf, exp_len, number);
  def_check_range_untouched(buf, GUARD_SIZE);
  def_check_range_untouched(&test_buf[exp_len + 1], TEST_BUFSIZE - GUARD_SIZE - exp_len - 1);

  /* check with too large buffer */
  memset(buf, MAGIC_UNTOUCHED_BYTE, sizeof(buf));
  lwip_itoa(test_buf, exp_len + 4, number);
  def_check_range_untouched(buf, GUARD_SIZE);
  fail_unless(test_buf[exp_len] == 0);
  fail_unless(!memcmp(test_buf, expected, exp_len));
  def_check_range_untouched(&test_buf[exp_len + 4], TEST_BUFSIZE - GUARD_SIZE - exp_len - 4);
}

START_TEST(test_def_lwip_itoa)
{
  char ch;

  LWIP_UNUSED_ARG(_i);

  lwip_itoa(&ch, 0, 0);
  lwip_itoa(&ch, 1, 0);
  fail_unless(ch == '\0');

  test_def_itoa(0, "0");
  test_def_itoa(1, "1");
  test_def_itoa(-1, "-1");
  test_def_itoa(15, "15");
  test_def_itoa(-15, "-15");
  test_def_itoa(156, "156");
  test_def_itoa(1192, "1192");
  test_def_itoa(-156, "-156");
}
END_TEST

START_TEST(test_def_lwip_memcmp_consttime)
{
  char a = 'a';
  char b = 'b';

  LWIP_UNUSED_ARG(_i);

  fail_unless(lwip_memcmp_consttime(NULL, NULL, 0) == 0);
  fail_unless(lwip_memcmp_consttime(&a, &a, sizeof(a)) == 0);
  fail_unless(lwip_memcmp_consttime(&a, &b, sizeof(a)) != 0);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
def_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_def_lwip_strnstr),
    TESTFUNC(test_def_lwip_strnistr),
    TESTFUNC(test_def_lwip_stricmp),
    TESTFUNC(test_def_lwip_strincmp),
    TESTFUNC(test_def_lwip_itoa),
    TESTFUNC(test_def_lwip_memcmp_consttime)
  };
  return create_suite("DEF", tests, sizeof(tests)/sizeof(testfunc), def_setup, def_teardown);
}
