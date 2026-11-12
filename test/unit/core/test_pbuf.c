#include "test_pbuf.h"

#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/tcpip.h"

#if !LWIP_STATS || !MEM_STATS ||!MEMP_STATS
#error "This tests needs MEM- and MEMP-statistics enabled"
#endif
#if !LWIP_TCP || !TCP_QUEUE_OOSEQ || !LWIP_WND_SCALE
#error "This test needs TCP OOSEQ queueing and window scaling enabled"
#endif

/* Setups/teardown functions */

static void
pbuf_setup(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
pbuf_teardown(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

#if LWIP_SUPPORT_CUSTOM_PBUF
static struct pbuf *custom_free_p;

static void
custom_free(struct pbuf *p)
{
  custom_free_p = p;
}

START_TEST(test_pbuf_alloced_custom)
{
  struct pbuf_custom cp;
  struct pbuf *p;

  memset(&cp, 0, sizeof(cp));
  cp.custom_free_function = custom_free;

  p = pbuf_alloced_custom(PBUF_IP, 0xffffU, PBUF_POOL, &cp, NULL, 0);
  fail_unless(p == NULL);

  p = pbuf_alloced_custom(PBUF_IP, 0U, PBUF_POOL, &cp, NULL, 100);
  fail_unless(p != NULL && p->payload == NULL);

  custom_free_p = NULL;
  pbuf_free(p);
  fail_unless(custom_free_p == p);

  p = pbuf_alloced_custom(PBUF_IP, 0U, PBUF_POOL, &cp, &cp, 100);
  fail_unless(p != NULL && p->payload != NULL);

  pbuf_realloc(p, 0U);

  custom_free_p = NULL;
  pbuf_ref(p);
  pbuf_free(p);
  fail_unless(custom_free_p == NULL);
  pbuf_free(p);
  fail_unless(custom_free_p == p);
}
#endif

static void
free_allocated_pbufs(struct pbuf *head)
{
  struct pbuf *p;

  while (head != NULL) {
    p = head;
    head = (struct pbuf *)p->payload;
    pbuf_free(p);
  }
}

START_TEST(test_pbuf_alloc_failures)
{
  struct pbuf *head;
  struct pbuf *p;
  struct pbuf *q;
  struct pbuf *r;
  int ret;
  LWIP_UNUSED_ARG(_i);

  if (sizeof(u16_t) == sizeof(mem_size_t)) {
    /* Payload length overflow */
    p = pbuf_alloc(PBUF_IP, 0xffffU, PBUF_RAM);
    fail_unless(p == NULL);

    /* Allocation length overflow */
    p = pbuf_alloc(PBUF_RAW, 0xffffU, PBUF_RAM);
    fail_unless(p == NULL);
  }

  /* Exhaust MEMP_PBUF_POOL */

  head = NULL;

  while (1) {
    p = pbuf_alloc(PBUF_RAW, 0xffffU, PBUF_POOL);
    if (p == NULL) {
      break;
    }

    p->payload = head;
    head = p;
  }

  free_allocated_pbufs(head);

  do {
    ret = tcpip_thread_poll_one();
  } while (ret == 0);

  /* Exhaust MEMP_PBUF */

  head = NULL;

  while (1) {
    p = pbuf_alloc_reference(NULL, 0, PBUF_ROM);
    if (p == NULL) {
      break;
    }

    p->payload = head;
    head = p;
  }

  free_allocated_pbufs(head);

  /* Exhaust mem_malloc() */

  head = NULL;

  while (1) {
    p = pbuf_alloc(PBUF_RAW, 0x8000U, PBUF_RAM);

    if (p == NULL) {
      q = pbuf_alloc(PBUF_RAW, 0xffffU, PBUF_POOL);
      fail_unless(q != NULL);

      if (q != NULL) {
        r = pbuf_coalesce(q, PBUF_RAW);
        fail_unless(r == q);

        r = pbuf_clone(PBUF_RAW, PBUF_RAM, q);
        fail_unless(r == NULL);

        pbuf_free(q);
      }

      break;
    }

    p->payload = head;
    head = p;
  }

  free_allocated_pbufs(head);
}
END_TEST

#define TESTBUFSIZE_1 65535
#define TESTBUFSIZE_2 65530
#define TESTBUFSIZE_3 50050
static u8_t testbuf_1[TESTBUFSIZE_1];
static u8_t testbuf_1a[TESTBUFSIZE_1];
static u8_t testbuf_2[TESTBUFSIZE_2];
static u8_t testbuf_2a[TESTBUFSIZE_2];
static u8_t testbuf_3[TESTBUFSIZE_3 + 1];
static u8_t testbuf_3a[TESTBUFSIZE_3];

/* Test functions */
START_TEST(test_pbuf_alloc_zero_pbufs)
{
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, 0, PBUF_ROM);
  fail_unless(p != NULL);
  if (p != NULL) {
    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_RAW, 0, PBUF_RAM);
  fail_unless(p != NULL);
  if (p != NULL) {
    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_RAW, 0, PBUF_REF);
  fail_unless(p != NULL);
  if (p != NULL) {
    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_RAW, 0, PBUF_POOL);
  fail_unless(p != NULL);
  if (p != NULL) {
    pbuf_free(p);
  }
}
END_TEST

START_TEST(test_pbuf_realloc)
{
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, 0xffffU, PBUF_POOL);
  fail_unless(p != NULL);

  if (p != NULL) {
    pbuf_realloc(p, 0xffffU);
    pbuf_realloc(p, 0x8000U);
    pbuf_realloc(p, 0U);
    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_RAW, 100, PBUF_RAM);
  fail_unless(p != NULL);

  if (p != NULL) {
    pbuf_realloc(p, 100U);
    pbuf_realloc(p, 50U);
    pbuf_realloc(p, 0U);
    pbuf_free(p);
  }
}
END_TEST

START_TEST(test_pbuf_header)
{
  struct pbuf *p;
  struct pbuf *q;
  u8_t err;
  u8_t *payload;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_IP, 100, PBUF_RAM);
  fail_unless(p != NULL);

  if (p != NULL) {
    payload = (u8_t *)p->payload;

#ifdef LWIP_NOASSERT
    err = pbuf_add_header(NULL, 0);
    fail_unless(err == 1);
#endif

    err = pbuf_add_header(p, 0x10000U);
    fail_unless(err == 1);

    err = pbuf_add_header(p, 0xffffU);
    fail_unless(err == 1);

    err = pbuf_add_header(p, 200);
    fail_unless(err == 1);

    err = pbuf_add_header(p, 0);
    fail_unless(err == 0);
    fail_unless(p->payload == payload);

    err = pbuf_header(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 1);

    err = pbuf_header_force(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 2);

    err = pbuf_add_header(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 3);

    err = pbuf_add_header_force(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 4);

    err = pbuf_header_force(p, -1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 3);

    err = pbuf_header(p, -1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 2);

    err = pbuf_remove_header(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 1);

    err = pbuf_remove_header(p, 0);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 1);

#ifdef LWIP_NOASSERT
    err = pbuf_remove_header(NULL, 0);
    fail_unless(err == 1);
#endif

    err = pbuf_remove_header(p, 0x10000U);
    fail_unless(err == 1);

    err = pbuf_remove_header(p, 0xffffU);
    fail_unless(err == 1);

    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_IP, 100, PBUF_REF);
  fail_unless(p != NULL);

  if (p != NULL) {
    payload = (u8_t *)p->payload;

    err = pbuf_add_header(p, 1);
    fail_unless(err == 1);

    err = pbuf_add_header_force(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload - 1);

    err = pbuf_remove_header(p, 1);
    fail_unless(err == 0);
    fail_unless(p->payload == payload);

    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_RAW, 0xffffU, PBUF_POOL);

  if (p != NULL) {
    q = pbuf_free_header(p, 0x8000U);
    fail_unless(q != NULL);

    p = pbuf_free_header(q, 0x8000U);
    fail_unless(p == NULL);
  }
}
END_TEST

START_TEST(test_pbuf_chain)
{
  struct pbuf *p;
  struct pbuf *q;
  struct pbuf *r;
  u16_t p_clen;
  u16_t q_clen;
  LWIP_UNUSED_ARG(_i);

  pbuf_ref(NULL);
  pbuf_cat(NULL, NULL);

  p = pbuf_alloc(PBUF_IP, 100, PBUF_RAM);
  fail_unless(p != NULL);

  if (p != NULL) {
    p_clen = pbuf_clen(p);
    pbuf_cat(NULL, p);
    pbuf_cat(p, NULL);

    q = pbuf_alloc(PBUF_IP, 100, PBUF_RAM);
    fail_unless(q != NULL);

    if (q != NULL) {
      q_clen = pbuf_clen(q);
      pbuf_cat(p, q);
      fail_unless(pbuf_clen(p) == p_clen + q_clen);
      p_clen += q_clen;
    }

    q = pbuf_alloc(PBUF_IP, 100, PBUF_RAM);
    fail_unless(q != NULL);

    if (q != NULL) {
      q_clen = pbuf_clen(q);
      pbuf_chain(p, q);
      fail_unless(pbuf_clen(p) == p_clen + q_clen);
      pbuf_free(q);
    }

    pbuf_free(p);
  }

  p = pbuf_alloc(PBUF_IP, 100, PBUF_RAM);
  fail_unless(p != NULL);

  if (p != NULL) {
    q = pbuf_alloc(PBUF_IP, 100, PBUF_RAM);
    fail_unless(q != NULL);

    if (q != NULL) {
      pbuf_chain(p, q);
      r = pbuf_dechain(p);
      fail_unless(r == q);

      r = pbuf_dechain(p);
      fail_unless(r == NULL);

      pbuf_free(q);
    }

    pbuf_free(p);
  }
}
END_TEST

START_TEST(test_pbuf_get_contiguous)
{
  u8_t buf[128];
  struct pbuf *p;
  struct pbuf *q;
  u8_t *b;
  LWIP_UNUSED_ARG(_i);

  b = (u8_t *)pbuf_get_contiguous(NULL, NULL, 0, 0, 0);
  fail_unless(b == NULL);

  p = pbuf_alloc(PBUF_RAW, 64, PBUF_RAM);
  fail_unless(p != NULL);

  if (p != NULL) {
    b = (u8_t *)pbuf_get_contiguous(p, buf, 0, 1, 0);
    fail_unless(b == NULL);

    b = (u8_t *)pbuf_get_contiguous(p, buf, 128, 128, 0);
    fail_unless(b == NULL);

    b = (u8_t *)pbuf_get_contiguous(p, buf, 128, 1, 1);
    fail_unless(b - 1 == p->payload);

    b = (u8_t *)pbuf_get_contiguous(p, buf, 128, 1, 100);
    fail_unless(b == NULL);

    q = pbuf_alloc(PBUF_RAW, 64, PBUF_RAM);
    fail_unless(q != NULL);

    if (q != NULL) {
      pbuf_cat(p, q);

      b = (u8_t *)pbuf_get_contiguous(p, NULL, 0, 200, 1);
      fail_unless(b == NULL);

      b = (u8_t *)pbuf_get_contiguous(p, buf, 128, 128, 0);
      fail_unless(b == buf);
    }

    pbuf_free(p);
  }
}
END_TEST

/** Call pbuf_copy on a pbuf with zero length */
START_TEST(test_pbuf_copy_zero_pbuf)
{
  struct pbuf *p1, *p2, *p3;
  err_t err;
  LWIP_UNUSED_ARG(_i);

  p1 = pbuf_alloc(PBUF_RAW, 1024, PBUF_RAM);
  fail_unless(p1 != NULL);
  fail_unless(p1->ref == 1);

  p2 = pbuf_alloc(PBUF_RAW, 2, PBUF_POOL);
  fail_unless(p2 != NULL);
  fail_unless(p2->ref == 1);
  p2->len = p2->tot_len = 0;

  pbuf_cat(p1, p2);
  fail_unless(p1->ref == 1);
  fail_unless(p2->ref == 1);

  p3 = pbuf_alloc(PBUF_RAW, p1->tot_len, PBUF_POOL);
  fail_unless(p3 != NULL);
  err = pbuf_copy(p3, p1);
  fail_unless(err == ERR_VAL);

  pbuf_free(p1);
  pbuf_free(p3);
}
END_TEST

/** Call pbuf_copy on pbufs with chains of different sizes */
START_TEST(test_pbuf_copy_unmatched_chains)
{
  uint16_t i, j;
  err_t err;
  struct pbuf *source, *dest, *p;
  LWIP_UNUSED_ARG(_i);

  source = NULL;
  /* Build source pbuf from linked 16 byte parts,
   * with payload bytes containing their offset */
  for (i = 0; i < 8; i++) {
    p = pbuf_alloc(PBUF_RAW, 16, PBUF_RAM);
    fail_unless(p != NULL);
    for (j = 0; j < p->len; j++) {
        ((u8_t*)p->payload)[j] = (u8_t)((i << 4) | j);
    }
    if (source) {
        pbuf_cat(source, p);
    } else {
        source = p;
    }
  }
  for (i = 0; i < source->tot_len; i++) {
    fail_unless(pbuf_get_at(source, i) == i);
  }

  /* Build dest pbuf from other lengths */
  dest = pbuf_alloc(PBUF_RAW, 35, PBUF_RAM);
  fail_unless(dest != NULL);
  p = pbuf_alloc(PBUF_RAW, 81, PBUF_RAM);
  fail_unless(p != NULL);
  pbuf_cat(dest, p);
  p = pbuf_alloc(PBUF_RAW, 27, PBUF_RAM);
  fail_unless(p != NULL);
  pbuf_cat(dest, p);

  /* Copy contents and verify data */
  err = pbuf_copy(dest, source);
  fail_unless(err == ERR_OK);
  for (i = 0; i < source->tot_len; i++) {
    fail_unless(pbuf_get_at(dest, i) == i);
  }

  pbuf_free(source);
  pbuf_free(dest);
}
END_TEST

START_TEST(test_pbuf_copy_partial_pbuf)
{
  struct pbuf *a, *b, *dest;
  char lwip[] = "lwip ";
  char packet[] = "packet";
  err_t err;
  LWIP_UNUSED_ARG(_i);

  a = pbuf_alloc(PBUF_RAW, 5, PBUF_REF);
  fail_unless(a != NULL);
  a->payload = lwip;
  b = pbuf_alloc(PBUF_RAW, 7, PBUF_REF);
  fail_unless(b != NULL);
  b->payload = packet;
  pbuf_cat(a, b);
  dest = pbuf_alloc(PBUF_RAW, 14, PBUF_RAM);
  fail_unless(dest != NULL);
  memset(dest->payload, 0, dest->len);

  /* From is NULL */
  err = pbuf_copy_partial_pbuf(dest, NULL, a->tot_len, 4);
  fail_unless(err == ERR_ARG);
  /* To is NULL */
  err = pbuf_copy_partial_pbuf(NULL, a, a->tot_len, 1);
  fail_unless(err == ERR_ARG);
  /* Don't copy if data will not fit */
  err = pbuf_copy_partial_pbuf(dest, a, a->tot_len, 4);
  fail_unless(err == ERR_ARG);
  /* Don't copy if length is longer than source */
  err = pbuf_copy_partial_pbuf(dest, a, a->tot_len + 1, 0);
  fail_unless(err == ERR_ARG);
  /* Normal copy */
  err = pbuf_copy_partial_pbuf(dest, a, a->tot_len, 0);
  fail_unless(err == ERR_OK);
  fail_unless(strcmp("lwip packet", (char*)dest->payload) == 0);
  /* Copy at offset */
  err = pbuf_copy_partial_pbuf(dest, a, a->tot_len, 1);
  fail_unless(err == ERR_OK);
  fail_unless(strcmp("llwip packet", (char*)dest->payload) == 0);
  /* Copy at offset with shorter length */
  err = pbuf_copy_partial_pbuf(dest, a, 6, 6);
  fail_unless(err == ERR_OK);
  fail_unless(strcmp("llwip lwip p", (char*)dest->payload) == 0);
  /* Copy with shorter length */
  err = pbuf_copy_partial_pbuf(dest, a, 5, 0);
  fail_unless(err == ERR_OK);
  fail_unless(strcmp("lwip  lwip p", (char*)dest->payload) == 0);

  pbuf_free(dest);
  pbuf_free(a);
}
END_TEST

START_TEST(test_pbuf_split_64k_on_small_pbufs)
{
  struct pbuf *p, *rest=NULL;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, 1, PBUF_POOL);
  fail_unless(p != NULL);
  pbuf_split_64k(p, &rest);
  fail_unless(p->tot_len == 1);
  pbuf_free(p);
}
END_TEST

START_TEST(test_pbuf_queueing_bigger_than_64k)
{
  int i;
  err_t err;
  struct pbuf *p1, *p2, *p3, *rest2=NULL, *rest3=NULL;
  LWIP_UNUSED_ARG(_i);

  for(i = 0; i < TESTBUFSIZE_1; i++) {
    testbuf_1[i] = (u8_t)rand();
  }
  for(i = 0; i < TESTBUFSIZE_2; i++) {
    testbuf_2[i] = (u8_t)rand();
  }
  for(i = 0; i < TESTBUFSIZE_3; i++) {
    testbuf_3[i] = (u8_t)rand();
  }

  p1 = pbuf_alloc(PBUF_RAW, TESTBUFSIZE_1, PBUF_POOL);
  fail_unless(p1 != NULL);
  p2 = pbuf_alloc(PBUF_RAW, TESTBUFSIZE_2, PBUF_POOL);
  fail_unless(p2 != NULL);
  p3 = pbuf_alloc(PBUF_RAW, TESTBUFSIZE_3, PBUF_POOL);
  fail_unless(p3 != NULL);
  err = pbuf_take(NULL, testbuf_1, TESTBUFSIZE_1);
  fail_unless(err == ERR_ARG);
  err = pbuf_take(p1, NULL, TESTBUFSIZE_1);
  fail_unless(err == ERR_ARG);
  err = pbuf_take(p1, testbuf_1, TESTBUFSIZE_1);
  fail_unless(err == ERR_OK);
  err = pbuf_take(p2, testbuf_2, TESTBUFSIZE_2);
  fail_unless(err == ERR_OK);
  err = pbuf_take(p3, testbuf_3, TESTBUFSIZE_3 + 1);
  fail_unless(err == ERR_MEM);
  err = pbuf_take(p3, testbuf_3, TESTBUFSIZE_3);
  fail_unless(err == ERR_OK);

  pbuf_cat(p1, p2);
  pbuf_cat(p1, p3);

  pbuf_split_64k(p1, &rest2);
  fail_unless(p1->tot_len == TESTBUFSIZE_1);
  fail_unless(rest2->tot_len == (u16_t)((TESTBUFSIZE_2+TESTBUFSIZE_3) & 0xFFFF));
  pbuf_split_64k(rest2, &rest3);
  fail_unless(rest2->tot_len == TESTBUFSIZE_2);
  fail_unless(rest3->tot_len == TESTBUFSIZE_3);

  pbuf_copy_partial(p1, testbuf_1a, TESTBUFSIZE_1, 0);
  pbuf_copy_partial(rest2, testbuf_2a, TESTBUFSIZE_2, 0);
  pbuf_copy_partial(rest3, testbuf_3a, TESTBUFSIZE_3, 0);
  fail_if(memcmp(testbuf_1, testbuf_1a, TESTBUFSIZE_1));
  fail_if(memcmp(testbuf_2, testbuf_2a, TESTBUFSIZE_2));
  fail_if(memcmp(testbuf_3, testbuf_3a, TESTBUFSIZE_3));

  pbuf_free(p1);
  pbuf_free(rest2);
  pbuf_free(rest3);
}
END_TEST

/* Test for bug that writing with pbuf_take_at() did nothing
 * and returned ERR_OK when writing at beginning of a pbuf
 * in the chain.
 */
START_TEST(test_pbuf_take_at_edge)
{
  err_t res;
  u8_t *out;
  int i;
  u8_t testdata[] = { 0x01, 0x08, 0x82, 0x02 };
  struct pbuf *p;
  struct pbuf *q;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, 1024, PBUF_POOL);
  fail_unless(p != NULL);
  q = p->next;

  /* alloc big enough to get a chain of pbufs */
  fail_if(p->tot_len == p->len);
  memset(p->payload, 0, p->len);
  memset(q->payload, 0, q->len);

  /* copy data to the beginning of first pbuf */
  res = pbuf_take_at(p, &testdata, sizeof(testdata), 0);
  fail_unless(res == ERR_OK);

  out = (u8_t*)p->payload;
  for (i = 0; i < (int)sizeof(testdata); i++) {
    fail_unless(out[i] == testdata[i],
      "Bad data at pos %d, was %02X, expected %02X", i, out[i], testdata[i]);
  }

  /* copy data to the just before end of first pbuf */
  res = pbuf_take_at(p, &testdata, sizeof(testdata), p->len - 1);
  fail_unless(res == ERR_OK);

  out = (u8_t*)p->payload;
  fail_unless(out[p->len - 1] == testdata[0],
    "Bad data at pos %d, was %02X, expected %02X", p->len - 1, out[p->len - 1], testdata[0]);
  out = (u8_t*)q->payload;
  for (i = 1; i < (int)sizeof(testdata); i++) {
    fail_unless(out[i-1] == testdata[i],
      "Bad data at pos %d, was %02X, expected %02X", p->len - 1 + i, out[i-1], testdata[i]);
  }

  /* copy data to the beginning of second pbuf */
  res = pbuf_take_at(p, &testdata, sizeof(testdata), p->len);
  fail_unless(res == ERR_OK);

  out = (u8_t*)p->payload;
  for (i = 0; i < (int)sizeof(testdata); i++) {
    fail_unless(out[i] == testdata[i],
      "Bad data at pos %d, was %02X, expected %02X", p->len+i, out[i], testdata[i]);
  }
  pbuf_free(p);
}
END_TEST

/* Verify pbuf_put_at()/pbuf_get_at() when using
 * offsets equal to beginning of new pbuf in chain
 */
START_TEST(test_pbuf_get_put_at_edge)
{
  u8_t *out;
  u8_t testdata = 0x01;
  u8_t getdata;
  struct pbuf *p;
  struct pbuf *q;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, 1024, PBUF_POOL);
  fail_unless(p != NULL);
  q = p->next;

  /* alloc big enough to get a chain of pbufs */
  fail_if(p->tot_len == p->len);
  memset(p->payload, 0, p->len);
  memset(q->payload, 0, q->len);

  /* put byte at the beginning of second pbuf */
  pbuf_put_at(p, p->len, testdata);

  out = (u8_t*)q->payload;
  fail_unless(*out == testdata,
    "Bad data at pos %d, was %02X, expected %02X", p->len, *out, testdata);

  getdata = pbuf_get_at(p, p->len);
  fail_unless(*out == getdata,
    "pbuf_get_at() returned bad data at pos %d, was %02X, expected %02X", p->len, getdata, *out);
  pbuf_free(p);
}
END_TEST

START_TEST(test_pbuf_memstr)
{
  u8_t buf[2];
  char str[2];
  struct pbuf *p;
  u16_t result;
  LWIP_UNUSED_ARG(_i);

  p = pbuf_alloc(PBUF_RAW, 0x8000U, PBUF_POOL);
  fail_unless(p != NULL);

  if (p != NULL) {
    result = pbuf_memcmp(p, 0xffffU, buf, 0);
    fail_unless(result == 0xffff);

    pbuf_put_at(p, 0x0U, 0);
    pbuf_put_at(p, 0x1U, 1);
    pbuf_put_at(p, 0x2U, 2);
    pbuf_put_at(p, 0x7ffeU, 1);
    pbuf_put_at(p, 0x7fffU, 2);

    buf[0] = 1;
    buf[1] = 2;
    result = pbuf_memcmp(p, 0x7ffeU, buf, 2);
    fail_unless(result == 0);

    result = pbuf_memfind(p, buf, 2, 0x7ffeU);
    fail_unless(result == 0x7ffe);

    result = pbuf_strstr(p, NULL);
    fail_unless(result == 0xffff);

    str[0] = 0;
    result = pbuf_strstr(p, str);
    fail_unless(result == 0xffff);

    str[0] = 1;
    str[1] = 0;
    result = pbuf_strstr(p, str);
    fail_unless(result == 0x1);

    buf[0] = 3;

    result = pbuf_memfind(p, buf, 2, 0x7ffeU);
    fail_unless(result == 0xffff);

    result = pbuf_memfind(p, buf, 2, 0x9000U);
    fail_unless(result == 0xffff);

    result = pbuf_memcmp(p, 0x7ffeU, buf, 2);
    fail_unless(result == 1);

    pbuf_free(p);
  }
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
pbuf_suite(void)
{
  testfunc tests[] = {
#if LWIP_SUPPORT_CUSTOM_PBUF
    TESTFUNC(test_pbuf_alloced_custom),
#endif
    TESTFUNC(test_pbuf_alloc_failures),
    TESTFUNC(test_pbuf_alloc_zero_pbufs),
    TESTFUNC(test_pbuf_realloc),
    TESTFUNC(test_pbuf_header),
    TESTFUNC(test_pbuf_chain),
    TESTFUNC(test_pbuf_get_contiguous),
    TESTFUNC(test_pbuf_copy_zero_pbuf),
    TESTFUNC(test_pbuf_copy_unmatched_chains),
    TESTFUNC(test_pbuf_copy_partial_pbuf),
    TESTFUNC(test_pbuf_split_64k_on_small_pbufs),
    TESTFUNC(test_pbuf_queueing_bigger_than_64k),
    TESTFUNC(test_pbuf_take_at_edge),
    TESTFUNC(test_pbuf_get_put_at_edge),
    TESTFUNC(test_pbuf_memstr)
  };
  return create_suite("PBUF", tests, sizeof(tests)/sizeof(testfunc), pbuf_setup, pbuf_teardown);
}
