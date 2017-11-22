/**
 * @file
 * Sockets stresstest
 *
 * This file uses the lwIP socket API to do stress tests that should test the
 * stability when used in many different situations, with many concurrent
 * sockets making concurrent transfers in different manners.
 *
 * - test rely on loopback sockets for now, so netif drivers are not tested
 * - all enabled functions shall be used
 * - parallelism of the tests depend on enough resources being available
 *   (configure your lwipopts.h settings high enough)
 * - test should also be able to run in your target, to test your 
 */
 
 /*
 * Copyright (c) 2017 Simon Goldschmidt
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 *
 */

#include "lwip/opt.h"
#include "sockets_stresstest.h"

#include "lwip/sockets.h"
#include "lwip/sys.h"

#include <stdio.h>
#include <string.h>

#define TEST_TIME_SECONDS     10
#define TEST_TXRX_BUFSIZE     (TCP_MSS * 2)
#define TEST_MAX_RXWAIT_MS    500
#define TEST_MAX_CONNECTIONS  1

#define TEST_MODE_SELECT      0x01
#define TEST_MODE_POLL        0x02
#define TEST_MODE_NONBLOCKING 0x04
#define TEST_MODE_RECVTIMEO   0x08

static int sockets_stresstest_numthreads;



static void
fill_test_data(void *buf, size_t buf_len_bytes)
{
  u8_t *p = (u8_t*)buf;
  u16_t i, chk;

  LWIP_ASSERT("buffer too short", buf_len_bytes > 4);
  LWIP_ASSERT("buffer too big", buf_len_bytes <= 0xFFFF);
  /* store the total number of bytes */
  p[0] = (u8_t)(buf_len_bytes >> 8);
  p[1] = (u8_t)buf_len_bytes;

  /* fill buffer with random */
  chk = 0;
  for (i = 4; i < buf_len_bytes; i++) {
    u8_t rnd = (u8_t)LWIP_RAND();
    p[i] = rnd;
    chk += rnd;
  }
  /* store checksum */
  p[2] = (u8_t)(chk >> 8);
  p[3] = (u8_t)chk;
}

static size_t
check_test_data(const void *buf, size_t buf_len_bytes)
{
  u8_t *p = (u8_t*)buf;
  u16_t i, chk, chk_rx, len_rx;

  LWIP_ASSERT("buffer too short", buf_len_bytes > 4);
  len_rx = (((u16_t)p[0]) << 8) | p[1];
  LWIP_ASSERT("len too short", len_rx > 4);
  if (len_rx > buf_len_bytes) {
    /* not all data received in this segment */
    printf("check-\n");
    return buf_len_bytes;
  }
  chk_rx = (((u16_t)p[2]) << 8) | p[3];
  /* calculate received checksum */
  chk = 0;
  for (i = 4; i < len_rx; i++) {
    chk += p[i];
  }
  LWIP_ASSERT("invalid checksum", chk == chk_rx);
  if (len_rx < buf_len_bytes) {
    size_t data_left = buf_len_bytes - len_rx;
    memmove(p, &p[len_rx], data_left);
    return data_left;
  }
  /* if we come here, we received exactly one chunk
     -> next offset is 0 */
  return 0;
}

static size_t
recv_and_check_data_return_offset(int s, char *rxbuf, size_t rxbufsize, size_t rxoff, int *closed, const char *dbg)
{
  ssize_t ret;

  ret = lwip_read(s, &rxbuf[rxoff], rxbufsize - rxoff);
  if (ret == 0) {
    *closed = 1;
    return rxoff;
  }
  *closed = 0;
  printf("%s %d rx %d\n", dbg, s, (int)ret);
  LWIP_ASSERT("ret > 0", ret > 0);
  return check_test_data(rxbuf, rxoff + ret);
}

static void
sockets_stresstest_conn_client(void *arg)
{
  struct sockaddr_storage addr;
  struct sockaddr_in *addr_in;
  int s, ret;
  char txbuf[TEST_TXRX_BUFSIZE];
  char rxbuf[TEST_TXRX_BUFSIZE];
  size_t rxoff = 0;
  u32_t max_time = sys_now() + (TEST_TIME_SECONDS * 1000);

  memcpy(&addr, arg, sizeof(addr));
  LWIP_ASSERT("", addr.ss_family == AF_INET);
  addr_in = (struct sockaddr_in *)&addr;
  addr_in->sin_addr.s_addr = inet_addr("127.0.0.1");

  /* sleep a random time between 1 and 2 seconds */
  sys_msleep(1000 + (LWIP_RAND() % 1000));

  /* connect to the server */
  s = lwip_socket(addr.ss_family, SOCK_STREAM, 0);
  LWIP_ASSERT("s >= 0", s >= 0);
  ret = lwip_connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_storage));
  LWIP_ASSERT("ret == 0", ret == 0);

  while (sys_now() < max_time) {
    int closed;
    struct pollfd pfd;
    pfd.fd = s;
    pfd.revents = 0;
    pfd.events = POLLIN;
    ret = lwip_poll(&pfd, 1, LWIP_RAND() % TEST_MAX_RXWAIT_MS);
    if (ret) {
      /* read some */
      LWIP_ASSERT("pfd.revents == POLLIN", pfd.revents == POLLIN);
      rxoff = recv_and_check_data_return_offset(s, rxbuf, sizeof(rxbuf), rxoff, &closed, "cli");
      LWIP_ASSERT("client got closed", !closed);
    } else {
      /* timeout, send some */
      size_t send_len = (LWIP_RAND() % (sizeof(txbuf) - 4)) + 4;
      fill_test_data(txbuf, send_len);
      printf("cli %d tx %d\n", s, (int)send_len);
      ret = lwip_write(s, txbuf, send_len);
      LWIP_ASSERT("ret >= 0", ret >= 0);
    }
  }
  ret = lwip_close(s);
  LWIP_ASSERT("ret == 0", ret == 0);
  {
    SYS_ARCH_DECL_PROTECT(lev);
    SYS_ARCH_PROTECT(lev);
    LWIP_ASSERT("", sockets_stresstest_numthreads > 0);
    sockets_stresstest_numthreads--;
    SYS_ARCH_UNPROTECT(lev);
  }
}

static void
sockets_stresstest_conn_server(void *arg)
{
  int s, ret;
  char txbuf[TEST_TXRX_BUFSIZE];
  char rxbuf[TEST_TXRX_BUFSIZE];
  size_t rxoff = 0;

  s = (int)arg;

  while (1) {
    int closed;
    struct pollfd pfd;
    pfd.fd = s;
    pfd.revents = 0;
    pfd.events = POLLIN;
    ret = lwip_poll(&pfd, 1, LWIP_RAND() % TEST_MAX_RXWAIT_MS);
    if (ret) {
      if (pfd.revents & POLLERR) {
        /* closed? */
        lwip_close(s);
        break;
      }
      /* read some */
      LWIP_ASSERT("pfd.revents == POLLIN", pfd.revents == POLLIN);
      rxoff = recv_and_check_data_return_offset(s, rxbuf, sizeof(rxbuf), rxoff, &closed, "srv");
      if (closed) {
        break;
      }
    } else {
      /* timeout, send some */
      size_t send_len = (LWIP_RAND() % (sizeof(txbuf) - 4)) + 4;
      fill_test_data(txbuf, send_len);
      printf("srv %d tx %d\n", s, (int)send_len);
      ret = lwip_write(s, txbuf, send_len);
      LWIP_ASSERT("ret >= 0", ret >= 0);
    }
  }
  ret = lwip_close(s);
  LWIP_ASSERT("ret == 0", ret == 0);
  {
    SYS_ARCH_DECL_PROTECT(lev);
    SYS_ARCH_PROTECT(lev);
    LWIP_ASSERT("", sockets_stresstest_numthreads > 0);
    sockets_stresstest_numthreads--;
    SYS_ARCH_UNPROTECT(lev);
  }
}

static void
sockets_stresstest_listener(void *arg)
{
  int slisten;
  int ret;
  int i;
  /* limit the number of connections */
  const int max_connections = LWIP_MIN(TEST_MAX_CONNECTIONS, MEMP_NUM_TCP_PCB/3);
  struct sockaddr_storage addr;
  socklen_t addr_len;

  LWIP_UNUSED_ARG(arg);

  slisten = lwip_socket(AF_INET, SOCK_STREAM, 0);
  LWIP_ASSERT("slisten >= 0", slisten >= 0);

  memset(&addr, 0, sizeof(addr));
  addr.ss_family = AF_INET;
  ret = lwip_bind(slisten, (struct sockaddr *)&addr, sizeof(addr));

  ret = lwip_listen(slisten, 0);
  LWIP_ASSERT("ret == 0", ret == 0);

  addr_len = sizeof(addr);
  ret = lwip_getsockname(slisten, (struct sockaddr *)&addr, &addr_len);
  LWIP_ASSERT("ret == 0", ret == 0);

  for (i = 0; i < max_connections; i++) {
    sys_thread_t t;
    sockets_stresstest_numthreads++;
    t = sys_thread_new("sockets_stresstest_conn_client", sockets_stresstest_conn_client, (void*)&addr, 0, 0);
    LWIP_ASSERT("thread != NULL", t != 0);
  }

  while(1) {
    struct sockaddr_storage aclient;
    socklen_t aclient_len = sizeof(aclient);
    int sclient = lwip_accept(slisten, (struct sockaddr *)&aclient, &aclient_len);
#if 1
    /* using server threads */
    {
      sys_thread_t t;
      sockets_stresstest_numthreads++;
      t = sys_thread_new("sockets_stresstest_conn_server", sockets_stresstest_conn_server, (void*)sclient, 0, 0);
      LWIP_ASSERT("thread != NULL", t != 0);
    }
#else
    /* using server select */
#endif
  }
}

void
sockets_stresstest_init(void)
{
  sys_thread_t t;
  t = sys_thread_new("sockets_stresstest_listener", sockets_stresstest_listener, NULL, 0, 0);
  LWIP_ASSERT("thread != NULL", t != 0);
}
