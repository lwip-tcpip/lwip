/**
 * @file
 * lwIP iPerf server implementation
 */

/**
 * @defgroup iperf Iperf server
 * @ingroup apps
 *
 * This is a simple performance measuring client/server to check your bandwidth using
 * iPerf2 on a PC as server/client.
 * It provides both TCP and UDP client/server implementation.
 *
 * @todo:
 * - protect combined sessions handling (via 'related_master_state') against reallocation
 *   (this is a pointer address, currently, so if the same memory is allocated again,
 *    session pairs (tx/rx) can be confused on reallocation)
 */

/*
 * Copyright (c) 2014 Simon Goldschmidt
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
 * Author: Simon Goldschmidt
 */

#include "lwip/apps/lwiperf.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/sys.h"
#include "lwip/inet.h"

#include <string.h>

/* TCP and UDP implementations below */
#if LWIP_TCP || LWIP_UDP

/** Change this if you don't want to lwiperf to listen to any IP version */
#ifndef LWIPERF_SERVER_IP_TYPE
#define LWIPERF_SERVER_IP_TYPE      IPADDR_TYPE_ANY
#endif

/* File internal memory allocation (struct lwiperf_*): this defaults to
   the heap */
#ifndef LWIPERF_ALLOC
#define LWIPERF_ALLOC(type)         mem_malloc(sizeof(type))
#define LWIPERF_FREE(type, item)    mem_free(item)
#endif

/** This is the Iperf settings struct sent from the client */
typedef struct _lwiperf_settings {
#define LWIPERF_FLAGS_ANSWER_TEST 0x80000000
#define LWIPERF_FLAGS_ANSWER_NOW  0x00000001
  u32_t flags;
  u32_t num_threads; /* unused for now */
  u32_t remote_port;
  u32_t buffer_len; /* unused for now */
  u32_t win_band; /* TCP window / UDP rate */
  u32_t amount; /* pos. value: bytes?; neg. values: time (unit is 10ms: 1/100 second) */
} lwiperf_settings_t;

/** Basic connection handle */
struct _lwiperf_state_base;
typedef struct _lwiperf_state_base lwiperf_state_base_t;
struct _lwiperf_state_base {
  /* linked list */
  lwiperf_state_base_t *next;
  /* 1=tcp, 0=udp */
  u8_t tcp;
  /* 1=server, 0=client */
  u8_t server;
  /* master state used to abort sessions (e.g. listener, main client) */
  lwiperf_state_base_t *related_master_state;
};

/** List of active iperf sessions */
static lwiperf_state_base_t *lwiperf_all_connections;

/** Add an iperf session to the 'active' list */
static void
lwiperf_list_add(lwiperf_state_base_t *item)
{
  item->next = lwiperf_all_connections;
  lwiperf_all_connections = item;
}

/** Remove an iperf session from the 'active' list */
static void
lwiperf_list_remove(lwiperf_state_base_t *item)
{
  lwiperf_state_base_t *prev = NULL;
  lwiperf_state_base_t *iter;
  for (iter = lwiperf_all_connections; iter != NULL; prev = iter, iter = iter->next) {
    if (iter == item) {
      if (prev == NULL) {
        lwiperf_all_connections = iter->next;
      } else {
        prev->next = iter->next;
      }
      /* @debug: ensure this item is listed only once */
      for (iter = iter->next; iter != NULL; iter = iter->next) {
        LWIP_ASSERT("duplicate entry", iter != item);
      }
      break;
    }
  }
}

static lwiperf_state_base_t *
lwiperf_list_find(lwiperf_state_base_t *item)
{
  lwiperf_state_base_t *iter;
  for (iter = lwiperf_all_connections; iter != NULL; iter = iter->next) {
    if (iter == item) {
      return item;
    }
  }
  return NULL;
}

/* ===== TCP iPerf implementation ===== */
#if LWIP_TCP && LWIP_CALLBACK_API

/** Specify the idle timeout (in seconds) after that the test fails */
#ifndef LWIPERF_TCP_MAX_IDLE_SEC
#define LWIPERF_TCP_MAX_IDLE_SEC    10U
#endif
#if LWIPERF_TCP_MAX_IDLE_SEC > 255
#error LWIPERF_TCP_MAX_IDLE_SEC must fit into an u8_t
#endif

/** If this is 1, check that received data has the correct format */
#ifndef LWIPERF_CHECK_RX_DATA
#define LWIPERF_CHECK_RX_DATA       0
#endif

/** Connection handle for a TCP iperf session */
typedef struct _lwiperf_state_tcp {
  lwiperf_state_base_t base;
  struct tcp_pcb *server_pcb;
  struct tcp_pcb *conn_pcb;
  u32_t time_started;
  lwiperf_report_fn report_fn;
  void *report_arg;
  u8_t poll_count;
  u8_t next_num;
  /* 1=start server when client is closed */
  u8_t client_tradeoff_mode;
  u32_t bytes_transferred;
  lwiperf_settings_t settings;
  u8_t have_settings_buf;
  u8_t specific_remote;
  ip_addr_t remote_addr;
} lwiperf_state_tcp_t;

/** A const buffer to send from: we want to measure sending, not copying! */
static const u8_t lwiperf_txbuf_const[1600] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
};

static err_t lwiperf_tcp_poll(void *arg, struct tcp_pcb *tpcb);
static void lwiperf_tcp_err(void *arg, err_t err);
static err_t lwiperf_start_tcp_server_impl(const ip_addr_t *local_addr, u16_t local_port,
                                           lwiperf_report_fn report_fn, void *report_arg,
                                           lwiperf_state_base_t *related_master_state, lwiperf_state_tcp_t **state);


/** Call the report function of an iperf tcp session */
static void
lwip_tcp_conn_report(lwiperf_state_tcp_t *conn, enum lwiperf_report_type report_type)
{
  if ((conn != NULL) && (conn->report_fn != NULL)) {
    u32_t now, duration_ms, bandwidth_kbitpsec;
    now = sys_now();
    duration_ms = now - conn->time_started;
    if (duration_ms == 0) {
      bandwidth_kbitpsec = 0;
    } else {
      bandwidth_kbitpsec = (conn->bytes_transferred / duration_ms) * 8U;
    }
    conn->report_fn(conn->report_arg, report_type,
                    &conn->conn_pcb->local_ip, conn->conn_pcb->local_port,
                    &conn->conn_pcb->remote_ip, conn->conn_pcb->remote_port,
                    conn->bytes_transferred, duration_ms, bandwidth_kbitpsec);
  }
}

/** Close an iperf tcp session */
static void
lwiperf_tcp_close(lwiperf_state_tcp_t *conn, enum lwiperf_report_type report_type)
{
  err_t err;

  lwiperf_list_remove(&conn->base);
  lwip_tcp_conn_report(conn, report_type);
  if (conn->conn_pcb != NULL) {
    tcp_arg(conn->conn_pcb, NULL);
    tcp_poll(conn->conn_pcb, NULL, 0);
    tcp_sent(conn->conn_pcb, NULL);
    tcp_recv(conn->conn_pcb, NULL);
    tcp_err(conn->conn_pcb, NULL);
    err = tcp_close(conn->conn_pcb);
    if (err != ERR_OK) {
      /* don't want to wait for free memory here... */
      tcp_abort(conn->conn_pcb);
    }
  } else if (conn->server_pcb != NULL) {
    /* no conn pcb, this is the listener pcb */
    err = tcp_close(conn->server_pcb);
    LWIP_ASSERT("error", err == ERR_OK);
  }
  LWIPERF_FREE(lwiperf_state_tcp_t, conn);
}

/** Try to send more data on an iperf tcp session */
static err_t
lwiperf_tcp_client_send_more(lwiperf_state_tcp_t *conn)
{
  int send_more;
  err_t err;
  u16_t txlen;
  u16_t txlen_max;
  void *txptr;
  u8_t apiflags;

  LWIP_ASSERT("conn invalid", (conn != NULL) && conn->base.tcp && (conn->base.server == 0));

  do {
    send_more = 0;
    if (conn->settings.amount & PP_HTONL(0x80000000)) {
      /* this session is time-limited */
      u32_t now = sys_now();
      u32_t diff_ms = now - conn->time_started;
      u32_t time = (u32_t) - (s32_t)lwip_htonl(conn->settings.amount);
      u32_t time_ms = time * 10;
      if (diff_ms >= time_ms) {
        /* time specified by the client is over -> close the connection */
        lwiperf_tcp_close(conn, LWIPERF_TCP_DONE_CLIENT);
        return ERR_OK;
      }
    } else {
      /* this session is byte-limited */
      u32_t amount_bytes = lwip_htonl(conn->settings.amount);
      /* @todo: this can send up to 1*MSS more than requested... */
      if (conn->bytes_transferred >= amount_bytes) {
        /* all requested bytes transferred -> close the connection */
        lwiperf_tcp_close(conn, LWIPERF_TCP_DONE_CLIENT);
        return ERR_OK;
      }
    }

    if (conn->bytes_transferred < 24) {
      /* transmit the settings a first time */
      txptr = &((u8_t *)&conn->settings)[conn->bytes_transferred];
      txlen_max = (u16_t)(24 - conn->bytes_transferred);
      apiflags = TCP_WRITE_FLAG_COPY;
    } else if (conn->bytes_transferred < 48) {
      /* transmit the settings a second time */
      txptr = &((u8_t *)&conn->settings)[conn->bytes_transferred - 24];
      txlen_max = (u16_t)(48 - conn->bytes_transferred);
      apiflags = TCP_WRITE_FLAG_COPY | TCP_WRITE_FLAG_MORE;
      send_more = 1;
    } else {
      /* transmit data */
      /* @todo: every x bytes, transmit the settings again */
      txptr = LWIP_CONST_CAST(void *, &lwiperf_txbuf_const[conn->bytes_transferred % 10]);
      txlen_max = TCP_MSS;
      if (conn->bytes_transferred == 48) { /* @todo: fix this for intermediate settings, too */
        txlen_max = TCP_MSS - 24;
      }
      apiflags = 0; /* no copying needed */
      send_more = 1;
    }
    txlen = txlen_max;
    do {
      err = tcp_write(conn->conn_pcb, txptr, txlen, apiflags);
      if (err ==  ERR_MEM) {
        txlen /= 2;
      }
    } while ((err == ERR_MEM) && (txlen >= (TCP_MSS / 2)));

    if (err == ERR_OK) {
      conn->bytes_transferred += txlen;
    } else {
      send_more = 0;
    }
  } while (send_more);

  tcp_output(conn->conn_pcb);
  return ERR_OK;
}

/** TCP sent callback, try to send more data */
static err_t
lwiperf_tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
  lwiperf_state_tcp_t *conn = (lwiperf_state_tcp_t *)arg;
  /* @todo: check 'len' (e.g. to time ACK of all data)? for now, we just send more... */
  LWIP_ASSERT("invalid conn", conn->conn_pcb == tpcb);
  LWIP_UNUSED_ARG(tpcb);
  LWIP_UNUSED_ARG(len);

  conn->poll_count = 0;

  return lwiperf_tcp_client_send_more(conn);
}

/** TCP connected callback (active connection), send data now */
static err_t
lwiperf_tcp_client_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
  lwiperf_state_tcp_t *conn = (lwiperf_state_tcp_t *)arg;
  LWIP_ASSERT("invalid conn", conn->conn_pcb == tpcb);
  LWIP_UNUSED_ARG(tpcb);
  if (err != ERR_OK) {
    lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_REMOTE);
    return ERR_OK;
  }
  conn->poll_count = 0;
  conn->time_started = sys_now();
  return lwiperf_tcp_client_send_more(conn);
}

/** Start TCP connection back to the client (either parallel or after the
 * receive test has finished.
 */
static err_t
lwiperf_tx_start_impl(const ip_addr_t *remote_ip, u16_t remote_port, lwiperf_settings_t *settings, lwiperf_report_fn report_fn,
                      void *report_arg, lwiperf_state_base_t *related_master_state, lwiperf_state_tcp_t **new_conn)
{
  err_t err;
  lwiperf_state_tcp_t *client_conn;
  struct tcp_pcb *newpcb;
  ip_addr_t remote_addr;

  LWIP_ASSERT("remote_ip != NULL", remote_ip != NULL);
  LWIP_ASSERT("remote_ip != NULL", settings != NULL);
  LWIP_ASSERT("new_conn != NULL", new_conn != NULL);
  *new_conn = NULL;

  client_conn = (lwiperf_state_tcp_t *)LWIPERF_ALLOC(lwiperf_state_tcp_t);
  if (client_conn == NULL) {
    return ERR_MEM;
  }
  newpcb = tcp_new_ip_type(IP_GET_TYPE(remote_ip));
  if (newpcb == NULL) {
    LWIPERF_FREE(lwiperf_state_tcp_t, client_conn);
    return ERR_MEM;
  }
  memset(client_conn, 0, sizeof(lwiperf_state_tcp_t));
  client_conn->base.tcp = 1;
  client_conn->base.related_master_state = related_master_state;
  client_conn->conn_pcb = newpcb;
  client_conn->time_started = sys_now(); /* @todo: set this again on 'connected' */
  client_conn->report_fn = report_fn;
  client_conn->report_arg = report_arg;
  client_conn->next_num = 4; /* initial nr is '4' since the header has 24 byte */
  client_conn->bytes_transferred = 0;
  memcpy(&client_conn->settings, settings, sizeof(*settings));
  client_conn->have_settings_buf = 1;

  tcp_arg(newpcb, client_conn);
  tcp_sent(newpcb, lwiperf_tcp_client_sent);
  tcp_poll(newpcb, lwiperf_tcp_poll, 2U);
  tcp_err(newpcb, lwiperf_tcp_err);

  ip_addr_copy(remote_addr, *remote_ip);

  err = tcp_connect(newpcb, &remote_addr, remote_port, lwiperf_tcp_client_connected);
  if (err != ERR_OK) {
    lwiperf_tcp_close(client_conn, LWIPERF_TCP_ABORTED_LOCAL);
    return err;
  }
  lwiperf_list_add(&client_conn->base);
  *new_conn = client_conn;
  return ERR_OK;
}

static err_t
lwiperf_tx_start_passive(lwiperf_state_tcp_t *conn)
{
  err_t ret;
  lwiperf_state_tcp_t *new_conn = NULL;
  u16_t remote_port = (u16_t)lwip_htonl(conn->settings.remote_port);

  ret = lwiperf_tx_start_impl(&conn->conn_pcb->remote_ip, remote_port, &conn->settings, conn->report_fn, conn->report_arg,
    conn->base.related_master_state, &new_conn);
  if (ret == ERR_OK) {
    LWIP_ASSERT("new_conn != NULL", new_conn != NULL);
    new_conn->settings.flags = 0; /* prevent the remote side starting back as client again */
  }
  return ret;
}

/** Receive data on an iperf tcp session */
static err_t
lwiperf_tcp_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  u8_t tmp;
  u16_t tot_len;
  u32_t packet_idx;
  struct pbuf *q;
  lwiperf_state_tcp_t *conn = (lwiperf_state_tcp_t *)arg;

  LWIP_ASSERT("pcb mismatch", conn->conn_pcb == tpcb);
  LWIP_UNUSED_ARG(tpcb);

  if (err != ERR_OK) {
    lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_REMOTE);
    return ERR_OK;
  }
  if (p == NULL) {
    /* connection closed -> test done */
    if (conn->settings.flags & PP_HTONL(LWIPERF_FLAGS_ANSWER_TEST)) {
      if ((conn->settings.flags & PP_HTONL(LWIPERF_FLAGS_ANSWER_NOW)) == 0) {
        /* client requested transmission after end of test */
        lwiperf_tx_start_passive(conn);
      }
    }
    lwiperf_tcp_close(conn, LWIPERF_TCP_DONE_SERVER);
    return ERR_OK;
  }
  tot_len = p->tot_len;

  conn->poll_count = 0;

  if ((!conn->have_settings_buf) || ((conn->bytes_transferred - 24) % (1024 * 128) == 0)) {
    /* wait for 24-byte header */
    if (p->tot_len < sizeof(lwiperf_settings_t)) {
      lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_LOCAL_DATAERROR);
      pbuf_free(p);
      return ERR_OK;
    }
    if (!conn->have_settings_buf) {
      if (pbuf_copy_partial(p, &conn->settings, sizeof(lwiperf_settings_t), 0) != sizeof(lwiperf_settings_t)) {
        lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_LOCAL);
        pbuf_free(p);
        return ERR_OK;
      }
      conn->have_settings_buf = 1;
      if (conn->settings.flags & PP_HTONL(LWIPERF_FLAGS_ANSWER_TEST)) {
        if (conn->settings.flags & PP_HTONL(LWIPERF_FLAGS_ANSWER_NOW)) {
          /* client requested parallel transmission test */
          err_t err2 = lwiperf_tx_start_passive(conn);
          if (err2 != ERR_OK) {
            lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_LOCAL_TXERROR);
            pbuf_free(p);
            return ERR_OK;
          }
        }
      }
    } else {
      if (conn->settings.flags & PP_HTONL(LWIPERF_FLAGS_ANSWER_TEST)) {
        if (pbuf_memcmp(p, 0, &conn->settings, sizeof(lwiperf_settings_t)) != 0) {
          lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_LOCAL_DATAERROR);
          pbuf_free(p);
          return ERR_OK;
        }
      }
    }
    conn->bytes_transferred += sizeof(lwiperf_settings_t);
    if (conn->bytes_transferred <= 24) {
      conn->time_started = sys_now();
      tcp_recved(tpcb, p->tot_len);
      pbuf_free(p);
      return ERR_OK;
    }
    conn->next_num = 4; /* 24 bytes received... */
    tmp = pbuf_remove_header(p, 24);
    LWIP_ASSERT("pbuf_remove_header failed", tmp == 0);
    LWIP_UNUSED_ARG(tmp); /* for LWIP_NOASSERT */
  }

  packet_idx = 0;
  for (q = p; q != NULL; q = q->next) {
#if LWIPERF_CHECK_RX_DATA
    const u8_t *payload = (const u8_t *)q->payload;
    u16_t i;
    for (i = 0; i < q->len; i++) {
      u8_t val = payload[i];
      u8_t num = val - '0';
      if (num == conn->next_num) {
        conn->next_num++;
        if (conn->next_num == 10) {
          conn->next_num = 0;
        }
      } else {
        lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_LOCAL_DATAERROR);
        pbuf_free(p);
        return ERR_OK;
      }
    }
#endif
    packet_idx += q->len;
  }
  LWIP_ASSERT("count mismatch", packet_idx == p->tot_len);
  conn->bytes_transferred += packet_idx;
  tcp_recved(tpcb, tot_len);
  pbuf_free(p);
  return ERR_OK;
}

/** Error callback, iperf tcp session aborted */
static void
lwiperf_tcp_err(void *arg, err_t err)
{
  lwiperf_state_tcp_t *conn = (lwiperf_state_tcp_t *)arg;
  LWIP_UNUSED_ARG(err);

  /* pcb is already deallocated, prevent double-free */
  conn->conn_pcb = NULL;
  conn->server_pcb = NULL;

  lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_REMOTE);
}

/** TCP poll callback, try to send more data */
static err_t
lwiperf_tcp_poll(void *arg, struct tcp_pcb *tpcb)
{
  lwiperf_state_tcp_t *conn = (lwiperf_state_tcp_t *)arg;
  LWIP_ASSERT("pcb mismatch", conn->conn_pcb == tpcb);
  LWIP_UNUSED_ARG(tpcb);
  if (++conn->poll_count >= LWIPERF_TCP_MAX_IDLE_SEC) {
    lwiperf_tcp_close(conn, LWIPERF_TCP_ABORTED_LOCAL);
    return ERR_OK; /* lwiperf_tcp_close frees conn */
  }

  if (!conn->base.server) {
    lwiperf_tcp_client_send_more(conn);
  }

  return ERR_OK;
}

/** This is called when a new client connects for an iperf tcp session */
static err_t
lwiperf_tcp_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
  lwiperf_state_tcp_t *s, *conn;
  if ((err != ERR_OK) || (newpcb == NULL) || (arg == NULL)) {
    return ERR_VAL;
  }

  s = (lwiperf_state_tcp_t *)arg;
  LWIP_ASSERT("invalid session", s->base.server);
  LWIP_ASSERT("invalid listen pcb", s->server_pcb != NULL);
  LWIP_ASSERT("invalid conn pcb", s->conn_pcb == NULL);
  if (s->specific_remote) {
    LWIP_ASSERT("s->base.related_master_state != NULL", s->base.related_master_state != NULL);
    if (!ip_addr_eq(&newpcb->remote_ip, &s->remote_addr)) {
      /* this listener belongs to a client session, and this is not the correct remote */
      return ERR_VAL;
    }
  } else {
    LWIP_ASSERT("s->base.related_master_state == NULL", s->base.related_master_state == NULL);
  }

  conn = (lwiperf_state_tcp_t *)LWIPERF_ALLOC(lwiperf_state_tcp_t);
  if (conn == NULL) {
    return ERR_MEM;
  }
  memset(conn, 0, sizeof(lwiperf_state_tcp_t));
  conn->base.tcp = 1;
  conn->base.server = 1;
  conn->base.related_master_state = &s->base;
  conn->conn_pcb = newpcb;
  conn->time_started = sys_now();
  conn->report_fn = s->report_fn;
  conn->report_arg = s->report_arg;

  /* setup the tcp rx connection */
  tcp_arg(newpcb, conn);
  tcp_recv(newpcb, lwiperf_tcp_recv);
  tcp_poll(newpcb, lwiperf_tcp_poll, 2U);
  tcp_err(conn->conn_pcb, lwiperf_tcp_err);

  if (s->specific_remote) {
    /* this listener belongs to a client, so make the client the master of the newly created connection */
    conn->base.related_master_state = s->base.related_master_state;
    /* if dual mode or (tradeoff mode AND client is done): close the listener */
    if (!s->client_tradeoff_mode || !lwiperf_list_find(s->base.related_master_state)) {
      /* prevent report when closing: this is expected */
      s->report_fn = NULL;
      lwiperf_tcp_close(s, LWIPERF_TCP_ABORTED_LOCAL);
    }
  }
  lwiperf_list_add(&conn->base);
  return ERR_OK;
}

/**
 * @ingroup iperf
 * Start a TCP iperf server on the default TCP port (5001) and listen for
 * incoming connections from iperf clients.
 *
 * @returns a connection handle that can be used to abort the server
 *          by calling @ref lwiperf_abort()
 */
void *
lwiperf_start_tcp_server_default(lwiperf_report_fn report_fn, void *report_arg)
{
  return lwiperf_start_tcp_server(IP_ADDR_ANY, LWIPERF_TCP_PORT_DEFAULT,
                                  report_fn, report_arg);
}

/**
 * @ingroup iperf
 * Start a TCP iperf server on a specific IP address and port and listen for
 * incoming connections from iperf clients.
 *
 * @returns a connection handle that can be used to abort the server
 *          by calling @ref lwiperf_abort()
 */
void *
lwiperf_start_tcp_server(const ip_addr_t *local_addr, u16_t local_port,
                         lwiperf_report_fn report_fn, void *report_arg)
{
  err_t err;
  lwiperf_state_tcp_t *state = NULL;

  err = lwiperf_start_tcp_server_impl(local_addr, local_port, report_fn, report_arg,
    NULL, &state);
  if (err == ERR_OK) {
    return state;
  }
  return NULL;
}

static err_t lwiperf_start_tcp_server_impl(const ip_addr_t *local_addr, u16_t local_port,
                                           lwiperf_report_fn report_fn, void *report_arg,
                                           lwiperf_state_base_t *related_master_state, lwiperf_state_tcp_t **state)
{
  err_t err;
  struct tcp_pcb *pcb;
  lwiperf_state_tcp_t *s;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("state != NULL", state != NULL);

  if (local_addr == NULL) {
    return ERR_ARG;
  }

  s = (lwiperf_state_tcp_t *)LWIPERF_ALLOC(lwiperf_state_tcp_t);
  if (s == NULL) {
    return ERR_MEM;
  }
  memset(s, 0, sizeof(lwiperf_state_tcp_t));
  s->base.tcp = 1;
  s->base.server = 1;
  s->base.related_master_state = related_master_state;
  s->report_fn = report_fn;
  s->report_arg = report_arg;

  pcb = tcp_new_ip_type(LWIPERF_SERVER_IP_TYPE);
  if (pcb == NULL) {
    return ERR_MEM;
  }
  err = tcp_bind(pcb, local_addr, local_port);
  if (err != ERR_OK) {
    return err;
  }
  s->server_pcb = tcp_listen_with_backlog(pcb, 1);
  if (s->server_pcb == NULL) {
    if (pcb != NULL) {
      tcp_close(pcb);
    }
    LWIPERF_FREE(lwiperf_state_tcp_t, s);
    return ERR_MEM;
  }
  pcb = NULL;

  tcp_arg(s->server_pcb, s);
  tcp_accept(s->server_pcb, lwiperf_tcp_accept);

  lwiperf_list_add(&s->base);
  *state = s;
  return ERR_OK;
}

/**
 * @ingroup iperf
 * Start a TCP iperf client to the default TCP port (5001).
 *
 * @returns a connection handle that can be used to abort the client
 *          by calling @ref lwiperf_abort()
 */
void* lwiperf_start_tcp_client_default(const ip_addr_t* remote_addr,
                               lwiperf_report_fn report_fn, void* report_arg)
{
  return lwiperf_start_tcp_client(remote_addr, LWIPERF_TCP_PORT_DEFAULT, LWIPERF_CLIENT,
                                  report_fn, report_arg);
}

/**
 * @ingroup iperf
 * Start a TCP iperf client to a specific IP address and port.
 *
 * @returns a connection handle that can be used to abort the client
 *          by calling @ref lwiperf_abort()
 */
void* lwiperf_start_tcp_client(const ip_addr_t* remote_addr, u16_t remote_port,
  enum lwiperf_client_type type, lwiperf_report_fn report_fn, void* report_arg)
{
  err_t ret;
  lwiperf_settings_t settings;
  lwiperf_state_tcp_t *state = NULL;

  memset(&settings, 0, sizeof(settings));
  switch (type) {
  case LWIPERF_CLIENT:
    /* Unidirectional tx only test */
    settings.flags = 0;
    break;
  case LWIPERF_DUAL:
    /* Do a bidirectional test simultaneously */
    settings.flags = htonl(LWIPERF_FLAGS_ANSWER_TEST | LWIPERF_FLAGS_ANSWER_NOW);
    break;
  case LWIPERF_TRADEOFF:
    /* Do a bidirectional test individually */
    settings.flags = htonl(LWIPERF_FLAGS_ANSWER_TEST);
    break;
  default:
    /* invalid argument */
    return NULL;
  }
  settings.num_threads = htonl(1);
  settings.remote_port = htonl(LWIPERF_TCP_PORT_DEFAULT);
  /* TODO: implement passing duration/amount of bytes to transfer */
  settings.amount = htonl((u32_t)-1000);

  ret = lwiperf_tx_start_impl(remote_addr, remote_port, &settings, report_fn, report_arg, NULL, &state);
  if (ret == ERR_OK) {
    LWIP_ASSERT("state != NULL", state != NULL);
    if (type != LWIPERF_CLIENT) {
      /* start corresponding server now */
      lwiperf_state_tcp_t *server = NULL;
      ret = lwiperf_start_tcp_server_impl(&state->conn_pcb->local_ip, LWIPERF_TCP_PORT_DEFAULT,
        report_fn, report_arg, (lwiperf_state_base_t *)state, &server);
      if (ret != ERR_OK) {
        /* starting server failed, abort client */
        lwiperf_abort(state);
        return NULL;
      }
      /* make this server accept one connection only */
      server->specific_remote = 1;
      server->remote_addr = state->conn_pcb->remote_ip;
      if (type == LWIPERF_TRADEOFF) {
        /* tradeoff means that the remote host connects only after the client is done,
           so keep the listen pcb open until the client is done */
        server->client_tradeoff_mode = 1;
      }
    }
    return state;
  }
  return NULL;
}

#endif /* LWIP_TCP && LWIP_CALLBACK_API */

/**
 * @ingroup iperf
 * Abort an iperf session (handle returned by lwiperf_start_tcp_server*() or
 * lwiperf_start_udp_server*())
 */
void
lwiperf_abort(void *lwiperf_session)
{
  lwiperf_state_base_t *i, *dealloc, *last = NULL;

  LWIP_ASSERT_CORE_LOCKED();

  for (i = lwiperf_all_connections; i != NULL; ) {
    if ((i == lwiperf_session) || (i->related_master_state == lwiperf_session)) {
      dealloc = i;
      i = i->next;
      if (last != NULL) {
        last->next = i;
      } else {
        lwiperf_all_connections = i;
      }
      LWIPERF_FREE(lwiperf_state_base_t, dealloc);
    } else {
      last = i;
      i = i->next;
    }
  }
}

/* ===== UDP iPerf implementation ===== */
#if LWIP_UDP

/** iPerf2 UDP datagram header (first 12 bytes of each UDP payload) */
typedef struct _lwiperf_udp_hdr {
  s32_t id;         /* datagram ID: positive = normal, negative = final/done */
  u32_t tv_sec;     /* timestamp seconds */
  u32_t tv_usec;    /* timestamp microseconds */
} lwiperf_udp_hdr_t;

/** iPerf2 server report sent back to client at end of UDP test */
typedef struct _lwiperf_udp_server_report {
  s32_t flags;
  s32_t total_len1;   /* high 32 bits of total bytes */
  s32_t total_len2;   /* low 32 bits of total bytes */
  s32_t stop_sec;
  s32_t stop_usec;
  s32_t error_cnt;
  s32_t out_of_order_cnt;
  s32_t datagrams;
  s32_t jitter1;      /* jitter seconds */
  s32_t jitter2;      /* jitter microseconds */
} lwiperf_udp_server_report_t;

/** Timeout in ms for UDP server idle (no packets received) before concluding test */
#ifndef LWIPERF_UDP_SERVER_IDLE_TIMEOUT_MS
#define LWIPERF_UDP_SERVER_IDLE_TIMEOUT_MS  1000U
#endif

/** Default UDP client datagram size (bytes, including UDP header payload) */
#ifndef LWIPERF_UDP_DATAGRAM_SIZE
#define LWIPERF_UDP_DATAGRAM_SIZE  1470U
#endif

/** Default UDP client test duration (ms) */
#ifndef LWIPERF_UDP_CLIENT_DURATION_MS
#define LWIPERF_UDP_CLIENT_DURATION_MS  10000U
#endif

/** Default UDP client target rate (kbit/s) */
#ifndef LWIPERF_UDP_CLIENT_RATE_KBPS
#define LWIPERF_UDP_CLIENT_RATE_KBPS  1000U
#endif

/** Connection handle for a UDP iperf server session */
typedef struct _lwiperf_state_udp {
  lwiperf_state_base_t base;
  struct udp_pcb *pcb;
  u32_t time_started;
  u32_t last_pkt_time;
  lwiperf_report_fn report_fn;
  void *report_arg;
  u32_t bytes_transferred;
  s32_t next_id;
  s32_t out_of_order;
  s32_t error_cnt;
  s32_t datagrams;
  u8_t  test_running;
  ip_addr_t remote_addr;
  u16_t remote_port;
  /* client-specific fields */
  u32_t duration_ms;
  u16_t rate_kbitpsec;
  s32_t udp_seq;
} lwiperf_state_udp_t;

/** UDP server receive callback */
static void
lwiperf_udp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                 const ip_addr_t *addr, u16_t port)
{
  lwiperf_state_udp_t *conn = (lwiperf_state_udp_t *)arg;
  lwiperf_udp_hdr_t hdr;
  u32_t now;

  if ((p == NULL) || (conn == NULL)) {
    if (p != NULL) {
      pbuf_free(p);
    }
    return;
  }

  if (p->tot_len < sizeof(lwiperf_udp_hdr_t)) {
    pbuf_free(p);
    return;
  }

  /* Extract the iPerf2 UDP header */
  pbuf_copy_partial(p, &hdr, sizeof(hdr), 0);
  hdr.id = (s32_t)lwip_ntohl((u32_t)hdr.id);

  now = sys_now();

  if (!conn->test_running) {
    /* First packet starts the test */
    conn->test_running = 1;
    conn->time_started = now;
    conn->next_id = 0;
    conn->out_of_order = 0;
    conn->error_cnt = 0;
    conn->datagrams = 0;
    conn->bytes_transferred = 0;
    ip_addr_copy(conn->remote_addr, *addr);
    conn->remote_port = port;
  }

  conn->last_pkt_time = now;
  conn->datagrams++;
  conn->bytes_transferred += p->tot_len;

  if (hdr.id < 0) {
    /* Negative ID = final datagram (client is done).
     * Send server report back to client. */
    u32_t duration_ms = now - conn->time_started;
    u32_t bandwidth_kbitpsec;
    lwiperf_udp_server_report_t report;
    struct pbuf *rp;

    if (duration_ms == 0) {
      bandwidth_kbitpsec = 0;
    } else {
      bandwidth_kbitpsec = (conn->bytes_transferred / duration_ms) * 8U;
    }

    /* Build the server report */
    memset(&report, 0, sizeof(report));
    report.flags = (s32_t)lwip_htonl(0x80000000UL); /* HEADER_VERSION1 */
    report.total_len1 = 0;
    report.total_len2 = (s32_t)lwip_htonl((u32_t)conn->bytes_transferred);
    report.stop_sec = (s32_t)lwip_htonl(duration_ms / 1000U);
    report.stop_usec = (s32_t)lwip_htonl((duration_ms % 1000U) * 1000U);
    report.error_cnt = (s32_t)lwip_htonl((u32_t)conn->error_cnt);
    report.out_of_order_cnt = (s32_t)lwip_htonl((u32_t)conn->out_of_order);
    report.datagrams = (s32_t)lwip_htonl((u32_t)conn->datagrams);
    report.jitter1 = 0;
    report.jitter2 = 0;

    /* Send report back to client (prepend the received header) */
    rp = pbuf_alloc(PBUF_TRANSPORT,
                    (u16_t)(sizeof(lwiperf_udp_hdr_t) + sizeof(report)), PBUF_RAM);
    if (rp != NULL) {
      lwiperf_udp_hdr_t rpt_hdr;
      rpt_hdr.id = (s32_t)lwip_htonl((u32_t)hdr.id);
      rpt_hdr.tv_sec = 0;
      rpt_hdr.tv_usec = 0;
      pbuf_take_at(rp, &rpt_hdr, sizeof(rpt_hdr), 0);
      pbuf_take_at(rp, &report, sizeof(report), (u16_t)sizeof(rpt_hdr));
      udp_sendto(pcb, rp, addr, port);
      pbuf_free(rp);
    }

    /* Call user report callback */
    if (conn->report_fn != NULL) {
      conn->report_fn(conn->report_arg, LWIPERF_UDP_DONE_SERVER,
                      &pcb->local_ip, pcb->local_port,
                      addr, port,
                      conn->bytes_transferred, duration_ms, bandwidth_kbitpsec);
    }

    /* Reset for next test */
    conn->test_running = 0;
    conn->bytes_transferred = 0;
    conn->datagrams = 0;
    conn->out_of_order = 0;
    conn->error_cnt = 0;
  } else {
    /* Track out-of-order and lost packets */
    if (hdr.id == conn->next_id) {
      conn->next_id++;
    } else if (hdr.id > conn->next_id) {
      /* Packets were lost */
      conn->error_cnt += (hdr.id - conn->next_id);
      conn->next_id = hdr.id + 1;
    } else {
      /* Out of order */
      conn->out_of_order++;
    }
  }

  pbuf_free(p);
}

/**
 * @ingroup iperf
 * Start a UDP iperf server on the default port (5001).
 *
 * @returns a connection handle that can be used to abort the server
 *          by calling @ref lwiperf_abort()
 */
void *
lwiperf_start_udp_server_default(lwiperf_report_fn report_fn, void *report_arg)
{
  return lwiperf_start_udp_server(IP_ADDR_ANY, LWIPERF_UDP_PORT_DEFAULT,
                                  report_fn, report_arg);
}

/**
 * @ingroup iperf
 * Start a UDP iperf server on a specific IP address and port.
 * The server listens for incoming iPerf2 UDP datagrams and measures
 * receive bandwidth and packet loss.
 *
 * @returns a connection handle that can be used to abort the server
 *          by calling @ref lwiperf_abort()
 */
void *
lwiperf_start_udp_server(const ip_addr_t *local_addr, u16_t local_port,
                         lwiperf_report_fn report_fn, void *report_arg)
{
  lwiperf_state_udp_t *state;
  struct udp_pcb *pcb;
  err_t err;

  LWIP_ASSERT_CORE_LOCKED();

  if (local_addr == NULL) {
    return NULL;
  }

  state = (lwiperf_state_udp_t *)LWIPERF_ALLOC(lwiperf_state_udp_t);
  if (state == NULL) {
    return NULL;
  }
  memset(state, 0, sizeof(lwiperf_state_udp_t));
  state->base.tcp = 0;
  state->base.server = 1;
  state->base.related_master_state = NULL;
  state->report_fn = report_fn;
  state->report_arg = report_arg;
  state->test_running = 0;

  pcb = udp_new_ip_type(LWIPERF_SERVER_IP_TYPE);
  if (pcb == NULL) {
    LWIPERF_FREE(lwiperf_state_udp_t, state);
    return NULL;
  }

  err = udp_bind(pcb, local_addr, local_port);
  if (err != ERR_OK) {
    udp_remove(pcb);
    LWIPERF_FREE(lwiperf_state_udp_t, state);
    return NULL;
  }

  state->pcb = pcb;
  udp_recv(pcb, lwiperf_udp_recv, state);

  lwiperf_list_add(&state->base);
  return state;
}

/**
 * @ingroup iperf
 * Start a UDP iperf client to the default port (5001) with default settings.
 * Duration: 10 seconds, Rate: 1 Mbit/s
 *
 * @returns a connection handle that can be used to abort the client
 *          by calling @ref lwiperf_abort()
 */
void *
lwiperf_start_udp_client_default(const ip_addr_t *remote_addr,
                                 lwiperf_report_fn report_fn, void *report_arg)
{
  return lwiperf_start_udp_client(remote_addr, LWIPERF_UDP_PORT_DEFAULT,
                                  LWIPERF_UDP_CLIENT_DURATION_MS,
                                  LWIPERF_UDP_CLIENT_RATE_KBPS,
                                  report_fn, report_arg);
}

/**
 * @ingroup iperf
 * Start a UDP iperf client to a specific IP address and port.
 * Sends UDP datagrams at the specified rate for the specified duration.
 * Compatible with iPerf2 UDP server mode.
 *
 * @param remote_addr IP address of the remote iperf server
 * @param remote_port port of the remote iperf server
 * @param duration_ms test duration in milliseconds
 * @param rate_kbitpsec target sending rate in kbit/s
 * @param report_fn callback to report results
 * @param report_arg user argument passed to report_fn
 *
 * @returns a connection handle that can be used to abort the client
 *          by calling @ref lwiperf_abort()
 */
void *
lwiperf_start_udp_client(const ip_addr_t *remote_addr, u16_t remote_port,
                         u32_t duration_ms, u16_t rate_kbitpsec,
                         lwiperf_report_fn report_fn, void *report_arg)
{
  lwiperf_state_udp_t *state;
  struct udp_pcb *pcb;
  err_t err;

  LWIP_ASSERT_CORE_LOCKED();

  if (remote_addr == NULL) {
    return NULL;
  }

  state = (lwiperf_state_udp_t *)LWIPERF_ALLOC(lwiperf_state_udp_t);
  if (state == NULL) {
    return NULL;
  }
  memset(state, 0, sizeof(lwiperf_state_udp_t));
  state->base.tcp = 0;
  state->base.server = 0;
  state->base.related_master_state = NULL;
  state->report_fn = report_fn;
  state->report_arg = report_arg;
  state->duration_ms = duration_ms;
  state->rate_kbitpsec = rate_kbitpsec;
  state->udp_seq = 0;
  state->test_running = 1;
  state->time_started = sys_now();
  state->bytes_transferred = 0;
  ip_addr_copy(state->remote_addr, *remote_addr);
  state->remote_port = remote_port;

  pcb = udp_new_ip_type(IP_GET_TYPE(remote_addr));
  if (pcb == NULL) {
    LWIPERF_FREE(lwiperf_state_udp_t, state);
    return NULL;
  }

  err = udp_connect(pcb, remote_addr, remote_port);
  if (err != ERR_OK) {
    udp_remove(pcb);
    LWIPERF_FREE(lwiperf_state_udp_t, state);
    return NULL;
  }

  state->pcb = pcb;
  lwiperf_list_add(&state->base);
  return state;
}

/**
 * @ingroup iperf
 * Poll function for UDP iperf client - call this periodically from your main loop
 * or a timer to drive the UDP client transmissions.
 *
 * @param session handle returned by lwiperf_start_udp_client()
 * @returns 1 if test is still running, 0 if test is done
 */
u8_t
lwiperf_udp_client_poll(void *session)
{
  lwiperf_state_udp_t *conn = (lwiperf_state_udp_t *)session;
  struct pbuf *p;
  lwiperf_udp_hdr_t hdr;
  u32_t now;
  u32_t elapsed_ms;
  u16_t dgram_size;

  if ((conn == NULL) || (conn->base.tcp != 0) || (conn->base.server != 0)) {
    return 0;
  }

  if (!conn->test_running) {
    return 0;
  }

  now = sys_now();
  elapsed_ms = now - conn->time_started;

  dgram_size = LWIPERF_UDP_DATAGRAM_SIZE;

  if (elapsed_ms >= conn->duration_ms) {
    /* Test duration exceeded - send final datagram with negative ID */
    p = pbuf_alloc(PBUF_TRANSPORT, dgram_size, PBUF_RAM);
    if (p != NULL) {
      u32_t duration_ms = now - conn->time_started;
      u32_t bandwidth_kbitpsec;

      /* Fill with pattern data */
      memset(p->payload, '0', p->tot_len);

      /* Write header with negative sequence number to signal end */
      hdr.id = (s32_t)lwip_htonl((u32_t)(-(conn->udp_seq + 1)));
      hdr.tv_sec = lwip_htonl(now / 1000U);
      hdr.tv_usec = lwip_htonl((now % 1000U) * 1000U);
      pbuf_take_at(p, &hdr, sizeof(hdr), 0);

      udp_send(conn->pcb, p);
      conn->bytes_transferred += p->tot_len;
      pbuf_free(p);

      /* Report done */
      if (duration_ms == 0) {
        bandwidth_kbitpsec = 0;
      } else {
        bandwidth_kbitpsec = (conn->bytes_transferred / duration_ms) * 8U;
      }

      if (conn->report_fn != NULL) {
        conn->report_fn(conn->report_arg, LWIPERF_UDP_DONE_CLIENT,
                        &conn->pcb->local_ip, conn->pcb->local_port,
                        &conn->remote_addr, conn->remote_port,
                        conn->bytes_transferred, duration_ms, bandwidth_kbitpsec);
      }

      /* Clean up */
      conn->test_running = 0;
      lwiperf_list_remove(&conn->base);
      udp_remove(conn->pcb);
      LWIPERF_FREE(lwiperf_state_udp_t, conn);
    }
    return 0;
  }

  /* Send a datagram */
  p = pbuf_alloc(PBUF_TRANSPORT, dgram_size, PBUF_RAM);
  if (p != NULL) {
    /* Fill payload with pattern */
    memset(p->payload, '0', p->tot_len);

    /* Write iPerf2 header */
    hdr.id = (s32_t)lwip_htonl((u32_t)conn->udp_seq);
    hdr.tv_sec = lwip_htonl(now / 1000U);
    hdr.tv_usec = lwip_htonl((now % 1000U) * 1000U);
    pbuf_take_at(p, &hdr, sizeof(hdr), 0);

    udp_send(conn->pcb, p);
    conn->bytes_transferred += p->tot_len;
    conn->udp_seq++;
    pbuf_free(p);
  }

  return 1;
}

#endif /* LWIP_UDP */

#endif /* LWIP_TCP || LWIP_UDP */
