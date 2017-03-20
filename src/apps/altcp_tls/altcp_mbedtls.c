/**
 * @file
 * Application layered TCP connection API (to be used from TCPIP thread)
 *
 * This file contains a TLS layer using mbedTLS
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

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/altcp.h"
#include "lwip/priv/altcp_priv.h"
#include "lwip/mem.h"

/* TODO: which includes are really needed? */
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/platform.h"

#include <string.h>

typedef struct altcp_mbedtls_state_s {
  mbedtls_ssl_context ssl_context;
  /* chain of rx pbufs (before decryption) */
  struct pbuf* rx;
  u8_t handshake_done;
} altcp_mbedtls_state_t;

/* Variable prototype, the actual declaration is at the end of this file
   since it contains pointers to static functions declared here */
extern const struct altcp_functions altcp_mbedtls_functions;

/* global configuration (not connection-specific) */
static mbedtls_ssl_config conf;
#ifdef MBEDTLS_SSL_CACHE_C
/* cache for cached fast connection startup */
static struct mbedtls_ssl_cache_context cache;
#endif

static err_t altcp_mbedtls_setup(struct altcp_pcb *conn, struct altcp_pcb *inner_conn);

static altcp_mbedtls_state_t *
altcp_mbedtls_alloc(void)
{
  altcp_mbedtls_state_t *ret = (altcp_mbedtls_state_t *)mem_malloc(sizeof(altcp_mbedtls_state_t));
  if (ret != NULL) {
    memset(ret, 0, sizeof(altcp_mbedtls_state_t));
  }
  return ret;
}

static void
altcp_mbedtls_free(altcp_mbedtls_state_t *state)
{
  LWIP_ASSERT("state != NULL", state != NULL);
  mem_free(state);
}

/* callback functions from mbedtls (I/O) */
static int
altcp_mbedtls_bio_send(void* ctx, const unsigned char* dataptr, size_t size)
{
  struct altcp_pcb *conn = (struct altcp_pcb *) ctx;
  int written = 0;
  size_t size_left = size;
  u8_t apiflags = ALTCP_WRITE_FLAG_COPY;

  while (size_left) {
    u16_t write_len = (u16_t)LWIP_MIN(size_left, 0xFFFF);
    err_t err = altcp_write(conn, (const void *)dataptr, write_len, apiflags);
    if (err == ERR_OK) {
      written += write_len;
      size_left -= write_len;
    } else {
      LWIP_ASSERT("tls_write, tcp_write: ERR MEM", err == ERR_MEM );
      break;
    }
  }
  return written;
}

static int
altcp_mbedtls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)ctx;
  altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t *)conn->state;
  struct pbuf* p;
  u16_t ret;
  /* limit number of byts to copy to fit into an s16_t for pbuf_header */
  u16_t copy_len = (u16_t)LWIP_MIN(len, 0x7FFF);
  err_t err;

  if (state == NULL) {
    return 0;
  }
  p = state->rx;

  LWIP_ASSERT("len is too big", len <= 0xFFFF);

  if (p == NULL) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  //PFTRACE(("-after handshake: remote port: %d pbuf len: %d pbuf tot len %d\n",pcb->remote_port, p->len, p->tot_len));
  ret = pbuf_copy_partial(p, buf, copy_len, 0);
  LWIP_ASSERT("ret <= p->len", ret <= p->len);
  err = pbuf_header(p, -(s16_t)ret);
  LWIP_ASSERT("error", err == ERR_OK);
  if(p->len == 0) {
    state->rx = p->next;
    p->next = NULL;
    pbuf_free(p);
  }

  return ret;
}

/* callback functions from inner connection */
static err_t
altcp_mbedtls_lower_accept(void *arg, struct altcp_pcb *accepted_conn, err_t err)
{
  struct altcp_pcb *listen_conn = (struct altcp_pcb *)arg;
  if (listen_conn && listen_conn->accept) {
    err_t setup_err;
    /* create a new altcp_conn to pass to the next 'accept' callback */
    struct altcp_pcb *new_conn = altcp_alloc();
    if (new_conn == NULL) {
      return ERR_MEM;
    }
    setup_err = altcp_mbedtls_setup(new_conn, accepted_conn);
    if (setup_err != ERR_OK) {
      altcp_free(new_conn);
      return setup_err;
    }
    return listen_conn->accept(listen_conn->arg, new_conn, err);
  }
  return ERR_ARG;
}

static err_t
altcp_mbedtls_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    /* upper connected is called when handshake is done */
    return ERR_OK;
  }
  return ERR_VAL;
}

static err_t
altcp_mbedtls_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (!conn) {
    if (p != NULL) {
      /* prevent memory leaks */
      pbuf_free(p);
    }
    return ERR_RST;
  }
  altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t *)conn->state;
  LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
  LWIP_ASSERT("conn->state != NULL", conn->state != NULL);

  /* handle NULL pbufs or other errors */
  if ((p == NULL) || (err != ERR_OK)) {
    if (state->handshake_done) {
      if (conn->recv) {
        return conn->recv(conn->arg, conn, p, err);
      } else {
        if (p) {
          pbuf_free(p);
        }
        altcp_close(conn);
        return ERR_OK;
      }
    } else {
      /* before connection setup is done: call 'err' */
      if (p) {
        pbuf_free(p);
      }
      if (conn->err) {
        conn->err(conn->arg, ERR_CLSD);
      }
      altcp_close(conn);
    }
  }

  // If there are more pbufs waiting for encryption, new pbuf is appended to queue.
  if (state->rx == NULL) {
    state->rx = p;
  } else {
    LWIP_ASSERT("rx pbuf overflow", (int)p->tot_len + (int)p->len <= 0xFFFF);
    pbuf_cat(state->rx, p);
  }

  if (!state->handshake_done) {
    /* handle connection setup (handshake not done) */
    int ret;

    /* during handshake: mark all data as received */
    altcp_recved(conn, p->tot_len);

    ret = mbedtls_ssl_handshake(&state->ssl_context);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      /* handshake not done, wait for more recv calls */
      return ERR_OK;
    }
    if (ret != 0) {
      LWIP_ASSERT("mbedtls_ssl_handshake failed \n", ret == 0);
      // ssl context reset()
      // current connection has to be closed!
      // tls_close()
      conn->recv(conn->arg, conn, NULL, ERR_OK);
      /*if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }*/
      return ERR_OK;
    }
    state->handshake_done = 1;
    /* issue "connect" callback" to upper connection */
    if (conn->connected) {
      conn->connected(conn->arg, conn, ERR_OK);
    }
  } else {
    /* handle connection data */
    int ret;
    //  TODO: call recved for unencrypted overhead only
    altcp_recved(conn, p->tot_len);

    do {
      struct pbuf *buf = pbuf_alloc(PBUF_RAW, PBUF_POOL_BUFSIZE, PBUF_RAM);
      if (buf == NULL) {
        // try again later?
        // TODO: close connection?
        return ERR_OK;
      }

      // encrypted buf-> payload always 29 Bytes shorter than received p->payload
      ret = mbedtls_ssl_read(&state->ssl_context, (unsigned char *)buf->payload, PBUF_POOL_BUFSIZE);
      if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
          LWIP_ASSERT("new connection on same source port.\n", 0);//ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT);
          // client is initiating a new connection using the same source port -> close connection or make handshake
        } else if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
          //PFTRACE(("LWIP ASSERT remote port: %d, ret: %d", pcb->remote_port, ret));
          //LWIP_ASSERT("connection was closed gracefully\n", ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY);
          //LWIP_ASSERT("connection was reset by peer\n", ret == MBEDTLS_ERR_NET_CONN_RESET);
          //pbuf_free(buf);
          //return ERR_OK;
        } else {
          //LWIP_ASSERT("TODO", 0);
          pbuf_free(buf);
          return ERR_OK;
        }
        pbuf_free(buf);
        //http_abort_conn();...
        return ERR_ABRT; // TODO: close 'pcb'?
      } else {
        LWIP_ASSERT("TODO", ret <= 0xFFFF && ret <= PBUF_POOL_BUFSIZE);
        pbuf_realloc(buf, (uint16_t)ret);
      
        //PFTRACE(("tls pbuf tot len= %d ",pbuf_len - buf->tot_len));
        //tcp_recved(pcb, pbuf_len-buf->tot_len);
        //tcp_recved(pcb, pbuf_len);
        //PFTRACE(("- after encryprion remote port: %d rcv_wnd %d, buf len: %d buf tot len %d\n", pcb->remote_port, pcb->rcv_wnd, buf->len, buf->tot_len));
        if (conn->recv) {
          conn->recv(conn->arg, conn, buf, err); // TODO: check return value
        }
        /* TODO: if(conn->state != ESTABLISHED)
        {
            //time2= (uint64_t)pfGetSystemTime();
            //PFTRACE(("TLS_RECV (in while), TCP Remote port: %d Time dif: %d", pcb->remote_port, (int) (time2-time1)));

          return ERR_OK;
        }*/
      }
    }
    while (ret > 0);
  }
  return ERR_OK;
}

static err_t
altcp_mbedtls_lower_sent(void *arg, struct altcp_pcb *inner_conn, u16_t len)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    if (!state->handshake_done) {
      /* TODO: do something here? */
      return ERR_OK;
    }
    if (conn->sent) {
      return conn->sent(conn->arg, conn, len);
    }
  }
  return ERR_OK;
}

static err_t
altcp_mbedtls_lower_poll(void *arg, struct altcp_pcb *inner_conn)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    if (conn->poll) {
      return conn->poll(conn->arg, conn);
    }
  }
  return ERR_OK;
}

static void
altcp_mbedtls_lower_err(void *arg, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    if (conn->err) {
      conn->err(conn->arg, err);
    }
  }
}

/* setup functions */
static void
altcp_mbedtls_setup_callbacks(struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  altcp_arg(inner_conn, conn);
  altcp_recv(inner_conn, altcp_mbedtls_lower_recv);
  altcp_sent(inner_conn, altcp_mbedtls_lower_sent);
  altcp_err(inner_conn, altcp_mbedtls_lower_err);
  /* tcp_poll is set when interval is set by application */
  /* listen is set totally different :-) */
}

/* TODO: return error? */
static err_t
altcp_mbedtls_setup(struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  int ret;
  /* allocate mbedtls context */
  altcp_mbedtls_state_t *state = altcp_mbedtls_alloc();
  if (state == NULL) {
    return ERR_MEM;
  }
  /* initialize mbedtls context: */
  mbedtls_ssl_init(&state->ssl_context);
  ret = mbedtls_ssl_setup(&state->ssl_context, &conf);
  if (ret != 0) {
    LWIP_ASSERT("mbedtls_ssl_setup failed. \n", ret == 0);
    /* TODO: convert 'ret' to err_t */
    return ERR_MEM;
  }
  /* tell mbedtls about our I/O functions */
  mbedtls_ssl_set_bio(&state->ssl_context, conn, altcp_mbedtls_bio_send, altcp_mbedtls_bio_recv, NULL);

  altcp_mbedtls_setup_callbacks(conn, inner_conn);
  conn->inner_conn = inner_conn;
  conn->fns = &altcp_mbedtls_functions;
  return ERR_OK;
}

struct altcp_pcb *
altcp_tls_new(struct altcp_pcb *inner_pcb)
{
  struct altcp_pcb *ret;
  if (inner_pcb == NULL) {
    return NULL;
  }
  ret = altcp_alloc();
  if (ret != NULL) {
    if (altcp_mbedtls_setup(ret, inner_pcb) != ERR_OK) {
      altcp_free(ret);
      return NULL;
    }
  }
  return ret;
}

static void
altcp_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
  LWIP_UNUSED_ARG(str);
  LWIP_UNUSED_ARG(level);
  LWIP_UNUSED_ARG(file);
  LWIP_UNUSED_ARG(line);
  LWIP_UNUSED_ARG(ctx);
}

struct tls_malloc_helper
{
  size_t c;
  size_t len;
};

struct tls_malloc_stats_s
{
  size_t allocedBytes;
  size_t allocCnt;
  size_t maxBytes;
  size_t totalBytes;
};
struct tls_malloc_stats_s tls_malloc_stats;
volatile int tls_malloc_clear_stats;

static void *tls_malloc(size_t c, size_t len)
{
  struct tls_malloc_helper* hlpr;
  void* ret;
  if(tls_malloc_clear_stats)
  {
    if(tls_malloc_clear_stats)
    {
      tls_malloc_clear_stats = 0;
      memset(&tls_malloc_stats, 0, sizeof(tls_malloc_stats));
    }
  }
  //LWIP_MEMPOOL_ALLOC(name);
  hlpr = (struct tls_malloc_helper*)mem_malloc(sizeof(struct tls_malloc_helper) + (c*len));
  //LWIP_ASSERT("alloc failure", hlpr != NULL);
  if(hlpr == NULL)
  {
    return NULL;
  }
  tls_malloc_stats.allocCnt++;
  tls_malloc_stats.allocedBytes += c*len;
  if(tls_malloc_stats.allocedBytes > tls_malloc_stats.maxBytes)
  {
    tls_malloc_stats.maxBytes = tls_malloc_stats.allocedBytes;
  }
  tls_malloc_stats.totalBytes += c*len;
  hlpr->c = c;
  hlpr->len = len;
  ret = hlpr + 1;
  memset(ret, 0, c*len); // zeroing the allocated chunk is required!
  return ret;
}

static void tls_free(void * ptr)
{
  struct tls_malloc_helper* hlpr;
  if(ptr == NULL)
  {
    return; // this obviously happens...
  }
  hlpr = ((struct tls_malloc_helper*)ptr)-1;
  if(!tls_malloc_clear_stats)
  {
    tls_malloc_stats.allocedBytes -= hlpr->c*hlpr->len;
  }
  //LWIP_MEMPOOL_FREE(name, x);
  mem_free(hlpr);
}

int dummy_rng(void *ctx, unsigned char *buffer , size_t len)
{
  static size_t ctr;
  size_t i;
  LWIP_UNUSED_ARG(ctx);
  for(i = 0; i < len; i++) {
    buffer[i] = (unsigned char)++ctr;
  }
  return 0;
}

err_t
altcp_tls_global_init(const u8_t *privkey, size_t privkey_len,
                      const u8_t *privkey_pass, size_t privkey_pass_len,
                      const u8_t *cert, size_t cert_len)
{
  int ret;
  static mbedtls_entropy_context entropy;
  static mbedtls_ctr_drbg_context ctr_drbg;
  static mbedtls_x509_crt srvcert;
  static mbedtls_pk_context pkey;

  /* TODO: set mbedtls allocation methods */
  //mbedtls_platform_set_calloc_free( &tls_malloc, &tls_free );

  mbedtls_ssl_config_init( &conf );
  mbedtls_x509_crt_init( &srvcert );
  mbedtls_pk_init( &pkey );
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );

  /* Load the certificates and private key */
  ret = mbedtls_x509_crt_parse(&srvcert, cert, cert_len);
  if (ret != 0) {
    LWIP_ASSERT("mbedtls_x509_crt_parse failed. \n", ret == 0);
    /* TODO: convert 'ret' to err_t */
    return ERR_ARG;
  }
  //key_pem_format[privkeylen]='\0';
  ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) privkey, privkey_len, privkey_pass, privkey_pass_len);
  if (ret != 0) {
    LWIP_ASSERT("mbedtls_pk_parse_public_key failed. \n", ret == 0);
    /* TODO: convert 'ret' to err_t */
    return ERR_ARG;
  }

  /* Seed the RNG (TODO: add custom entropy) */
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_rng, &entropy, NULL, 0);
  if (ret != 0) {
    LWIP_ASSERT("mbedtls_ctr_drbg_seed failed. \n", ret == 0);
    /* TODO: convert 'ret' to err_t */
    return ERR_VAL;
  }

  /* Setup ssl context (TODO: what's different for a client here? -> might better be done on listen/connect) */
  ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    LWIP_ASSERT("mbedtls_ssl_config_defaults failed.\n", ret == 0);
    /* TODO: convert 'ret' to err_t */
    return ERR_VAL;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, altcp_mbedtls_debug, stdout);
#ifdef MBEDTLS_SSL_CACHE_C
  mbedtls_ssl_conf_session_cache(&conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
  //mbedtls_ssl_cache_set_timeout(&cache, 30);
  mbedtls_ssl_cache_set_max_entries(&cache, 30);
#endif

  mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
  ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
  if (ret != 0) {
    LWIP_ASSERT("mbedtls_ssl_conf_own_cert failed.\n", ret == 0);
    /* TODO: convert 'ret' to err_t */
    return ERR_VAL;
  }
  return ERR_OK;
}

/* "virtual" functions */
static void
altcp_mbedtls_set_poll(struct altcp_pcb *conn, u8_t interval)
{
  if (conn != NULL) {
    altcp_poll(conn->inner_conn, altcp_mbedtls_lower_poll, interval);
  }
}

static void
altcp_mbedtls_recved(struct altcp_pcb *conn, u16_t len)
{
  if (conn != NULL) {
    altcp_recved(conn->inner_conn, len);
  }
}

static err_t
altcp_mbedtls_bind(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  return altcp_bind(conn->inner_conn, ipaddr, port);
}

static err_t
altcp_mbedtls_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  conn->connected = connected;
  return altcp_connect(conn->inner_conn, ipaddr, port, altcp_mbedtls_lower_connected);
}

static struct altcp_pcb *
altcp_mbedtls_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
  struct altcp_pcb *lpcb;
  if (conn == NULL) {
    return NULL;
  }
  lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
  if (lpcb != NULL) {
    conn->inner_conn = lpcb;
    altcp_accept(lpcb, altcp_mbedtls_lower_accept);
    return conn;
  }
  return NULL;
}

static void
altcp_mbedtls_abort(struct altcp_pcb *conn)
{
  if (conn != NULL) {
    altcp_abort(conn->inner_conn);
  }
}

static err_t
altcp_mbedtls_close(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  return altcp_close(conn->inner_conn);
}

static err_t
altcp_mbedtls_shutdown(struct altcp_pcb *conn, int shut_rx, int shut_tx)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  return altcp_shutdown(conn->inner_conn, shut_rx, shut_tx);
}

static err_t
altcp_mbedtls_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
  int ret;
  altcp_mbedtls_state_t *state;

  LWIP_UNUSED_ARG(apiflags);

  if (conn == NULL) {
    return ERR_VAL;
  }

  state = (altcp_mbedtls_state_t*)conn->state;

  ret = mbedtls_ssl_write(&state->ssl_context, (const unsigned char *)dataptr, len);
  if(ret == len) {
    return ERR_OK;
  } else {
    /* assumption: either everything sent or error */
    LWIP_ASSERT("ret <= 0", ret <= 0);
    /* TODO: convert error to err_t */
    return ERR_MEM;
  }
}

static err_t
altcp_mbedtls_output(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  return altcp_output(conn->inner_conn);
}

static u16_t
altcp_mbedtls_mss(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return 0;
  }
  return altcp_mss(conn->inner_conn);
}

static u16_t
altcp_mbedtls_sndbuf(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return 0;
  }
  return altcp_sndbuf(conn->inner_conn);
}

static u16_t
altcp_mbedtls_sndqueuelen(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return 0;
  }
  return altcp_sndqueuelen(conn->inner_conn);
}

static void
altcp_mbedtls_setprio(struct altcp_pcb *conn, u8_t prio)
{
  if (conn != NULL) {
    altcp_setprio(conn->inner_conn, prio);
  }
}

static void
altcp_mbedtls_dealloc(struct altcp_pcb *conn)
{
  LWIP_UNUSED_ARG(conn);
  /* TODO: clean up and free tls state */
}

const struct altcp_functions altcp_mbedtls_functions = {
  altcp_mbedtls_set_poll,
  altcp_mbedtls_recved,
  altcp_mbedtls_bind,
  altcp_mbedtls_connect,
  altcp_mbedtls_listen,
  altcp_mbedtls_abort,
  altcp_mbedtls_close,
  altcp_mbedtls_shutdown,
  altcp_mbedtls_write,
  altcp_mbedtls_output,
  altcp_mbedtls_mss,
  altcp_mbedtls_sndbuf,
  altcp_mbedtls_sndqueuelen,
  altcp_mbedtls_setprio,
  altcp_mbedtls_dealloc
};

#endif /* LWIP_ALTCP */
