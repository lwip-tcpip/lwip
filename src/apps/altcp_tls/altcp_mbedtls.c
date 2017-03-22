/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file provides a TLS layer using mbedTLS
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
 * Missing things / @todo:
 * - RX data is acknowledged after receiving (tcp_recved is called when enqueueing
 *   the pbuf for mbedTLS receive, not when processed by mbedTLS or the inner
 *   connection; altcp_recved() from inner connection does nothing)
 * - TX data is marked as 'sent' (i.e. acknowledged; sent callback is called) right
 *   after enqueueing for transmission, not when actually ACKed be the remote host.
 * - Client connections starting with 'connect()' are not handled yet...
 * - some unhandled things are caught by LWIP_ASSERTs...
 * - only one mbedTLS configuration is supported yet (i.e. one certificate, settings, etc.)
 *
 * Configuration:
 * - define ALTCP_MBEDTLS_RNG_FN to a custom GOOD rng function returning 0 on success:
 *   int my_rng_fn(void *ctx, unsigned char *buffer , size_t len)
 * - define ALTCP_MBEDTLS_ENTROPY_PTR and ALTCP_MBEDTLS_ENTROPY_LEN to something providing
 *   GOOD custom entropy
 */

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS

#include "lwip/altcp.h"
#include "lwip/priv/altcp_priv.h"

#include "altcp_mbedtls_structs.h"
#include "altcp_mbedtls_mem.h"

/* @todo: which includes are really needed? */
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

#include <string.h>

#ifndef ALTCP_MBEDTLS_ENTROPY_PTR
#define ALTCP_MBEDTLS_ENTROPY_PTR   NULL
#endif
#ifndef ALTCP_MBEDTLS_ENTROPY_LEN
#define ALTCP_MBEDTLS_ENTROPY_LEN   0
#endif

/* Variable prototype, the actual declaration is at the end of this file
   since it contains pointers to static functions declared here */
extern const struct altcp_functions altcp_mbedtls_functions;

/** Our global mbedTLS configuration (server-specific, not connection-specific) */
struct altcp_tls_config
{
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
#if defined(MBEDTLS_SSL_CACHE_C) && ALTCP_MBEDTLS_SESSION_CACHE_TIMEOUT_SECONDS
  /** Inter-connection cache for fast connection startup */
  struct mbedtls_ssl_cache_context cache;
#endif
};

static err_t altcp_mbedtls_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static void altcp_mbedtls_dealloc(struct altcp_pcb *conn);
static err_t altcp_mbedtls_handle_rx_data(struct altcp_pcb *conn);
static int altcp_mbedtls_bio_send(void* ctx, const unsigned char* dataptr, size_t size);


/* callback functions from inner/lower connection: */

/** Accept callback from lower connection (i.e. TCP)
 * Allocate one of our structures, assign it to the new connection's 'state' and
 * call the new connection's 'accepted' callback. If that succeeds, we wait
 * to receive connection setup handshake bytes from the client.
 */
static err_t
altcp_mbedtls_lower_accept(void *arg, struct altcp_pcb *accepted_conn, err_t err)
{
  struct altcp_pcb *listen_conn = (struct altcp_pcb *)arg;
  if (listen_conn && listen_conn->state && listen_conn->accept) {
    err_t setup_err;
    altcp_mbedtls_state_t *listen_state = (altcp_mbedtls_state_t *)listen_conn->state;
    /* create a new altcp_conn to pass to the next 'accept' callback */
    struct altcp_pcb *new_conn = altcp_alloc();
    if (new_conn == NULL) {
      return ERR_MEM;
    }
    setup_err = altcp_mbedtls_setup(listen_state->conf, new_conn, accepted_conn);
    if (setup_err != ERR_OK) {
      altcp_free(new_conn);
      return setup_err;
    }
    return listen_conn->accept(listen_conn->arg, new_conn, err);
  }
  return ERR_ARG;
}

/** Connected callback from lower connection (i.e. TCP).
 * Not really implemented/tested yet...
 */
static err_t
altcp_mbedtls_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    /* upper connected is called when handshake is done */
    LWIP_UNUSED_ARG(err);
    LWIP_ASSERT("TODO: implement active connect", 0);
    return ERR_OK;
  }
  return ERR_VAL;
}

/** Recv callback from lower connection (i.e. TCP)
 * This one mainly differs between connection setup/handshake (data is fed into mbedTLS only)
 * and application phase (data is decoded by mbedTLS and passed on to the application).
 */
static err_t
altcp_mbedtls_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err)
{
  altcp_mbedtls_state_t *state;
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (!conn) {
    /* no connection given as arg? should not happen, but prevent pbuf/conn leaks */
    if (p != NULL) {
      pbuf_free(p);
    }
    altcp_close(inner_conn);
    return ERR_CLSD;
  }
  state = (altcp_mbedtls_state_t *)conn->state;
  LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
  if (!state) {
    /* already closed */
    if (p != NULL) {
      pbuf_free(p);
    }
    altcp_close(inner_conn);
    return ERR_CLSD;
  }

  /* handle NULL pbufs or other errors */
  if ((p == NULL) || (err != ERR_OK)) {
    err_t err = ERR_OK;
    if (p == NULL) {
      /* remote host sent FIN, remember this (SSL state is destroyed
         when both sides are closed only!) */
      state->flags |= ALTCP_MBEDTLS_FLAGS_RX_CLOSED;
    }
    if (state->flags & ALTCP_MBEDTLS_FLAGS_UPPER_CALLED) {
      /* need to notify upper layer (e.g. 'accept' called or 'connect' succeeded) */
      if (conn->recv) {
        err = conn->recv(conn->arg, conn, p, err);
      } else {
        /* no recv callback? close connection */
        if (p) {
          pbuf_free(p);
        }
        altcp_close(conn);
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
    if (conn->state && ((state->flags & ALTCP_MBEDTLS_FLAGS_CLOSED) == ALTCP_MBEDTLS_FLAGS_CLOSED)) {
      altcp_mbedtls_dealloc(conn);
    }
    return err;
  }

  /* If we come here, the connection is in good state (handshake phase or application data phase).
     Queue up the pbuf for processing as handshake data or application data. */
  if (state->rx == NULL) {
    state->rx = p;
  } else {
    LWIP_ASSERT("rx pbuf overflow", (int)p->tot_len + (int)p->len <= 0xFFFF);
    pbuf_cat(state->rx, p);
  }

  if (!(state->flags & ALTCP_MBEDTLS_FLAGS_HANDSHAKE_DONE)) {
    /* handle connection setup (handshake not done) */
    int ret;

    /* during handshake: mark all data as received */
    altcp_recved(conn->inner_conn, p->tot_len);

    ret = mbedtls_ssl_handshake(&state->ssl_context);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      /* handshake not done, wait for more recv calls */
      return ERR_OK;
    }
    if (ret != 0) {
      LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_ssl_handshake failed: %d", ret));
      /* handshake failed, connection has to be closed */
      conn->recv(conn->arg, conn, NULL, ERR_OK);
      if (altcp_close(conn->inner_conn) != ERR_OK) {
        altcp_abort(conn->inner_conn);
      }
      return ERR_OK;
    }
    /* If we come here, handshake succeeded. */
    LWIP_ASSERT("rx pbufs left at end of handshake", state->rx == NULL);
    state->flags |= ALTCP_MBEDTLS_FLAGS_HANDSHAKE_DONE;
    /* issue "connect" callback" to upper connection (this can only happen for active open) */
    if (conn->connected) {
      conn->connected(conn->arg, conn, ERR_OK);
    }
    return ERR_OK;
  } else {
    /* handle application data */
    /* @todo: call recved for unencrypted overhead only */
    altcp_recved(conn->inner_conn, p->tot_len);
    return altcp_mbedtls_handle_rx_data(conn);
  }
}

/* Helper function that processes rx application data stored in rx pbuf chain */
static err_t
altcp_mbedtls_handle_rx_data(struct altcp_pcb *conn)
{
  int ret;
  altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t *)conn->state;
  if (!state) {
    return ERR_VAL;
  }
  if (!(state->flags & ALTCP_MBEDTLS_FLAGS_HANDSHAKE_DONE)) {
    /* handshake not done yet */
    return ERR_VAL;
  }
  do {
    /* allocate a full-sized unchained PBUF_POOL: this is for RX! */
    struct pbuf *buf = pbuf_alloc(PBUF_RAW, PBUF_POOL_BUFSIZE, PBUF_POOL);
    if (buf == NULL) {
      /* We're short on pbufs, try again later from 'poll' or 'recv' callbacks.
         @todo: close on excessive allocation failures or leave this up to upper conn? */
      return ERR_OK;
    }

    /* decrypt application data, this pulls encrypted RX data off state->rx pbuf chain */
    ret = mbedtls_ssl_read(&state->ssl_context, (unsigned char *)buf->payload, PBUF_POOL_BUFSIZE);
    if (ret < 0) {
      if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
        /* client is initiating a new connection using the same source port -> close connection or make handshake */
        LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("new connection on same source port"));
        LWIP_ASSERT("TODO: new connection on same source port, close this connection", 0);
      } else if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
          LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("connection was closed gracefully"));
        } else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
          LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("connection was reset by peer"));
        }
        pbuf_free(buf);
        return ERR_OK;
      } else {
        pbuf_free(buf);
        return ERR_OK;
      }
      pbuf_free(buf);
      altcp_abort(conn);
      return ERR_ABRT;
    } else {
      LWIP_ASSERT("bogus receive length", ret <= 0xFFFF && ret <= PBUF_POOL_BUFSIZE);
      /* trim pool pbuf to actually decoded length */
      pbuf_realloc(buf, (uint16_t)ret);

      if (conn->recv) {
        err_t err;
        state->rx_passed_unrecved += buf->tot_len;
        err = conn->recv(conn->arg, conn, buf, ERR_OK);
        if (err == ERR_ABRT) {
          return ERR_ABRT;
        }
      } else {
        pbuf_free(buf);
      }
    }
  }
  while (ret > 0);
  return ERR_OK;
}

/** Receive callback function called from mbedtls (set via mbedtls_ssl_set_bio)
 * This function mainly copies data from pbufs and frees the pbufs after copying.
 */
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
  copy_len = LWIP_MIN(copy_len, p->len);
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

/** Sent callback from lower connection (i.e. TCP)
 * @todo: Pass on the correct number of bytes to the application.
 *        This is somewhat tricky as we don't know the data/overhead ratio...
 */
static err_t
altcp_mbedtls_lower_sent(void *arg, struct altcp_pcb *inner_conn, u16_t len)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    u16_t sent_upper;
    altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    if (!state || !(state->flags & ALTCP_MBEDTLS_FLAGS_HANDSHAKE_DONE)) {
      /* @todo: do something here? */
      return ERR_OK;
    }
    /* @todo: this is not accurate yet, need to fix byte counting to upper and lower conn */
    sent_upper = (u16_t)LWIP_MIN(len, state->tx_unacked);
    state->tx_unacked -= sent_upper;
    if (conn->sent && sent_upper) {
      return conn->sent(conn->arg, conn, len);
    }
  }
  return ERR_OK;
}

/** Poll callback from lower connection (i.e. TCP)
 * Just pass this on to the application.
 * @todo: retry sending if 
 */
static err_t
altcp_mbedtls_lower_poll(void *arg, struct altcp_pcb *inner_conn)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    /* check if there's unreceived rx data */
    altcp_mbedtls_handle_rx_data(conn);
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
    /* @todo: deallocate/close this connection? */
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

static err_t
altcp_mbedtls_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  int ret;
  struct altcp_tls_config *config = (struct altcp_tls_config *)conf;
  altcp_mbedtls_state_t *state;
  if (!conf) {
    return ERR_ARG;
  }
  /* allocate mbedtls context */
  state = altcp_mbedtls_alloc(conf);
  if (state == NULL) {
    return ERR_MEM;
  }
  /* initialize mbedtls context: */
  mbedtls_ssl_init(&state->ssl_context);
  ret = mbedtls_ssl_setup(&state->ssl_context, &config->conf);
  if (ret != 0) {
    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_ssl_setup failed"));
    /* @todo: convert 'ret' to err_t */
    altcp_mbedtls_free(conf, state);
    return ERR_MEM;
  }
  /* tell mbedtls about our I/O functions */
  mbedtls_ssl_set_bio(&state->ssl_context, conn, altcp_mbedtls_bio_send, altcp_mbedtls_bio_recv, NULL);

  altcp_mbedtls_setup_callbacks(conn, inner_conn);
  conn->inner_conn = inner_conn;
  conn->fns = &altcp_mbedtls_functions;
  conn->state = state;
  return ERR_OK;
}

struct altcp_pcb *
altcp_tls_new(struct altcp_tls_config* config, struct altcp_pcb *inner_pcb)
{
  struct altcp_pcb *ret;
  if (inner_pcb == NULL) {
    return NULL;
  }
  ret = altcp_alloc();
  if (ret != NULL) {
    if (altcp_mbedtls_setup(config, ret, inner_pcb) != ERR_OK) {
      altcp_free(ret);
      return NULL;
    }
  }
  return ret;
}

#if ALTCP_MBEDTLS_DEBUG != LWIP_DBG_OFF
static void
altcp_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
  LWIP_UNUSED_ARG(str);
  LWIP_UNUSED_ARG(level);
  LWIP_UNUSED_ARG(file);
  LWIP_UNUSED_ARG(line);
  LWIP_UNUSED_ARG(ctx);
  /* @todo: output debug string :-) */
}
#endif

#ifndef ALTCP_MBEDTLS_RNG_FN
/** ATTENTION: It is *really* important to *NOT* use this dummy RNG in production code!!!! */
int dummy_rng(void *ctx, unsigned char *buffer , size_t len)
{
  static size_t ctr;
  size_t i;
  LWIP_UNUSED_ARG(ctx);
  for (i = 0; i < len; i++) {
    buffer[i] = (unsigned char)++ctr;
  }
  return 0;
}
#define ALTCP_MBEDTLS_RNG_FN dummy_rng
#endif /* ALTCP_MBEDTLS_RNG_FN */

/** Create new TLS configuration
 * ATTENTION: Server certificate and private key have to be added outside this function!
 */
struct altcp_tls_config*
altcp_tls_create_config(void)
{
  int ret;
  struct altcp_tls_config *conf;

  altcp_mbedtls_mem_init();

  conf = (struct altcp_tls_config *)altcp_mbedtls_alloc_config(sizeof(struct altcp_tls_config));
  if (conf == NULL) {
    return NULL;
  }

  mbedtls_ssl_config_init(&conf->conf);
  mbedtls_entropy_init(&conf->entropy);
  mbedtls_ctr_drbg_init(&conf->ctr_drbg);

  /* Seed the RNG */
  ret = mbedtls_ctr_drbg_seed(&conf->ctr_drbg, ALTCP_MBEDTLS_RNG_FN, &conf->entropy, ALTCP_MBEDTLS_ENTROPY_PTR, ALTCP_MBEDTLS_ENTROPY_LEN);
  if (ret != 0) {
    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_ctr_drbg_seed failed: %d", ret));
    altcp_mbedtls_free_config(conf);
    return NULL;
  }

  /* Setup ssl context (@todo: what's different for a client here? -> might better be done on listen/connect) */
  ret = mbedtls_ssl_config_defaults(&conf->conf, MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_ssl_config_defaults failed: %d", ret));
    altcp_mbedtls_free_config(conf);
    return NULL;
  }

  mbedtls_ssl_conf_rng(&conf->conf, mbedtls_ctr_drbg_random, &conf->ctr_drbg);
#if ALTCP_MBEDTLS_DEBUG != LWIP_DBG_OFF
  mbedtls_ssl_conf_dbg(&conf->conf, altcp_mbedtls_debug, stdout);
#endif
#if defined(MBEDTLS_SSL_CACHE_C) && ALTCP_MBEDTLS_SESSION_CACHE_TIMEOUT_SECONDS
  mbedtls_ssl_conf_session_cache(&conf->conf, &conf->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
  mbedtls_ssl_cache_set_timeout(&conf->cache, 30);
  mbedtls_ssl_cache_set_max_entries(&conf->cache, 30);
#endif

  return conf;
}

/** Create new TLS configuration
 * This is a suboptimal version that gets the encrypted private key and its password,
 * as well as the server certificate.
 */
struct altcp_tls_config*
altcp_tls_create_config_privkey_cert(const u8_t *privkey, size_t privkey_len,
                      const u8_t *privkey_pass, size_t privkey_pass_len,
                      const u8_t *cert, size_t cert_len)
{
  int ret;
  static mbedtls_x509_crt srvcert;
  static mbedtls_pk_context pkey;
  struct altcp_tls_config *conf = altcp_tls_create_config();
  if (conf == NULL) {
    return NULL;
  }

  mbedtls_x509_crt_init(&srvcert);
  mbedtls_pk_init(&pkey);

  /* Load the certificates and private key */
  ret = mbedtls_x509_crt_parse(&srvcert, cert, cert_len);
  if (ret != 0) {
    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_x509_crt_parse failed: %d", ret));
    altcp_mbedtls_free_config(conf);
    return NULL;
  }

  ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) privkey, privkey_len, privkey_pass, privkey_pass_len);
  if (ret != 0) {
    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_pk_parse_public_key failed: %d", ret));
    altcp_mbedtls_free_config(conf);
    return NULL;
  }

  mbedtls_ssl_conf_ca_chain(&conf->conf, srvcert.next, NULL);
  ret = mbedtls_ssl_conf_own_cert(&conf->conf, &srvcert, &pkey);
  if (ret != 0) {
    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_ssl_conf_own_cert failed: %d", ret));
    altcp_mbedtls_free_config(conf);
    return NULL;
  }
  return conf;
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
  altcp_mbedtls_state_t *state;
  if (conn == NULL) {
    return;
  }
  state = (altcp_mbedtls_state_t*)conn->state;
  if (state == NULL) {
    return;
  }
  if (!(state->flags & ALTCP_MBEDTLS_FLAGS_HANDSHAKE_DONE)) {
    return;
  }
  LWIP_ASSERT("recved mismatch", state->rx_passed_unrecved >= len);  
  state->rx_passed_unrecved -= len;

  /* to pass this down, we need to convert 'altcp_recved' handling in lower_recv first
  altcp_recved(conn->inner_conn, len);*/
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
  altcp_mbedtls_state_t *state;
  if (conn == NULL) {
    return ERR_VAL;
  }
  state = (altcp_mbedtls_state_t*)conn->state;
  if (state != NULL) {
    if (state->rx != NULL) {
      pbuf_free(state->rx);
      state->rx = NULL;
    }
    state->flags |= ALTCP_MBEDTLS_FLAGS_TX_CLOSED;
    if (state->flags & ALTCP_MBEDTLS_FLAGS_RX_CLOSED) {
      altcp_mbedtls_dealloc(conn);
    }
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

/** Write data to a TLS connection. Calls into mbedTLS, which in turn calls into
 * @ref altcp_mbedtls_bio_send() to send the encrypted data
 */
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
  if (state == NULL) {
    /* @todo: which error? */
    return ERR_CLSD;
  }
  if (!(state->flags & ALTCP_MBEDTLS_FLAGS_HANDSHAKE_DONE)) {
    /* @todo: which error? */
    return ERR_VAL;
  }

  ret = mbedtls_ssl_write(&state->ssl_context, (const unsigned char *)dataptr, len);
  if(ret == len) {
    state->tx_unacked += len;
    return ERR_OK;
  } else if (ret <= 0) {
    /* @todo: convert error to err_t */
    return ERR_MEM;
  } else {
    /* assumption: either everything sent or error */
    LWIP_ASSERT("ret <= 0", 0);
    return ERR_MEM;
  }
}

/** Send callback function called from mbedtls (set via mbedtls_ssl_set_bio)
 * This function is either called during handshake or when sending application
 * data via @ref altcp_mbedtls_write (or altcp_write)
 */
static int
altcp_mbedtls_bio_send(void* ctx, const unsigned char* dataptr, size_t size)
{
  struct altcp_pcb *conn = (struct altcp_pcb *) ctx;
  int written = 0;
  size_t size_left = size;
  u8_t apiflags = TCP_WRITE_FLAG_COPY;

  LWIP_ASSERT("conn != NULL", conn != NULL);

  while (size_left) {
    u16_t write_len = (u16_t)LWIP_MIN(size_left, 0xFFFF);
    err_t err = altcp_write(conn->inner_conn, (const void *)dataptr, write_len, apiflags);
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
  /* @todo: LWIP_MIN(mss, mbedtls_ssl_get_max_frag_len()) ? */
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
  /* clean up and free tls state */
  if (conn) {
    altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t*)conn->state;
    if (state) {
      mbedtls_ssl_free(&state->ssl_context);
      state->flags = 0;
      altcp_mbedtls_free(state->conf, state);
    }
    conn->state = NULL;
  }
}

err_t
altcp_mbedtls_get_tcp_addrinfo(struct altcp_pcb *conn, int local, ip_addr_t *addr, u16_t *port)
{
  if (conn) {
    return altcp_get_tcp_addrinfo(conn->inner_conn, local, addr, port);
  }
  return ERR_VAL;
}

#ifdef LWIP_DEBUG
enum tcp_state
altcp_mbedtls_dbg_get_tcp_state(struct altcp_pcb *conn)
{
  if (conn) {
    return altcp_dbg_get_tcp_state(conn->inner_conn);
  }
  return CLOSED;
}
#endif


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
  altcp_mbedtls_dealloc,
  altcp_mbedtls_get_tcp_addrinfo
#ifdef LWIP_DEBUG
  ,altcp_mbedtls_dbg_get_tcp_state
#endif
};

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS */
#endif /* LWIP_ALTCP */
