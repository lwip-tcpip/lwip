/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file provides a TLS layer using openHiTLS (Chinese national cryptography
 * protocol library)
 */

/*
 * Copyright (c) 2026 openHiTLS
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
 * Author: Hui Zhang
 *
 */

#include "lwip/opt.h"
#include "lwip/sys.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_hitls_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_HITLS

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/priv/altcp_priv.h"
#include "lwip/mem.h"

#include "altcp_tls_hitls_structs.h"

#include "bsl_uio.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls.h"
#include "hitls_type.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_x509.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_crypt_type.h"
#if LWIP_ALTCP_HITLS_SESSION_RESUMPTION
#include "hitls_session.h"
#endif
#if LWIP_ALTCP_HITLS_ALPN
#include "hitls_alpn.h"
#endif

#include <string.h>

#define ALTCP_HITLS_DEBUG_SERIOUS      (ALTCP_HITLS_DEBUG | LWIP_DBG_LEVEL_SERIOUS)

#define HITLS_ERROR_CODE_FORMAT "(0x%08x)"

/* Variable prototype, the actual declaration is at the end of this file
   since it contains pointers to static functions declared here */
extern const struct altcp_functions altcp_hitls_functions;

static err_t altcp_hitls_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err);
static err_t altcp_hitls_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static err_t altcp_hitls_lower_recv_process(struct altcp_pcb *conn, altcp_hitls_state_t *state);
static err_t altcp_hitls_handle_rx_appldata(struct altcp_pcb *conn, altcp_hitls_state_t *state);

err_t
altcp_tls_hitls_init(void)
{
  s32_t ret = BSL_ERR_Init();
  if (ret != BSL_SUCCESS) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("hitls err init failed" HITLS_ERROR_CODE_FORMAT "\n", ret));
    return ERR_VAL;
  }

  s32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
  if (ret != CRYPT_SUCCESS) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("hitls crypt init failed" HITLS_ERROR_CODE_FORMAT "\n", ret));
    return ERR_VAL;
  }

  return ERR_OK;
}

void
altcp_tls_hitls_deinit(void)
{
  HITLS_CertMethodDeinit();
  CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}

/* callback functions from inner/lower connection: */

/** Accept callback from lower connection (i.e. TCP)
 * Allocate one of our structures, assign it to the new connection's 'state' and
 * call the new connection's 'accepted' callback. If that succeeds, we wait
 * to receive connection setup handshake bytes from the client.
 */
static err_t
altcp_hitls_lower_accept(void *arg, struct altcp_pcb *accepted_conn, err_t err)
{
  struct altcp_pcb *listen_conn = (struct altcp_pcb *)arg;
  if (listen_conn && listen_conn->state && listen_conn->accept) {
    err_t setup_err;
    altcp_hitls_state_t *listen_state = (altcp_hitls_state_t *)listen_conn->state;
    struct altcp_pcb *new_conn = altcp_alloc();
    if (new_conn == NULL) {
      return ERR_MEM;
    }
    setup_err = altcp_hitls_setup(listen_state->conf, new_conn, accepted_conn);
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
altcp_hitls_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  LWIP_UNUSED_ARG(inner_conn);
  if (conn && conn->state) {
    altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

    if (err != ERR_OK) {
      if (conn->connected) {
        return conn->connected(conn->arg, conn, err);
      }
    }

    state->overhead_bytes_adjust = 0;

    return altcp_hitls_lower_recv_process(conn, state);
  }

  return ERR_VAL;
}

/* Call recved for possibly more than an u16_t */
static void
altcp_hitls_lower_recved(struct altcp_pcb *inner_conn, int recvd_cnt)
{
  while (recvd_cnt > 0) {
    u16_t recvd_part = (u16_t)LWIP_MIN(recvd_cnt, 0xFFFF);
    altcp_recved(inner_conn, recvd_part);
    recvd_cnt -= recvd_part;
  }
}

/** Recv callback from lower connection (i.e. TCP)
 * This one mainly differs between connection setup/handshake (data is fed into HiTLS only)
 * and application phase (data is decoded by HiTLS and passed on to the application).
 */
static err_t
altcp_hitls_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err)
{
  altcp_hitls_state_t *state;
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;

  LWIP_ASSERT("no err expected", err == ERR_OK);
  LWIP_UNUSED_ARG(err);

  if (!conn) {
    /* no connection given as arg? should not happen, but prevent pbuf/conn leaks */
    if (p != NULL) {
      pbuf_free(p);
    }
    altcp_close(inner_conn);
    return ERR_CLSD;
  }
  state = (altcp_hitls_state_t *)conn->state;
  LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
  if (!state) {
    /* already closed */
    if (p != NULL) {
      pbuf_free(p);
    }
    altcp_close(inner_conn);
    return ERR_CLSD;
  }

  if (p == NULL) {
    /* remote host sent FIN, remember this (SSL state is destroyed
      when both sides are closed only!) */
    if ((state->flags & (ALTCP_HITLS_FLAGS_HANDSHAKE_DONE | ALTCP_HITLS_FLAGS_UPPER_CALLED)) ==
      (ALTCP_HITLS_FLAGS_HANDSHAKE_DONE | ALTCP_HITLS_FLAGS_UPPER_CALLED)) {
      /* need to notify upper layer (e.g. 'accept' called or 'connect' succeeded) */
      if ((state->rx != NULL) || (state->rx_app != NULL)) {
        state->flags |= ALTCP_HITLS_FLAGS_RX_CLOSE_QUEUED;
        /* this is a normal close (FIN) but we have unprocessed data, so delay the FIN */
        altcp_hitls_handle_rx_appldata(conn, state);
        return ERR_OK;
      }
      state->flags |= ALTCP_HITLS_FLAGS_RX_CLOSED;
      if (conn->recv) {
        return conn->recv(conn->arg, conn, NULL, ERR_OK);
      }
    } else {
      /* before connection setup is done: call 'err' */
      if (conn->err) {
        conn->err(conn->arg, ERR_ABRT);
      }
      altcp_close(conn);
    }
    return ERR_OK;
  }

  /* If we come here, the connection is in good state (handshake phase or application data phase).
     Queue up the pbuf for processing as handshake data or application data. */
  if (state->rx == NULL) {
    state->rx = p;
  } else {
    LWIP_ASSERT("rx pbuf overflow", (int)p->tot_len + (int)p->len <= 0xFFFF);
    pbuf_cat(state->rx, p);
  }

  return altcp_hitls_lower_recv_process(conn, state);
}

static err_t
altcp_hitls_lower_recv_process(struct altcp_pcb *conn, altcp_hitls_state_t *state)
{
  if (!(state->flags & ALTCP_HITLS_FLAGS_HANDSHAKE_DONE)) {
    /* handle connection setup (handshake not done) */
    bool is_server = false;
    (void)HITLS_IsServer(state->hitls_ctx, &is_server);
    s32_t ret = is_server ? HITLS_Accept(state->hitls_ctx) : HITLS_Connect(state->hitls_ctx);
    /* try to send data... */
    altcp_output(conn->inner_conn);
    if (state->uio_bytes_read > 0) {
      /* acknowledge all bytes read */
      altcp_hitls_lower_recved(conn->inner_conn, state->uio_bytes_read);
      state->uio_bytes_read = 0;
    }

    if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY) {
      /* handshake not done, wait for more recv calls */
      LWIP_ASSERT("rx chain should be empty during handshake", state->rx == NULL);
      return ERR_OK;
    }

    if (ret != HITLS_SUCCESS) {
      LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("tls handshake failed" HITLS_ERROR_CODE_FORMAT "\n", ret));
      if (conn->err) {
        conn->err(conn->arg, ERR_CLSD);
      }
      if (altcp_close(conn) != ERR_OK) {
        altcp_abort(conn);
      }
      return ERR_OK;
    }

    /* If we come here, handshake succeeded. */
    LWIP_ASSERT("state", state->uio_bytes_read == 0);
    LWIP_ASSERT("state", state->uio_bytes_appl == 0);
    state->flags |= ALTCP_HITLS_FLAGS_HANDSHAKE_DONE;
    /* issue "connect" callback" to upper connection (this can only happen for active open) */
    if (conn->connected) {
      err_t err = conn->connected(conn->arg, conn, ERR_OK);
      if (err != ERR_OK) {
        return err;
      }
    }
    if (state->rx == NULL) {
      return ERR_OK;
    }
  }
  /* handle application data */
  return altcp_hitls_handle_rx_appldata(conn, state);
}

/* Pass queued decoded rx data to application */
static err_t
altcp_hitls_pass_rx_data(struct altcp_pcb *conn, altcp_hitls_state_t *state)
{
  err_t err;
  struct pbuf *buf;
  LWIP_ASSERT("conn != NULL", conn != NULL);
  LWIP_ASSERT("state != NULL", state != NULL);
  buf = state->rx_app;
  if (buf) {
    state->rx_app = NULL;

    if (conn->recv) {
      u16_t tot_len = buf->tot_len;
      /* this needs to be increased first because the 'recved' call may come nested */
      state->rx_passed_unrecved += tot_len;
      state->flags |= ALTCP_HITLS_FLAGS_UPPER_CALLED;
      err = conn->recv(conn->arg, conn, buf, ERR_OK);
      if (err != ERR_OK) {
        if (err == ERR_ABRT) {
          return ERR_ABRT;
        }
        /* not received, leave the pbuf(s) queued (and decrease 'unrecved' again) */
        LWIP_ASSERT("state == conn->state", state == conn->state);
        state->rx_app = buf;
        state->rx_passed_unrecved -= tot_len;
        LWIP_ASSERT("state->rx_passed_unrecved >= 0", state->rx_passed_unrecved >= 0);
        if (state->rx_passed_unrecved < 0) {
          state->rx_passed_unrecved = 0;
        }
        return err;
      }
    } else {
      pbuf_free(buf);
    }
  } else if ((state->flags & (ALTCP_HITLS_FLAGS_RX_CLOSE_QUEUED | ALTCP_HITLS_FLAGS_RX_CLOSED)) ==
             ALTCP_HITLS_FLAGS_RX_CLOSE_QUEUED) {
    state->flags |= ALTCP_HITLS_FLAGS_RX_CLOSED;
    if (conn->recv) {
      return conn->recv(conn->arg, conn, NULL, ERR_OK);
    }
  }

  /* application may have close the connection */
  if (conn->state != state) {
    /* return error code to ensure altcp_hitls_handle_rx_appldata() exits the loop */
    return ERR_ARG;
  }
  return ERR_OK;
}

/* Helper function that processes rx application data */
static err_t
altcp_hitls_handle_rx_appldata(struct altcp_pcb *conn, altcp_hitls_state_t *state)
{
  s32_t ret;
  LWIP_ASSERT("state != NULL", state != NULL);

  if (!(state->flags & ALTCP_HITLS_FLAGS_HANDSHAKE_DONE)) {
    return ERR_VAL;
  }

  u32_t read_len;
  do {
    struct pbuf *buf = pbuf_alloc(PBUF_RAW, PBUF_POOL_BUFSIZE, PBUF_POOL);
    if (buf == NULL) {
      return ERR_OK;
    }

    read_len = 0;
    /* decrypt application data, this pulls encrypted RX data off state->rx pbuf chain */
    ret = HITLS_Read(state->hitls_ctx, (u8_t *)buf->payload, PBUF_POOL_BUFSIZE, &read_len);
    if (read_len > 0) {
      LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("Decrypted %d bytes\n", read_len));

      pbuf_realloc(buf, (u16_t)read_len);
      state->uio_bytes_appl += (s32_t)read_len;

      if (state->rx_app == NULL) {
        state->rx_app = buf;
      } else {
        pbuf_cat(state->rx_app, buf);
      }
    } else {
      pbuf_free(buf);
      buf = NULL;
    }

    if (state->uio_bytes_read > 0) {
      altcp_recved(conn->inner_conn, (u16_t)state->uio_bytes_read);
      state->uio_bytes_read = 0;
    }

    err_t err = altcp_hitls_pass_rx_data(conn, state);
    if (err != ERR_OK) {
      if (err == ERR_ABRT) {
        /* Connection aborted by upper layer */
        /* recv callback needs to return this as the pcb is deallocated */
        return ERR_ABRT;
      }
      /* we hide all other errors as we retry feeding the pbuf to the app later */
      return ERR_OK;
    }
  } while (ret == HITLS_SUCCESS);

  if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY && ret != HITLS_REC_NORMAL_IO_BUSY) {
    if (ret == HITLS_CM_LINK_CLOSED || ret == HITLS_REC_NORMAL_IO_EOF) {
      if (conn->recv) {
        conn->recv(conn->arg, conn, NULL, ERR_OK);
      }
      if (altcp_close(conn) != ERR_OK) {
        altcp_abort(conn);
      }
      return ERR_OK;
    } else {
      LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("tls read returned unexpected error" HITLS_ERROR_CODE_FORMAT "\n", ret));
      if (conn->err) {
        conn->err(conn->arg, ERR_CLSD);
      }
      if (altcp_close(conn) != ERR_OK) {
        altcp_abort(conn);
      }
      return ERR_OK;
    }
  }

  return ERR_OK;
}

/* UIO callback functions */

static s32_t
altcp_hitls_uio_read(BSL_UIO *uio, void *buf, u32_t len, u32_t *read_len)
{
  altcp_hitls_uio_ctx_t *uio_ctx;
  altcp_hitls_state_t *state;
  struct pbuf *p;
  u32_t copy_len;
  err_t err;

  if (uio == NULL || buf == NULL || read_len == NULL) {
    return BSL_UIO_FAIL;
  }

  uio_ctx = (altcp_hitls_uio_ctx_t *)BSL_UIO_GetUserData(uio);
  if (uio_ctx == NULL || uio_ctx->state == NULL) {
    return BSL_UIO_FAIL;
  }

  state = uio_ctx->state;
  p = state->rx;
  *read_len = 0;

  if (p == NULL || (p->len == 0 && p->next == NULL)) {
    if (p) {
      pbuf_free(p);
      state->rx = NULL;
    }

    if ((state->flags & (ALTCP_HITLS_FLAGS_RX_CLOSE_QUEUED | ALTCP_HITLS_FLAGS_RX_CLOSED)) ==
      ALTCP_HITLS_FLAGS_RX_CLOSE_QUEUED) {
      LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("Connection closing while reading\n"));
      return BSL_UIO_IO_EOF;
    }

    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("No data available, waiting\n"));
    return BSL_SUCCESS;
  }

  copy_len = LWIP_MIN(len, p->len);
  /* copy the data */
  *read_len = pbuf_copy_partial(p, buf, copy_len, 0);
  /* hide the copied bytes from the pbuf */
  err = pbuf_remove_header(p, *read_len);
  LWIP_ASSERT("error", err == ERR_OK);
  if (p->len == 0) {
    state->rx = p->next;
    p->next = NULL;
    pbuf_free(p);
  }

  state->uio_bytes_read += (s32_t)(*read_len);
  return BSL_SUCCESS;
}

static s32_t
altcp_hitls_uio_write(BSL_UIO *uio, const void *buf, u32_t len, u32_t *write_len)
{
  altcp_hitls_uio_ctx_t *uio_ctx;
  altcp_hitls_state_t *state;
  struct altcp_pcb *conn;
  const u8_t *dataptr = (const u8_t *)buf;
  u32_t size_left = len;
  u32_t written = 0;
  u8_t apiflags = TCP_WRITE_FLAG_COPY;

  if (uio == NULL || buf == NULL || write_len == NULL) {
    return BSL_UIO_FAIL;
  }

  uio_ctx = (altcp_hitls_uio_ctx_t *)BSL_UIO_GetUserData(uio);
  if (uio_ctx == NULL || uio_ctx->conn == NULL) {
    return BSL_UIO_FAIL;
  }

  conn = uio_ctx->conn;
  state = uio_ctx->state;
  LWIP_ASSERT("conn != NULL", conn != NULL);
  LWIP_ASSERT("state != NULL", state != NULL);
  *write_len = 0;

  if (conn->inner_conn == NULL) {
    return BSL_UIO_IO_EXCEPTION;
  }

  while (size_left > 0) {
    u16_t write_part = (u16_t)LWIP_MIN(size_left, 0xFFFF);
    err_t err = altcp_write(conn->inner_conn, dataptr + written, write_part, apiflags);

    if (err == ERR_OK) {
      written += write_part;
      size_left -= write_part;
      state->overhead_bytes_adjust += (s32_t)write_part;
    } else if (err == ERR_MEM) {
      if (written > 0) {
        *write_len = written;
        return BSL_SUCCESS;
      }
      return BSL_UIO_IO_BUSY;
    } else {
      LWIP_ASSERT("tls_write, tcp_write: err != ERR MEM", 0);
      return BSL_UIO_IO_EXCEPTION;
    }
  }

  *write_len = written;
  return BSL_SUCCESS;
}

static s32_t
altcp_hitls_uio_ctrl(BSL_UIO *uio, s32_t cmd, s32_t larg, void *parg)
{
  LWIP_UNUSED_ARG(larg);
  LWIP_UNUSED_ARG(parg); /* for LWIP_NOASSERT */
  altcp_hitls_uio_ctx_t *uio_ctx;

  if (uio == NULL) {
    return BSL_UIO_FAIL;
  }

  uio_ctx = (altcp_hitls_uio_ctx_t *)BSL_UIO_GetUserData(uio);
  if (!uio_ctx) {
    return BSL_UIO_FAIL;
  }

  switch (cmd) {
    case BSL_UIO_FLUSH:
      if (uio_ctx->conn && uio_ctx->conn->inner_conn) {
        altcp_output(uio_ctx->conn->inner_conn);
      } else {
        LWIP_DEBUGF(ALTCP_HITLS_DEBUG | LWIP_DBG_LEVEL_WARNING, ("Flush failed, no connection\n"));
      }
      return BSL_SUCCESS;
    default:
      LWIP_DEBUGF(ALTCP_HITLS_DEBUG | LWIP_DBG_LEVEL_WARNING, ("Unsupported uio ctrl cmd %d\n", cmd));
      return BSL_UIO_FAIL;
  }
}

static BSL_UIO *
altcp_hitls_create_uio(struct altcp_pcb *conn, altcp_hitls_state_t *state)
{
  BSL_UIO *uio;
  altcp_hitls_uio_ctx_t *uio_ctx;

  BSL_UIO_Method *method = BSL_UIO_NewMethod();
  if (!method) {
    return NULL;
  }

  /* Set method type and callback functions */
  (void)BSL_UIO_SetMethodType(method, BSL_UIO_TCP);
  (void)BSL_UIO_SetMethod(method, BSL_UIO_READ_CB, altcp_hitls_uio_read);
  (void)BSL_UIO_SetMethod(method, BSL_UIO_WRITE_CB, altcp_hitls_uio_write);
  (void)BSL_UIO_SetMethod(method, BSL_UIO_CTRL_CB, altcp_hitls_uio_ctrl);

  /* Create UIO object */
  uio = BSL_UIO_New(method);
  BSL_UIO_FreeMethod(method); /* Method has been copied, can be released */

  if (!uio) {
    return NULL;
  }
  BSL_UIO_SetInit(uio, true); /* Set uio initialization state to true */

  uio_ctx = (altcp_hitls_uio_ctx_t *)mem_malloc(sizeof(altcp_hitls_uio_ctx_t));
  if (uio_ctx == NULL) {
    BSL_UIO_Free(uio);
    return NULL;
  }

  uio_ctx->conn = conn;
  uio_ctx->state = state;

  /* Associate context with uio - using hitls user data mechanism */
  (void)BSL_UIO_SetUserData(uio, uio_ctx);

  return uio;
}

/** Sent callback from lower connection (i.e. TCP)
 * This only informs the upper layer the number of ACKed bytes.
 * This now take care of TLS added bytes so application receive
 * correct ACKed bytes.
 */
static err_t
altcp_hitls_lower_sent(void *arg, struct altcp_pcb *inner_conn, u16_t len)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  LWIP_UNUSED_ARG(inner_conn);

  if (conn == NULL) {
    return ERR_OK;
  }

  altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
  LWIP_ASSERT("state", state != NULL);
  LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

  s32_t overhead = state->overhead_bytes_adjust > (s32_t)len ? (s32_t)len : state->overhead_bytes_adjust;
  state->overhead_bytes_adjust -= (s32_t)len;
  u16_t app_len = len - (u16_t)overhead;

  if (app_len > 0) {
    state->overhead_bytes_adjust += (s32_t)app_len;
    if (conn->sent != NULL) {
      return conn->sent(conn->arg, conn, app_len);
    }
  }
  return ERR_OK;
}

/** Poll callback from lower connection (i.e. TCP)
 * Just pass this on to the application.
 * @todo: retry sending?
 */
static err_t
altcp_hitls_lower_poll(void *arg, struct altcp_pcb *inner_conn)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  LWIP_UNUSED_ARG(inner_conn);

  if (conn == NULL) {
    return ERR_OK;
  }
  LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
  /* check if there's unreceived rx data */
  if (conn->state) {
    altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
    /* try to send more if we failed before */
    (void)HITLS_Flush(state->hitls_ctx);
    if (altcp_hitls_handle_rx_appldata(conn, state) == ERR_ABRT) {
      return ERR_ABRT;
    }
  }

  if (conn->poll) {
    return conn->poll(conn->arg, conn);
  }

  return ERR_OK;
}

static void
altcp_hitls_lower_err(void *arg, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    conn->inner_conn = NULL; /* already freed */
    if (conn->err) {
      conn->err(conn->arg, err);
    }
    altcp_free(conn);
  }
}

/* setup functions */

static void
altcp_hitls_remove_callbacks(struct altcp_pcb *inner_conn)
{
  altcp_arg(inner_conn, NULL);
  altcp_recv(inner_conn, NULL);
  altcp_sent(inner_conn, NULL);
  altcp_err(inner_conn, NULL);
  altcp_poll(inner_conn, NULL, inner_conn->pollinterval);
}

static void
altcp_hitls_setup_callbacks(struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  altcp_arg(inner_conn, conn);
  altcp_recv(inner_conn, altcp_hitls_lower_recv);
  altcp_sent(inner_conn, altcp_hitls_lower_sent);
  altcp_err(inner_conn, altcp_hitls_lower_err);
}

static altcp_hitls_state_t *
altcp_hitls_alloc(void *conf)
{
  altcp_hitls_state_t *state = (altcp_hitls_state_t *)mem_malloc(sizeof(altcp_hitls_state_t));
  if (state) {
    memset(state, 0, sizeof(altcp_hitls_state_t));
    state->conf = conf;
  }
  return state;
}

static void
altcp_hitls_free(void *conf, altcp_hitls_state_t *state)
{
  LWIP_UNUSED_ARG(conf);

  if (state) {
    mem_free(state);
  }
}

static err_t
altcp_hitls_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  s32_t ret;
  struct altcp_tls_config *config = (struct altcp_tls_config *)conf;
  altcp_hitls_state_t *state;

  if (!conf) {
    return ERR_ARG;
  }
  LWIP_ASSERT("invalid inner_conn", conn != inner_conn);

  state = altcp_hitls_alloc(conf);
  if (!state) {
    return ERR_MEM;
  }

  state->hitls_ctx = HITLS_New(config->hitls_config);
  if (!state->hitls_ctx) {
    altcp_hitls_free(conf, state);
    return ERR_MEM;
  }

  BSL_UIO *uio = altcp_hitls_create_uio(conn, state);
  if (!uio) {
    goto ERR;
  }

  ret = HITLS_SetUio(state->hitls_ctx, uio);
  BSL_UIO_Free(uio);
  if (ret != HITLS_SUCCESS) {
    goto ERR;
  }

  ret = HITLS_SetEndPoint(state->hitls_ctx, !config->is_server);
  if (ret != HITLS_SUCCESS) {
    goto ERR;
  }

  altcp_hitls_setup_callbacks(conn, inner_conn);
  conn->inner_conn = inner_conn;
  conn->fns = &altcp_hitls_functions;
  conn->state = state;

  return ERR_OK;
ERR:
  HITLS_Free(state->hitls_ctx);
  altcp_hitls_free(conf, state);
  return ERR_MEM;
}

struct altcp_pcb *
altcp_tls_wrap(struct altcp_tls_config *config, struct altcp_pcb *inner_pcb)
{
  struct altcp_pcb *ret;

  if (inner_pcb == NULL) {
    return NULL;
  }

  if (config == NULL) {
    return NULL;
  }

  ret = altcp_alloc();
  if (ret != NULL) {
    if (altcp_hitls_setup(config, ret, inner_pcb) != ERR_OK) {
      altcp_free(ret);
      return NULL;
    }
  }

  return ret;
}

void
altcp_tls_init_session(struct altcp_tls_session *session)
{
  if (session) {
    if (session->hitls_session) {
      HITLS_SESS_Free(session->hitls_session);
      session->hitls_session = NULL;
    }
  }
}

err_t
altcp_tls_get_session(struct altcp_pcb *conn, struct altcp_tls_session *session)
{
#if LWIP_ALTCP_HITLS_SESSION_RESUMPTION
  if (session && conn && conn->state) {
    altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;

    HITLS_SESS_Free(session->hitls_session);
    session->hitls_session = HITLS_GetDupSession(state->hitls_ctx);
    return session->hitls_session ? ERR_OK : ERR_VAL;
  }
  return ERR_ARG;
#else
  LWIP_UNUSED_ARG(conn);
  LWIP_UNUSED_ARG(session);
  return ERR_VAL;
#endif
}

err_t
altcp_tls_set_session(struct altcp_pcb *conn, struct altcp_tls_session *session)
{
#if LWIP_ALTCP_HITLS_SESSION_RESUMPTION
  if (session && conn && conn->state) {
    altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
    s32_t ret;

    if (session->hitls_session == NULL) {
      return ERR_VAL;
    }

    ret = HITLS_SetSession(state->hitls_ctx, session->hitls_session);
    return ret == HITLS_SUCCESS ? ERR_OK : ERR_VAL;
  }
  return ERR_ARG;
#else
  LWIP_UNUSED_ARG(conn);
  LWIP_UNUSED_ARG(session);
  return ERR_VAL;
#endif
}

void
altcp_tls_free_session(struct altcp_tls_session *session)
{
  if (session) {
#if LWIP_ALTCP_HITLS_SESSION_RESUMPTION
    HITLS_SESS_Free(session->hitls_session);
#endif
    session->hitls_session = NULL;
  }
}

void *
altcp_tls_context(struct altcp_pcb *conn)
{
  if (conn && conn->state) {
    altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
    return state->hitls_ctx;
  }
  return NULL;
}

#if LWIP_ALTCP_HITLS_ALPN
static int
altcp_hitls_build_alpn_list(const char **protos, u8_t **alpn_protos, u32_t *alpn_protos_len)
{
  size_t total_len = 0;
  size_t offset = 0;
  u8_t *alpn_list;
  int i;

  if (alpn_protos == NULL || alpn_protos_len == NULL) {
    return -1;
  }
  *alpn_protos = NULL;
  *alpn_protos_len = 0;

  if (protos == NULL || protos[0] == NULL) {
    return 0;
  }

  for (i = 0; protos[i] != NULL; i++) {
    size_t proto_len = strlen(protos[i]);
    if (proto_len == 0 || proto_len > 255 ||
        total_len > (size_t)0xffffffffUL - proto_len - 1) {
      return -1;
    }
    total_len += proto_len + 1;
  }

  alpn_list = (u8_t *)mem_malloc(total_len);
  if (alpn_list == NULL) {
    return -1;
  }

  for (i = 0; protos[i] != NULL; i++) {
    size_t proto_len = strlen(protos[i]);
    alpn_list[offset++] = (u8_t)proto_len;
    memcpy(&alpn_list[offset], protos[i], proto_len);
    offset += proto_len;
  }

  *alpn_protos = alpn_list;
  *alpn_protos_len = (u32_t)total_len;
  return 0;
}

static s32_t
altcp_hitls_alpn_select_cb(HITLS_Ctx *ctx, u8_t **selected_proto, u8_t *selected_proto_len,
    u8_t *client_alpn_list, u32_t client_alpn_list_len, void *user_data)
{
  struct altcp_tls_config *conf = (struct altcp_tls_config *)user_data;
  s32_t ret;

  LWIP_UNUSED_ARG(ctx);

  if (conf == NULL || conf->alpn_protos == NULL || conf->alpn_protos_len == 0) {
    return HITLS_ALPN_ERR_NOACK;
  }

  ret = HITLS_SelectAlpnProtocol(selected_proto, selected_proto_len,
    conf->alpn_protos, conf->alpn_protos_len, client_alpn_list, client_alpn_list_len);
  if (ret != HITLS_SUCCESS || selected_proto == NULL || *selected_proto == NULL) {
    return HITLS_ALPN_ERR_ALERT_FATAL;
  }

  return HITLS_ALPN_ERR_OK;
}
#endif

int
altcp_tls_configure_alpn_protocols(struct altcp_tls_config *conf, const char **protos)
{
#if LWIP_ALTCP_HITLS_ALPN
  u8_t *alpn_protos = NULL;
  u32_t alpn_protos_len = 0;
  s32_t ret;

  if (conf == NULL || conf->hitls_config == NULL) {
    return -1;
  }

  if (altcp_hitls_build_alpn_list(protos, &alpn_protos, &alpn_protos_len) != 0) {
    return -1;
  }

  if (conf->is_server) {
    ret = HITLS_CFG_SetAlpnProtosSelectCb(conf->hitls_config,
      alpn_protos_len ? altcp_hitls_alpn_select_cb : NULL,
      alpn_protos_len ? conf : NULL);
    if (ret != HITLS_SUCCESS) {
      if (alpn_protos != NULL) {
        mem_free(alpn_protos);
      }
      return -1;
    }
    if (conf->alpn_protos != NULL) {
      mem_free(conf->alpn_protos);
    }
    conf->alpn_protos = alpn_protos;
    conf->alpn_protos_len = alpn_protos_len;
    return 0;
  }

  ret = HITLS_CFG_SetAlpnProtos(conf->hitls_config, alpn_protos, alpn_protos_len);
  if (alpn_protos != NULL) {
    mem_free(alpn_protos);
  }
  return ret == HITLS_SUCCESS ? 0 : -1;
#else
  LWIP_UNUSED_ARG(conf);
  LWIP_UNUSED_ARG(protos);
  return -1;
#endif
}

static s32_t
altcp_hitls_add_ca_certs_to_config(HITLS_Config *config, const u8_t *ca, size_t ca_Len)
{
  BSL_Buffer caBuf = {.data = (u8_t *)(uintptr_t)ca, .dataLen = ca_Len};
  HITLS_X509_List *caCerts = NULL;
  u32_t certCount = 0;

  s32_t hiRet = HITLS_X509_CertParseBundleBuff(BSL_FORMAT_UNKNOWN, &caBuf, &caCerts);
  if (hiRet != HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("CA certificate bundle parse failed: %d\n", hiRet));
    return hiRet;
  }

  HITLS_X509_Cert *tmp = BSL_LIST_GET_FIRST(caCerts);
  while (tmp != NULL) {
    hiRet = HITLS_CFG_AddCertToStore(config, tmp, TLS_CERT_STORE_TYPE_DEFAULT, true);
    if (hiRet != HITLS_SUCCESS) {
      LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("Add CA certificate to store failed: %d\n", hiRet));
      BSL_LIST_FREE(caCerts, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
      return hiRet;
    }
    certCount++;
    tmp = BSL_LIST_GET_NEXT(caCerts);
  }

  BSL_LIST_FREE(caCerts, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
  LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("All %d CA certificates added successfully\n", certCount));
  return HITLS_SUCCESS;
}

static s32_t
hitls_password_cb(char *buf, s32_t bufLen, s32_t flag, void *userdata)
{
  (void)flag;
  altcp_hitls_pass_userdata_t *data = (altcp_hitls_pass_userdata_t *)userdata;
  if (buf == NULL || bufLen <= 0 || data == NULL || data->pass == NULL || data->len == 0 ||
      data->len > (size_t)bufLen) {
    return 0;
  }
  if (memcpy(buf, data->pass, data->len) != buf) {
    return 0;
  }
  return (s32_t)data->len;
}

static void
hitls_free_password_userdata(altcp_hitls_pass_userdata_t *userdata)
{
  if (userdata == NULL) {
    return;
  }
  if (userdata->pass != NULL) {
    (void)memset(userdata->pass, 0, userdata->len);
    mem_free(userdata->pass);
  }
  mem_free(userdata);
}

static altcp_hitls_pass_userdata_t *
altcp_hitls_create_password_cb_userdata(const u8_t *privkey_pass, size_t privkey_pass_len)
{
  altcp_hitls_pass_userdata_t *userdata = (altcp_hitls_pass_userdata_t *)mem_malloc(
    sizeof(altcp_hitls_pass_userdata_t));
  if (userdata == NULL) {
    return NULL;
  }
  u8_t *pass = (u8_t *)mem_malloc(privkey_pass_len);
  if (pass == NULL) {
    mem_free(userdata);
    return NULL;
  }
  if (memcpy(pass, privkey_pass, privkey_pass_len) != pass) {
    mem_free(pass);
    mem_free(userdata);
    return NULL;
  }
  userdata->pass = pass;
  userdata->len = privkey_pass_len;
  return userdata;
}

static s32_t
altcp_hitls_load_key_buffer(HITLS_Config *hitls_config,
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len)
{
  altcp_hitls_pass_userdata_t *userdata = NULL;
  s32_t ret;

  if (privkey_pass != NULL && privkey_pass_len > 0) {
    userdata = altcp_hitls_create_password_cb_userdata(privkey_pass, privkey_pass_len);
    if (userdata == NULL) {
      return HITLS_MEMALLOC_FAIL;
    }
    ret = HITLS_CFG_SetDefaultPasswordCb(hitls_config, hitls_password_cb);
    if (ret != HITLS_SUCCESS) {
      hitls_free_password_userdata(userdata);
      return ret;
    }
    ret = HITLS_CFG_SetDefaultPasswordCbUserdata(hitls_config, userdata);
    if (ret != HITLS_SUCCESS) {
      hitls_free_password_userdata(userdata);
      return ret;
    }
  }

  ret = HITLS_CFG_LoadKeyBuffer(hitls_config, privkey, privkey_len, TLS_PARSE_FORMAT_PEM);
  if (userdata != NULL) {
    (void)HITLS_CFG_SetDefaultPasswordCbUserdata(hitls_config, NULL);
    hitls_free_password_userdata(userdata);
  }
  return ret;
}

static s32_t
altcp_hitls_add_crl_to_config(HITLS_Config *config, const u8_t *crl, size_t crl_len)
{
  if (crl == NULL || crl_len == 0) {
    return HITLS_SUCCESS;
  }
  HITLS_CERT_Store *store = HITLS_CFG_GetCertStore(config);
  if (store == NULL) {
    return HITLS_INVALID_INPUT;
  }
  BSL_Buffer crl_buf = {.data = (u8_t *)(uintptr_t)crl, .dataLen = crl_len};
  HITLS_X509_List *crl_list = NULL;
  s32_t ret = HITLS_X509_CrlParseBundleBuff(BSL_FORMAT_UNKNOWN, &crl_buf, &crl_list);
  if (ret != HITLS_SUCCESS) {
    return ret;
  }
  HITLS_X509_Crl *crl_tmp = BSL_LIST_GET_FIRST(crl_list);
  while (crl_tmp != NULL) {
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CRL, crl_tmp, 0);
    if (ret != HITLS_SUCCESS) {
      BSL_LIST_FREE(crl_list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
      return ret;
    }
    crl_tmp = BSL_LIST_GET_NEXT(crl_list);
  }
  BSL_LIST_FREE(crl_list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
  return ret;
}

static err_t
altcp_hitls_config_load_privkey_cert(struct altcp_tls_config *config,
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
  s32_t ret;

  if (config == NULL || config->hitls_config == NULL ||
      privkey == NULL || privkey_len == 0 ||
      cert == NULL || cert_len == 0) {
    return ERR_ARG;
  }

  ret = HITLS_CFG_LoadCertBuffer(config->hitls_config, cert, cert_len, TLS_PARSE_FORMAT_PEM);
  if (ret != HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("HITLS_CFG_LoadCertBuffer failed" HITLS_ERROR_CODE_FORMAT "\n", ret));
    return ERR_VAL;
  }

  ret = altcp_hitls_load_key_buffer(config->hitls_config, privkey, privkey_len,
    privkey_pass, privkey_pass_len);
  if (ret != HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("HITLS_CFG_LoadKeyBuffer failed" HITLS_ERROR_CODE_FORMAT "\n", ret));
    return ERR_VAL;
  }

  return ERR_OK;
}

/** Create new TLS configuration
 * ATTENTION: Server certificate and private key have to be added outside this function!
 */
static struct altcp_tls_config *
altcp_hitls_create_config(u8_t is_server,
  const u8_t *privkey, size_t privkey_len, const u8_t *privkey_pass, size_t privkey_pass_len,
  const u8_t *cert, size_t cert_len)
{
  struct altcp_tls_config *config = (struct altcp_tls_config *)mem_malloc(sizeof(struct altcp_tls_config));
  if (config == NULL) {
    return NULL;
  }
  memset(config, 0, sizeof(struct altcp_tls_config));
  config->is_server = is_server;

  config->hitls_config = HITLS_CFG_NewTLS12Config();
  if (config->hitls_config == NULL) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("HITLS_CFG_NewTLSConfig failed\n"));
    mem_free(config);
    return NULL;
  }

  if (cert != NULL || privkey != NULL) {
    config->cert_max = 1;
    if (altcp_hitls_config_load_privkey_cert(config, privkey, privkey_len,
        privkey_pass, privkey_pass_len, cert, cert_len) != ERR_OK) {
      goto ERR;
    }
    config->cert_count = 1;
  }
  return config;
ERR:
  altcp_tls_free_config(config);
  return NULL;
}

struct altcp_tls_config *
altcp_tls_create_config_server(u8_t cert_count)
{
  struct altcp_tls_config *conf = altcp_hitls_create_config(1, NULL, 0, NULL, 0, NULL, 0);
  if (conf == NULL) {
    return NULL;
  }

  conf->cert_max = cert_count;
  return conf;
}

err_t
altcp_tls_config_server_add_privkey_cert(struct altcp_tls_config *config,
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
  err_t err;

  if (config == NULL) {
    return ERR_ARG;
  }
  if (config->cert_count >= config->cert_max) {
    return ERR_MEM;
  }

  err = altcp_hitls_config_load_privkey_cert(config, privkey, privkey_len,
    privkey_pass, privkey_pass_len, cert, cert_len);
  if (err == ERR_OK) {
    config->cert_count++;
  }
  return err;
}

struct altcp_tls_config *
altcp_tls_create_config_server_privkey_cert(const u8_t *privkey, size_t privkey_len,
              const u8_t *privkey_pass, size_t privkey_pass_len,
              const u8_t *cert, size_t cert_len)
{
  struct altcp_tls_config *conf = altcp_tls_create_config_server(1);
  if (conf == NULL) {
    return NULL;
  }

  if (altcp_tls_config_server_add_privkey_cert(conf, privkey, privkey_len,
      privkey_pass, privkey_pass_len, cert, cert_len) != ERR_OK) {
    altcp_tls_free_config(conf);
    return NULL;
  }

  return conf;
}

struct altcp_tls_config *
altcp_tls_create_config_client(const u8_t *ca, size_t ca_len)
{
  struct altcp_tls_config *conf = altcp_hitls_create_config(0, NULL, 0, NULL, 0, NULL, 0);
  if (conf == NULL) {
    return NULL;
  }

  if (ca != NULL && ca_len > 0) {
    if (altcp_hitls_add_ca_certs_to_config(conf->hitls_config, ca, ca_len) != HITLS_SUCCESS) {
      altcp_tls_free_config(conf);
      return NULL;
    }
  }

  return conf;
}

struct altcp_tls_config *
altcp_tls_create_config_client_2wayauth(const u8_t *ca, size_t ca_len,
  const u8_t *privkey, size_t privkey_len, const u8_t *privkey_pass, size_t privkey_pass_len,
  const u8_t *cert, size_t cert_len)
{
  struct altcp_tls_config *conf = altcp_hitls_create_config(0, privkey, privkey_len, privkey_pass, privkey_pass_len,
    cert, cert_len);
  if (conf == NULL) {
    return NULL;
  }
  if (ca != NULL && ca_len > 0) {
    if (altcp_hitls_add_ca_certs_to_config(conf->hitls_config, ca, ca_len) != HITLS_SUCCESS) {
      altcp_tls_free_config(conf);
      return NULL;
    }
  }

  return conf;
}

void
altcp_tls_free_config(struct altcp_tls_config *conf)
{
  if (conf != NULL) {
    if (conf->hitls_config) {
      HITLS_CFG_FreeConfig(conf->hitls_config);
    }
    mem_free(conf);
  }
}

/* "virtual" functions */
static void
altcp_hitls_set_poll(struct altcp_pcb *conn, u8_t interval)
{
  if (conn != NULL) {
    altcp_poll(conn->inner_conn, altcp_hitls_lower_poll, interval);
  }
}

static void
altcp_hitls_recved(struct altcp_pcb *conn, u16_t len)
{
  if (conn == NULL) {
    return;
  }
  altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
  if (state == NULL) {
    return;
  }
  if (!(state->flags & ALTCP_HITLS_FLAGS_HANDSHAKE_DONE)) {
    return;
  }
  u16_t lower_recved = len;
  if (lower_recved > (u16_t)state->rx_passed_unrecved) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG, ("bogus recved count (len > state->rx_passed_unrecved / %d / %d)\n",
                    len, state->rx_passed_unrecved));
    lower_recved = (u16_t)state->rx_passed_unrecved;
  }
  state->rx_passed_unrecved -= (s32_t)lower_recved;
  altcp_recved(conn->inner_conn, lower_recved);
}

static err_t
altcp_hitls_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  conn->connected = connected;
  return altcp_connect(conn->inner_conn, ipaddr, port, altcp_hitls_lower_connected);
}

static struct altcp_pcb *
altcp_hitls_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
  if (conn == NULL) {
    return NULL;
  }
  struct altcp_pcb *lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
  if (lpcb == NULL) {
    return NULL;
  }
  altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
  HITLS_Free(state->hitls_ctx);
  state->hitls_ctx = NULL;

  conn->inner_conn = lpcb;
  altcp_accept(lpcb, altcp_hitls_lower_accept);
  return conn;
}

static void
altcp_hitls_abort(struct altcp_pcb *conn)
{
  if (conn != NULL) {
    altcp_abort(conn->inner_conn);
  }
}

static err_t
altcp_hitls_close(struct altcp_pcb *conn)
{
  struct altcp_pcb *inner_conn;
  if (conn == NULL) {
    return ERR_VAL;
  }

  inner_conn = conn->inner_conn;
  if (inner_conn != NULL) {
    err_t err;
    altcp_poll_fn oldpoll = inner_conn->poll;
    altcp_hitls_remove_callbacks(inner_conn);
    err = altcp_close(inner_conn);
    if (err != ERR_OK) {
      /* not closed, set up all callbacks again */
      altcp_hitls_setup_callbacks(conn, inner_conn);
      /* poll callback is not included in the above */
      altcp_poll(inner_conn, oldpoll, inner_conn->pollinterval);
      return err;
    }

    conn->inner_conn = NULL;
  }

  altcp_free(conn);
  return ERR_OK;
}

static u16_t
altcp_hitls_sndbuf(struct altcp_pcb *conn)
{
  if (conn) {
    altcp_hitls_state_t *state = (altcp_hitls_state_t*)conn->state;
    if (!state || !(state->flags & ALTCP_HITLS_FLAGS_HANDSHAKE_DONE)) {
      return 0;
    }
    if (conn->inner_conn) {
      u16_t sndbuf = altcp_sndbuf(conn->inner_conn);
      /* Take care of record header, IV, AuthTag */
      u32_t write_size = 0;
      (void)HITLS_GetMaxWriteSize(state->hitls_ctx, &write_size);
      /* REC_MAX_WRITE_ENCRYPTED(16 + 64) + tls_record_header(5) = 85 */
      if (sndbuf > 85) {
        return (u16_t)LWIP_MIN((u32_t)(sndbuf - 85), write_size);
      }
    }
  }
  /* fallback: use sendbuf of the inner connection */
  return altcp_default_sndbuf(conn);
}

/** Write data to a TLS connection. Calls into HiTLS, which in turn calls into
 * @ref altcp_hitls_uio_write() to send the encrypted data
 */
static err_t
altcp_hitls_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
  s32_t ret;
  altcp_hitls_state_t *state;
  u32_t write_len = 0;

  LWIP_UNUSED_ARG(apiflags);

  if (conn == NULL) {
    return ERR_VAL;
  }

  state = (altcp_hitls_state_t *)conn->state;
  if (state == NULL) {
    return ERR_ARG;
  }

  if (!(state->flags & ALTCP_HITLS_FLAGS_HANDSHAKE_DONE)) {
    return ERR_VAL;
  }

  ret = HITLS_Write(state->hitls_ctx, (const u8_t *)dataptr, len, &write_len);

  altcp_output(conn->inner_conn);

  if (ret == HITLS_SUCCESS && write_len == len) {
    state->overhead_bytes_adjust -= (s32_t)len;
    return ERR_OK;
  } else if (ret == HITLS_REC_NORMAL_IO_BUSY) {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("Operation would block, wrote %d/%d bytes\n", write_len, len));
    return ERR_MEM;
  } else {
    LWIP_DEBUGF(ALTCP_HITLS_DEBUG_SERIOUS, ("HITLS_Write failed: %d, wrote %d/%d bytes\n", ret, write_len, len));
    return ERR_VAL;
  }
}

static u16_t
altcp_hitls_mss(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return 0;
  }

  return altcp_mss(conn->inner_conn);
}

static void
altcp_hitls_dealloc(struct altcp_pcb *conn)
{
  if (conn == NULL || conn->state == NULL) {
    return;
  }

  altcp_hitls_state_t *state = (altcp_hitls_state_t *)conn->state;
  BSL_UIO *uio = HITLS_GetUio(state->hitls_ctx);
  if (uio) {
    altcp_hitls_uio_ctx_t *uio_ctx = (altcp_hitls_uio_ctx_t *)BSL_UIO_GetUserData(uio);
    if (uio_ctx) {
        mem_free(uio_ctx);
        (void)BSL_UIO_SetUserData(uio, NULL);
    }
  }

  if (state->hitls_ctx) {
    HITLS_Free(state->hitls_ctx);
  }
  state->flags = 0;
  if (state->rx) {
    pbuf_free(state->rx);
    state->rx = NULL;
  }

  altcp_hitls_free(state->conf, state);
  conn->state = NULL;
}

const struct altcp_functions altcp_hitls_functions = {
  altcp_hitls_set_poll,
  altcp_hitls_recved,
  altcp_default_bind,
  altcp_hitls_connect,
  altcp_hitls_listen,
  altcp_hitls_abort,
  altcp_hitls_close,
  altcp_default_shutdown,
  altcp_hitls_write,
  altcp_default_output,
  altcp_hitls_mss,
  altcp_hitls_sndbuf,
  altcp_default_sndqueuelen,
  altcp_default_nagle_disable,
  altcp_default_nagle_enable,
  altcp_default_nagle_disabled,
  altcp_default_setprio,
  altcp_hitls_dealloc,
  altcp_default_get_tcp_addrinfo,
  altcp_default_get_ip,
  altcp_default_get_port
#if LWIP_TCP_KEEPALIVE
  , altcp_default_keepalive_disable
  , altcp_default_keepalive_enable
#endif
#ifdef LWIP_DEBUG
  , altcp_default_dbg_get_tcp_state
#endif
};

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_HITLS */
#endif /* LWIP_ALTCP */
