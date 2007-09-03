/**
 * @file
 * Sequential API Internal module
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"
#include "lwip/arch.h"
#include "lwip/api_msg.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "lwip/igmp.h"

#if !NO_SYS

/* forward declarations */
#if LWIP_TCP
static err_t do_writemore(struct netconn *conn);
static void do_close_internal(struct netconn *conn);
#endif

#if LWIP_RAW
/**
 * Receive callback function for RAW netconns.
 * Doesn't 'eat' the packet, only references it and sends it to
 * conn->recvmbox
 *
 * @see raw.h (struct raw_pcb.recv) for parameters and return value
 */
static u8_t
recv_raw(void *arg, struct raw_pcb *pcb, struct pbuf *p,
    struct ip_addr *addr)
{
  struct netbuf *buf;
  struct netconn *conn;

  conn = arg;

  if ((conn != NULL) && (conn->recvmbox != SYS_MBOX_NULL)) {
    buf = memp_malloc(MEMP_NETBUF);
    if (buf == NULL) {
      return 0;
    }
    pbuf_ref(p);
    buf->p = p;
    buf->ptr = p;
    buf->addr = addr;
    buf->port = pcb->protocol;

    conn->recv_avail += p->tot_len;
    /* Register event with callback */
    if (conn->callback)
      (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, p->tot_len);
    sys_mbox_post(conn->recvmbox, buf);
  }

  return 0; /* do not eat the packet */
}
#endif /* LWIP_RAW*/

#if LWIP_UDP
/**
 * Receive callback function for UDP netconns.
 * Posts the packet to conn->recvmbox or deletes it on memory error.
 *
 * @see udp.h (struct udp_pcb.recv) for parameters
 */
static void
recv_udp(void *arg, struct udp_pcb *pcb, struct pbuf *p,
   struct ip_addr *addr, u16_t port)
{
  struct netbuf *buf;
  struct netconn *conn;

  LWIP_UNUSED_ARG(pcb);

  conn = arg;

  if ((conn == NULL) || (conn->recvmbox == SYS_MBOX_NULL)) {
    pbuf_free(p);
    return;
  }

  buf = memp_malloc(MEMP_NETBUF);
  if (buf == NULL) {
    pbuf_free(p);
    return;
  } else {
    buf->p = p;
    buf->ptr = p;
    buf->addr = addr;
    buf->port = port;
  }

  conn->recv_avail += p->tot_len;
  /* Register event with callback */
  if (conn->callback)
    (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, p->tot_len);
  sys_mbox_post(conn->recvmbox, buf);
}
#endif /* LWIP_UDP */

#if LWIP_TCP
/**
 * Receive callback function for TCP netconns.
 * Posts the packet to conn->recvmbox or deletes it on memory error.
 *
 * @see tcp.h (struct tcp_pcb.recv) for parameters and return value
 */
static err_t
recv_tcp(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  struct netconn *conn;
  u16_t len;

  LWIP_UNUSED_ARG(pcb);

  conn = arg;

  if ((conn == NULL) || (conn->recvmbox == SYS_MBOX_NULL)) {
    pbuf_free(p);
    return ERR_VAL;
  }

  conn->err = err;
  if (p != NULL) {
    len = p->tot_len;
    conn->recv_avail += len;
  } else {
    len = 0;
  }
  /* Register event with callback */
  if (conn->callback)
    (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, len);
  sys_mbox_post(conn->recvmbox, p);

  return ERR_OK;
}

/**
 * Poll callback function for TCP netconns.
 * Wakes up an application thread that waits for a connection to close
 * or data to be sent. The application thread then takes the
 * appropriate action to go on.
 *
 * Signals the conn->sem.
 * netconn_close waits for conn->sem if closing failed.
 *
 * @see tcp.h (struct tcp_pcb.poll) for parameters and return value
 */
static err_t
poll_tcp(void *arg, struct tcp_pcb *pcb)
{
  struct netconn *conn = arg;

  LWIP_UNUSED_ARG(pcb);
  LWIP_ASSERT("conn != NULL", (conn != NULL));

  if (conn->state == NETCONN_WRITE) {
    do_writemore(conn);
  } else if (conn->state == NETCONN_CLOSE) {
    do_close_internal(conn);
  }

  return ERR_OK;
}

/**
 * Sent callback function for TCP netconns.
 * Signals the conn->sem and calls conn->callback.
 * netconn_write waits for conn->sem if send buffer is low.
 *
 * @see tcp.h (struct tcp_pcb.sent) for parameters and return value
 */
static err_t
sent_tcp(void *arg, struct tcp_pcb *pcb, u16_t len)
{
  struct netconn *conn = arg;

  LWIP_UNUSED_ARG(pcb);
  LWIP_ASSERT("conn != NULL", (conn != NULL));

  if (conn->state == NETCONN_WRITE) {
    LWIP_ASSERT("conn->pcb.tcp != NULL", conn->pcb.tcp != NULL);
    do_writemore(conn);
  } else if (conn->state == NETCONN_CLOSE) {
    do_close_internal(conn);
  }

  if (conn && conn->callback) {
    if ((conn->pcb.tcp != NULL) && (tcp_sndbuf(conn->pcb.tcp) > TCP_SNDLOWAT)) {
      (*conn->callback)(conn, NETCONN_EVT_SENDPLUS, len);
    }
  }
  
  return ERR_OK;
}

/**
 * Error callback function for TCP netconns.
 * Signals conn->sem, posts to all conn mboxes and calls conn->callback.
 * The application thread has then to decide what to do.
 *
 * @see tcp.h (struct tcp_pcb.err) for parameters
 */
static void
err_tcp(void *arg, err_t err)
{
  struct netconn *conn;

  conn = arg;
  LWIP_ASSERT("conn != NULL", (conn != NULL));

  conn->pcb.tcp = NULL;

  conn->err = err;
  if (conn->recvmbox != SYS_MBOX_NULL) {
    /* Register event with callback */
    if (conn->callback)
      (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
    sys_mbox_post(conn->recvmbox, NULL);
  }
  if (conn->mbox != SYS_MBOX_NULL && conn->state == NETCONN_CONNECT) {
    conn->state = NETCONN_NONE;
    sys_mbox_post(conn->mbox, NULL);
  }
  if (conn->acceptmbox != SYS_MBOX_NULL) {
     /* Register event with callback */
    if (conn->callback)
      (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
    sys_mbox_post(conn->acceptmbox, NULL);
  }
  if ((conn->state == NETCONN_WRITE) || (conn->state == NETCONN_CLOSE)) {
    /* calling do_writemore/do_close_internal is not necessary
       since the pcb has already been deleted! */
    conn->state = NETCONN_NONE;
    /* wake up the waiting task */
    sys_mbox_post(conn->mbox, NULL);
  }
}

/**
 * Setup a tcp_pcb with the correct callback function pointers
 * and their arguments.
 *
 * @param conn the TCP netconn to setup
 */
static void
setup_tcp(struct netconn *conn)
{
  struct tcp_pcb *pcb;

  pcb = conn->pcb.tcp;
  tcp_arg(pcb, conn);
  tcp_recv(pcb, recv_tcp);
  tcp_sent(pcb, sent_tcp);
  tcp_poll(pcb, poll_tcp, 4);
  tcp_err(pcb, err_tcp);
}

/**
 * Accept callback function for TCP netconns.
 * Allocates a new netconn and posts that to conn->acceptmbox.
 *
 * @see tcp.h (struct tcp_pcb_listen.accept) for parameters and return value
 */
static err_t
accept_function(void *arg, struct tcp_pcb *newpcb, err_t err)
{
  struct netconn *newconn;
  struct netconn *conn;

#if API_MSG_DEBUG
#if TCP_DEBUG
  tcp_debug_print_state(newpcb->state);
#endif /* TCP_DEBUG */
#endif /* API_MSG_DEBUG */
  conn = (struct netconn *)arg;

  LWIP_ERROR("accept_function: invalid conn->acceptmbox",
             conn->acceptmbox != SYS_MBOX_NULL, return ERR_VAL;);

  newconn = memp_malloc(MEMP_NETCONN);
  if (newconn == NULL) {
    return ERR_MEM;
  }
  newconn->recvmbox = sys_mbox_new();
  if (newconn->recvmbox == SYS_MBOX_NULL) {
    memp_free(MEMP_NETCONN, newconn);
    return ERR_MEM;
  }
  newconn->mbox = sys_mbox_new();
  if (newconn->mbox == SYS_MBOX_NULL) {
    sys_mbox_free(newconn->recvmbox);
    memp_free(MEMP_NETCONN, newconn);
    return ERR_MEM;
  }
  /* Allocations were OK, setup the PCB etc */
  newconn->type = NETCONN_TCP;
  newconn->pcb.tcp = newpcb;
  setup_tcp(newconn);
  newconn->state = NETCONN_NONE;
  newconn->acceptmbox = SYS_MBOX_NULL;
  newconn->err = err;
  /* Register event with callback */
  if (conn->callback) {
    (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
  }
  /* We have to set the callback here even though
   * the new socket is unknown. Mark the socket as -1. */
  newconn->callback = conn->callback;
  newconn->socket = -1;
  newconn->recv_avail = 0;
#if LWIP_SO_RCVTIMEO
  newconn->recv_timeout = 0;
#endif /* LWIP_SO_RCVTIMEO */

  sys_mbox_post(conn->acceptmbox, newconn);
  return ERR_OK;
}
#endif /* LWIP_TCP */

/**
 * Create a new pcb of a specific type.
 * Called from do_newconn().
 *
 * @param msg the api_msg_msg describing the connection type
 * @return msg->conn->err, but the return value is currently ignored
 */
static err_t
pcb_new(struct api_msg_msg *msg)
{
   msg->conn->err = ERR_OK;

   /* Allocate a PCB for this connection */
   switch(NETCONNTYPE_GROUP(msg->conn->type)) {
#if LWIP_RAW
   case NETCONN_RAW:
     msg->conn->pcb.raw = raw_new(msg->msg.n.proto);
     if(msg->conn->pcb.raw == NULL) {
       msg->conn->err = ERR_MEM;
       break;
     }
     raw_recv(msg->conn->pcb.raw, recv_raw, msg->conn);
     break;
#endif /* LWIP_RAW */
#if LWIP_UDP
   case NETCONN_UDP:
     msg->conn->pcb.udp = udp_new();
     if(msg->conn->pcb.udp == NULL) {
       msg->conn->err = ERR_MEM;
       break;
     }
#if LWIP_UDPLITE
     if (msg->conn->type==NETCONN_UDPLITE)     udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_UDPLITE);
#endif /* LWIP_UDPLITE */
     if (msg->conn->type==NETCONN_UDPNOCHKSUM) udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_NOCHKSUM);
     udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
     break;
#endif /* LWIP_UDP */
#if LWIP_TCP
   case NETCONN_TCP:
     msg->conn->pcb.tcp = tcp_new();
     if(msg->conn->pcb.tcp == NULL) {
       msg->conn->err = ERR_MEM;
       break;
     }
     setup_tcp(msg->conn);
     break;
#endif /* LWIP_TCP */
   default:
     /* Unsupported netconn type, e.g. protocol disabled */
     msg->conn->err = ERR_VAL;
     break;
   }

  return msg->conn->err;
}

/**
 * Create a new pcb of a specific type inside a netconn.
 * Called from netconn_new_with_proto_and_callback.
 *
 * @param msg the api_msg_msg describing the connection type
 */
void
do_newconn(struct api_msg_msg *msg)
{
   if(msg->conn->pcb.tcp == NULL) {
     pcb_new(msg);
   }
   /* Else? This "new" connection already has a PCB allocated. */
   /* Is this an error condition? Should it be deleted? */
   /* We currently just are happy and return. */

   TCPIP_APIMSG_ACK(msg);
}

#if LWIP_TCP
static void
do_close_internal(struct netconn *conn)
{
  err_t err;

  LWIP_ASSERT("invalid conn", (conn != NULL));
  LWIP_ASSERT("this is for tcp netconns only", (conn->type == NETCONN_TCP));
  LWIP_ASSERT("conn must be in state NETCONN_CLOSE", (conn->state == NETCONN_CLOSE));
  LWIP_ASSERT("pcb already closed", (conn->pcb.tcp != NULL));

  /* Set back some callback pointers */
  if (conn->pcb.tcp->state == LISTEN) {
    tcp_arg(conn->pcb.tcp, NULL);
    tcp_accept(conn->pcb.tcp, NULL);
  } else {
    tcp_recv(conn->pcb.tcp, NULL);
  }
  /* Try to close the connection */
  err = tcp_close(conn->pcb.tcp);
  if (err == ERR_OK) {
    /* Closing succeeded */
    conn->state = NETCONN_NONE;
    /* Set back some callback pointers as conn is going away */
    tcp_err(conn->pcb.tcp, NULL);
    tcp_poll(conn->pcb.tcp, NULL, 4);
    tcp_sent(conn->pcb.tcp, NULL);
    tcp_recv(conn->pcb.tcp, NULL);
    tcp_arg(conn->pcb.tcp, NULL);
    conn->pcb.tcp = NULL;
    conn->err = err;
    /* Trigger select() in socket layer */
    if (conn->callback) {
        /* this should send something else so the errorfd is set,
           not the read and write fd! */
        (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
        (*conn->callback)(conn, NETCONN_EVT_SENDPLUS, 0);
    }
    /* wake up the application task */
    sys_mbox_post(conn->mbox, NULL);
  }
  /* If closing didn't succeed, we get called again either
     from poll_tcp or from sent_tcp */
}
#endif /* LWIP_TCP */

/**
 * Delete the pcb inside a netconn.
 * Called from netconn_delete.
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_delconn(struct api_msg_msg *msg)
{
  if (msg->conn->pcb.tcp != NULL) {
    switch (NETCONNTYPE_GROUP(msg->conn->type)) {
#if LWIP_RAW
    case NETCONN_RAW:
      raw_remove(msg->conn->pcb.raw);
      break;
#endif /* LWIP_RAW */
#if LWIP_UDP
    case NETCONN_UDP:
      msg->conn->pcb.udp->recv_arg = NULL;
      udp_remove(msg->conn->pcb.udp);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP
    case NETCONN_TCP:
      msg->conn->state = NETCONN_CLOSE;
      do_close_internal(msg->conn);
      /* conn->callback is called inside do_close_internal, before releasing
         the application thread, so we can return at this point! */
      return;
#endif /* LWIP_TCP */
    default:
      break;
    }
  }
  /* tcp netconns don't come here! */

  /* Trigger select() in socket layer */
  if (msg->conn->callback) {
      /* this send should something else so the errorfd is set,
         not the read and write fd! */
      (*msg->conn->callback)(msg->conn, NETCONN_EVT_RCVPLUS, 0);
      (*msg->conn->callback)(msg->conn, NETCONN_EVT_SENDPLUS, 0);
  }

  if (msg->conn->mbox != SYS_MBOX_NULL) {
    sys_mbox_post(msg->conn->mbox, NULL);
  }
}

/**
 * Bind a pcb contained in a netconn
 * Called from netconn_bind.
 *
 * @param msg the api_msg_msg pointing to the connection and containing
 *            the IP address and port to bind to
 */
void
do_bind(struct api_msg_msg *msg)
{
  if (msg->conn->err == ERR_OK) {
    if (msg->conn->pcb.tcp != NULL) {
      switch (NETCONNTYPE_GROUP(msg->conn->type)) {
#if LWIP_RAW
      case NETCONN_RAW:
        msg->conn->err = raw_bind(msg->conn->pcb.raw, msg->msg.bc.ipaddr);
        break;
#endif /* LWIP_RAW */
#if LWIP_UDP
      case NETCONN_UDP:
        msg->conn->err = udp_bind(msg->conn->pcb.udp, msg->msg.bc.ipaddr, msg->msg.bc.port);
        break;
#endif /* LWIP_UDP */
#if LWIP_TCP
      case NETCONN_TCP:
        msg->conn->err = tcp_bind(msg->conn->pcb.tcp, msg->msg.bc.ipaddr, msg->msg.bc.port);
        break;
#endif /* LWIP_TCP */
      default:
        break;
      }
    } else {
      /* msg->conn->pcb is NULL */
      msg->conn->err = ERR_VAL;
    }
  }
  TCPIP_APIMSG_ACK(msg);
}

#if LWIP_TCP
/**
 * TCP callback function if a connection (opened by tcp_connect/do_connect) has
 * been established (or reset by the remote host).
 *
 * @see tcp.h (struct tcp_pcb.connected) for parameters and return values
 */
static err_t
do_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct netconn *conn;

  LWIP_UNUSED_ARG(pcb);

  conn = arg;

  if (conn == NULL) {
    return ERR_VAL;
  }

  conn->err = err;
  if (conn->type == NETCONN_TCP && err == ERR_OK) {
    setup_tcp(conn);
  }
  conn->state = NETCONN_NONE;
  sys_mbox_post(conn->mbox, NULL);
  return ERR_OK;
}
#endif /* LWIP_TCP */

/**
 * Connect a pcb contained inside a netconn
 * Called from netconn_connect.
 *
 * @param msg the api_msg_msg pointing to the connection and containing
 *            the IP address and port to connect to
 */
void
do_connect(struct api_msg_msg *msg)
{
  if (msg->conn->pcb.tcp == NULL) {
    sys_mbox_post(msg->conn->mbox, NULL);
    return;
  }

  switch (NETCONNTYPE_GROUP(msg->conn->type)) {
#if LWIP_RAW
  case NETCONN_RAW:
    msg->conn->err = raw_connect(msg->conn->pcb.raw, msg->msg.bc.ipaddr);
    sys_mbox_post(msg->conn->mbox, NULL);
    break;
#endif /* LWIP_RAW */
#if LWIP_UDP
  case NETCONN_UDP:
    msg->conn->err = udp_connect(msg->conn->pcb.udp, msg->msg.bc.ipaddr, msg->msg.bc.port);
    sys_mbox_post(msg->conn->mbox, NULL);
    break;
#endif /* LWIP_UDP */
#if LWIP_TCP
  case NETCONN_TCP:
    msg->conn->state = NETCONN_CONNECT;
    setup_tcp(msg->conn);
    msg->conn->err = tcp_connect(msg->conn->pcb.tcp, msg->msg.bc.ipaddr, msg->msg.bc.port,
                                 do_connected);
    break;
#endif /* LWIP_TCP */
  default:
    break;
  }
}

/**
 * Connect a pcb contained inside a netconn
 * Only used for UDP netconns.
 * Called from netconn_disconnect.
 *
 * @param msg the api_msg_msg pointing to the connection to disconnect
 */
void
do_disconnect(struct api_msg_msg *msg)
{
#if LWIP_UDP
  if (NETCONNTYPE_GROUP(msg->conn->type) == NETCONN_UDP) {
    udp_disconnect(msg->conn->pcb.udp);
  }
#endif /* LWIP_UDP */
  TCPIP_APIMSG_ACK(msg);
}

/**
 * Set a TCP pcb contained in a netconn into listen mode
 * Called from netconn_listen.
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_listen(struct api_msg_msg *msg)
{
#if LWIP_TCP
  if (msg->conn->err == ERR_OK) {
    if (msg->conn->pcb.tcp != NULL) {
      if (msg->conn->type == NETCONN_TCP) {
        if (msg->conn->pcb.tcp->state == CLOSED) {
          struct tcp_pcb* lpcb = tcp_listen(msg->conn->pcb.tcp);
          if (lpcb == NULL) {
            msg->conn->err = ERR_MEM;
          } else {
            if (msg->conn->acceptmbox == SYS_MBOX_NULL) {
              if ((msg->conn->acceptmbox = sys_mbox_new()) == SYS_MBOX_NULL) {
                msg->conn->err = ERR_MEM;
              }
            }
            if (msg->conn->err == ERR_OK) {
              msg->conn->state = NETCONN_LISTEN;
              msg->conn->pcb.tcp = lpcb;
              tcp_arg(msg->conn->pcb.tcp, msg->conn);
              tcp_accept(msg->conn->pcb.tcp, accept_function);
            }
          }
        } else {
          msg->conn->err = ERR_CONN;
        }
      }
    }
  }
#endif /* LWIP_TCP */
  TCPIP_APIMSG_ACK(msg);
}

/**
 * Send some data on a RAW or UDP pcb contained in a netconn
 * Called from netconn_send
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_send(struct api_msg_msg *msg)
{
  if (msg->conn->err == ERR_OK) {
    if (msg->conn->pcb.tcp != NULL) {
      switch (NETCONNTYPE_GROUP(msg->conn->type)) {
#if LWIP_RAW
      case NETCONN_RAW:
        if (msg->msg.b->addr == NULL) {
          msg->conn->err = raw_send(msg->conn->pcb.raw, msg->msg.b->p);
        } else {
          msg->conn->err = raw_sendto(msg->conn->pcb.raw, msg->msg.b->p, msg->msg.b->addr);
        }
        break;
#endif
#if LWIP_UDP
      case NETCONN_UDP:
        if (msg->msg.b->addr == NULL) {
          msg->conn->err = udp_send(msg->conn->pcb.udp, msg->msg.b->p);
        } else {
          msg->conn->err = udp_sendto(msg->conn->pcb.udp, msg->msg.b->p, msg->msg.b->addr, msg->msg.b->port);
        }
        break;
#endif /* LWIP_UDP */
      default:
        break;
      }
    }
  }
  TCPIP_APIMSG_ACK(msg);
}

/**
 * Recv some data from a RAW or UDP pcb contained in a netconn
 * Called from netconn_recv
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_recv(struct api_msg_msg *msg)
{
#if LWIP_TCP
  if (msg->conn->err == ERR_OK) {
    if (msg->conn->pcb.tcp != NULL) {
      if (msg->conn->type == NETCONN_TCP) {
        tcp_recved(msg->conn->pcb.tcp, msg->msg.r.len);
      }
    }
  }
#endif /* LWIP_TCP */
  TCPIP_APIMSG_ACK(msg);
}

#if LWIP_TCP
/**
 * See if more data needs to be written from a previous call to netconn_write.
 * Called initially from do_write. If the first call can't send all data
 * (because of low memory or empty send-buffer), this function is called again
 * from sent_tcp() or poll_tcp() to send more data. If all data is sent, the
 * blocking application thread (waiting in netconn_write) is released.
 *
 * @param conn netconn (that is currently in state NETCONN_WRITE) to process
 * @return ERR_OK
 *         ERR_MEM if LWIP_TCPIP_CORE_LOCKING=1 and sending hasn't yet finished
 */
err_t
do_writemore(struct netconn *conn)
{
  err_t err;
  void *dataptr;
  u16_t len, available;
  u8_t write_finished = 0;

  LWIP_ASSERT("conn->state == NETCONN_WRITE", (conn->state == NETCONN_WRITE));

  dataptr = (u8_t*)conn->write_msg->msg.w.dataptr + conn->write_offset;
  if ((conn->write_msg->msg.w.len - conn->write_offset > 0xffff)) { /* max_u16_t */
    len = 0xffff;
#if LWIP_TCPIP_CORE_LOCKING
    conn->write_delayed = 1;
#endif
  } else {
    len = conn->write_msg->msg.w.len - conn->write_offset;
  }
  available = tcp_sndbuf(conn->pcb.tcp);
  if (available < len) {
    /* don't try to write more than sendbuf */
    len = available;
#if LWIP_TCPIP_CORE_LOCKING
    conn->write_delayed = 1;
#endif
  }

  err = tcp_write(conn->pcb.tcp, dataptr, len, conn->write_msg->msg.w.copy);
  LWIP_ASSERT("do_writemore: invalid length!", ((conn->write_offset + len) <= conn->write_msg->msg.w.len));
  if (err == ERR_OK) {
    conn->write_offset += len;
    if (conn->write_offset == conn->write_msg->msg.w.len) {
      /* everything was written */
      write_finished = 1;
      conn->write_msg = NULL;
      conn->write_offset = 0;
    }
    err = tcp_output_nagle(conn->pcb.tcp);
    conn->err = err;
    if ((conn->callback) && (err == ERR_OK) &&
        (tcp_sndbuf(conn->pcb.tcp) <= TCP_SNDLOWAT)) {
      (*conn->callback)(conn, NETCONN_EVT_SENDMINUS, len);
    }
  } else if (err == ERR_MEM) {
#if LWIP_TCPIP_CORE_LOCKING
    conn->write_delayed = 1;
#endif
  } else {
    /* if ERR_MEM, we wait for sent_tcp or poll_tcp to be called */
    conn->err = err;
    /* since we've had an error (except temporary running out of memory,
       we don't try writing any more */
    write_finished = 1;
  }

  if (write_finished) {
    /* everything was written: set back connection state
       and back to application task */
    conn->state = NETCONN_NONE;
#if LWIP_TCPIP_CORE_LOCKING
    if (conn->write_delayed != 0)
#endif
    {
      sys_mbox_post(conn->mbox, NULL);
    }
  }
#if LWIP_TCPIP_CORE_LOCKING
  else
    return ERR_MEM;
#endif
  return ERR_OK;
}
#endif /* LWIP_TCP */

/**
 * Send some data on a TCP pcb contained in a netconn
 * Called from netconn_write
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_write(struct api_msg_msg *msg)
{
  if (msg->conn->err == ERR_OK) {
    if ((msg->conn->pcb.tcp != NULL) && (msg->conn->type == NETCONN_TCP)) {
#if LWIP_TCP
      msg->conn->state = NETCONN_WRITE;
      /* set all the variables used by do_writemore */
      msg->conn->write_msg = msg;
      msg->conn->write_offset = 0;
#if LWIP_TCPIP_CORE_LOCKING
      msg->conn->write_delayed = 0;
      if (do_writemore(msg->conn) != ERR_OK) {
        LWIP_ASSERT("state!", msg->conn->state == NETCONN_WRITE);
        UNLOCK_TCPIP_CORE();
        sys_arch_mbox_fetch(msg->conn->mbox, NULL, 0);
        LOCK_TCPIP_CORE();
        LWIP_ASSERT("state!", msg->conn->state == NETCONN_NONE);
      }
#else
      do_writemore(msg->conn);
#endif
      /* for both cases: if do_writemore was called, don't ACK the APIMSG! */
      return;
#endif /* LWIP_TCP */
#if (LWIP_UDP || LWIP_RAW)
    } else {
      msg->conn->err = ERR_VAL;
#endif /* (LWIP_UDP || LWIP_RAW) */
    }
  }
  TCPIP_APIMSG_ACK(msg);
}

/**
 * Close a TCP pcb contained in a netconn
 * Called from netconn_close
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_close(struct api_msg_msg *msg)
{
#if LWIP_TCP
  if ((msg->conn->pcb.tcp != NULL) && (msg->conn->type == NETCONN_TCP)) {
      msg->conn->state = NETCONN_CLOSE;
      do_close_internal(msg->conn);
      /* for tcp netconns, do_close_internal ACKs the message */
  } else
#endif /* LWIP_TCP */
  {
    msg->conn->err = ERR_VAL;
    TCPIP_APIMSG_ACK(msg);
  }
}

#if LWIP_IGMP
/**
 * Join multicast groups for UDP netconns.
 * Called from netconn_join_leave_group
 *
 * @param msg the api_msg_msg pointing to the connection
 */
void
do_join_leave_group(struct api_msg_msg *msg)
{ 
  if (msg->conn->err == ERR_OK) {
    if (msg->conn->pcb.tcp != NULL) {
      if (NETCONNTYPE_GROUP(msg->conn->type) == NETCONN_UDP) {
#if LWIP_UDP
        if (msg->msg.jl.join_or_leave == NETCONN_JOIN) {
          msg->conn->err = igmp_joingroup ( msg->msg.jl.interface, msg->msg.jl.multiaddr);
        } else {
          msg->conn->err = igmp_leavegroup( msg->msg.jl.interface, msg->msg.jl.multiaddr);
        }
#endif /* LWIP_UDP */
#if (LWIP_TCP || LWIP_RAW)
      } else {
        msg->conn->err = ERR_VAL;
#endif /* (LWIP_TCP || LWIP_RAW) */
      }
    }
  }
  TCPIP_APIMSG_ACK(msg);
}
#endif /* LWIP_IGMP */

#endif /* !NO_SYS */
