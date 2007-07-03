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

/* This is the part of the API that is linked with
   the application */

#include <string.h>
#include "lwip/opt.h"
#include "lwip/api.h"
#include "lwip/api_msg.h"
#include "lwip/tcpip.h"
#include "lwip/memp.h"

#if !NO_SYS
/**
 **********************************
 * Netbuf functions
 **********************************
 */

/**
 * Create (allocate) and initialize a new netbuf.
 * The netbuf doesn't yet contain a packet buffer!
 *
 * @return a pointer to a new netbuf
 *         NULL on lack of memory
 */
struct
netbuf *netbuf_new(void)
{
  struct netbuf *buf;

  buf = memp_malloc(MEMP_NETBUF);
  if (buf != NULL) {
    buf->p = NULL;
    buf->ptr = NULL;
    buf->addr = NULL;
    return buf;
  } else {
    return NULL;
  }
}

/**
 * Deallocate a netbuf allocated by netbuf_new().
 *
 * @param buf pointer to a netbuf allocated by netbuf_new()
 */
void
netbuf_delete(struct netbuf *buf)
{
  if (buf != NULL) {
    if (buf->p != NULL) {
      pbuf_free(buf->p);
      buf->p = buf->ptr = NULL;
    }
    memp_free(MEMP_NETBUF, buf);
  }
}

/**
 * Allocate memory for a packet buffer for a given netbuf.
 *
 * @param buf the netbuf for which to allocate a packet buffer
 * @param size the size of the packet buffer to allocate
 * @return pointer to the allocated memory
 *         NULL if no memory could be allocated
 */
void *
netbuf_alloc(struct netbuf *buf, u16_t size)
{
  LWIP_ERROR("netbuf_alloc: invalid buf", (buf != NULL), return NULL;);

  /* Deallocate any previously allocated memory. */
  if (buf->p != NULL) {
    pbuf_free(buf->p);
  }
  buf->p = pbuf_alloc(PBUF_TRANSPORT, size, PBUF_RAM);
  if (buf->p == NULL) {
     return NULL;
  }
  buf->ptr = buf->p;
  return buf->p->payload;
}

/**
 * Free the packet buffer included in a netbuf
 *
 * @param buf pointer to the netbuf which contains the packet buffer to free
 */
void
netbuf_free(struct netbuf *buf)
{
  LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return;);
  if (buf->p != NULL) {
    pbuf_free(buf->p);
  }
  buf->p = buf->ptr = NULL;
}

/**
 * Let a netbuf reference existing (non-volatile) data.
 *
 * @param buf netbuf which should reference the data
 * @param dataptr pointer to the data to reference
 * @param size size of the data
 * @return ERR_OK if data is referenced
 *         ERR_MEM if data couldn't be referenced due to lack of memory
 */
err_t
netbuf_ref(struct netbuf *buf, const void *dataptr, u16_t size)
{
  LWIP_ERROR("netbuf_ref: invalid buf", (buf != NULL), return ERR_ARG;);
  if (buf->p != NULL) {
    pbuf_free(buf->p);
  }
  buf->p = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_REF);
  if (buf->p == NULL) {
    buf->ptr = NULL;
    return ERR_MEM;
  }
  buf->p->payload = (void*)dataptr;
  buf->p->len = buf->p->tot_len = size;
  buf->ptr = buf->p;
  return ERR_OK;
}

/**
 * Chain one netbuf to another (@see pbuf_chain)
 *
 * @param head the first netbuf
 * @param tail netbuf to chain after head
 */
void
netbuf_chain(struct netbuf *head, struct netbuf *tail)
{
  LWIP_ERROR("netbuf_ref: invalid head", (head != NULL), return;);
  LWIP_ERROR("netbuf_chain: invalid tail", (tail != NULL), return;);
  pbuf_chain(head->p, tail->p);
  head->ptr = head->p;
  memp_free(MEMP_NETBUF, tail);
}

/**
 * Get the data pointer and length of the data inside a netbuf.
 *
 * @param buf netbuf to get the data from
 * @param dataptr pointer to a void pointer where to store the data pointer
 * @param len pointer to an u16_t where the length of the data is stored
 * @return ERR_OK if the information was retreived,
 *         ERR_BUF on error.
 */
err_t
netbuf_data(struct netbuf *buf, void **dataptr, u16_t *len)
{
  LWIP_ERROR("netbuf_data: invalid buf", (buf != NULL), return ERR_ARG;);
  LWIP_ERROR("netbuf_data: invalid dataptr", (dataptr != NULL), return ERR_ARG;);
  LWIP_ERROR("netbuf_data: invalid len", (len != NULL), return ERR_ARG;);

  if (buf->ptr == NULL) {
    return ERR_BUF;
  }
  *dataptr = buf->ptr->payload;
  *len = buf->ptr->len;
  return ERR_OK;
}

/**
 * Move the current data pointer of a packet buffer contained in a netbuf
 * to the next part.
 * The packet buffer itself is not modified.
 *
 * @param buf the netbuf to modify
 * @return -1 if there is no next part
 *         1  if moved to the next part but now there is no next part
 *         0  if moved to the next part and there are still more parts
 */
s8_t
netbuf_next(struct netbuf *buf)
{
  LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return -1;);
  if (buf->ptr->next == NULL) {
    return -1;
  }
  buf->ptr = buf->ptr->next;
  if (buf->ptr->next == NULL) {
    return 1;
  }
  return 0;
}

/**
 * Move the current data pointer of a packet buffer contained in a netbuf
 * to the beginning of the packet.
 * The packet buffer itself is not modified.
 *
 * @param buf the netbuf to modify
 */
void
netbuf_first(struct netbuf *buf)
{
  LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return;);
  buf->ptr = buf->p;
}

/**
 * Copy (part of) the contents of a packet buffer contained in a netbuf
 * to an application supplied buffer.
 *
 * @param buf the netbuf from which to copy data
 * @param dataptr the application supplied buffer
 * @param len length of data to copy (dataptr must be big enough)
 * @param offset offset into the packet buffer from where to begin copying len bytes
 */
void
netbuf_copy_partial(struct netbuf *buf, void *dataptr, u16_t len, u16_t offset)
{
  struct pbuf *p;
  u16_t left;
  u16_t buf_copy_len;

  LWIP_ERROR("netbuf_copy_partial: invalid buf", (buf != NULL), return;);
  LWIP_ERROR("netbuf_copy_partial: invalid dataptr", (dataptr != NULL), return;);

  left = 0;

  if(buf == NULL || dataptr == NULL) {
    return;
  }

  /* Note some systems use byte copy if dataptr or one of the pbuf payload pointers are unaligned. */
  for(p = buf->p; len != 0 && p != NULL; p = p->next) {
    if ((offset != 0) && (offset >= p->len)) {
      /* don't copy from this buffer -> on to the next */
      offset -= p->len;
    } else {
      /* copy from this buffer. maybe only partially. */
      buf_copy_len = p->len - offset;
      if (buf_copy_len > len)
          buf_copy_len = len;
      /* copy the necessary parts of the buffer */
      MEMCPY(&((char*)dataptr)[left], &((char*)p->payload)[offset], buf_copy_len);
      left += buf_copy_len;
      len -= buf_copy_len;
      offset = 0;
    }
  }
}

/**
 **********************************
 * Netconn functions
 **********************************
 */

/**
 * Create a new netconn (of a specific type) that has a callback function.
 * The corresponding pcb is also created.
 *
 * @param t the type of 'connection' to create (@see enum netconn_type)
 * @param proto the IP protocol for RAW IP pcbs
 * @param callback a function to call on status changes (RX available, TX'ed)
 * @return a newly allocated struct netconn or
 *         NULL on memory error
 */
struct
netconn *netconn_new_with_proto_and_callback(enum netconn_type t, u8_t proto,
                                   void (*callback)(struct netconn *, enum netconn_evt, u16_t len))
{
  struct netconn *conn;
  struct api_msg msg;

  conn = memp_malloc(MEMP_NETCONN);
  if (conn == NULL) {
    return NULL;
  }

  conn->err = ERR_OK;
  conn->type = t;
  conn->pcb.tcp = NULL;

  if ((conn->mbox = sys_mbox_new()) == SYS_MBOX_NULL) {
    memp_free(MEMP_NETCONN, conn);
    return NULL;
  }
  conn->recvmbox = SYS_MBOX_NULL;
  conn->acceptmbox = SYS_MBOX_NULL;
  conn->state        = NETCONN_NONE;
  conn->socket       = 0;
  conn->callback     = callback;
  conn->recv_avail   = 0;
#if LWIP_SO_RCVTIMEO
  conn->recv_timeout = 0;
#endif /* LWIP_SO_RCVTIMEO */

  msg.function = do_newconn;
  msg.msg.msg.n.proto = proto;
  msg.msg.conn = conn;
  TCPIP_APIMSG(&msg);

  if (conn->err != ERR_OK) {
    sys_mbox_free(conn->mbox);
    memp_free(MEMP_NETCONN, conn);
    return NULL;
  }

  return conn;
}

/**
 * Close a netconn 'connection' and free its resources.
 * UDP and RAW connection are completely closed, TCP pcbs might still be in a waitstate
 * after this returns.
 *
 * @param conn the netconn to delete
 * @return ERR_OK if the connection was deleted
 */
err_t
netconn_delete(struct netconn *conn)
{
  struct api_msg msg;
  void *mem;

  /* No ASSERT here because possible to get a (conn == NULL) if we got an accept error */
  if (conn == NULL) {
    return ERR_OK;
  }

  msg.function = do_delconn;
  msg.msg.conn = conn;
  tcpip_apimsg(&msg);

  /* Drain the recvmbox. */
  if (conn->recvmbox != SYS_MBOX_NULL) {
    while (sys_mbox_tryfetch(conn->recvmbox, &mem) != SYS_MBOX_EMPTY) {
      if (conn->type == NETCONN_TCP) {
        if(mem != NULL)
          pbuf_free((struct pbuf *)mem);
      } else {
        netbuf_delete((struct netbuf *)mem);
      }
    }
    sys_mbox_free(conn->recvmbox);
    conn->recvmbox = SYS_MBOX_NULL;
  }

  /* Drain the acceptmbox. */
  if (conn->acceptmbox != SYS_MBOX_NULL) {
    while (sys_mbox_tryfetch(conn->acceptmbox, &mem) != SYS_MBOX_EMPTY) {
      netconn_delete((struct netconn *)mem);
    }
    sys_mbox_free(conn->acceptmbox);
    conn->acceptmbox = SYS_MBOX_NULL;
  }

  sys_mbox_free(conn->mbox);
  conn->mbox = SYS_MBOX_NULL;

  memp_free(MEMP_NETCONN, conn);
  return ERR_OK;
}

/**
 * Get the type of a netconn (as enum netconn_type).
 *
 * @param conn the netconn of which to get the type
 * @return the netconn_type of conn
 */
enum netconn_type
netconn_type(struct netconn *conn)
{
  LWIP_ERROR("netconn_type: invalid conn", (conn != NULL), return NETCONN_INVALID;);
  return conn->type;
}

/**
 * Get the current perr a netconn is connected to.
 * This might only be temporary for UDP netconns,
 * doesn't work for RAW netconns and returns garbage
 * if called for a TCP listen netconn.
 *
 * @param conn the netconn to query
 * @param addr a pointer to which to save the remote IP address
 * @param port a pointer to which to save the remote port
 * @return ERR_CONN for invalid connections
 *         ERR_OK if the information was retrieved
 */
err_t
netconn_peer(struct netconn *conn, struct ip_addr *addr, u16_t *port)
{
  LWIP_ERROR("netconn_peer: invalid conn", (conn != NULL), return ERR_ARG;);
  switch (NETCONNTYPE_GROUP(conn->type)) {
  case NETCONN_RAW:
    /* return an error as connecting is only a helper for upper layers */
    return ERR_CONN;
  case NETCONN_UDP:
    if (conn->pcb.udp == NULL ||
  ((conn->pcb.udp->flags & UDP_FLAGS_CONNECTED) == 0))
     return ERR_CONN;
    *addr = (conn->pcb.udp->remote_ip);
    *port = conn->pcb.udp->remote_port;
    break;
  case NETCONN_TCP:
    if (conn->pcb.tcp == NULL)
      return ERR_CONN;
    *addr = (conn->pcb.tcp->remote_ip);
    *port = conn->pcb.tcp->remote_port;
    break;
  }
  return ERR_OK;
}

/**
 * Get the local IP address and port of a netconn.
 * For RAW netconns, this returns the protocol instead of a port!
 *
 * @param conn the netconn to query
 * @param addr a pointer to which to save the local IP address
 * @param port a pointer to which to save the local port (or protocol for RAW)
 * @return ERR_OK if the information was retrieved
 */
err_t
netconn_addr(struct netconn *conn, struct ip_addr **addr, u16_t *port)
{
  LWIP_ERROR("netconn_addr: invalid conn", (conn != NULL), return ERR_ARG;);
  LWIP_ERROR("netconn_addr: invalid addr", (addr != NULL), return ERR_ARG;);
  LWIP_ERROR("netconn_addr: invalid port", (port != NULL), return ERR_ARG;);
  switch (NETCONNTYPE_GROUP(conn->type)) {
  case NETCONN_RAW:
    *addr = &(conn->pcb.raw->local_ip);
    *port = conn->pcb.raw->protocol;
    break;
  case NETCONN_UDP:
    *addr = &(conn->pcb.udp->local_ip);
    *port = conn->pcb.udp->local_port;
    break;
  case NETCONN_TCP:
    *addr = &(conn->pcb.tcp->local_ip);
    *port = conn->pcb.tcp->local_port;
    break;
  }
  return ERR_OK;
}

/**
 * Bind a netconn to a specific local IP address and port.
 * Binding one netconn twice might not always be checked correctly!
 *
 * @param conn the netconn to bind
 * @param addr the local IP address to bind the netconn to (use IP_ADDR_ANY
 *             to bind to all addresses)
 * @param port the local port to bind the netconn to (not used for RAW)
 * @return ERR_OK if bound, any other err_t on failure
 */
err_t
netconn_bind(struct netconn *conn, struct ip_addr *addr, u16_t port)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_bind: invalid conn", (conn != NULL), return ERR_ARG;);

  if (conn->type != NETCONN_TCP && conn->recvmbox == SYS_MBOX_NULL) {
    if ((conn->recvmbox = sys_mbox_new()) == SYS_MBOX_NULL) {
      return ERR_MEM;
    }
  }

  msg.function = do_bind;
  msg.msg.conn = conn;
  msg.msg.msg.bc.ipaddr = addr;
  msg.msg.msg.bc.port = port;
  TCPIP_APIMSG(&msg);
  return conn->err;
}

/**
 * Connect a netconn to a specific remote IP address and port.
 *
 * @param conn the netconn to connect
 * @param addr the remote IP address to connect to
 * @param port the remote port to connect to (no used for RAW)
 * @return ERR_OK if connected, return value of tcp_/udp_/raw_connect otherwise
 */
err_t
netconn_connect(struct netconn *conn, struct ip_addr *addr, u16_t port)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_connect: invalid conn", (conn != NULL), return ERR_ARG;);

  if (conn->recvmbox == SYS_MBOX_NULL) {
    if ((conn->recvmbox = sys_mbox_new()) == SYS_MBOX_NULL) {
      return ERR_MEM;
    }
  }

  msg.function = do_connect;
  msg.msg.conn = conn;
  msg.msg.msg.bc.ipaddr = addr;
  msg.msg.msg.bc.port = port;
  /* This is the only function which need to not block tcpip_thread */
  tcpip_apimsg(&msg);
  return conn->err;
}

/**
 * Disconnect a netconn from its current peer (only valid for UDP netconns).
 *
 * @param conn the netconn to disconnect
 * @return TODO: return value is not set here...
 */
err_t
netconn_disconnect(struct netconn *conn)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_disconnect: invalid conn", (conn != NULL), return ERR_ARG;);

  msg.function = do_disconnect;
  msg.msg.conn = conn;
  TCPIP_APIMSG(&msg);
  return conn->err;

}

/**
 * Set a TCP netconn into listen mode
 *
 * @param conn the tcp netconn to set to listen mode
 * @return ERR_OK if the netconn was set to listen (UDP and RAW netconns
 *         don't return any error (yet?))
 */
err_t
netconn_listen(struct netconn *conn)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_listen: invalid conn", (conn != NULL), return ERR_ARG;);

  msg.function = do_listen;
  msg.msg.conn = conn;
  TCPIP_APIMSG(&msg);
  return conn->err;
}

/**
 * Accept a new connection on a TCP listening netconn.
 *
 * @param conn the TCP listen netconn
 * @return the newly accepted netconn or NULL on timeout
 */
struct netconn *
netconn_accept(struct netconn *conn)
{
  struct netconn *newconn;

  LWIP_ERROR("netconn_accept: invalid conn",       (conn != NULL),                      return NULL;);
  LWIP_ERROR("netconn_accept: invalid acceptmbox", (conn->acceptmbox != SYS_MBOX_NULL), return NULL;);

  #if LWIP_SO_RCVTIMEO
  if (sys_arch_mbox_fetch(conn->acceptmbox, (void *)&newconn, conn->recv_timeout)==SYS_ARCH_TIMEOUT) {
    newconn = NULL;
  }
  #else
  sys_arch_mbox_fetch(conn->acceptmbox, (void *)&newconn, 0);
  #endif /* LWIP_SO_RCVTIMEO*/

  /* Register event with callback */
  if (conn->callback)
    (*conn->callback)(conn, NETCONN_EVT_RCVMINUS, 0);

  return newconn;
}

/**
 * Receive data (in form of a netbuf containing a packet buffer) from a netconn
 *
 * @param conn the netconn from which to receive data
 * @return a new netbuf containing received data or NULL on memory error or timeout
 */
struct netbuf *
netconn_recv(struct netconn *conn)
{
  struct api_msg msg;
  struct netbuf *buf = NULL;
  struct pbuf *p;
  u16_t len;

  LWIP_ERROR("netconn_recv: invalid conn",  (conn != NULL), return NULL;);

  if (conn->recvmbox == SYS_MBOX_NULL) {
    if ((conn->recvmbox = sys_mbox_new()) == SYS_MBOX_NULL) {
      conn->err = ERR_CONN;
      return NULL;
    }
  }

  if (conn->err != ERR_OK) {
    return NULL;
  }

  if (conn->type == NETCONN_TCP) {
#if LWIP_TCP
    if (conn->pcb.tcp->state == LISTEN) {
      conn->err = ERR_CONN;
      return NULL;
    }

    buf = memp_malloc(MEMP_NETBUF);

    if (buf == NULL) {
      conn->err = ERR_MEM;
      return NULL;
    }

#if LWIP_SO_RCVTIMEO
    if (sys_arch_mbox_fetch(conn->recvmbox, (void *)&p, conn->recv_timeout)==SYS_ARCH_TIMEOUT) {
      p = NULL;
    }
#else
    sys_arch_mbox_fetch(conn->recvmbox, (void *)&p, 0);
#endif /* LWIP_SO_RCVTIMEO*/

    if (p != NULL) {
      len = p->tot_len;
      conn->recv_avail -= len;
    } else {
      len = 0;
    }

    /* Register event with callback */
    if (conn->callback)
      (*conn->callback)(conn, NETCONN_EVT_RCVMINUS, len);

    /* If we are closed, we indicate that we no longer wish to use the socket */
    if (p == NULL) {
      memp_free(MEMP_NETBUF, buf);
      conn->err = ERR_CLSD;
      return NULL;
    }

    buf->p = p;
    buf->ptr = p;
    buf->port = 0;
    buf->addr = NULL;

    /* Let the stack know that we have taken the data. */
    msg.function = do_recv;
    msg.msg.conn = conn;
    if (buf != NULL) {
      msg.msg.msg.r.len = buf->p->tot_len;
    } else {
      msg.msg.msg.r.len = 1;
    }
    TCPIP_APIMSG(&msg);
#endif /* LWIP_TCP */
  } else {
#if (LWIP_UDP || LWIP_RAW)
#if LWIP_SO_RCVTIMEO
    if (sys_arch_mbox_fetch(conn->recvmbox, (void *)&buf, conn->recv_timeout)==SYS_ARCH_TIMEOUT) {
      buf = NULL;
    }
#else
    sys_arch_mbox_fetch(conn->recvmbox, (void *)&buf, 0);
#endif /* LWIP_SO_RCVTIMEO*/
    if (buf!=NULL) {
      conn->recv_avail -= buf->p->tot_len;
      /* Register event with callback */
      if (conn->callback)
        (*conn->callback)(conn, NETCONN_EVT_RCVMINUS, buf->p->tot_len);
    }
#endif /* (LWIP_UDP || LWIP_RAW) */
  }

  LWIP_DEBUGF(API_LIB_DEBUG, ("netconn_recv: received %p (err %d)\n", (void *)buf, conn->err));

  return buf;
}

/**
 * Send data (in form of a netbuf) to a specific remote IP address and port.
 * Only to be used for UDP and RAW netconns (not TCP).
 *
 * @param conn the netconn over which to send data
 * @param buf a netbuf containing the data to send
 * @param addr the remote IP address to which to send the data
 * @param addr the remote port to which to send the data
 * @return ERR_OK if data was sent, any other err_t on error
 */
err_t
netconn_sendto(struct netconn *conn, struct netbuf *buf, struct ip_addr *addr, u16_t port)
{
  if (buf != NULL) {
    buf->addr = addr;
    buf->port = port;
    return netconn_send(conn, buf);
  }
  return ERR_VAL;
}

/**
 * Send data over a UDP or RAW netconn (that is already connected).
 *
 * @param conn the UDP or RAW netconn over which to send data
 * @param buf a netbuf containing the data to send
 * @return ERR_OK if data was sent, any other err_t on error
 */
err_t
netconn_send(struct netconn *conn, struct netbuf *buf)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_send: invalid conn",  (conn != NULL), return ERR_ARG;);

  if (conn->err != ERR_OK) {
    return conn->err;
  }

  LWIP_DEBUGF(API_LIB_DEBUG, ("netconn_send: sending %d bytes\n", buf->p->tot_len));
  msg.function = do_send;
  msg.msg.conn = conn;
  msg.msg.msg.b = buf;
  TCPIP_APIMSG(&msg);
  return conn->err;
}

/**
 * Send data over a TCP netconn.
 *
 * @param conn the TCP netconn over which to send data
 * @param dataptr pointer to the application buffer that contains the data to send
 * @param size size of the application data to send
 * @param copy flag: 1 = copy the data, 0 = data is non-volatile, can be sent by reference
 * @return ERR_OK if data was sent, any other err_t on error
 */
err_t
netconn_write(struct netconn *conn, const void *dataptr, int size, u8_t copy)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_write: invalid conn",  (conn != NULL), return ERR_ARG;);
  LWIP_ERROR("netconn_write: invalid conn->type",  (conn->type == NETCONN_TCP), return ERR_VAL;);

  if (conn->err != ERR_OK) {
    return conn->err;
  }

  msg.function = do_write;
  msg.msg.conn = conn;
  msg.msg.msg.w.dataptr = dataptr;
  msg.msg.msg.w.copy = copy;
  msg.msg.msg.w.len = size;
  /* For locking the core: this _can_ be delayed on low memory/low send buffer,
     but if it is, this is done inside api_msg.c:do_write(), so we can use the
     non-blocking version here. */
  TCPIP_APIMSG(&msg);

  return conn->err;
}

/**
 * Close a TCP netconn (doesn't delete it).
 *
 * @param conn the TCP netconn to close
 * @return ERR_OK if the netconn was closed, any other err_t on error
 */
err_t
netconn_close(struct netconn *conn)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_close: invalid conn",  (conn != NULL), return ERR_ARG;);

  msg.function = do_close;
  msg.msg.conn = conn;
  tcpip_apimsg(&msg);
  return conn->err;
}

#if LWIP_IGMP
/**
 * Join multicast groups for UDP netconns.
 *
 * @param conn the UDP netconn for which to change multicast addresses
 * @param multiaddr IP address of the multicast group to join or leave
 * @param interface the IP address of the network interface on which to send
 *                  the igmp message
 * @param join_or_leave flag whether to send a join- or leave-message
 * @return ERR_OK if the action was taken, any err_t on error
 */
err_t
netconn_join_leave_group(struct netconn *conn,
                         struct ip_addr *multiaddr,
                         struct ip_addr *interface,
                         enum netconn_igmp join_or_leave)
{
  struct api_msg msg;

  LWIP_ERROR("netconn_join_leave_group: invalid conn",  (conn != NULL), return ERR_ARG;);

  if (conn->err != ERR_OK) {
    return conn->err;
  }

  msg.function = do_join_leave_group;
  msg.msg.conn = conn;
  msg.msg.msg.jl.multiaddr = multiaddr;
  msg.msg.msg.jl.interface = interface;
  msg.msg.msg.jl.join_or_leave = join_or_leave;
  TCPIP_APIMSG(&msg);
  return conn->err;
}
#endif /* LWIP_IGMP */

#endif /* !NO_SYS */
