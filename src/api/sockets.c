/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
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

#include "lwip/debug.h"
#include "lwip/api.h"

#include "lwip/sockets.h"

#define NUM_SOCKETS 10

struct lwip_socket {
  struct netconn *conn;
  struct netbuf *lastdata;
  u16_t lastoffset;
};

static struct lwip_socket sockets[NUM_SOCKETS];

/*-----------------------------------------------------------------------------------*/
static struct lwip_socket *
get_socket(int s)
{
  struct lwip_socket *sock;
  
  if(s > NUM_SOCKETS) {
    /* errno = EBADF; */
    return NULL;
  }
  
  sock = &sockets[s];

  if(sock->conn == NULL) {
    /* errno = EBADF; */
    return NULL;
  }
  return sock;
}
/*-----------------------------------------------------------------------------------*/
static int
alloc_socket(struct netconn *newconn)
{
  int i;
  
  /* allocate a new socket identifier */
  for(i = 0; i < NUM_SOCKETS; ++i) {
    if(sockets[i].conn == NULL) {
      sockets[i].conn = newconn;
      sockets[i].lastdata = NULL;
      sockets[i].lastoffset = 0;
      return i;
    }
  }
  return -1;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_accept(int s, struct sockaddr *addr, int *addrlen)
{
  struct lwip_socket *sock;
  struct netconn *newconn;
  struct ip_addr *naddr;
  u16_t port;
  int newsock;

  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }
  
  newconn = netconn_accept(sock->conn);
    
  /* get the IP address and port of the remote host */
  netconn_peer(newconn, &naddr, &port);
  
  ((struct sockaddr_in *)addr)->sin_addr.s_addr = naddr->addr;
  ((struct sockaddr_in *)addr)->sin_port = port;

  newsock = alloc_socket(newconn);
  if(newsock == -1) {  
    netconn_delete(newconn);
    /* errno = ENOBUFS; */
  }
  return newsock;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_bind(int s, struct sockaddr *name, int namelen)
{
  struct lwip_socket *sock;
  struct ip_addr remote_addr;
  u16_t remote_port;
  err_t err;
  
  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }
  
  remote_addr.addr = ((struct sockaddr_in *)name)->sin_addr.s_addr;
  remote_port = ((struct sockaddr_in *)name)->sin_port;
  
  err = netconn_bind(sock->conn, &remote_addr, ntohs(remote_port));

  if(err != ERR_OK) {
    /* errno = ... */
    return -1;
  }

  return 0;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_close(int s)
{
  struct lwip_socket *sock;
  
  DEBUGF(SOCKETS_DEBUG, ("close: socket %d\n", s));
  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }
  
  
  netconn_delete(sock->conn);
  if(sock->lastdata != NULL) {
    netbuf_delete(sock->lastdata);
  }
  sock->lastdata = NULL;
  sock->lastoffset = 0;
  sock->conn = NULL;
  return 0;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_connect(int s, struct sockaddr *name, int namelen)
{
  struct lwip_socket *sock;
  struct ip_addr remote_addr;
  u16_t remote_port;
  err_t err;

  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }
  
  remote_addr.addr = ((struct sockaddr_in *)name)->sin_addr.s_addr;
  remote_port = ((struct sockaddr_in *)name)->sin_port;
  
  err = netconn_connect(sock->conn, &remote_addr, ntohs(remote_port));

  if(err != ERR_OK) {
    /* errno = ... */
    return -1;
  }

  return 0;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_listen(int s, int backlog)
{
  struct lwip_socket *sock;    
  err_t err;
  
  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }
 
  err = netconn_listen(sock->conn);

  if(err != ERR_OK) {
    /* errno = ... */
    return -1;
  }

  return 0;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_recvfrom(int s, void *mem, int len, unsigned int flags,
	      struct sockaddr *from, int *fromlen)
{
  struct lwip_socket *sock;
  struct netbuf *buf;
  u16_t buflen, copylen;
  struct ip_addr *addr;
  u16_t port;

  
  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }

  /* Check if there is data left from the last recv operation. */
  if(sock->lastdata != NULL) {    
    buf = sock->lastdata;
  } else {
    /* No data was left from the previous operation, so we try to get
       some from the network. */
    buf = netconn_recv(sock->conn);
    
    if(buf == NULL) {
      /* We should really do some error checking here. */
      return 0;
    }
  }
  
  buflen = netbuf_len(buf);

  buflen -= sock->lastoffset;
  
  if(len > buflen) {
    copylen = buflen;
  } else {
    copylen = len;
  }
  
  /* copy the contents of the received buffer into
     the supplied memory pointer mem */
  netbuf_copy_partial(buf, mem, copylen, sock->lastoffset);

  /* If this is a TCP socket, check if there is data left in the
     buffer. If so, it should be saved in the sock structure for next
     time around. */
  if(netconn_type(sock->conn) == NETCONN_TCP && buflen - copylen > 0) {
    sock->lastdata = buf;
    sock->lastoffset += copylen;
  } else {
    sock->lastdata = NULL;
    sock->lastoffset = 0;
    netbuf_delete(buf);
  }

  /* Check to see from where the data was. */
  if(from != NULL && fromlen != NULL) {
    addr = netbuf_fromaddr(buf);
    port = netbuf_fromport(buf);  
    ((struct sockaddr_in *)from)->sin_addr.s_addr = addr->addr;
    ((struct sockaddr_in *)from)->sin_port = port;
    *fromlen = sizeof(struct sockaddr_in);
  }
  
  return copylen;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_read(int s, void *mem, int len)
{
  return lwip_recv(s, mem, len, 0);
}
/*-----------------------------------------------------------------------------------*/
int
lwip_recv(int s, void *mem, int len, unsigned int flags)
{
  return lwip_recvfrom(s, mem, len, flags, NULL, NULL);
}
/*-----------------------------------------------------------------------------------*/
int
lwip_send(int s, void *data, int size, unsigned int flags)
{
  struct lwip_socket *sock;
  struct netbuf *buf;
  err_t err;

  DEBUGF(SOCKETS_DEBUG, ("send: socket %d, size %d\n", s, size));

  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }  
  
  switch(netconn_type(sock->conn)) {
  case NETCONN_UDP:
    /* create a buffer */
    buf = netbuf_new();

    if(buf == NULL) {
      /* errno = ENOBUFS; */
      return -1;
    }
    
    /* make the buffer point to the data that should
       be sent */
    netbuf_ref(buf, data, size);

    /* send the data */
    err = netconn_send(sock->conn, buf);

    /* deallocated the buffer */
    netbuf_delete(buf);
    break;
  case NETCONN_TCP:
    err = netconn_write(sock->conn, data, size, NETCONN_COPY);
    break;
  default:
    err = ERR_ARG;
    break;
  }
  if(err != ERR_OK) {
    /* errno = ... */
    return -1;    
  }
    
  return size;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_sendto(int s, void *data, int size, unsigned int flags,
       struct sockaddr *to, int tolen)
{
  struct lwip_socket *sock;
  struct ip_addr remote_addr, *addr;
  u16_t remote_port, port;
  int ret;

  sock = get_socket(s);
  if(sock == NULL) {
    return -1;
  }
  
  /* get the peer if currently connected */
  netconn_peer(sock->conn, &addr, &port);
  
  remote_addr.addr = ((struct sockaddr_in *)to)->sin_addr.s_addr;
  remote_port = ((struct sockaddr_in *)to)->sin_port;
  netconn_connect(sock->conn, &remote_addr, remote_port);
  
  ret = lwip_send(s, data, size, flags);

  /* reset the remote address and port number
     of the connection */
  netconn_connect(sock->conn, addr, port);
  return ret;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_socket(int domain, int type, int protocol)
{
  struct netconn *conn;
  int i;

  /* create a netconn */
  switch(type) {
  case SOCK_DGRAM:
    conn = netconn_new(NETCONN_UDP);
    break;
  case SOCK_STREAM:
    conn = netconn_new(NETCONN_TCP);
    break;
  default:
    /* errno = ... */
    return -1;
  }

  if(conn == NULL) {
    DEBUGF(SOCKETS_DEBUG, ("socket: could not create netconn.\n"));
    /* errno = ENOBUFS; */
    return -1;
  }

  i = alloc_socket(conn);

  if(i == -1) {
    /* errno = ENOBUFS; */
    netconn_delete(conn);
  }
  return i;
}
/*-----------------------------------------------------------------------------------*/
int
lwip_write(int s, void *data, int size)
{
   return lwip_send(s, data, size, 0);
}
/*-----------------------------------------------------------------------------------*/
