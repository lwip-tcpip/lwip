/*
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
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

#include <string.h>
#include <stdio.h>

#include "lwip/mem.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/api.h"
#include "lwip/stats.h"

static unsigned char buffer[1024];

struct command {
  struct netconn *conn;
  s8_t (* exec)(struct command *);
  u8_t nargs;
  char *args[10];
};

/* Following #undefs are here to keep compiler from issuing warnings
   about them being double defined. (They are defined in lwip/inet.h
   as well as the Unix #includes below.) */
#undef htonl
#undef ntohl
#undef htons
#undef ntohs
#undef HTONL
#undef NTOHL
#undef HTONS
#undef NTOHS
#undef IP_HDRINCL

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <limits.h>

#define ESUCCESS 0
#define ESYNTAX -1
#define ETOOFEW -2
#define ETOOMANY -3
#define ECLOSED -4

#define NCONNS 10
static struct netconn *conns[NCONNS];

static char help_msg[] = "Avaliable commands:\n\
open [IP address] [TCP port]: opens a TCP connection to the specified address.\n\
lstn [TCP port]: sets up a server on the specified port.\n\
acpt [connection #]: waits for an incoming connection request.\n\
send [connection #] [message]: sends a message on a TCP connection.\n\
udpc [local UDP port] [IP address] [remote port]: opens a UDP \"connection\".\n\
udpl [local UDP port] [IP address] [remote port]: opens a UDP-Lite \"connection\".\n\
udpn [local UDP port] [IP address] [remote port]: opens a UDP \"connection\" without checksums.\n\
udpb [local port] [remote port]: opens a UDP broadcast \"connection\".\n\
usnd [connection #] [message]: sends a message on a UDP connection.\n\
recv [connection #]: recieves data on a TCP or UDP connection.\n\
clos [connection #]: closes a TCP or UDP connection.\n\
stat: prints out lwIP statistics.\n\
quit: quits.\n";

static char *stat_msgs[] = {
  "Link level * transmitted ",
  "             retransmitted ",
  "           * received ",
  "             forwarded ",
  "           * dropped ",
  "           * checksum errors ",
  "           * length errors ",
  "           * memory errors ",
  "             routing errors ",
  "             protocol errors ",
  "             option errors ",
  "           * misc errors ",
  "             cache hits ",  
  "IP         * transmitted ",
  "             retransmitted ",
  "           * received ",
  "           * forwarded ",
  "           * dropped ",
  "           * checksum errors ",
  "           * length errors ",
  "           * memory errors ",
  "           * routing errors ",
  "           * protocol errors ",
  "           * option errors ",
  "           * misc errors ",
  "             cache hits ",
  "ICMP       * transmitted ",
  "             retransmitted ",
  "           * received ",
  "             forwarded ",
  "           * dropped ",
  "           * checksum errors ",
  "             length errors ",
  "           * memory errors ",
  "             routing errors ",
  "           * protocol errors ",
  "             option errors ",
  "           * misc errors ",
  "             cache hits ",  
  "UDP        * transmitted ",
  "             retransmitted ",
  "           * received ",
  "             forwarded ",
  "           * dropped ",
  "           * checksum errors ",
  "           * length errors ",
  "           * memory errors ",
  "           * routing errors ",
  "           * protocol errors ",
  "             option errors ",
  "           * misc errors ",
  "             cache hits ",  
  "TCP        * transmitted ",
  "           * retransmitted ",
  "           * received ",
  "             forwarded ",
  "           * dropped ",
  "           * checksum errors ",
  "           * length errors ",
  "           * memory errors ",
  "           * routing errors ",
  "           * protocol errors ",
  "           * option errors ",
  "           * misc errors ",
  "           * cache hits ",  
  "Pbufs      * avaiable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "             reclaimed ",
  "             pbuf_alloc() locked ",
  "             pbuf_refresh() locked ",
  "Memory     * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "Memp PBUF  * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "UDP PCB    * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "TCP PCB    * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "TCP LISTEN * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "TCP SEG    * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "Netbufs    * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "Netconns   * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "API msgs   * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "TCPIP msgs * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "Timeouts   * avaliable ",
  "           * used ",
  "           * high water mark ",
  "           * errors ",
  "           * reclaimed ",
  "Semaphores * used ",
  "           * high water mark ",
  "           * errors ",
  "Mailboxes  * used ",
  "           * high water mark ",
  "           * errors "
};
/*-----------------------------------------------------------------------------------*/
static void
sendstr(const char *str, struct netconn *conn)
{
  netconn_write(conn, (void *)str, strlen(str), NETCONN_NOCOPY);
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_open(struct command *com)
{
  struct ip_addr ipaddr;
  u16_t port;
  int i;
  err_t err;

  if(inet_aton(com->args[0], (struct in_addr *)&ipaddr) == -1) {
    sendstr(strerror(errno), com->conn);
    return ESYNTAX;
  }
  port = strtol(com->args[1], NULL, 10);

  /* Find the first unused connection in conns. */
  for(i = 0; i < NCONNS && conns[i] != NULL; i++);

  if(i == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Opening connection to ", com->conn);
  netconn_write(com->conn, com->args[0], strlen(com->args[0]), NETCONN_COPY);
  sendstr(":", com->conn);
  netconn_write(com->conn, com->args[1], strlen(com->args[1]), NETCONN_COPY);
  sendstr("\n", com->conn);

  conns[i] = netconn_new(NETCONN_TCP);
  if(conns[i] == NULL) {    
    sendstr("Could not create connection identifier (out of memory).\n", com->conn); 
    return ESUCCESS;
  }
  err = netconn_connect(conns[i], &ipaddr, port);
  if(err != ERR_OK) {
    fprintf(stderr, "error %s\n", lwip_strerr(err));
    sendstr("Could not connect to remote host: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    netconn_delete(conns[i]);
    conns[i] = NULL;
    return ESUCCESS;
  }

  sendstr("Opened connection, connection identifier is ", com->conn);
  sprintf((char *)buffer, "%d\n", i);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);
  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_lstn(struct command *com)
{
  u16_t port;
  int i;
  err_t err;

  port = strtol(com->args[0], NULL, 10);

  /* Find the first unused connection in conns. */
  for(i = 0; i < NCONNS && conns[i] != NULL; i++);

  if(i == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Opening a listening connection on port ", com->conn);
  netconn_write(com->conn, com->args[0], strlen(com->args[0]), NETCONN_COPY);
  sendstr("\n", com->conn);

  conns[i] = netconn_new(NETCONN_TCP);
  if(conns[i] == NULL) {    
    sendstr("Could not create connection identifier (out of memory).\n", com->conn); 
    return ESUCCESS;
  }
  
  err = netconn_bind(conns[i], IP_ADDR_ANY, port);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not bind: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }
  
  err = netconn_listen(conns[i]);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not listen: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Opened connection, connection identifier is ", com->conn);
  sprintf((char *)buffer, "%d\n", i);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);
  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------*/
static s8_t
com_clos(struct command *com)
{
  int i;
  err_t err;
  
  i = strtol(com->args[0], NULL, 10);

  if(i > NCONNS) {
    sendstr("Connection identifier too high.\n", com->conn);
    return ESUCCESS;
  }
  if(conns[i] == NULL) {
    sendstr("Connection identifier not in use.\n", com->conn);
    return ESUCCESS;
  }

  err = netconn_close(conns[i]);
  if(err != ERR_OK) {
    sendstr("Could not close connection: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Connection closed.\n", com->conn);
  netconn_delete(conns[i]);
  conns[i] = NULL;
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_acpt(struct command *com)
{
  int i, j;

  /* Find the first unused connection in conns. */
  for(j = 0; j < NCONNS && conns[j] != NULL; j++);

  if(j == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  i = strtol(com->args[0], NULL, 10);

  if(i > NCONNS) {
    sendstr("Connection identifier too high.\n", com->conn);
    return ESUCCESS;
  }
  if(conns[i] == NULL) {
    sendstr("Connection identifier not in use.\n", com->conn);
    return ESUCCESS;
  }

  conns[j] = netconn_accept(conns[i]);
  
  if(conns[j] == NULL) {
    sendstr("Could not accept connection: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(netconn_err(conns[i])), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Accepted connection, connection identifier for new connection is ", com->conn);
  sprintf((char *)buffer, "%d\n", j);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);

  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_stat(struct command *com)
{
  int i;
  char buf[100];
  u16_t len;
  
  for(i = 0; i < sizeof(struct stats_) / 2; i++) {
    len = sprintf(buf, "%d", ((u16_t *)&stats)[i]);
    sendstr(stat_msgs[i], com->conn);
    netconn_write(com->conn, buf, len, NETCONN_COPY);
    sendstr("\n", com->conn);
  }

  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_send(struct command *com)
{
  int i;
  err_t err;
  int len;
  
  i = strtol(com->args[0], NULL, 10);

  if(i > NCONNS) {
    sendstr("Connection identifier too high.\n", com->conn);
    return ESUCCESS;
  }

  if(conns[i] == NULL) {
    sendstr("Connection identifier not in use.\n", com->conn);
    return ESUCCESS;
  }

  len = strlen(com->args[1]);
  com->args[1][len] = '\r';
  com->args[1][len + 1] = '\n';
  com->args[1][len + 2] = 0;
  
  err = netconn_write(conns[i], com->args[1], len + 3, NETCONN_COPY);
  if(err != ERR_OK) {
    sendstr("Could not send data: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }
  
  sendstr("Data enqueued for sending.\n", com->conn);
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_recv(struct command *com)
{
  int i;
  err_t err;
  struct netbuf *buf;
  u16_t len;
  
  i = strtol(com->args[0], NULL, 10);

  if(i > NCONNS) {
    sendstr("Connection identifier too high.\n", com->conn);
    return ESUCCESS;
  }

  if(conns[i] == NULL) {
    sendstr("Connection identifier not in use.\n", com->conn);
    return ESUCCESS;
  }

  buf = netconn_recv(conns[i]);
  if(buf != NULL) {
      
    netbuf_copy(buf, buffer, 1024);
    len = netbuf_len(buf);
    sendstr("Reading from connection:\n", com->conn);
    netconn_write(com->conn, buffer, len, NETCONN_COPY);
    netbuf_delete(buf);
  } else {
    sendstr("EOF.\n", com->conn); 
  }
  err = netconn_err(conns[i]);
  if(err != ERR_OK) {
    sendstr("Could not receive data: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_udpc(struct command *com)
{
  struct ip_addr ipaddr;
  u16_t lport, rport;
  int i;
  err_t err;

  lport = strtol(com->args[0], NULL, 10);
  if(inet_aton(com->args[1], (struct in_addr *)&ipaddr) == -1) {
    sendstr(strerror(errno), com->conn);
    return ESYNTAX;
  }
  rport = strtol(com->args[2], NULL, 10);

  /* Find the first unused connection in conns. */
  for(i = 0; i < NCONNS && conns[i] != NULL; i++);

  if(i == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Setting up UDP connection from port ", com->conn);
  netconn_write(com->conn, com->args[0], strlen(com->args[0]), NETCONN_COPY);
  sendstr(" to ", com->conn);
  netconn_write(com->conn, com->args[1], strlen(com->args[1]), NETCONN_COPY);
  sendstr(":", com->conn);
  netconn_write(com->conn, com->args[2], strlen(com->args[2]), NETCONN_COPY);
  sendstr("\n", com->conn);

  conns[i] = netconn_new(NETCONN_UDP);
  if(conns[i] == NULL) {    
    sendstr("Could not create connection identifier (out of memory).\n", com->conn); 
    return ESUCCESS;
  }

  err = netconn_connect(conns[i], &ipaddr, rport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not connect to remote host: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  err = netconn_bind(conns[i], IP_ADDR_ANY, lport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not bind: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Connection set up, connection identifier is ", com->conn);
  sprintf((char *)buffer, "%d\n", i);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);
  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_udpl(struct command *com)
{
  struct ip_addr ipaddr;
  u16_t lport, rport;
  int i;
  err_t err;

  lport = strtol(com->args[0], NULL, 10);
  if(inet_aton(com->args[1], (struct in_addr *)&ipaddr) == -1) {
    sendstr(strerror(errno), com->conn);
    return ESYNTAX;
  }
  rport = strtol(com->args[2], NULL, 10);

  /* Find the first unused connection in conns. */
  for(i = 0; i < NCONNS && conns[i] != NULL; i++);

  if(i == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Setting up UDP-Lite connection from port ", com->conn);
  netconn_write(com->conn, com->args[0], strlen(com->args[0]), NETCONN_COPY);
  sendstr(" to ", com->conn);
  netconn_write(com->conn, com->args[1], strlen(com->args[1]), NETCONN_COPY);
  sendstr(":", com->conn);
  netconn_write(com->conn, com->args[2], strlen(com->args[2]), NETCONN_COPY);
  sendstr("\n", com->conn);

  conns[i] = netconn_new(NETCONN_UDPLITE);
  if(conns[i] == NULL) {    
    sendstr("Could not create connection identifier (out of memory).\n", com->conn); 
    return ESUCCESS;
  }

  err = netconn_connect(conns[i], &ipaddr, rport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not connect to remote host: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  err = netconn_bind(conns[i], IP_ADDR_ANY, lport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not bind: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Connection set up, connection identifier is ", com->conn);
  sprintf((char *)buffer, "%d\n", i);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);
  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_udpn(struct command *com)
{
  struct ip_addr ipaddr;
  u16_t lport, rport;
  int i;
  err_t err;

  lport = strtol(com->args[0], NULL, 10);
  if(inet_aton(com->args[1], (struct in_addr *)&ipaddr) == -1) {
    sendstr(strerror(errno), com->conn);
    return ESYNTAX;
  }
  rport = strtol(com->args[2], NULL, 10);

  /* Find the first unused connection in conns. */
  for(i = 0; i < NCONNS && conns[i] != NULL; i++);

  if(i == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Setting up UDP connection without checksums from port ", com->conn);
  netconn_write(com->conn, com->args[0], strlen(com->args[0]), NETCONN_COPY);
  sendstr(" to ", com->conn);
  netconn_write(com->conn, com->args[1], strlen(com->args[1]), NETCONN_COPY);
  sendstr(":", com->conn);
  netconn_write(com->conn, com->args[2], strlen(com->args[2]), NETCONN_COPY);
  sendstr("\n", com->conn);

  conns[i] = netconn_new(NETCONN_UDPNOCHKSUM);
  if(conns[i] == NULL) {    
    sendstr("Could not create connection identifier (out of memory).\n", com->conn); 
    return ESUCCESS;
  }

  err = netconn_connect(conns[i], &ipaddr, rport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not connect to remote host: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  err = netconn_bind(conns[i], IP_ADDR_ANY, lport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not bind: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Connection set up, connection identifier is ", com->conn);
  sprintf((char *)buffer, "%d\n", i);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);
  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_udpb(struct command *com)
{
  struct ip_addr ipaddr;
  u16_t lport, rport;
  int i;
  err_t err;
  struct ip_addr bcaddr;

  lport = strtol(com->args[0], NULL, 10);
  if(inet_aton(com->args[1], (struct in_addr *)&ipaddr) == -1) {
    sendstr(strerror(errno), com->conn);
    return ESYNTAX;
  }
  rport = strtol(com->args[2], NULL, 10);

  /* Find the first unused connection in conns. */
  for(i = 0; i < NCONNS && conns[i] != NULL; i++);

  if(i == NCONNS) {
    sendstr("No more connections avaliable, sorry.\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Setting up UDP broadcast connection from port ", com->conn);
  netconn_write(com->conn, com->args[0], strlen(com->args[0]), NETCONN_COPY);
  sendstr(" to ", com->conn);
  netconn_write(com->conn, com->args[1], strlen(com->args[1]), NETCONN_COPY);
  sendstr("\n", com->conn);

  conns[i] = netconn_new(NETCONN_UDP);
  if(conns[i] == NULL) {    
    sendstr("Could not create connection identifier (out of memory).\n", com->conn); 
    return ESUCCESS;
  }

  err = netconn_connect(conns[i], &ipaddr, rport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not connect to remote host: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  IP4_ADDR(&bcaddr, 255,255,255,255);
  err = netconn_bind(conns[i], &bcaddr, lport);
  if(err != ERR_OK) {
    netconn_delete(conns[i]);
    conns[i] = NULL;
    sendstr("Could not bind: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }

  sendstr("Connection set up, connection identifier is ", com->conn);
  sprintf((char *)buffer, "%d\n", i);
  netconn_write(com->conn, buffer, strlen((const char *)buffer), NETCONN_COPY);
  
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_usnd(struct command *com)
{
  int i;
  err_t err;
  struct netbuf *buf;
  char *mem;
  
  i = strtol(com->args[0], NULL, 10);

  if(i > NCONNS) {
    sendstr("Connection identifier too high.\n", com->conn);
    return ESUCCESS;
  }

  if(conns[i] == NULL) {
    sendstr("Connection identifier not in use.\n", com->conn);
    return ESUCCESS;
  }

  buf = netbuf_new();
  mem = netbuf_alloc(buf, strlen(com->args[1]) + 1);
  if(mem == NULL) {
    sendstr("Could not allocate memory for sending.\n", com->conn);
    return ESUCCESS;
  }
  strncpy(mem, com->args[1], strlen(com->args[1]) + 1);
  err = netconn_send(conns[i], buf);
  netbuf_delete(buf);
  if(err != ERR_OK) {
    sendstr("Could not send data: ", com->conn);
#ifdef LWIP_DEBUG
    sendstr(lwip_strerr(err), com->conn);
#else
    sendstr("(debugging must be turned on for error message to appear)", com->conn);
#endif /* LWIP_DEBUG */
    sendstr("\n", com->conn);
    return ESUCCESS;
  }
  
  sendstr("Data sent.\n", com->conn);
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
com_help(struct command *com)
{
  sendstr(help_msg, com->conn);
  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static s8_t
parse_command(struct command *com, u32_t len)
{
  u16_t i;
  u16_t bufp;
  
  if(strncmp((const char *)buffer, "open", 4) == 0) {
    com->exec = com_open;
    com->nargs = 2;
  } else if(strncmp((const char *)buffer, "lstn", 4) == 0) {
    com->exec = com_lstn;
    com->nargs = 1;
  } else if(strncmp((const char *)buffer, "acpt", 4) == 0) {
    com->exec = com_acpt;
    com->nargs = 1;
  } else if(strncmp((const char *)buffer, "clos", 4) == 0) {
    com->exec = com_clos;
    com->nargs = 1;
  } else if(strncmp((const char *)buffer, "stat", 4) == 0) {
    com->exec = com_stat;
    com->nargs = 0;
  } else if(strncmp((const char *)buffer, "send", 4) == 0) {
    com->exec = com_send;
    com->nargs = 2;
  } else if(strncmp((const char *)buffer, "recv", 4) == 0) {
    com->exec = com_recv;
    com->nargs = 1;
  } else if(strncmp((const char *)buffer, "udpc", 4) == 0) {
    com->exec = com_udpc;
    com->nargs = 3;
  } else if(strncmp((const char *)buffer, "udpb", 4) == 0) {
    com->exec = com_udpb;
    com->nargs = 2;
  } else if(strncmp((const char *)buffer, "udpl", 4) == 0) {
    com->exec = com_udpl;
    com->nargs = 3;
  } else if(strncmp((const char *)buffer, "udpn", 4) == 0) {
    com->exec = com_udpn;
    com->nargs = 3;
  } else if(strncmp((const char *)buffer, "usnd", 4) == 0) {
    com->exec = com_usnd;
    com->nargs = 2;
  } else if(strncmp((const char *)buffer, "help", 4) == 0) {
    com->exec = com_help;
    com->nargs = 0;
  } else if(strncmp((const char *)buffer, "quit", 4) == 0) {
    printf("quit\n");
    return ECLOSED;
  } else {
    return ESYNTAX;
  }

  if(com->nargs == 0) {
    return ESUCCESS;
  }
  bufp = 0;
  for(; bufp < len && buffer[bufp] != ' '; bufp++);
  for(i = 0; i < 10; i++) {
    for(; bufp < len && buffer[bufp] == ' '; bufp++);
    if(buffer[bufp] == '\r' ||
       buffer[bufp] == '\n') {
      buffer[bufp] = 0;
      if(i < com->nargs - 1) {
	return ETOOFEW;
      }
      if(i > com->nargs - 1) {
	return ETOOMANY;
      }
      break;
    }    
    if(bufp > len) {
      return ETOOFEW;
    }    
    com->args[i] = (char *)&buffer[bufp];
    for(; bufp < len && buffer[bufp] != ' ' && buffer[bufp] != '\r' &&
	  buffer[bufp] != '\n'; bufp++) {
      if(buffer[bufp] == '\\') {
	buffer[bufp] = ' ';
      }
    }
    if(bufp > len) {
      return ESYNTAX;
    }
    buffer[bufp] = 0;
    bufp++;
    if(i == com->nargs - 1) {
      break;
    }

  }

  return ESUCCESS;
}
/*-----------------------------------------------------------------------------------*/
static void
error(s8_t err, struct netconn *conn)
{
  switch(err) {
  case ESYNTAX:
    sendstr("## Syntax error\n", conn);
    break;
  case ETOOFEW:
    sendstr("## Too few arguments to command given\n", conn);
    break;
  case ETOOMANY:
    sendstr("## Too many arguments to command given\n", conn);
    break;
  }
}
/*-----------------------------------------------------------------------------------*/
static void
prompt(struct netconn *conn)
{
  sendstr("> ", conn);
}  
/*-----------------------------------------------------------------------------------*/
static void
shell_main(struct netconn *conn)
{
  struct netbuf *buf;
  u32_t len;
  struct command com;
  s8_t err;
  int i;
  
  do {
    buf = netconn_recv(conn);
    if(buf != NULL) {
      netbuf_copy(buf, buffer, 1024);
      len = netbuf_len(buf);
      netbuf_delete(buf);
      if(len >= 4) {
	if(buffer[0] != 0xff && 
	   buffer[1] != 0xfe) {
	  err = parse_command(&com, len);
	  if(err == ESUCCESS) {	
	    com.conn = conn;
	    err = com.exec(&com);
	  }
	  if(err != ESUCCESS) {
	    error(err, conn);
	  }
	  if(err == ECLOSED) {
	    printf("Closed\n");
	    error(err, conn);
	    goto close;
	  }
	} else {
	  sendstr("\n\n"
	          "lwIP simple interactive shell.\n"
	          "(c) Copyright 2001, Swedish Institute of Computer Science.\n"
	          "Written by Adam Dunkels.\n"
	          "For help, try the \"help\" command.\n", conn);
	}
      }
    }
    if(buf != NULL) {
      prompt(conn);
    }
  } while(buf != NULL);
  printf("buf == NULL err %s\n", lwip_strerr(conn->err));
 close:  
  netconn_close(conn);
  
  for(i = 0; i < NCONNS; i++) {
    if(conns[i] != NULL) {
      netconn_delete(conns[i]);
    }
    conns[i] = NULL;
  }
  
}
/*-----------------------------------------------------------------------------------*/
static void 
shell_thread(void *arg)
{
  struct netconn *conn, *newconn;
  
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, NULL, 23);
  netconn_listen(conn);

  while(1) {
    newconn = netconn_accept(conn);
    shell_main(newconn);
    netconn_delete(newconn);
  }
}
/*-----------------------------------------------------------------------------------*/
void
shell_init(void)     
{
  sys_thread_new(shell_thread, NULL);
}




