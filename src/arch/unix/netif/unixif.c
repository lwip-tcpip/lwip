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

#include "lwip/debug.h"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "lwip/stats.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "netif/unixif.h"
#include "lwip/sys.h"

#include "lwip/list.h"

#include "netif/tcpdump.h"

#define UNIXIF_BPS 512000
#define UNIXIF_QUEUELEN 6
/*#define UNIXIF_DROP_FIRST      */

struct unixif_buf {
  struct pbuf *p;
  unsigned short len, tot_len;
  void *payload;  
};

struct unixif {
  int fd;
  sys_sem_t sem;
  struct list *q;
};


/*-----------------------------------------------------------------------------------*/
static int
unix_socket_client(char *name)
{
  int fd, len;
  struct sockaddr_un unix_addr;

                                /* create a Unix domain stream socket */
  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("unixif: unix_socket_client: socket");
    return(-1);
  }
  
                                /* fill socket address structure w/our address */
  memset(&unix_addr, 0, sizeof(unix_addr));
  unix_addr.sun_family = AF_UNIX;
  sprintf(unix_addr.sun_path, "%s%05d", "/var/tmp/", getpid());
#ifndef linux
  len = sizeof(unix_addr.sun_len) + sizeof(unix_addr.sun_family) +
    strlen(unix_addr.sun_path) + 1;
  unix_addr.sun_len = len;
#else
  len = sizeof(unix_addr.sun_family) +
    strlen(unix_addr.sun_path) + 1;
#endif /* linux */
  
  unlink(unix_addr.sun_path);             /* in case it already exists */
  if(bind(fd, (struct sockaddr *) &unix_addr,
	   sizeof(struct sockaddr_un)) < 0) {
    perror("unixif: unix_socket_client: socket");
    return(-1);
  }
  if(chmod(unix_addr.sun_path, S_IRWXU | S_IRWXO) < 0) {
    perror("unixif: unix_socket_client: socket");
    return(-1);
  }
  
                                /* fill socket address structure w/server's addr */
  memset(&unix_addr, 0, sizeof(unix_addr));
  unix_addr.sun_family = AF_UNIX;
  strcpy(unix_addr.sun_path, name);
#ifndef linux
  len = sizeof(unix_addr.sun_len) + sizeof(unix_addr.sun_family) +
    strlen(unix_addr.sun_path) + 1;  
  unix_addr.sun_len = len;
#else
  len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path) + 1;    
#endif /* linux */
  if(connect(fd, (struct sockaddr *) &unix_addr,
	     sizeof(struct sockaddr_un)) < 0) {
    perror("unixif: unix_socket_client: socket");
    return(-1);
  }
  return(fd);
}

/*-----------------------------------------------------------------------------------*/
static int
unix_socket_server(char *name)
{
  int fd, len;
  struct sockaddr_un unix_addr;

  /* create a Unix domain stream socket */
  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("unixif: unix_socket_server: socket");
    return(-1);
  }
  
  unlink(name);   /* in case it already exists */
  
  /* fill in socket address structure */
  memset(&unix_addr, 0, sizeof(unix_addr));
  unix_addr.sun_family = AF_UNIX;
  strcpy(unix_addr.sun_path, name);
#ifndef linux
  len = sizeof(unix_addr.sun_len) + sizeof(unix_addr.sun_family) +
    strlen(unix_addr.sun_path) + 1;
  unix_addr.sun_len = len;
#else
  len = sizeof(unix_addr.sun_family) +
    strlen(unix_addr.sun_path) + 1;
#endif /* linux */
  
  /* bind the name to the descriptor */
  if(bind(fd, (struct sockaddr *) &unix_addr,
	   sizeof(struct sockaddr_un)) < 0) {
    perror("unixif: unix_socket_server: bind");
    return(-1);
  }

  if(chmod(unix_addr.sun_path, S_IRWXU | S_IRWXO) < 0) {
    perror("unixif: unix_socket_server: chmod");
    return(-1);
  }


  if(listen(fd, 5) < 0) {  /* tell kernel we're a server */
    perror("unixif: unix_socket_server: listen");
    return(-1);
  }
  
  return(fd);
}
/*-----------------------------------------------------------------------------------*/
static void
unixif_input_handler(void *data)
{
  struct netif *netif;
  struct unixif *unixif;
  char buf[4096], *bufptr;
  int len, plen, rlen;
  struct pbuf *p, *q;

  netif = data;
  unixif = netif->state;

  len = read(unixif->fd, &plen, sizeof(int));
  if(len == -1) {
    perror("unixif_irq_handler: read");
    abort();
  }

  DEBUGF(UNIXIF_DEBUG, ("unixif_irq_handler: len == %d plen == %d bytes\n", len, plen));  
  if(len == sizeof(int)) {

    if(plen < 20 || plen > 1500) {
      DEBUGF(UNIXIF_DEBUG, ("plen %d!\n", plen));
      return;
    }

    len = read(unixif->fd, buf, plen);
    if(len == -1) {
      perror("unixif_irq_handler: read");
      abort();
    }
    DEBUGF(UNIXIF_DEBUG, ("unixif_irq_handler: read %d bytes\n", len));
    p = pbuf_alloc(PBUF_LINK, len, PBUF_POOL);
    
    if(p != NULL) {
      rlen = len;
      bufptr = buf;
      q = p;
      while(rlen > 0) {
        bcopy(bufptr, q->payload, rlen > q->len? q->len: rlen);
        rlen -= q->len;
        bufptr += q->len;
        q = q->next;
      }
      pbuf_realloc(p, len);
#ifdef LINK_STATS
      stats.link.recv++;
#endif /* LINK_STATS */
      tcpdump(p);
      netif->input(p, netif);
    } else {
      DEBUGF(UNIXIF_DEBUG, ("unixif_irq_handler: could not allocate pbuf\n"));
    }
      

  }
}
/*-----------------------------------------------------------------------------------*/
static void 
unixif_thread(void *arg)
{
  struct netif *netif;
  struct unixif *unixif;
  
  DEBUGF(UNIXIF_DEBUG, ("unixif_thread: started.\n"));

  netif = arg;
  unixif = netif->state;


  while(1) {
    sys_sem_wait(unixif->sem);
    unixif_input_handler(netif);
  }
  
}
/*-----------------------------------------------------------------------------------*/
static void 
unixif_thread2(void *arg)
{
  struct netif *netif;
  struct unixif *unixif;
  fd_set fdset;
  
  DEBUGF(UNIXIF_DEBUG, ("unixif_thread2: started.\n"));

  netif = arg;
  unixif = netif->state;

  while(1) {
    FD_ZERO(&fdset);
    FD_SET(unixif->fd, &fdset);
  
    if(select(unixif->fd + 1, &fdset, NULL, NULL, NULL) > 0) {
      sys_sem_signal(unixif->sem);
    }
  }
}
/*-----------------------------------------------------------------------------------*/
static void unixif_output_timeout(void *arg);

static err_t
unixif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
  struct unixif *unixif;
  struct unixif_buf *buf;
  unixif = netif->state;

  buf = malloc(sizeof(struct unixif_buf));
  buf->p = p;
  buf->len = p->len;
  buf->tot_len = p->tot_len;
  buf->payload = p->payload;

  if(list_elems(unixif->q) == 0) {
    pbuf_ref(p);
    list_push(unixif->q, buf);
    sys_timeout((double)p->tot_len * 8000.0 / UNIXIF_BPS, unixif_output_timeout,
		netif);

    DEBUGF(UNIXIF_DEBUG, ("unixif_output: first on list\n"));
    
  } else {
    pbuf_ref(p);
    if(list_push(unixif->q, buf) == 0) {
#ifdef UNIXIF_DROP_FIRST
      struct unixif_buf *buf2;
      
      buf2 = list_pop(unixif->q);
      pbuf_free(buf2->p);
      free(buf2);
      list_push(unixif->q, buf);
#else
      free(buf);
      pbuf_free(p);
      
      DEBUGF(UNIXIF_DEBUG, ("unixif_output: drop\n"));
      
#endif /* UNIXIF_DROP_FIRST */
#ifdef LINK_STATS
      stats.link.drop++;
#endif /* LINK_STATS */

    } else {
      DEBUGF(UNIXIF_DEBUG, ("unixif_output: on list\n"));
    }

  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static void
unixif_output_timeout(void *arg)
{  
  struct pbuf *p, *q;  
  int i, j, len;
  unsigned short plen, ptot_len;
  struct unixif_buf *buf;
  void *payload;
  struct netif *netif;
  struct unixif *unixif;
  char *data;

  netif = arg;
  unixif = netif->state;

  DEBUGF(UNIXIF_DEBUG, ("unixif_output_timeout\n"));

  /*  buf = unixif->q[0];
  unixif->q[0] = unixif->q[1];
  unixif->q[1] = NULL;*/
  buf = list_pop(unixif->q);
  
  p = buf->p;

  plen = p->len;
  ptot_len = p->tot_len;
  payload = p->payload;
  
  p->len = buf->len;
  p->tot_len = buf->tot_len;
  p->payload = buf->payload;
  
  
  if(p->tot_len == 0) {

    DEBUGF(UNIXIF_DEBUG, ("p->len!\n"));
    abort();
  }
  data = malloc(p->tot_len);

  i = 0;
  for(q = p; q != NULL; q = q->next) {
    for(j = 0; j < q->len; j++) {
      data[i] = ((char *)q->payload)[j];
      i++;
    }
  }

  DEBUGF(UNIXIF_DEBUG, ("unixif_output: sending %d (%d) bytes\n",
			p->len, p->tot_len));
  
  len = p->tot_len;
  if(write(unixif->fd, &len, sizeof(int)) == -1) {
    perror("unixif_output: write");
    abort();
  }
    
  if(write(unixif->fd, data, p->tot_len) == -1) {
    perror("unixif_output: write");
    abort();
  }
  tcpdump(p);
#ifdef LINK_STATS
  stats.link.xmit++;
#endif /* LINK_STATS */

  free(data);
  free(buf);
  p->len = plen;
  p->tot_len = ptot_len;
  p->payload = payload;

  pbuf_free(p);
    
  /*  if(unixif->q[0] != NULL) {
    sys_timeout(unixif->q[0]->tot_len * 8000 / UNIXIF_BPS,
		unixif_output_timeout, netif);
		}*/
  if(list_elems(unixif->q) > 0) {
    sys_timeout(((struct unixif_buf *)list_first(unixif->q))->tot_len *
		8000.0 / UNIXIF_BPS,
		unixif_output_timeout, netif);
  }
}
/*-----------------------------------------------------------------------------------*/
void
unixif_init_server(struct netif *netif)
{
  int fd, fd2;
  struct sockaddr_un addr;
  socklen_t len;
  struct unixif *unixif;

  fd = unix_socket_server("/tmp/unixif");

  if(fd == -1) {
    perror("unixif_server");
    abort();
  }
  DEBUGF(UNIXIF_DEBUG, ("unixif_server: fd %d\n", fd));
    
  unixif = malloc(sizeof(struct unixif));
  netif->state = unixif;
  netif->name[0] = 'u';
  netif->name[1] = 'n';
  netif->output = unixif_output;
  unixif->q = list_new(UNIXIF_QUEUELEN);

  printf("Now run ./simnode.\n");
  len = sizeof(addr);
  fd2 = accept(fd, (struct sockaddr *)&addr, &len);
  
  if(fd2 == -1) {
    perror("unixif_accept");
    abort();
  } 

  DEBUGF(UNIXIF_DEBUG, ("unixif_accept: %d\n", fd2));

  unixif->fd = fd2;
  unixif->sem = sys_sem_new(0);
  sys_thread_new(unixif_thread, netif);
  sys_thread_new(unixif_thread2, netif);
}
/*-----------------------------------------------------------------------------------*/
void
unixif_init_client(struct netif *netif)
{
  struct unixif *unixif;
  unixif = malloc(sizeof(struct unixif));
  netif->state = unixif;
  netif->name[0] = 'u';
  netif->name[1] = 'n';
  netif->output = unixif_output;
  
  unixif->fd = unix_socket_client("/tmp/unixif");
  if(unixif->fd == -1) {
    perror("unixif_init");
    abort();
  }
  unixif->q = list_new(UNIXIF_QUEUELEN);
  unixif->sem = sys_sem_new(0);
  sys_thread_new(unixif_thread, netif);
  sys_thread_new(unixif_thread2, netif);
}
/*-----------------------------------------------------------------------------------*/


