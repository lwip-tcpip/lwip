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

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>


#include "lwip/debug.h"

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

#include "netif/etharp.h"

#ifdef linux
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#define DEVTAP "/dev/net/tun"
#else  /* linux */
#define DEVTAP "/dev/tap0"
#endif /* linux */

#define IFNAME0 't'
#define IFNAME1 'p'

static const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}};

struct tapif {
  struct eth_addr *ethaddr;
  /* Add whatever per-interface state that is needed here. */
  int fd;
};

/* Forward declarations. */
static void  tapif_input(struct netif *netif);
static err_t tapif_output(struct netif *netif, struct pbuf *p,
			       struct ip_addr *ipaddr);

static void tapif_thread(void *data);

/*-----------------------------------------------------------------------------------*/
static void
low_level_init(struct netif *netif)
{
  struct tapif *tapif;
  char buf[100];

  tapif = netif->state;
  
  /* Obtain MAC address from network interface. */

  /* (We just fake an address...) */
  tapif->ethaddr->addr[0] = 0x1;
  tapif->ethaddr->addr[1] = 0x2;
  tapif->ethaddr->addr[2] = 0x3;
  tapif->ethaddr->addr[3] = 0x4;
  tapif->ethaddr->addr[4] = 0x5;
  tapif->ethaddr->addr[5] = 0x6;

  /* Do whatever else is needed to initialize interface. */
  
  tapif->fd = open(DEVTAP, O_RDWR);
  DEBUGF(TAPIF_DEBUG, ("tapif_init: fd %d\n", tapif->fd));
  if(tapif->fd == -1) {
    perror("tapif_init");
    exit(1);
  }

#ifdef linux
  {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (ioctl(tapif->fd, TUNSETIFF, (void *) &ifr) < 0) {
      perror(buf);
      exit(1);
    }
  }
#endif /* Linux */

  snprintf(buf, sizeof(buf), "ifconfig tap0 inet %d.%d.%d.%d",
           ip4_addr1(&(netif->gw)),
           ip4_addr2(&(netif->gw)),
           ip4_addr3(&(netif->gw)),
           ip4_addr4(&(netif->gw)));
  
  DEBUGF(TAPIF_DEBUG, ("tapif_init: system(\"%s\");\n", buf));
  system(buf);
  sys_thread_new(tapif_thread, netif);

}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct pbuf *q;
  char buf[1500];
  char *bufptr;
  struct tapif *tapif;

  tapif = netif->state;
  
  /* initiate transfer(); */
  
  bufptr = &buf[0];
  
  for(q = p; q != NULL; q = q->next) {
    /* Send the data from the pbuf to the interface, one pbuf at a
       time. The size of the data in each pbuf is kept in the ->len
       variable. */    
    /* send data from(q->payload, q->len); */
    bcopy(q->payload, bufptr, q->len);
    bufptr += q->len;
  }

  /* signal that packet should be sent(); */
  if(write(tapif->fd, buf, p->tot_len) == -1) {
    perror("tapif: write");
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
low_level_input(struct tapif *tapif)
{
  struct pbuf *p, *q;
  u16_t len;
  char buf[1500];
  char *bufptr;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  len = read(tapif->fd, buf, sizeof(buf));

  /*  if(((double)rand()/(double)RAND_MAX) < 0.1) {
    printf("drop\n");
    return NULL;
    }*/

  
  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_LINK, len, PBUF_POOL);
  
  if(p != NULL) {
    /* We iterate over the pbuf chain until we have read the entire
       packet into the pbuf. */
    bufptr = &buf[0];
    for(q = p; q != NULL; q = q->next) {
      /* Read enough bytes to fill this pbuf in the chain. The
         avaliable data in the pbuf is given by the q->len
         variable. */
      /* read data into(q->payload, q->len); */
      bcopy(bufptr, q->payload, q->len);
      bufptr += q->len;
    }
    /* acknowledge that packet has been read(); */
  } else {
    /* drop packet(); */
  }

  return p;  
}
/*-----------------------------------------------------------------------------------*/
static void 
tapif_thread(void *arg)
{
  struct netif *netif;
  struct tapif *tapif;
  fd_set fdset;
  int ret;
  
  netif = arg;
  tapif = netif->state;
  
  while(1) {
    FD_ZERO(&fdset);
    FD_SET(tapif->fd, &fdset);

    /* Wait for a packet to arrive. */
    ret = select(tapif->fd + 1, &fdset, NULL, NULL, NULL);

    if(ret == 1) {
      /* Handle incoming packet. */
      tapif_input(netif);
    } else if(ret == -1) {
      perror("tapif_thread: select");
    }
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * tapif_output():
 *
 * This function is called by the TCP/IP stack when an IP packet
 * should be sent. It calls the function called low_level_output() to
 * do the actuall transmission of the packet.
 *
 */
/*-----------------------------------------------------------------------------------*/
static err_t
tapif_output(struct netif *netif, struct pbuf *p,
		  struct ip_addr *ipaddr)
{
  p = etharp_output(netif, ipaddr, p);
  if(p != NULL) {
    low_level_output(netif, p);
    etharp_output_sent(p);
    p = NULL;
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * tapif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
tapif_input(struct netif *netif)
{
  struct tapif *tapif;
  struct eth_hdr *ethhdr;
  struct pbuf *p, *q;


  tapif = netif->state;
  
  p = low_level_input(tapif);

  if(p == NULL) {
    DEBUGF(TAPIF_DEBUG, ("tapif_input: low_level_input returned NULL\n"));
    return;
  }
  ethhdr = p->payload;

  q = NULL;
  switch(htons(ethhdr->type)) {
  case ETHTYPE_IP:
    DEBUGF(TAPIF_DEBUG, ("tapif_input: IP packet\n"));
    q = etharp_ip_input(netif, p);
    pbuf_header(p, -14);
    netif->input(p, netif);
    break;
  case ETHTYPE_ARP:
    DEBUGF(TAPIF_DEBUG, ("tapif_input: ARP packet\n"));
    q = etharp_arp_input(netif, tapif->ethaddr, p);
    break;
  default:
    pbuf_free(p);
    break;
  }
  if(q != NULL) {
    low_level_output(netif, q);
    pbuf_free(q);
  }

}
/*-----------------------------------------------------------------------------------*/
static void
arp_timer(void *arg)
{
  etharp_tmr();
  sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, NULL);
}
/*-----------------------------------------------------------------------------------*/
/*
 * tapif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
void
tapif_init(struct netif *netif)
{
  struct tapif *tapif;
    
  tapif = mem_malloc(sizeof(struct tapif));
  netif->state = tapif;
  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  netif->output = tapif_output;
  netif->linkoutput = low_level_output;
  
  tapif->ethaddr = (struct eth_addr *)&(netif->hwaddr[0]);
  
  low_level_init(netif);
  etharp_init();
  
  sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, NULL);
}
/*-----------------------------------------------------------------------------------*/
