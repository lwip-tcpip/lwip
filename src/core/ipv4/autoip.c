/**
 * @file
 *
 * AutoIP Automatic LinkLocal IP Configuration
 */

/*
 *
 * Copyright (c) 2007 Dominik Spies <kontakt@dspies.de>
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
 * Author: Dominik Spies <kontakt@dspies.de>
 *
 * This is a AutoIP implementation for the lwIP TCP/IP stack. It aims to conform
 * with RFC 3927.
 *
 *
 * Please coordinate changes and requests with Dominik Spies
 * <kontakt@dspies.de>
 */

/*******************************************************************************
 * USAGE:
 * 
 * define LWIP_AUTOIP 1
 * call autoip_fine_tmr() all AUTOIP_FINE_TIMER_MSECS msces,
 * that should be defined in autoip.h.
 * I recommend a value of 100. The value must divide 1000 with a remainder almost 0.
 * Possible values are 1000, 500, 333, 250, 200, 166, 142, 125, 111, 100 ....
 * 
 * 
 * Without DHCP:
 * call autoip_init() and autoip_start() after netif_add().
 * 
 * 
 * With DHCP:
 * Configure your DHCP Client
 * define LWIP_DHCP_AUTOIP_COOP 1 in lwipopts.h
 * 
 *******************************************************************************
 * 
 * TODO:
 * 
 * Solve compiler warnings:
 * 
 * warning: 'struct etharp_hdr' declared inside parameter list lwip/include/ipv4/lwip autoip.h line 92
 * warning: its scope is only this definition or declaration, which is probably not what you want lwip/include/ipv4/lwip autoip.h line 92
 * warning: passing argument 2 of 'apipa_arp_reply' from incompatible pointer type lwip/netif etharp.c line 543
 * 
 */

#include <stdlib.h>
#include <string.h>
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/autoip.h"
#include "netif/etharp.h"

#if LWIP_AUTOIP /* don't build if not configured for use in lwipopt.h */

/* static functions */
static void autoip_handle_arp_conflict(struct netif *netif);

/* creates random LL IP-Address */
static void autoip_create_rand_addr(struct ip_addr *RandomIPAddr);

/* sends an ARP announce */
static err_t autoip_arp_announce(struct netif *netif);

/* configure interface for use with current LL IP-Address */
static err_t autoip_bind(struct netif *netif);

/**
 * Initialize this module
 * seed random with MAC-Address for creating pseudo-ramdom linc-local address
 */
void
autoip_init(void)
{
  /* TODO MAC_ADDRESS macaddr; */
  
  LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | 3, ("autoip_init()\n"));
  
  /* TODO Get_Current_MAC_Address(&macaddr);*/
  /*srand(
      (macaddr.addr[2] << 24) |
      (macaddr.addr[3] << 16) |
      (macaddr.addr[4] <<  8) |
      (macaddr.addr[5] <<  0)
     );*/
}

/**
 * TODO: Add comment
 */
static void
autoip_handle_arp_conflict(struct netif *netif)
{
  /* Somehow detect if we are defending or retreating */
  unsigned char defend = 1; // tbd

  if(defend) {
    if(netif->autoip->lastconflict > 0) {
      /* retreat, there was a conflicting ARP in the last
       * DEFEND_INTERVAL seconds
       */
      LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE | 1, ("autoip_handle_arp_conflict(): we are defending, but in DEFEND_INTERVAL, retreating\n"));

      /* TODO: close all TCP sessions */
      autoip_start(netif);
    } else {
      LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE | 1, ("autoip_handle_arp_conflict(): we are defend, send ARP Announce\n"));
      autoip_arp_announce(netif);
      netif->autoip->lastconflict = DEFEND_INTERVAL * AUTOIP_FINE_TIMER_TICK_PER_SECOND;
    }
  } else {
    LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE | 1, ("autoip_handle_arp_conflict(): we do not defend, retreating\n"));
    /* TODO: close all TCP sessions */
    autoip_start(netif);
  }
}

/**
 * TODO: Add comment
 */
static void
autoip_create_rand_addr(struct ip_addr *RandomIPAddr)
{
  /* Here we create an IP-Address out of range 169.254.1.0 to 169.254.254.255
   * compliant to RFC 3927 Section 2.1
   * We have 254 * 256 possibilities
   */

  RandomIPAddr->addr = htonl((u32_t)(rand()  % (0xA9FEFEFF + 1 - 0xA9FE0100) + 0xA9FE0100));
}

/**
 * TODO: Add comment
 */
static err_t
autoip_arp_announce(struct netif *netif)
{
  struct eth_addr eth_addr_bc, eth_addr_zero;
  u8_t k = netif->hwaddr_len;

  while(k > 0) {
    k--;
    eth_addr_bc.addr[k]    = 0xFF;
    eth_addr_zero.addr[k]  = 0x00;
  }

  return etharp_raw( netif,
                     (struct eth_addr *)netif->hwaddr,
                     &eth_addr_bc,
                     (struct eth_addr *)netif->hwaddr,
                     &netif->autoip->llipaddr,
                     &eth_addr_zero,
                     &netif->autoip->llipaddr,
                     ARP_REQUEST
                   );
}

/**
 * TODO: Add comment
 */
static err_t
autoip_bind(struct netif *netif)
{
  struct autoip *autoip = netif->autoip;
  struct ip_addr sn_mask, gw_addr;
  LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | 3, ("autoip_bind(netif=%p) %c%c%"U16_F"\n", (void*)netif, netif->name[0], netif->name[1], (u16_t)netif->num));

  IP4_ADDR(&sn_mask, 255, 255, 0, 0);
  IP4_ADDR(&gw_addr, 0, 0, 0, 0);

  netif_set_ipaddr(netif, &autoip->llipaddr);
  netif_set_netmask(netif, &sn_mask);
  netif_set_gw(netif, &gw_addr);  

  /* bring the interface up */
  netif_set_up(netif);

  return ERR_OK;
}

/**
 * TODO: Add comment
 */
err_t
autoip_start(struct netif *netif)
{
  struct autoip *autoip = netif->autoip;
  err_t result = ERR_OK;

  if(netif_is_up(netif)) {
    netif_set_down(netif);
  }

  /* Set IP-Address, Netmask and Gateway to 0 to make sure that
   * ARP Packets are formed correctly
   */
  netif->ip_addr.addr = 0;
  netif->netmask.addr = 0;
  netif->gw.addr      = 0;

  LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("autoip_start(netif=%p) %c%c%"U16_F"\n", (void*)netif, netif->name[0], netif->name[1], (u16_t)netif->num));
  if(autoip == NULL) {
    /* no AutoIP client attached yet? */
    LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE, ("autoip_start(): starting new AUTOIP client\n"));
    autoip = mem_malloc(sizeof(struct autoip));
    if(autoip == NULL) {
      LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE, ("autoip_start(): could not allocate autoip\n"));
      return ERR_MEM;
    }
    memset( autoip, 0, sizeof(struct autoip));
    /* store this AutoIP client in the netif */
    netif->autoip = autoip;
    LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE, ("autoip_start(): allocated autoip"));
  } else {
    autoip->state = AUTOIP_STATE_OFF;
    autoip->ttw = 0;
    autoip->sent_num = 0;
    memset(&autoip->llipaddr, 0, sizeof(struct ip_addr));
    autoip->lastconflict = 0;
  }

  autoip_create_rand_addr(&(autoip->llipaddr));
  autoip->tried_llipaddr++;
  autoip->state = AUTOIP_STATE_PROBING;
  autoip->sent_num = 0;

  /* time to wait to first probe, this is randomly
   * choosen out of 0 to PROBE_WAIT seconds.
   * compliant to RFC 3927 Section 2.2.1
   */
  autoip->ttw = (rand() % (PROBE_WAIT * AUTOIP_FINE_TIMER_TICK_PER_SECOND));

  /*
   * if we tried more then MAX_CONFLICTS we must limit our rate for
   * accquiring and probing address
   * compliant to RFC 3927 Section 2.2.1
   */

  if(autoip->tried_llipaddr > MAX_CONFLICTS) {
    autoip->ttw = RATE_LIMIT_INTERVAL * AUTOIP_FINE_TIMER_TICK_PER_SECOND;
  }

  return result;
}

/**
 * TODO: Add comment
 */
err_t
autoip_stop(struct netif *netif)
{
  netif->autoip->state = AUTOIP_STATE_OFF;
  netif_set_down(netif);
  return ERR_OK;
}

/**
 * TODO: Add comment
 */
void
autoip_fine_tmr()
{
  struct netif *netif = netif_list;
  /* loop through netif's */
  while (netif != NULL) {
    /* only act on AutoIP configured interfaces */
    if (netif->autoip != NULL) {
      if(netif->autoip->lastconflict > 0) {
        netif->autoip->lastconflict--;
      }

      LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | 3, ("autoip_fine_tmr()AutoIP-Sate: %d\n", netif->autoip->state));

      switch(netif->autoip->state) {
        case AUTOIP_STATE_PROBING:
          if(netif->autoip->ttw > 0) {
            netif->autoip->ttw--;
          } else {
            if(netif->autoip->sent_num == PROBE_NUM) {
              netif->autoip->state = AUTOIP_STATE_ANNOUNCING;
              netif->autoip->sent_num = 0;
              netif->autoip->ttw = ANNOUNCE_WAIT * AUTOIP_FINE_TIMER_TICK_PER_SECOND;
            } else {
              etharp_request(netif, &(netif->autoip->llipaddr));
              LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | 3, ("autoip_fine_tmr() PROBING Sent Probe\n"));
              netif->autoip->sent_num++;
              /* calculate time to wait to next probe */
              netif->autoip->ttw = (rand() % ((PROBE_MAX - PROBE_MIN) * AUTOIP_FINE_TIMER_TICK_PER_SECOND) ) + PROBE_MIN * AUTOIP_FINE_TIMER_TICK_PER_SECOND;
            }
          }
          break;

        case AUTOIP_STATE_ANNOUNCING:
          if(netif->autoip->ttw > 0) {
            netif->autoip->ttw--;
          } else {
            if(netif->autoip->sent_num == 0) {
             /* We are here the first time, so we waited ANNOUNCE_WAIT seconds
              * Now we can bind to an IP address and use it
              */
              autoip_bind(netif);
            }

            if(netif->autoip->sent_num == ANNOUNCE_NUM) {
              netif->autoip->state = AUTOIP_STATE_BOUND;
              netif->autoip->sent_num = 0;
              netif->autoip->ttw = 0;
            } else {
              autoip_arp_announce(netif);
              LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | 3, ("autoip_fine_tmr() ANNOUNCING Sent Announce\n"));
              netif->autoip->sent_num++;
              netif->autoip->ttw = ANNOUNCE_INTERVAL * AUTOIP_FINE_TIMER_TICK_PER_SECOND;
            }
          }
          break;
      }
    }
    /* proceed to next network interface */
    netif = netif->next;
  }
}

/**
 * TODO: Add comment
 */
void
autoip_arp_reply(struct netif *netif, struct etharp_hdr *hdr)
{
  LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | 3, ("autoip_arp_reply()\n"));
  if ((netif->autoip != NULL) && (netif->autoip->state != AUTOIP_STATE_OFF)) {
   /* when ip.src == llipaddr && hw.src != netif->hwaddr
    *
    * when probing  ip.dst == llipaddr && hw.src != netif->hwaddr
    * we have a conflict and must solve it
    */
    struct ip_addr sipaddr, dipaddr;
    struct eth_addr netifaddr;
    netifaddr.addr[0] = netif->hwaddr[0];
    netifaddr.addr[1] = netif->hwaddr[1];
    netifaddr.addr[2] = netif->hwaddr[2];
    netifaddr.addr[3] = netif->hwaddr[3];
    netifaddr.addr[4] = netif->hwaddr[4];
    netifaddr.addr[5] = netif->hwaddr[5];

    /* Copy struct ip_addr2 to aligned ip_addr, to support compilers without
     * structure packing (not using structure copy which breaks strict-aliasing rules).
     */
    memcpy(&sipaddr, &hdr->sipaddr, sizeof(sipaddr));
    memcpy(&dipaddr, &hdr->dipaddr, sizeof(dipaddr));
      
    if (netif->autoip->state == AUTOIP_STATE_PROBING || (netif->autoip->state == AUTOIP_STATE_ANNOUNCING && netif->autoip->sent_num == 0)) {
     /* RFC 3927 Section 2.2.1:
      * from beginning to after ANNOUNCE_WAIT
      * seconds we have a conflict if
      * ip.src == llipaddr OR
      * ip.dst == llipaddr && hw.src != own hwaddr
      */
      if((ip_addr_cmp(&sipaddr, &netif->autoip->llipaddr)) || (ip_addr_cmp(&dipaddr, &netif->autoip->llipaddr) && !eth_addr_cmp(&netifaddr, &hdr->shwaddr))) {
        LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE | 1, ("autoip_arp_reply(): Probe Conflict detected\n"));
        autoip_start(netif);
      }
    } else {
     /* RFC 3927 Section 2.5:
      * in any state we have a conflict if
      * ip.src == llipaddr && hw.src != own hwaddr
      */
      if(ip_addr_cmp(&sipaddr, &netif->autoip->llipaddr)  && !eth_addr_cmp(&netifaddr, &hdr->shwaddr)) {
        LWIP_DEBUGF(AUTOIP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE | 1, ("autoip_arp_reply(): Conflicting ARP-Packet detected\n"));
        autoip_handle_arp_conflict(netif);
      }
    }
  }
}

#endif /* LWIP_AUTOIP */
