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

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/netif.h"

struct netif *netif_list = NULL;
struct netif *netif_default = NULL;

/**
 * Add a network interface to the list of lwIP netifs.
 *
 * @param ipaddr IP address for the new netif
 * @param netmask network mask for the new netif
 * @param gw default gateway IP address for the new netif
 * @init callback function that initializes the interface
 * @input callback function that...
 *
 * @return netif, or NULL if failed.
 */
struct netif *
netif_add(struct ip_addr *ipaddr, struct ip_addr *netmask,
	  struct ip_addr *gw,
	  void *state,
	  void (* init)(struct netif *netif),
	  err_t (* input)(struct pbuf *p, struct netif *netif))
{
  struct netif *netif;
  static int netifnum = 0;
  
  netif = mem_malloc(sizeof(struct netif));

  if(netif == NULL) {
    return NULL;
  }
  
  netif->state = state;
  netif->num = netifnum++;
  netif->input = input;
  ip_addr_set(&(netif->ip_addr), ipaddr);
  ip_addr_set(&(netif->netmask), netmask);
  ip_addr_set(&(netif->gw), gw);

  init(netif);
  
  netif->next = netif_list;
  netif_list = netif;
#if NETIF_DEBUG
  DEBUGF(NETIF_DEBUG, ("netif: added interface %c%c IP addr ",
		       netif->name[0], netif->name[1]));
  ip_addr_debug_print(ipaddr);
  DEBUGF(NETIF_DEBUG, (" netmask "));
  ip_addr_debug_print(netmask);
  DEBUGF(NETIF_DEBUG, (" gw "));  
  ip_addr_debug_print(gw);
  DEBUGF(NETIF_DEBUG, ("\n"));
#endif /* NETIF_DEBUG */
  return netif;
}
/*-----------------------------------------------------------------------------------*/
void netif_remove(struct netif * netif)
{
	if ( netif == NULL ) return;  
 
	/*  is it the first netif? */
	if(netif_list == netif) {
		netif_list = netif->next;
	}    
	else
	{	
		/*  look for netif further down the list */
		struct netif * tmpNetif;
 		for(tmpNetif = netif_list; tmpNetif != NULL; tmpNetif = tmpNetif->next) {
			if(tmpNetif->next == netif) {
				tmpNetif->next = netif->next;
				break;
			}    
		}
		if(tmpNetif == NULL)
			return; /*  we didn't find any netif today */
	}

	if(netif_default == netif)
		netif_default = NULL;

	DEBUGF(NETIF_DEBUG, ("netif_remove: removed netif"));
	mem_free( netif );
}

/*-----------------------------------------------------------------------------------*/
struct netif *
netif_find(char *name)
{
  struct netif *netif;
  u8_t num;
  
  if(name == NULL) {
    return NULL;
  }

  num = name[2] - '0';
 
  for(netif = netif_list; netif != NULL; netif = netif->next) {
    if(num == netif->num &&
       name[0] == netif->name[0] &&
       name[1] == netif->name[1]) {
      DEBUGF(NETIF_DEBUG, ("netif_find: found %s\n", name));
      return netif;
    }    
  }
  DEBUGF(NETIF_DEBUG, ("netif_find: didn't find %s\n", name));
  return NULL;
}
/*-----------------------------------------------------------------------------------*/
void
netif_set_ipaddr(struct netif *netif, struct ip_addr *ipaddr)
{
  ip_addr_set(&(netif->ip_addr), ipaddr);
  DEBUGF(NETIF_DEBUG, ("netif: setting IP address of interface %c%c to %d.%d.%d.%d\n",
		       netif->name[0], netif->name[1],
		       (u8_t)(ntohl(ipaddr->addr) >> 24 & 0xff),
		       (u8_t)(ntohl(ipaddr->addr) >> 16 & 0xff),
		       (u8_t)(ntohl(ipaddr->addr) >> 8 & 0xff),
		       (u8_t)(ntohl(ipaddr->addr) & 0xff)));
}
/*-----------------------------------------------------------------------------------*/
void
netif_set_gw(struct netif *netif, struct ip_addr *gw)
{
  ip_addr_set(&(netif->gw), gw);
}
/*-----------------------------------------------------------------------------------*/
void
netif_set_netmask(struct netif *netif, struct ip_addr *netmask)
{
  ip_addr_set(&(netif->netmask), netmask);
}
/*-----------------------------------------------------------------------------------*/
void
netif_set_default(struct netif *netif)
{
  netif_default = netif;
  DEBUGF(NETIF_DEBUG, ("netif: setting default interface %c%c\n",
		       netif ? netif->name[0] : '\'', netif ? netif->name[1] : '\''));
}
/*-----------------------------------------------------------------------------------*/
void
netif_init(void)
{
  netif_list = netif_default = NULL;
}
/*-----------------------------------------------------------------------------------*/
