/*
 * Copyright (c) 2001, 2002 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2001, 2002 Axon Digital Design B.V., The Netherlands.
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
 * This file is a contribution to the lwIP TCP/IP stack.
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code.
 * 
 * Author: Leon Woestenberg <leon.woestenberg@axon.tv>
 * 
 * This is a DHCP client for the lwIP TCP/IP stack, for releases newer than
 * lwIP 0.5.3 which has the new "etharp" module. It aims to conform with
 * RFC 2131 and RFC 2132.
 *
 * KNOWN BUG:
 * - Parsing of DHCP messages which use file/sname field overloading will
 * probably fail. Additional support for this must go into dhcp_unfold().
 * TODO:
 * - Add JavaDoc style documentation (API, internals).
 * - Make the unfold routine smarter to handle this
 * - Support for interfaces other than Ethernet (SLIP, PPP, ...)
 * - ...
 *
 * Please coordinate changes and requests with Leon Woestenberg
 * <leon.woestenberg@axon.tv>
 *
 * Integration with your code:
 *
 * In lwip/dhcp.h
 * #define DHCP_COARSE_TIMER_SECS (recommended 60 which is a minute)
 * #define DHCP_FINE_TIMER_MSECS (recommended 500 which equals TCP coarse timer)
 *
 * Then have your application call dhcp_coarse_tmr() and
 * dhcp_fine_tmr() on the defined intervals.
 *
 * How to boot the DHCP client
 *
 * First, call dhcp_init() to initialize the DHCP client.
 *
 * Then, use
 * struct dhcp_state *client = dhcp_start(struct netif *netif)
 * starts a DHCP client instance which configures the interface by
 * obtaining an IP address lease and maintaining it.
 *
 * Use dhcp_release(client) to end the lease and use dhcp_stop(client)
 * to remove the DHCP client.
 *
 */
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "netif/etharp.h"

#include "lwip/sys.h"
#include "lwipopts.h"
#include "lwip/dhcp.h"

/** find the active DHCP attached to the given network interface */
struct dhcp_state *dhcp_find_client(struct netif *netif);

/** transaction identifier, unique over all DHCP requests */
static u32_t xid = 0xABCD0000;
/** singly-linked list of DHCP clients that are active */
static struct dhcp_state *client_list = NULL;

/** DHCP client state machine functions */
static void dhcp_handle_ack(struct dhcp_state *state);
static void dhcp_handle_nak(struct dhcp_state *state);
static void dhcp_handle_offer(struct dhcp_state *state);
static err_t dhcp_discover(struct dhcp_state *state);
static err_t dhcp_select(struct dhcp_state *state);
static void dhcp_check(struct dhcp_state *state);
static err_t dhcp_decline(struct dhcp_state *state);
static void dhcp_bind(struct dhcp_state *state);
static err_t dhcp_rebind(struct dhcp_state *state);
static err_t dhcp_release(struct dhcp_state *state);
static void dhcp_set_state(struct dhcp_state *state, unsigned char new_state);

/** receive, unfold, parse and free incoming messages */
static void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port);
static err_t dhcp_unfold_reply(struct dhcp_state *state);
static u8_t *dhcp_get_option_ptr(struct dhcp_state *state, u8_t option_type);
static u8_t dhcp_get_option_byte(u8_t *ptr);
static u16_t dhcp_get_option_short(u8_t *ptr);
static u32_t dhcp_get_option_long(u8_t *ptr);
static void dhcp_free_reply(struct dhcp_state *state);

/** set the DHCP timers */
static void dhcp_timeout(struct dhcp_state *state);
static void dhcp_t1_timeout(struct dhcp_state *state);
static void dhcp_t2_timeout(struct dhcp_state *state);

#if DHCP_DOES_ARP_CHECK
/** called by ARP to notify us of ARP replies */
void dhcp_arp_reply(struct ip_addr *addr);
#endif

/** build outgoing messages */
static err_t dhcp_create_request(struct dhcp_state *state);
static void dhcp_delete_request(struct dhcp_state *state);
static void dhcp_option(struct dhcp_state *state, u8_t option_type, u8_t option_len);
static void dhcp_option_byte(struct dhcp_state *state, u8_t value);
static void dhcp_option_short(struct dhcp_state *state, u16_t value);
static void dhcp_option_long(struct dhcp_state *state, u32_t value);
static void dhcp_option_trailer(struct dhcp_state *state);

/**
 * Back-off the DHCP client because of a received NAK. Receiving a
 * NAK means the client asked for something non-sensible, for
 * example when it tries to renew a lease obtained on another network.
 *
 * We back-off and will end up restarting a fresh DHCP negotiation later.
 */ 
static void dhcp_handle_nak(struct dhcp_state *state) {
	u16_t msecs = 10 * 1000;
 	DEBUGF(DHCP_DEBUG, ("dhcp_handle_nak()"));
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_handle_nak(): request timeout %u msecs", msecs));
	dhcp_set_state(state, DHCP_BACKING_OFF);
}

/**
 * Checks if the offered address from the server is already in use.
 * 
 * It does so by sending an ARP request for the offered address and
 * entering CHECKING state. If no ARP reply is received within a small
 * interval, the address is assumed to be free for use by us.
 */
static void dhcp_check(struct dhcp_state *state)
{
  struct pbuf *p;
  err_t result;
	u16_t msecs;
 	DEBUGF(DHCP_DEBUG, ("dhcp_check()"));
  p = etharp_query(state->netif, &state->offered_ip_addr, NULL);
  if(p != NULL)
  {
   	DEBUGF(DHCP_DEBUG, ("dhcp_check(): sending ARP request len %u", p->tot_len));
    result = state->netif->linkoutput(state->netif, p);
    pbuf_free(p);
  }
	state->tries++;
	msecs = state->tries * 1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_check(): request timeout %u msecs", msecs));
	dhcp_set_state(state, DHCP_CHECKING);
}

/**
 * Remember the configuration offered by a DHCP server.
 * 
 */
static void dhcp_handle_offer(struct dhcp_state *state)
{
  u8_t *option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_SERVER_ID);
  if (option_ptr != NULL)
	{
  	state->server_ip_addr.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
  	DEBUGF(DHCP_DEBUG, ("dhcp_handle_offer(): server 0x%08lx", state->server_ip_addr.addr));
    /* remember offered address */
	  ip_addr_set(&state->offered_ip_addr, (struct ip_addr *)&state->msg_in->yiaddr);
  	DEBUGF(DHCP_DEBUG, ("dhcp_handle_offer(): offer for 0x%08lx", state->offered_ip_addr.addr));
		dhcp_select(state);
	}
	else
	{
		//dhcp_start(restart);
	}
}

/**
 * Select a DHCP server offer out of all offers.
 *
 * Simply select the first offer received.
 */
static err_t dhcp_select(struct dhcp_state *state)
{
	err_t result;
  u32_t msecs;
	DEBUGF(DHCP_DEBUG, ("dhcp_select()"));

	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{
		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_REQUEST);

		dhcp_option(state, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
		dhcp_option_short(state, 576);

    /* MUST request the offered IP address */
		dhcp_option(state, DHCP_OPTION_REQUESTED_IP, 4);
		dhcp_option_long(state, ntohl(state->offered_ip_addr.addr));

		dhcp_option(state, DHCP_OPTION_SERVER_ID, 4);
		dhcp_option_long(state, ntohl(state->server_ip_addr.addr));

 		dhcp_option(state, DHCP_OPTION_PARAMETER_REQUEST_LIST, 3);
		dhcp_option_byte(state, DHCP_OPTION_SUBNET_MASK);
		dhcp_option_byte(state, DHCP_OPTION_ROUTER);
		dhcp_option_byte(state, DHCP_OPTION_BROADCAST);

		dhcp_option_trailer(state);

		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);
		udp_send(state->pcb, state->p_out);
    // reconnect to any (or to server here?!)
		udp_connect(state->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
		dhcp_delete_request(state);
	}
	state->tries++;
	msecs = state->tries < 4 ? state->tries * 1000 : 4 * 1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_select(): request timeout %u msecs", msecs));
	dhcp_set_state(state, DHCP_REQUESTING);
	return result;
}

/**
 * The DHCP timer that checks for lease renewal/rebind timeouts.
 *
 */
void dhcp_coarse_tmr()
{
  struct dhcp_state *list_state = client_list;
 	DEBUGF(DHCP_DEBUG, ("dhcp_coarse_tmr():"));
	// loop through clients
  while (list_state != NULL)
	{
	  // timer is active (non zero), and triggers (zeroes) now
    if (list_state->t2_timeout-- == 1)
	  {
     	DEBUGF(DHCP_DEBUG, ("dhcp_coarse_tmr(): t2 timeout"));
		  // this clients' rebind timeout triggered
	    dhcp_t2_timeout(list_state);
	  }
	  // timer is active (non zero), and triggers (zeroes) now
    else if (list_state->t1_timeout-- == 1)
	  {
     	DEBUGF(DHCP_DEBUG, ("dhcp_coarse_tmr(): t1 timeout"));
		  // this clients' renewal timeout triggered
	    dhcp_t1_timeout(list_state);
	  }
		// proceed to next timer
		list_state = list_state->next;
	}
}

/**
 * The DHCP timer that handles DHCP negotiotion transaction timeouts.
 *
 */
void dhcp_fine_tmr()
{
  struct dhcp_state *list_state = client_list;
// 	DEBUGF(DHCP_DEBUG, ("dhcp_fine_tmr():"));
	// loop through clients
  while (list_state != NULL)
	{
	  // timer is active (non zero), and triggers (zeroes) now
    if (list_state->request_timeout-- == 1)
	  {
     	DEBUGF(DHCP_DEBUG, ("dhcp_fine_tmr(): request timeout"));
		  // this clients' request timeout triggered
	    dhcp_timeout(list_state);
	  }
		// proceed to next client
		list_state = list_state->next;
	}
}

/**
 * A DHCP negotiation transaction, or ARP request, has timed out.
 *
 * 
 */
static void dhcp_timeout(struct dhcp_state *state)
{
  DEBUGF(DHCP_DEBUG, ("dhcp_timeout()"));
  if ((state->state == DHCP_BACKING_OFF) || (state->state == DHCP_SELECTING))
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): restarting discovery"));
    dhcp_discover(state);
	}
	else if (state->state == DHCP_REQUESTING)
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): REQUESTING, DHCP request timed out"));
	  if (state->tries <= 5)
		{
		  dhcp_select(state);
		}
    else
		{
	    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): REQUESTING, releasing, restarting"));
      dhcp_release(state);
      dhcp_discover(state);
		}
	}
	else if (state->state == DHCP_CHECKING)
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): CHECKING, ARP request timed out"));
	  if (state->tries <= 1)
 		{
		  dhcp_check(state);
		}
		// no ARP replies on the offered address,
		// looks like the IP address is indeed free
	  else
		{
		  dhcp_bind(state);
		}
	}
	else if (state->state == DHCP_RENEWING)
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): RENEWING, DHCP request timed out"));
	  dhcp_renew(state);
  }
	else if (state->state == DHCP_REBINDING)
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): REBINDING, DHCP request timed out"));
	  if (state->tries <= 8)
		{
		  dhcp_rebind(state);
		}
	  else
		{
	    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): RELEASING, DISCOVERING"));
      dhcp_release(state);
      dhcp_discover(state);
		}
  }
}

/**
 * The renewal period has timed out.
 *
 */
static void dhcp_t1_timeout(struct dhcp_state *state)
{
  DEBUGF(DHCP_DEBUG, ("dhcp_t1_timeout()"));
  if ((state->state == DHCP_REQUESTING) || (state->state == DHCP_BOUND) || (state->state == DHCP_RENEWING))
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_t1_timeout(): must renew"));
    dhcp_renew(state);
	}
}

/**
 * The rebind period has timed out.
 *
 */
static void dhcp_t2_timeout(struct dhcp_state *state)
{
  DEBUGF(DHCP_DEBUG, ("dhcp_t2_timeout()"));
  if ((state->state == DHCP_REQUESTING) || (state->state == DHCP_BOUND) || (state->state == DHCP_RENEWING))
	{
	  DEBUGF(DHCP_DEBUG, ("dhcp_t2_timeout(): must rebind"));
    dhcp_rebind(state);
	}
}

/**
 * Extract options from the server ACK message.
 *
 */
static void dhcp_handle_ack(struct dhcp_state *state)
{
  u8_t *option_ptr;
  /* clear options we might not get from the ACK */
  state->offered_sn_mask.addr = 0;
  state->offered_gw_addr.addr = 0;
  state->offered_bc_addr.addr = 0;

  option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_LEASE_TIME);
  if (option_ptr != NULL)
	{
    state->offered_t0_lease = dhcp_get_option_long(option_ptr + 2);
    state->offered_t1_renew = state->offered_t0_lease / 2;
    state->offered_t2_rebind = state->offered_t0_lease;
  }
  /* renewal period */
  option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_T1);
  if (option_ptr != NULL)
	{
    state->offered_t1_renew = dhcp_get_option_long(option_ptr + 2);
  }
  /* rebind period */
  option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_T2);
  if (option_ptr != NULL)
	{
    state->offered_t2_rebind = dhcp_get_option_long(option_ptr + 2);
  }
  /* (y)our internet address */
  ip_addr_set(&state->offered_ip_addr, &state->msg_in->yiaddr);

  /* subnet mask */
  option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_SUBNET_MASK);
	if (option_ptr != NULL)
	{
    state->offered_sn_mask.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
	}

  /* gateway router */
  option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_ROUTER);
	if (option_ptr != NULL)
	{
    state->offered_gw_addr.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
	}

  /* broadcast address */
  option_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_BROADCAST);
	if (option_ptr != NULL)
	{
    state->offered_bc_addr.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
	}
}


/**
 * Initialize DHCP.
 *
 * Must be called prior to any other dhcp_*() function.
 *
 */
void dhcp_init(void)
{
	DEBUGF(DHCP_DEBUG, ("dhcp_init()"));
	/* this would be the proper way to stop all dhcp clients */
	/* but we need lwIP to be running at this point */
	/* while(client_list) dhcp_stop(client_list); */
	client_list = NULL;
}

/**
 * Start DHCP negotiation for a network interface.
 *
 * If no DHCP client instance was attached to this interface,
 * a new client is created first. If a DHCP client instance
 * was already present, it restarts negotiation.
 *
 * @return The DHCP client state, which must be passed for 
 * all subsequential dhcp_*() calls. NULL means there is
 * no (longer a) DHCP client attached to the interface
 * (due to unavailable memory or network resources).
 *
 */
struct dhcp_state *dhcp_start(struct netif *netif)
{
	struct dhcp_state *state = NULL;
	struct dhcp_state *list_state = client_list;
	err_t result = ERR_OK;

	DEBUGF(DHCP_DEBUG, ("dhcp_start()"));

  /* find the DHCP client attached to the given interface */
	state = dhcp_find_client(netif);
	DEBUGF(DHCP_DEBUG, ("dhcp_start(): finished parsing through list"));
  /* a DHCP client already attached to this interface? */
  if (state != NULL)
	{
		DEBUGF(DHCP_DEBUG, ("dhcp_start(): already active on interface"));
    /* just restart the DHCP negotiation */
  	result = dhcp_discover(state);
    if (result == ERR_OK)
    {
      return state;
    }
    else
    {
      dhcp_stop(state);
      return NULL;
    }
  }

	DEBUGF(DHCP_DEBUG, ("dhcp_start(): starting new DHCP client"));
	state = mem_malloc(sizeof(struct dhcp_state));
	if (state == NULL)
	{
		DEBUGF(DHCP_DEBUG, ("dhcp_start(): could not allocate dhcp_state"));
		return NULL;
	}
	bzero(state, sizeof(struct dhcp_state));

	DEBUGF(DHCP_DEBUG, ("dhcp_start(): allocated dhcp_state"));
	state->pcb = udp_new();
	if (state->pcb == NULL) {
		DEBUGF(DHCP_DEBUG, ("dhcp_start(): could not obtain pcb"));
		mem_free((void *)state);
    state = NULL;
		return NULL;
	}
	DEBUGF(DHCP_DEBUG, ("dhcp_start(): created new udp pcb"));
	state->netif = netif;
	/* enqueue in list of clients */
	/* we are last in list */
	state->next = NULL;
  /* empty list? */
	if (client_list == NULL)
	{
    /* single item at head of list */
	  client_list = state;
  }
	else
	{
    /* proceed to the last DHCP client state 
    while (list_state->next != NULL) list_state = list_state->next;
	  list_state->next = state;
	}
	dhcp_discover(state);
	return state;
}

/**
 * Inform a DHCP server of our manual configuration.
 * 
 * This informs DHCP servers of our fixed IP address configuration
 * by send an INFORM message. It does not involve DHCP address
 * configuration, it is just here to be nice.
 *
 */ 
void dhcp_inform(struct netif *netif)
{
	struct dhcp_state *state = NULL;
	err_t result = ERR_OK;
	state = mem_malloc(sizeof(struct dhcp_state));
	if (state == NULL)
	{
		DEBUGF(DHCP_DEBUG, ("dhcp_inform(): could not allocate dhcp_state"));
		return;
	}  
	bzero(state, sizeof(struct dhcp_state));

	DEBUGF(DHCP_DEBUG, ("dhcp_inform(): allocated dhcp_state"));
	state->pcb = udp_new();
	if (state->pcb == NULL) {
		DEBUGF(DHCP_DEBUG, ("dhcp_inform(): could not obtain pcb"));
		mem_free((void *)state);
		return;
	}
	DEBUGF(DHCP_DEBUG, ("dhcp_inform(): created new udp pcb"));
	state->netif = netif;
	// we are last in list 
	state->next = NULL;
	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{

		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_INFORM);

		dhcp_option(state, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
		dhcp_option_short(state, 576);

		dhcp_option_trailer(state);

		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);
		udp_send(state->pcb, state->p_out);
		udp_connect(state->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
		dhcp_delete_request(state);
	}

	if (state != NULL)
	{
		if (state->pcb != NULL) udp_remove(state->pcb);
    state->pcb = NULL;
		mem_free((void *)state);
  }
}

#if DHCP_DOES_ARP_CHECK
void dhcp_arp_reply(struct ip_addr *addr)
{
  struct dhcp_state *list_state = client_list;
 	DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply()"));
	// loop through clients
  while (list_state != NULL)
	{
   	DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply(): list_state %p", list_state));
	  // is this DHCP client doing an ARP check?
    if (list_state->state == DHCP_CHECKING)
		{
    	DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply(): CHECKING, arp reply for 0x%08lx", addr->addr));
      // does a host respond with the address we
			// were offered by the DHCP server?
      if (ip_addr_cmp(addr, &list_state->offered_ip_addr))
			{
			  // we will not accept the offered address
      	DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply(): arp reply matched with offered address, declining"));
				dhcp_decline(list_state);
			}
		}
		else
		{
    	DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply(): NOT CHECKING"));
		}
		// proceed to next timer
		list_state = list_state->next;
	}
}

/** 
 * Decline a
 *
 *
 */
static err_t dhcp_decline(struct dhcp_state *state)
{
	err_t result = ERR_OK;
	u16_t msecs;
	DEBUGF(DHCP_DEBUG, ("dhcp_decline()"));
	dhcp_set_state(state, DHCP_BACKING_OFF);
	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{
		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_DECLINE);

		dhcp_option(state, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
		dhcp_option_short(state, 576);

		dhcp_option_trailer(state);
    // resize pbuf to reflect true size of options
		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, &state->server_ip_addr, DHCP_SERVER_PORT);
		udp_send(state->pcb, state->p_out);
		dhcp_delete_request(state);
	}
	state->tries++;
	msecs = 10*1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_decline(): request timeout %u msecs", msecs));
	return result;
}
#endif


/**
 * Start the DHCP process, discover a DHCP server.
 *
 */
static err_t dhcp_discover(struct dhcp_state *state)
{
	err_t result = ERR_OK;
	u16_t msecs;
	DEBUGF(DHCP_DEBUG, ("dhcp_discover()"));
  ip_addr_set(&state->offered_ip_addr, IP_ADDR_ANY);
	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{
		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_DISCOVER);

		dhcp_option(state, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
		dhcp_option_short(state, 576);

		dhcp_option(state, DHCP_OPTION_PARAMETER_REQUEST_LIST, 3);
		dhcp_option_byte(state, DHCP_OPTION_SUBNET_MASK);
		dhcp_option_byte(state, DHCP_OPTION_ROUTER);
		dhcp_option_byte(state, DHCP_OPTION_BROADCAST);

		dhcp_option_trailer(state);

		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_recv(state->pcb, dhcp_recv, state);
		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);

		udp_send(state->pcb, state->p_out);
		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
		dhcp_delete_request(state);
	}
	state->tries++;
	msecs = state->tries < 4 ? (state->tries + 1) * 1000 : 10 * 1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_discover(): request timeout %u msecs", msecs));
	dhcp_set_state(state, DHCP_SELECTING);
	return result;
}


/**
 * Bind the interface to the offered IP address.
 *
 */
static void dhcp_bind(struct dhcp_state *state)
{
  struct ip_addr sn_mask, gw_addr;
	dhcp_set_state(state, DHCP_BOUND);
  /* temporary DHCP lease? */
  if (state->offered_t1_renew != 0xffffffffUL) {
    /* set renewal period timer */
   	DEBUGF(DHCP_DEBUG, ("dhcp_bind(): t1 renewal timer %lu secs", state->offered_t1_renew));
   	state->t1_timeout = (state->offered_t1_renew + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
		if (state->t1_timeout == 0) state->t1_timeout = 1;
 	  DEBUGF(DHCP_DEBUG, ("dhcp_bind(): request timeout %u msecs", state->offered_t1_renew*1000));
	}
  /* set renewal period timer */
  if (state->offered_t2_rebind != 0xffffffffUL)
	{
   	DEBUGF(DHCP_DEBUG, ("dhcp_bind(): t2 rebind timer %lu secs", state->offered_t2_rebind));
   	state->t2_timeout = (state->offered_t2_rebind + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
		if (state->t2_timeout == 0) state->t2_timeout = 1;
   	DEBUGF(DHCP_DEBUG, ("dhcp_bind(): request timeout %u msecs", state->offered_t2_rebind*1000));
	}

  ip_addr_set(&sn_mask, &state->offered_sn_mask);
  // subnet mask not given
	if (sn_mask.addr == 0)
	{
    // choose a safe subnet mask given the network class
	  u8_t first_octet = ip4_addr1(&sn_mask);
    if (first_octet <= 127) sn_mask.addr = htonl(0xff000000);
    else if (first_octet >= 192) sn_mask.addr = htonl(0xffffff00);
    else sn_mask.addr = htonl(0xffff0000);
	}
	DEBUGF(DHCP_DEBUG, ("dhcp_bind(): SN: 0x%08lx", sn_mask.addr));
	netif_set_netmask(state->netif, &sn_mask);

  ip_addr_set(&gw_addr, &state->offered_gw_addr);
  // gateway address not given
	if (gw_addr.addr == 0)
	{
    gw_addr.addr &= sn_mask.addr;
    gw_addr.addr |= 0x01000000;
	}
	DEBUGF(DHCP_DEBUG, ("dhcp_bind(): GW: 0x%08lx", gw_addr.addr));
	netif_set_gw(state->netif, &gw_addr);

	DEBUGF(DHCP_DEBUG, ("dhcp_bind(): IP: 0x%08lx", state->offered_ip_addr.addr));
	netif_set_ipaddr(state->netif, &state->offered_ip_addr);
}

/**
 * Renew an existing DHCP lease at the involved DHCP server.
 * 
 */
err_t dhcp_renew(struct dhcp_state *state)
{
	err_t result;
  u16_t msecs;
	DEBUGF(DHCP_DEBUG, ("dhcp_renew()"));
	dhcp_set_state(state, DHCP_RENEWING);

	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{

		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_REQUEST);

		dhcp_option(state, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
		dhcp_option_short(state, 576);

#if 0
		dhcp_option(state, DHCP_OPTION_REQUESTED_IP, 4);
		dhcp_option_long(state, ntohl(state->offered_ip_addr.addr));
#endif

#if 0
		dhcp_option(state, DHCP_OPTION_SERVER_ID, 4);
		dhcp_option_long(state, ntohl(state->server_ip_addr.addr));
#endif

		dhcp_option_trailer(state);

		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, &state->server_ip_addr, DHCP_SERVER_PORT);
		udp_send(state->pcb, state->p_out);
		dhcp_delete_request(state);
	}
	state->tries++;
  // back-off on retries, but to a maximum of 20 seconds
	msecs = state->tries < 10 ? state->tries * 2000 : 20 * 1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_renew(): request timeout %u msecs", msecs));
	return result;
}

/**
 * Rebind with a DHCP server for an existing DHCP lease.
 * 
 */
static err_t dhcp_rebind(struct dhcp_state *state)
{
	err_t result;
	u16_t msecs;
	DEBUGF(DHCP_DEBUG, ("dhcp_rebind()"));
	dhcp_set_state(state, DHCP_REBINDING);

	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{

		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_REQUEST);

		dhcp_option(state, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
		dhcp_option_short(state, 576);

#if 0
		dhcp_option(state, DHCP_OPTION_REQUESTED_IP, 4);
		dhcp_option_long(state, ntohl(state->offered_ip_addr.addr));

		dhcp_option(state, DHCP_OPTION_SERVER_ID, 4);
		dhcp_option_long(state, ntohl(state->server_ip_addr.addr));
#endif

		dhcp_option_trailer(state);

		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);
		udp_send(state->pcb, state->p_out);
		udp_connect(state->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
		dhcp_delete_request(state);
	}
	state->tries++;
	msecs = state->tries < 10 ? state->tries * 1000 : 10 * 1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_rebind(): request timeout %u msecs", msecs));
	return result;
}

/**
 * Rebind with a DHCP server for an existing DHCP lease.
 * 
 */
static err_t dhcp_release(struct dhcp_state *state)
{
	err_t result;
	u16_t msecs;
	DEBUGF(DHCP_DEBUG, ("dhcp_release()"));
 	// and idle DHCP client
	dhcp_set_state(state, DHCP_OFF);

	// create and initialize the DHCP message header
	result = dhcp_create_request(state);
	if (result == ERR_OK)
	{
		dhcp_option(state, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
		dhcp_option_byte(state, DHCP_RELEASE);

		dhcp_option_trailer(state);

		pbuf_realloc(state->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + state->options_out_len);

		udp_bind(state->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
		udp_connect(state->pcb, &state->server_ip_addr, DHCP_SERVER_PORT);
		udp_send(state->pcb, state->p_out);
		dhcp_delete_request(state);
	}
	state->tries++;
	msecs = state->tries < 10 ? state->tries * 1000 : 10 * 1000;
	state->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
 	DEBUGF(DHCP_DEBUG, ("dhcp_release(): request timeout %u msecs", msecs));
  // remove IP address from interface
	netif_set_ipaddr(state->netif, IP_ADDR_ANY);
	netif_set_gw(state->netif, IP_ADDR_ANY);
	netif_set_netmask(state->netif, IP_ADDR_ANY);
	return result;
}
/**
 * Remove the DHCP client from the interface.
 *
 * @param state The DHCP client state 
 */
void dhcp_stop(struct dhcp_state *state)
{
	struct dhcp_state *list_state = client_list;
	DEBUGF(DHCP_DEBUG, ("dhcp_stop()"));
	ASSERT("dhcp_stop: state != NULL", state != NULL);
	ASSERT("dhcp_stop: state->pcb != NULL", state->pcb != NULL);

	if (state != NULL)
	{
    if (state->pcb != NULL)
    {
		  udp_remove(state->pcb);
      state->pcb = NULL;
    }
    if (state->p != NULL)
    {
		  pbuf_free(state->p);
      state->p = NULL;
    }
		mem_free((void *)state);
		// at head of list?
		if (list_state == state)
		{
			// remove ourselves from head
			client_list = state->next;
		}
		// not at head
		else
		{
			// see if we can find a predecessor?
			while ((list_state != NULL) && (list_state->next != state))
			{
				// proceed to next state, if any
				list_state = list_state->next;
			}
			// found a predecessor?
			if (list_state != NULL)
			{
				// remove ourselves from list
				list_state->next = state->next;
			}
		}
	}
}

static void dhcp_set_state(struct dhcp_state *state, unsigned char new_state)
{
  if (new_state != state->state)
  {
   	state->state = new_state;
    state->tries = 0;
  }
}


static void dhcp_option(struct dhcp_state *state, u8_t option_type, u8_t option_len)
{
  ASSERT("dhcp_option_short: state->options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN", state->options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN);
  state->msg_out->options[state->options_out_len++] = option_type;
  state->msg_out->options[state->options_out_len++] = option_len;
}
static void dhcp_option_byte(struct dhcp_state *state, u8_t value)
{
  ASSERT("dhcp_option_short: state->options_out_len < DHCP_OPTIONS_LEN", state->options_out_len < DHCP_OPTIONS_LEN);
  state->msg_out->options[state->options_out_len++] = value;
}														 
static void dhcp_option_short(struct dhcp_state *state, u16_t value)
{
  ASSERT("dhcp_option_short: state->options_out_len + 2 <= DHCP_OPTIONS_LEN", state->options_out_len + 2 <= DHCP_OPTIONS_LEN);
  state->msg_out->options[state->options_out_len++] = (value & 0xff00U) >> 8;
  state->msg_out->options[state->options_out_len++] =  value & 0x00ffU;
}
static void dhcp_option_long(struct dhcp_state *state, u32_t value)
{
  ASSERT("dhcp_option_long: state->options_out_len + 4 <= DHCP_OPTIONS_LEN", state->options_out_len + 4 <= DHCP_OPTIONS_LEN);
  state->msg_out->options[state->options_out_len++] = (value & 0xff000000UL) >> 24;
  state->msg_out->options[state->options_out_len++] = (value & 0x00ff0000UL) >> 16;
  state->msg_out->options[state->options_out_len++] = (value & 0x0000ff00UL) >> 8;
  state->msg_out->options[state->options_out_len++] = (value & 0x000000ffUL);
}

/**
 * Extract the dhcp_msg and options each into linear pieces of memory.
 *
 */
static err_t dhcp_unfold_reply(struct dhcp_state *state)
{
  struct pbuf *p = state->p;
	u8_t *ptr;
	u16_t i;
	u16_t j = 0;
	state->msg_in = NULL;
	state->options_in = NULL;
	// options present?
	if (state->p->tot_len > sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN)
	{
		state->options_in_len = state->p->tot_len - (sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN);
		state->options_in = mem_malloc(state->options_in_len);
		if (state->options_in == NULL)
		{
			DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): could not allocate state->options")); 
			return ERR_MEM;
		}
	}
	state->msg_in = mem_malloc(sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN);
	if (state->msg_in == NULL)
	{
		DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): could not allocate state->msg_in")); 
		mem_free((void *)state->options_in);
		state->options_in = NULL;
		return ERR_MEM;
	}

	ptr = (u8_t *)state->msg_in;
	// proceed through struct dhcp_msg
	for (i = 0; i < sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN; i++)
	{
		*ptr++ = ((u8_t *)p->payload)[j++];
		// reached end of pbuf?
		if (j == p->len)
		{
		  // proceed to next pbuf in chain
			p = p->next;
			j = 0;
		}
	}
	DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): copied %u bytes into state->msg_in[]", i)); 
	if (state->options_in != NULL)
	{
		ptr = (u8_t *)state->options_in;
		// proceed through options
		for (i = 0; i < state->options_in_len; i++)
		{
			*ptr++ = ((u8_t *)p->payload)[j++];
			// reached end of pbuf?
			if (j == p->len)
			{
  		  // proceed to next pbuf in chain
				p = p->next;
				j = 0;
			}
		}
		DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): copied %u bytes to state->options_in[]", i)); 
	}
	return ERR_OK;
}

/**
 * Extract the dhcp_msg and options into linear pieces of memory.
 *
 */
static void dhcp_free_reply(struct dhcp_state *state)
{
  mem_free((void *)state->msg_in);
	mem_free((void *)state->options_in);
  DEBUGF(DHCP_DEBUG, ("dhcp_free_reply(): freed")); 
  state->msg_in = NULL;
  state->options_in = NULL;
  state->options_in_len = 0;
}


/**
 * Match incoming DHCP messages against a DHCP client, and trigger its state machine
 */
static void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
  struct dhcp_state *state = (struct dhcp_state *)arg;
  struct dhcp_msg *reply_msg = (struct dhcp_msg *)p->payload;
  DEBUGF(DHCP_DEBUG, ("dhcp_recv()"));
  DEBUGF(DHCP_DEBUG, ("pbuf->len = %u", p->len));
  DEBUGF(DHCP_DEBUG, ("pbuf->tot_len = %u", p->tot_len));
  state->p = p;
  if (reply_msg->op == DHCP_BOOTREPLY)
  {
    DEBUGF(DHCP_DEBUG, ("state->netif->hwaddr = %02x:%02x:%02x:%02x:%02x:%02x",
      state->netif->hwaddr[0], state->netif->hwaddr[1], state->netif->hwaddr[2],
      state->netif->hwaddr[3], state->netif->hwaddr[4],	state->netif->hwaddr[5]));
    // TODO: Add multi network interface support, look up the targetted
    // interface here.
    if ((state->netif->hwaddr[0] == reply_msg->chaddr[0]) &&
        (state->netif->hwaddr[1] == reply_msg->chaddr[1]) &&
        (state->netif->hwaddr[2] == reply_msg->chaddr[2]) &&
        (state->netif->hwaddr[3] == reply_msg->chaddr[3]) &&
        (state->netif->hwaddr[4] == reply_msg->chaddr[4]) &&
        (state->netif->hwaddr[5] == reply_msg->chaddr[5]))
    {
      // check if the transaction ID matches
      if (ntohl(reply_msg->xid) == state->xid)
      {
        // option fields could be unfold?
        if (dhcp_unfold_reply(state) == ERR_OK)
        {
          u8_t *options_ptr = NULL;
          DEBUGF(DHCP_DEBUG, ("searching DHCP_OPTION_MESSAGE_TYPE")); 
          options_ptr = dhcp_get_option_ptr(state, DHCP_OPTION_MESSAGE_TYPE);
          if (options_ptr != NULL)
          {
            u8_t msg_type = dhcp_get_option_byte(options_ptr + 2);
            if (msg_type == DHCP_ACK)
            {
              DEBUGF(DHCP_DEBUG, ("DHCP_ACK received")); 
              if (state->state == DHCP_REQUESTING)
              {
                dhcp_handle_ack(state);
                state->request_timeout = 0;
#if DHCP_DOES_ARP_CHECK
                dhcp_check(state);
#else
                dhcp_bind(state);
#endif
              }
              else if ((state->state == DHCP_REBOOTING) || (state->state == DHCP_REBINDING) ||(state->state == DHCP_RENEWING))
              {
                state->request_timeout = 0;
                dhcp_bind(state);
              }
            }
            // received a DHCP_NAK in appropriate state?
            else if ((msg_type == DHCP_NAK) &&
              ((state->state == DHCP_REBOOTING) || (state->state == DHCP_REQUESTING) || 
              (state->state == DHCP_REBINDING) || (state->state == DHCP_RENEWING  )))
            {
              DEBUGF(DHCP_DEBUG, ("DHCP_NAK received")); 
              state->request_timeout = 0;
              dhcp_handle_nak(state);
            }
            // received a DHCP_OFFER in DHCP_SELECTING state?
            else if ((msg_type == DHCP_OFFER) && (state->state == DHCP_SELECTING))
            {
              DEBUGF(DHCP_DEBUG, ("DHCP_OFFER received in DHCP_SELECTING state")); 
              state->request_timeout = 0;
              dhcp_handle_offer(state);
            }
          }
          else
          {
            DEBUGF(DHCP_DEBUG, ("DHCP_OPTION_MESSAGE_TYPE option not found")); 
          }
          dhcp_free_reply(state);
        }
      }
      else
      {
        DEBUGF(DHCP_DEBUG, ("reply_msg->xid=%lx does not match with state->xid=%lx",
          ntohl(reply_msg->xid), state->xid)); 		
      }
    }
    else
    {
      DEBUGF(DHCP_DEBUG, ("hardware address did not match")); 		
      DEBUGF(DHCP_DEBUG, ("reply_msg->chaddr = %02x:%02x:%02x:%02x:%02x:%02x",
        reply_msg->chaddr[0], reply_msg->chaddr[1], reply_msg->chaddr[2],
        reply_msg->chaddr[3], reply_msg->chaddr[4],	reply_msg->chaddr[5]));
    }
  }
  else
  {
    DEBUGF(DHCP_DEBUG, ("not a DHCP reply message, but type %u", reply_msg->op));
  }

  pbuf_free(p);
}


static err_t dhcp_create_request(struct dhcp_state *state)
{
  u16_t i;
  ASSERT("dhcp_create_request: state->p_out == NULL", state->p_out == NULL);
  ASSERT("dhcp_create_request: state->msg_out == NULL", state->msg_out == NULL);
  state->p_out = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcp_msg), PBUF_RAM);
	if (state->p_out == NULL)
	{
   	DEBUGF(DHCP_DEBUG, ("dhcp_create_request(): could not allocate pbuf"));
    return ERR_MEM;
  }
  state->xid = xid;	
  xid++;

	state->msg_out = (struct dhcp_msg *)state->p_out->payload;

  state->msg_out->op = DHCP_BOOTREQUEST;	
  state->msg_out->htype = DHCP_HTYPE_ETH;	
  state->msg_out->hlen = DHCP_HLEN_ETH;	
  state->msg_out->hops = 0;
  state->msg_out->xid = htonl(state->xid);	
  state->msg_out->secs = 0;
  state->msg_out->flags = 0;
  state->msg_out->ciaddr = state->netif->ip_addr.addr;
  state->msg_out->yiaddr = 0;
  state->msg_out->siaddr = 0;
  state->msg_out->giaddr = 0;
  for (i = 0; i < DHCP_CHADDR_LEN; i++) state->msg_out->chaddr[i] = state->netif->hwaddr[i];
  for (i = 0; i < DHCP_SNAME_LEN; i++) state->msg_out->sname[i] = 0;
  for (i = 0; i < DHCP_FILE_LEN; i++) state->msg_out->file[i] = 0;
	state->msg_out->cookie = htonl(0x63825363UL);
	state->options_out_len = 0;
  // fill options field with an incrementing array (for debugging purposes)
  for (i = 0; i < DHCP_OPTIONS_LEN; i++) state->msg_out->options[i] = i;
  return ERR_OK;
}

static void dhcp_delete_request(struct dhcp_state *state)
{
  ASSERT("dhcp_free_msg: state->p_out != NULL", state->p_out != NULL);
  ASSERT("dhcp_free_msg: state->msg_out != NULL", state->msg_out != NULL);
  pbuf_free(state->p_out);
	state->p_out = NULL;
	state->msg_out = NULL;
}

/**
 * Add a DHCP message trailer
 *
 * Adds the END option to the DHCP message, and up to
 * three padding bytes.
 */

static void dhcp_option_trailer(struct dhcp_state *state)
{
  ASSERT("dhcp_option_trailer: state->msg_out != NULL", state->msg_out != NULL);
  ASSERT("dhcp_option_trailer: state->options_out_len < DHCP_OPTIONS_LEN", state->options_out_len < DHCP_OPTIONS_LEN);
  state->msg_out->options[state->options_out_len++] = DHCP_OPTION_END;
  // packet is still too small, or not 4 byte aligned?
  while ((state->options_out_len < DHCP_MIN_OPTIONS_LEN) || (state->options_out_len & 3))
	{
    //DEBUGF(DHCP_DEBUG, ("dhcp_option_trailer: state->options_out_len=%u, DHCP_OPTIONS_LEN=%u", state->options_out_len, DHCP_OPTIONS_LEN));
    ASSERT("dhcp_option_trailer: state->options_out_len < DHCP_OPTIONS_LEN", state->options_out_len < DHCP_OPTIONS_LEN);
	  state->msg_out->options[state->options_out_len++] = 0;
	}
}

/**
 * Find the offset of a DHCP option inside the DHCP message.
 *
 * @param client DHCP client
 * @param option_type
 *
 * @return a byte offset into the UDP message where the option was found, or
 * zero if the given option was not found.
 */
static u8_t *dhcp_get_option_ptr(struct dhcp_state *state, u8_t option_type)
{
  u8_t overload = DHCP_OVERLOAD_NONE;

	// options available?
	if ((state->options_in != NULL) && (state->options_in_len > 0))
	{
	  // start with options field
	  u8_t *options = (u8_t *)state->options_in;
	  u16_t offset = 0;
		// at least 1 byte to read and no end marker, then at least 3 bytes to read?
		while ((offset < state->options_in_len) && (options[offset] != DHCP_OPTION_END))
    {
    	//DEBUGF(DHCP_DEBUG, ("msg_offset=%u, q->len=%u", msg_offset, q->len));
      // are the sname and/or file field overloaded with options?
		  if (options[offset] == DHCP_OPTION_OVERLOAD)
			{
   			DEBUGF(DHCP_DEBUG, ("overloaded message detected"));
			  // skip option type and length
			  offset += 2;
				overload = options[offset++];
			}
			// requested option found
			else if (options[offset] == option_type)
			{
   			DEBUGF(DHCP_DEBUG, ("option found at offset %u in options", offset));
			  return &options[offset];
			}
			// skip option
	 		else
			{
   			DEBUGF(DHCP_DEBUG, ("skipping option %u in options", options[offset]));
				// skip option type
			  offset++;
				// skip option length, and then length bytes
				offset += 1 + options[offset];
			}
		}
		// is this an overloaded message?
		if (overload != DHCP_OVERLOAD_NONE)
		{
		  u16_t field_len;
		  if (overload == DHCP_OVERLOAD_FILE)
			{
  			DEBUGF(DHCP_DEBUG, ("overloaded file field"));
			  options = (u8_t *)&state->msg_in->file;
  		  field_len = DHCP_FILE_LEN;
			}
		  else if (overload == DHCP_OVERLOAD_SNAME)
			{
  			DEBUGF(DHCP_DEBUG, ("overloaded sname field"));
			  options = (u8_t *)&state->msg_in->sname;
  		  field_len = DHCP_SNAME_LEN;
			}
		  else // TODO: check if else if () is necessary
			{
  			DEBUGF(DHCP_DEBUG, ("overloaded sname and file field"));
			  options = (u8_t *)&state->msg_in->sname;
  		  field_len = DHCP_FILE_LEN + DHCP_SNAME_LEN;
			}
      offset = 0;

  		// at least 1 byte to read and no end marker
  		while ((offset < field_len) && (options[offset] != DHCP_OPTION_END))
      {
  			if (options[offset] == option_type)
  			{
     			DEBUGF(DHCP_DEBUG, ("option found at offset=%u", offset));
  			  return &options[offset];
  			}
  			// skip option
  	 		else
  			{
     			DEBUGF(DHCP_DEBUG, ("skipping option %u", options[offset]));
  				// skip option type
  			  offset++;
  				offset += 1 + options[offset];
  			}
	  	}
		}
	}
	return 0;
}

/**
 * Return the byte of DHCP option data.
 *
 * @param client DHCP client.
 * @param ptr pointer obtained by dhcp_get_option_ptr().
 *
 * @return byte value at the given address.
 */
static u8_t dhcp_get_option_byte(u8_t *ptr)
{
	DEBUGF(DHCP_DEBUG, ("option byte value=%u", *ptr));
	return *ptr;
}														 

/**
 * Return the 16-bit value of DHCP option data.
 *
 * @param client DHCP client.
 * @param ptr pointer obtained by dhcp_get_option_ptr().
 *
 * @return byte value at the given address.
 */
static u16_t dhcp_get_option_short(u8_t *ptr)
{
  u16_t value;
	value = *ptr++ << 8;
	value |= *ptr;
	DEBUGF(DHCP_DEBUG, ("option short value=%u", value));
  return value;
}														 

/**
 * Return the 32-bit value of DHCP option data.
 *
 * @param client DHCP client.
 * @param ptr pointer obtained by dhcp_get_option_ptr().
 *
 * @return byte value at the given address.
 */
static u32_t dhcp_get_option_long(u8_t *ptr)
{
  u32_t value;
	value = (u32_t)(*ptr++) << 24;
	value |= (u32_t)(*ptr++) << 16;
	value |= (u32_t)(*ptr++) << 8;
	value |= (u32_t)(*ptr++);
	DEBUGF(DHCP_DEBUG, ("option long value=%lu", value));
	return value;
}														 

/**
 * Find the DHCP client attached to a network interface.
 *
 * Given an network interface, return the corresponding dhcp state
 * or NULL if the interface was not under DHCP control.
 */
struct dhcp_state *dhcp_find_client(struct netif *netif)
{
	struct dhcp_state *state = NULL;
	struct dhcp_state *list_state = client_list;

	DEBUGF(DHCP_DEBUG, ("dhcp_find_client()"));
  while ((state == NULL) && (list_state != NULL))
	{
   	DEBUGF(DHCP_DEBUG, ("dhcp_find_client(): checking state %p", list_state));
	  // this interface already has a DHCP client attached
	  if (list_state->netif == netif)
	  {
	    state = list_state;
     	DEBUGF(DHCP_DEBUG, ("dhcp_find_client(): interface already under DHCP control"));
		}
		if (list_state->next != NULL)
		{	  
      // select the next client state
		  list_state = list_state->next;
		}
		// reached end of list
		else
		{
     	DEBUGF(DHCP_DEBUG, ("dhcp_find_client(): end of list reached"));
		  break;
			// { state == NULL } 
			// { list_state is last item in list } 
		}
	}
	return state;
}
