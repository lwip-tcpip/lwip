/*
 * Copyright (c) 2001-2003 Leon Woestenberg <leon.woestenberg@gmx.net>
 * Copyright (c) 2001-2003 Axon Digital Design B.V., The Netherlands.
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
 * Author: Leon Woestenberg <leon.woestenberg@gmx.net>
 * 
 * This is a DHCP client for the lwIP TCP/IP stack. It aims to conform
 * with RFC 2131 and RFC 2132.
 *
 * TODO:
 * - Proper parsing of DHCP messages exploiting file/sname field overloading.
 * - Add JavaDoc style documentation (API, internals).
 * - Support for interfaces other than Ethernet (SLIP, PPP, ...)
 *
 * Please coordinate changes and requests with Leon Woestenberg
 * <leon.woestenberg@gmx.net>
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
 * dhcp_start(struct netif *netif);
 * starts a DHCP client instance which configures the interface by
 * obtaining an IP address lease and maintaining it.
 *
 * Use dhcp_release(netif) to end the lease and use dhcp_stop(netif)
 * to remove the DHCP client.
 *
 */
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/netif.h"
#include "netif/etharp.h"

#include "lwip/sys.h"
#include "lwipopts.h"
#include "lwip/dhcp.h"

/** transaction identifier, unique over all DHCP requests */
static u32_t xid = 0xABCD0000;

/** DHCP client state machine functions */
static void dhcp_handle_ack(struct dhcp *dhcp);
static void dhcp_handle_nak(struct dhcp *dhcp);
static void dhcp_handle_offer(struct dhcp *dhcp);

static err_t dhcp_discover(struct netif *netif);
static err_t dhcp_select(struct netif *netif);
static void dhcp_check(struct netif *netif);
static void dhcp_bind(struct netif *netif);
static err_t dhcp_decline(struct netif *netif);
static err_t dhcp_rebind(struct netif *netif);
static err_t dhcp_release(struct netif *netif);
static void dhcp_set_state(struct dhcp *dhcp, unsigned char new_state);

/** receive, unfold, parse and free incoming messages */
static void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port);
static err_t dhcp_unfold_reply(struct dhcp *dhcp);
static u8_t *dhcp_get_option_ptr(struct dhcp *dhcp, u8_t option_type);
static u8_t dhcp_get_option_byte(u8_t *ptr);
static u16_t dhcp_get_option_short(u8_t *ptr);
static u32_t dhcp_get_option_long(u8_t *ptr);
static void dhcp_free_reply(struct dhcp *dhcp);

/** set the DHCP timers */
static void dhcp_timeout(struct netif *netif);
static void dhcp_t1_timeout(struct dhcp *dhcp);
static void dhcp_t2_timeout(struct dhcp *dhcp);

/** build outgoing messages */
static err_t dhcp_create_request(struct dhcp *dhcp);
static void dhcp_delete_request(struct dhcp *dhcp);
static void dhcp_option(struct dhcp *dhcp, u8_t option_type, u8_t option_len);
static void dhcp_option_byte(struct dhcp *dhcp, u8_t value);
static void dhcp_option_short(struct dhcp *dhcp, u16_t value);
static void dhcp_option_long(struct dhcp *dhcp, u32_t value);
static void dhcp_option_trailer(struct dhcp *dhcp);

/**
 * Back-off the DHCP client (because of a received NAK response).
 *
 * Back-off the DHCP client because of a received NAK. Receiving a
 * NAK means the client asked for something non-sensible, for
 * example when it tries to renew a lease obtained on another network.
 *
 * We back-off and will end up restarting a fresh DHCP negotiation later.
 *
 * @param state pointer to DHCP state structure
 */ 
static void dhcp_handle_nak(struct dhcp *dhcp) {
  struct dhcp *dhcp = netif->dhcp;
  u16_t msecs = 10 * 1000;
  DEBUGF(DHCP_DEBUG, ("dhcp_handle_nak()"));
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
  DEBUGF(DHCP_DEBUG, ("dhcp_handle_nak(): set request timeout %u msecs", msecs));
  dhcp_set_state(dhcp, DHCP_BACKING_OFF);
}

/**
 * Checks if the offered address from the server is already in use.
 * 
 * It does so by sending an ARP request for the offered address and
 * entering CHECKING state. If no ARP reply is received within a small
 * interval, the address is assumed to be free for use by us.
 */
static void dhcp_check(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  struct pbuf *p;
  err_t result;
  u16_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_check()"));
  /* create an ARP query for the offered IP address, expecting that no host
     responds, as the IP address should not be in use. */
  p = etharp_query(netif, &dhcp->offered_ip_addr, NULL);
  if (p != NULL) {
    DEBUGF(DHCP_DEBUG, ("dhcp_check(): sending ARP request len %u", p->tot_len));
    result = dhcp->netif->linkoutput(netif, p);
    pbuf_free(p);
    p = NULL;
  }
  dhcp->tries++;
  msecs = 500;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
  DEBUGF(DHCP_DEBUG, ("dhcp_check(): set request timeout %u msecs", msecs));
  dhcp_set_state(dhcp, DHCP_CHECKING);
}

/**
 * Remember the configuration offered by a DHCP server.
 * 
 * @param state pointer to DHCP state structure
 */
static void dhcp_handle_offer(struct dhcp *dhcp)
{
  /* obtain the server address */
  u8_t *option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_SERVER_ID);
  if (option_ptr != NULL)
  {
    dhcp->server_ip_addr.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
    DEBUGF(DHCP_DEBUG, ("dhcp_handle_offer(): server 0x%08lx", dhcp->server_ip_addr.addr));
    /* remember offered address */
    ip_addr_set(&dhcp->offered_ip_addr, (struct ip_addr *)&dhcp->msg_in->yiaddr);
    DEBUGF(DHCP_DEBUG, ("dhcp_handle_offer(): offer for 0x%08lx", dhcp->offered_ip_addr.addr));
    dhcp_select(dhcp);
  }
}

/**
 * Select a DHCP server offer out of all offers.
 *
 * Simply select the first offer received.
 *
 * @param dhcp pointer to DHCP state structure
 * @return lwIP specific error (see error.h)
 */
static err_t dhcp_select(struct dhcp *dhcp)
{
  err_t result;
  u32_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_select()"));

  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK)
  {
    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_REQUEST);

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, 576);

    /* MUST request the offered IP address */
    dhcp_option(dhcp, DHCP_OPTION_REQUESTED_IP, 4);
    dhcp_option_long(dhcp, ntohl(dhcp->offered_ip_addr.addr));

    dhcp_option(dhcp, DHCP_OPTION_SERVER_ID, 4);
    dhcp_option_long(dhcp, ntohl(dhcp->server_ip_addr.addr));

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, 3);
    dhcp_option_byte(dhcp, DHCP_OPTION_SUBNET_MASK);
    dhcp_option_byte(dhcp, DHCP_OPTION_ROUTER);
    dhcp_option_byte(dhcp, DHCP_OPTION_BROADCAST);

    dhcp_option_trailer(dhcp);
    /* shrink the pbuf to the actual content length */
    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    /* TODO: we really should bind to a specific local interface here
       but we cannot specify an unconfigured netif as it is addressless */
    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    /* send broadcast to any DHCP server */
    udp_connect(dhcp->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);
    udp_send(dhcp->pcb, dhcp->p_out);
    /* reconnect to any (or to server here?!) */
    udp_connect(dhcp->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
    dhcp_delete_request(dhcp);
  }
  dhcp->tries++;
  msecs = dhcp->tries < 4 ? dhcp->tries * 1000 : 4 * 1000;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
  DEBUGF(DHCP_DEBUG, ("dhcp_select(): set request timeout %u msecs", msecs));
  dhcp_set_state(dhcp, DHCP_REQUESTING);
  return result;
}

/**
 * The DHCP timer that checks for lease renewal/rebind timeouts.
 *
 */
void dhcp_coarse_tmr()
{
  struct netif *netif = netif_list;
  DEBUGF(DHCP_DEBUG, ("dhcp_coarse_tmr():"));
  /* iterate through all network interfaces */
  while (netif != NULL) {
    /* only act on DHCP configured interfaces */
    if (netif->dhcp != NULL) {
      /* timer is active (non zero), and triggers (zeroes) now? */
      if (netif->dhcp->t2_timeout-- == 1) {
        DEBUGF(DHCP_DEBUG, ("dhcp_coarse_tmr(): t2 timeout"));
        /* this clients' rebind timeout triggered */
        dhcp_t2_timeout(netif);
      /* timer is active (non zero), and triggers (zeroes) now */
      } else if (netif->dhcp->t1_timeout-- == 1) {
        DEBUGF(DHCP_DEBUG, ("dhcp_coarse_tmr(): t1 timeout"));
        /* this clients' renewal timeout triggered */
        dhcp_t1_timeout(netif);
      }
    }
    /* proceed to next netif */
    netif = netif->next;
  }
}

/**
 * The DHCP timer that handles DHCP negotiation transaction timeouts.
 *
 */
void dhcp_fine_tmr()
{
  struct netif *netif = netif_list;
  /* loop through clients */
  while (netif != NULL) {
    /* only act on DHCP configured interfaces */
    if (netif->dhcp != NULL) {
      /* timer is active (non zero), and triggers (zeroes) now */
      if (netif->dhcp->request_timeout-- == 1) {
        DEBUGF(DHCP_DEBUG, ("dhcp_fine_tmr(): request timeout"));
        /* this clients' request timeout triggered */
        dhcp_timeout(netif);
      }
    }
    /* proceed to next network interface */
    netif = netif->next;
  }
}

/**
 * A DHCP negotiation transaction, or ARP request, has timed out.
 *
 * The timer that was started with the DHCP or ARP request has
 * timed out, indicating no response was received. 
 *
 * @param dhcp pointer to DHCP state structure
 * 
 */
static void dhcp_timeout(struct netif *netif)
{
  DEBUGF(DHCP_DEBUG, ("dhcp_timeout()"));
  /* back-off period has passed, or server selection timed out */
  if ((dhcp->state == DHCP_BACKING_OFF) || (dhcp->state == DHCP_SELECTING)) {
    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): restarting discovery"));
    dhcp_discover(dhcp);
  /* receiving the requested lease timed out */
  } else if (dhcp->state == DHCP_REQUESTING) {
    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): REQUESTING, DHCP request timed out"));
    if (dhcp->tries <= 5) {
      dhcp_select(dhcp);
    } else {
      DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): REQUESTING, releasing, restarting"));
      dhcp_release(dhcp);
      dhcp_discover(dhcp);
    }
  /* received no ARP reply for the offered address (which is good) */
  } else if (dhcp->state == DHCP_CHECKING) {
    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): CHECKING, ARP request timed out"));
    if (dhcp->tries <= 1) {
      dhcp_check(netif);
    /* no ARP replies on the offered address, 
       looks like the IP address is indeed free */
    } else {
      /* bind the interface to the offered address */
      dhcp_bind(netif);
    }
  }
  /* did not get response to renew request? */
  else if (dhcp->state == DHCP_RENEWING) {
    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): RENEWING, DHCP request timed out"));
    /* just retry renewal */ 
    /* note that the rebind timer will eventually time-out if renew does not work */
    dhcp_renew(dhcp);
  /* did not get response to rebind request? */
  } else if (dhcp->state == DHCP_REBINDING) {
    DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): REBINDING, DHCP request timed out"));
    if (dhcp->tries <= 8) {
      dhcp_rebind(dhcp);
    } else {
      DEBUGF(DHCP_DEBUG, ("dhcp_timeout(): RELEASING, DISCOVERING"));
      dhcp_release(dhcp);
      dhcp_discover(dhcp);
    }
  }
}

/**
 * The renewal period has timed out.
 *
 * @param dhcp pointer to DHCP state structure
 */
static void dhcp_t1_timeout(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  DEBUGF(DHCP_DEBUG, ("dhcp_t1_timeout()"));
  if ((dhcp->state == DHCP_REQUESTING) || (dhcp->state == DHCP_BOUND) || (dhcp->state == DHCP_RENEWING)) {
    /* just retry to renew */
    /* note that the rebind timer will eventually time-out if renew does not work */
    DEBUGF(DHCP_DEBUG, ("dhcp_t1_timeout(): must renew"));
    dhcp_renew(netif);
  }
}

/**
 * The rebind period has timed out.
 *
 */
static void dhcp_t2_timeout(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  DEBUGF(DHCP_DEBUG, ("dhcp_t2_timeout()"));
  if ((dhcp->state == DHCP_REQUESTING) || (dhcp->state == DHCP_BOUND) || (dhcp->state == DHCP_RENEWING)) {
    /* just retry to rebind */
    DEBUGF(DHCP_DEBUG, ("dhcp_t2_timeout(): must rebind"));
    dhcp_rebind(netif);
  }
}

/**
 * Extract options from the server ACK message.
 *
 * @param dhcp pointer to DHCP state structure
 */
static void dhcp_handle_ack(struct dhcp *dhcp)
{
  u8_t *option_ptr;
  /* clear options we might not get from the ACK */
  dhcp->offered_sn_mask.addr = 0;
  dhcp->offered_gw_addr.addr = 0;
  dhcp->offered_bc_addr.addr = 0;

  /* lease time given? */
  option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_LEASE_TIME);
  if (option_ptr != NULL) {
    /* remember offered lease time */
    dhcp->offered_t0_lease = dhcp_get_option_long(option_ptr + 2);
  }
  /* renewal period given? */
  option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_T1);
  if (option_ptr != NULL) {
    /* remember given renewal period */
    dhcp->offered_t1_renew = dhcp_get_option_long(option_ptr + 2);
  } else {
    /* calculate safe periods for renewal */
    dhcp->offered_t1_renew = dhcp->offered_t0_lease / 2;
  }

  /* renewal period given? */
  option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_T2);
  if (option_ptr != NULL) {
    /* remember given rebind period */
    dhcp->offered_t2_rebind = dhcp_get_option_long(option_ptr + 2);
  } else {
    /* calculate safe periods for rebinding */
    dhcp->offered_t2_rebind = dhcp->offered_t0_lease;
  }

  /* (y)our internet address */
  ip_addr_set(&dhcp->offered_ip_addr, &dhcp->msg_in->yiaddr);

  /* subnet mask */
  option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_SUBNET_MASK);
  /* subnet mask given? */
  if (option_ptr != NULL) {
    dhcp->offered_sn_mask.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
  }

  /* gateway router */
  option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_ROUTER);
  if (option_ptr != NULL) {
    dhcp->offered_gw_addr.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
  }

  /* broadcast address */
  option_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_BROADCAST);
  if (option_ptr != NULL) {
    dhcp->offered_bc_addr.addr = htonl(dhcp_get_option_long(&option_ptr[2]));
  }
}

/**
 * Start DHCP negotiation for a network interface.
 *
 * If no DHCP client instance was attached to this interface,
 * a new client is created first. If a DHCP client instance
 * was already present, it restarts negotiation.
 *
 * @param netif The lwIP network interface 
 * @return The DHCP client state, which must be passed for 
 * all subsequential dhcp_*() calls. NULL means there is
 * no (longer a) DHCP client attached to the interface
 * (due to unavailable memory or network resources).
 *
 */
struct dhcp *dhcp_start(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  err_t result = ERR_OK;

  DEBUGF(DHCP_DEBUG, ("dhcp_start(netif=%c%c%u)", netif->, netif->, netif->num));

  if (dhcp == NULL) {
    DEBUGF(DHCP_DEBUG, ("dhcp_start(): starting new DHCP client"));
    dhcp = mem_malloc(sizeof(struct dhcp));
    if (dhcp == NULL) {
      DEBUGF(DHCP_DEBUG, ("dhcp_start(): could not allocate dhcp"));
      netif->flags &= ~NETIF_FLAG_DHCP;
      return ERR_MEM;
    }
    /* clear data structure */
    memset(dhcp, 0, sizeof(struct dhcp));
    DEBUGF(DHCP_DEBUG, ("dhcp_start(): allocated dhcp"));
    dhcp->pcb = udp_new();
    if (dhcp->pcb == NULL) {
      DEBUGF(DHCP_DEBUG, ("dhcp_start(): could not obtain pcb"));
      mem_free((void *)dhcp);
      dhcp = NULL;
      netif->flags &= ~NETIF_FLAG_DHCP;
      return ERR_MEM;
    }
    /* store this dhcp client in the netif */
    netif->dhcp = dhcp;
    DEBUGF(DHCP_DEBUG, ("dhcp_start(): created new udp pcb"));
    DEBUGF(DHCP_DEBUG, ("dhcp_start(): starting DHCP configuration"));
  } else {
    DEBUGF(DHCP_DEBUG, ("dhcp_start(): restarting DHCP configuration"));
  }
  /* (re)start the DHCP negotiation */
  result = dhcp_discover(netif);
  if (result != ERR_OK) {
    /* free resources allocated above */
    dhcp_stop(netif);
  }
  return result;
}

/**
 * Inform a DHCP server of our manual configuration.
 * 
 * This informs DHCP servers of our fixed IP address configuration
 * by sending an INFORM message. It does not involve DHCP address
 * configuration, it is just here to be nice to the network.
 *
 * @param netif The lwIP network interface 
 *
 */ 
void dhcp_inform(struct netif *netif)
{
  struct dhcp *dhcp;
  err_t result = ERR_OK;
  dhcp = mem_malloc(sizeof(struct dhcp));
  if (dhcp == NULL) {
    DEBUGF(DHCP_DEBUG, ("dhcp_inform(): could not allocate dhcp"));
    return;
  }  
  memset(dhcp, 0, sizeof(struct dhcp));

  DEBUGF(DHCP_DEBUG, ("dhcp_inform(): allocated dhcp"));
  dhcp->pcb = udp_new();
  if (dhcp->pcb == NULL) {
    DEBUGF(DHCP_DEBUG, ("dhcp_inform(): could not obtain pcb"));
    mem_free((void *)dhcp);
    return;
  }
  DEBUGF(DHCP_DEBUG, ("dhcp_inform(): created new udp pcb"));
  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK) {

    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_INFORM);

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    /* TODO: use netif->mtu ?! */
    dhcp_option_short(dhcp, 576);

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);
    udp_send(dhcp->pcb, dhcp->p_out);
    udp_connect(dhcp->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
    dhcp_delete_request(dhcp);
  }

  if (dhcp != NULL)
  {
    if (dhcp->pcb != NULL) udp_remove(dhcp->pcb);
    dhcp->pcb = NULL;
    mem_free((void *)dhcp);
  }
}

#if DHCP_DOES_ARP_CHECK
/**
 * Match an ARP reply with the offered IP address.
 *
 * @param addr The IP address we received a reply from
 *
 */
void dhcp_arp_reply(struct netif *netif, struct ip_addr *addr)
{
  DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply()"));
  /* is this DHCP client doing an ARP check? */
  if ((netif->dhcp != NULL) && (netif->dhcp->state == DHCP_CHECKING)) {
    DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply(): CHECKING, arp reply for 0x%08lx", addr->addr));
    /* did a host respond with the address we
       were offered by the DHCP server? */
    if (ip_addr_cmp(addr, &dhcp->offered_ip_addr)) {
      /* we will not accept the offered address */
      DEBUGF(DHCP_DEBUG, ("dhcp_arp_reply(): arp reply matched with offered address, declining"));
      dhcp_decline(netif);
    }
  }
}

/** 
 * Decline an offered lease.
 *
 * Tell the DHCP server we do not accept the offered address.
 * One reason to decline the lease is when we find out the address
 * is already in use by another host (through ARP).
 */
static err_t dhcp_decline(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  err_t result = ERR_OK;
  u16_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_decline()"));
  dhcp_set_state(dhcp, DHCP_BACKING_OFF);
  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK)
  {
    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_DECLINE);

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, 576);

    dhcp_option_trailer(dhcp);
    /* resize pbuf to reflect true size of options */
    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, &dhcp->server_ip_addr, DHCP_SERVER_PORT);
    udp_send(dhcp->pcb, dhcp->p_out);
    dhcp_delete_request(dhcp);
  }
  dhcp->tries++;
  msecs = 10*1000;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
   DEBUGF(DHCP_DEBUG, ("dhcp_decline(): set request timeout %u msecs", msecs));
  return result;
}
#endif


/**
 * Start the DHCP process, discover a DHCP server.
 *
 */
static err_t dhcp_discover(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  err_t result = ERR_OK;
  u16_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_discover()"));
  ip_addr_set(&dhcp->offered_ip_addr, IP_ADDR_ANY);
  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK)
  {
    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_DISCOVER);

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, 576);

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, 3);
    dhcp_option_byte(dhcp, DHCP_OPTION_SUBNET_MASK);
    dhcp_option_byte(dhcp, DHCP_OPTION_ROUTER);
    dhcp_option_byte(dhcp, DHCP_OPTION_BROADCAST);

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    /* set receive callback function with netif as user data */
    udp_recv(dhcp->pcb, dhcp_recv, netif);
    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);

    udp_send(dhcp->pcb, dhcp->p_out);
    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
    dhcp_delete_request(dhcp);
  }
  dhcp->tries++;
  msecs = dhcp->tries < 4 ? (dhcp->tries + 1) * 1000 : 10 * 1000;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
   DEBUGF(DHCP_DEBUG, ("dhcp_discover(): set request timeout %u msecs", msecs));
  dhcp_set_state(dhcp, DHCP_SELECTING);
  return result;
}


/**
 * Bind the interface to the offered IP address.
 *
 * @param netif network interface to bind to the offered address
 */
static void dhcp_bind(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  struct ip_addr sn_mask, gw_addr;
  
  /* temporary DHCP lease? */
  if (dhcp->offered_t1_renew != 0xffffffffUL) {
    /* set renewal period timer */
    DEBUGF(DHCP_DEBUG, ("dhcp_bind(): t1 renewal timer %lu secs", dhcp->offered_t1_renew));
    dhcp->t1_timeout = (dhcp->offered_t1_renew + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
    if (dhcp->t1_timeout == 0) dhcp->t1_timeout = 1;
    DEBUGF(DHCP_DEBUG, ("dhcp_bind(): set request timeout %u msecs", dhcp->offered_t1_renew*1000));
  }
  /* set renewal period timer */
  if (dhcp->offered_t2_rebind != 0xffffffffUL) {
    DEBUGF(DHCP_DEBUG, ("dhcp_bind(): t2 rebind timer %lu secs", dhcp->offered_t2_rebind));
    dhcp->t2_timeout = (dhcp->offered_t2_rebind + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
    if (dhcp->t2_timeout == 0) dhcp->t2_timeout = 1;
    DEBUGF(DHCP_DEBUG, ("dhcp_bind(): set request timeout %u msecs", dhcp->offered_t2_rebind*1000));
  }
  /* copy offered network mask */
  ip_addr_set(&sn_mask, &dhcp->offered_sn_mask);

  /* subnet mask not given? */
  /* TODO: this is not a valid check. what if the network mask is 0??!! */
  if (sn_mask.addr == 0) {
    /* choose a safe subnet mask given the network class */
    u8_t first_octet = ip4_addr1(&sn_mask);
    if (first_octet <= 127) sn_mask.addr = htonl(0xff000000);
    else if (first_octet >= 192) sn_mask.addr = htonl(0xffffff00);
    else sn_mask.addr = htonl(0xffff0000);
  }

  ip_addr_set(&gw_addr, &dhcp->offered_gw_addr);
  /* gateway address not given? */
  if (gw_addr.addr == 0) {
    /* copy network address */
    gw_addr.addr = (&dhcp->offered_ip_addr & sn_mask.addr);
    /* use first host address on network as gateway */
    gw_addr.addr |= htonl(0x00000001);
  }

  DEBUGF(DHCP_DEBUG, ("dhcp_bind(): IP: 0x%08lx", dhcp->offered_ip_addr.addr));
  netif_set_ipaddr(netif, &dhcp->offered_ip_addr);
  DEBUGF(DHCP_DEBUG, ("dhcp_bind(): SN: 0x%08lx", sn_mask.addr));
  netif_set_netmask(netif, &sn_mask);
  DEBUGF(DHCP_DEBUG, ("dhcp_bind(): GW: 0x%08lx", gw_addr.addr));
  netif_set_gw(netif, &gw_addr);
  /* netif is now bound to DHCP leased address */
  dhcp_set_state(dhcp, DHCP_BOUND);
}

/**
 * Renew an existing DHCP lease at the involved DHCP server.
 * 
 * @param netif network interface which must renew its lease
 */
err_t dhcp_renew(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  err_t result;
  u16_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_renew()"));
  dhcp_set_state(dhcp, DHCP_RENEWING);

  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK) {

    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_REQUEST);

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    /* TODO: use netif->mtu in some way */
    dhcp_option_short(dhcp, 576);

#if 0
    dhcp_option(dhcp, DHCP_OPTION_REQUESTED_IP, 4);
    dhcp_option_long(dhcp, ntohl(dhcp->offered_ip_addr.addr));
#endif

#if 0
    dhcp_option(dhcp, DHCP_OPTION_SERVER_ID, 4);
    dhcp_option_long(dhcp, ntohl(dhcp->server_ip_addr.addr));
#endif
    /* append DHCP message trailer */
    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, &dhcp->server_ip_addr, DHCP_SERVER_PORT);
    udp_send(dhcp->pcb, dhcp->p_out);
    dhcp_delete_request(dhcp);
  }
  dhcp->tries++;
  /* back-off on retries, but to a maximum of 20 seconds */
  msecs = dhcp->tries < 10 ? dhcp->tries * 2000 : 20 * 1000;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
   DEBUGF(DHCP_DEBUG, ("dhcp_renew(): set request timeout %u msecs", msecs));
  return result;
}

/**
 * Rebind with a DHCP server for an existing DHCP lease.
 * 
 * @param netif network interface which must rebind with a DHCP server
 */
static err_t dhcp_rebind(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  err_t result;
  u16_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_rebind()"));
  dhcp_set_state(dhcp, DHCP_REBINDING);

  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK)
  {

    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_REQUEST);

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, 576);

#if 0
    dhcp_option(dhcp, DHCP_OPTION_REQUESTED_IP, 4);
    dhcp_option_long(dhcp, ntohl(dhcp->offered_ip_addr.addr));

    dhcp_option(dhcp, DHCP_OPTION_SERVER_ID, 4);
    dhcp_option_long(dhcp, ntohl(dhcp->server_ip_addr.addr));
#endif

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, IP_ADDR_BROADCAST, DHCP_SERVER_PORT);
    udp_send(dhcp->pcb, dhcp->p_out);
    udp_connect(dhcp->pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
    dhcp_delete_request(dhcp);
  }
  dhcp->tries++;
  msecs = dhcp->tries < 10 ? dhcp->tries * 1000 : 10 * 1000;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
   DEBUGF(DHCP_DEBUG, ("dhcp_rebind(): set request timeout %u msecs", msecs));
  return result;
}

/**
 * Release a DHCP lease.
 * 
 * @param netif network interface which must release its lease
 */
static err_t dhcp_release(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  err_t result;
  u16_t msecs;
  DEBUGF(DHCP_DEBUG, ("dhcp_release()"));
  /* idle DHCP client */
  dhcp_set_state(dhcp, DHCP_OFF);

  /* create and initialize the DHCP message header */
  result = dhcp_create_request(dhcp);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    dhcp_option_byte(dhcp, DHCP_RELEASE);

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN + dhcp->options_out_len);

    udp_bind(dhcp->pcb, IP_ADDR_ANY, DHCP_CLIENT_PORT);
    udp_connect(dhcp->pcb, &dhcp->server_ip_addr, DHCP_SERVER_PORT);
    udp_send(dhcp->pcb, dhcp->p_out);
    dhcp_delete_request(dhcp);
  }
  dhcp->tries++;
  msecs = dhcp->tries < 10 ? dhcp->tries * 1000 : 10 * 1000;
  dhcp->request_timeout = (msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS;
   DEBUGF(DHCP_DEBUG, ("dhcp_release(): set request timeout %u msecs", msecs));
  /* remove IP address from interface */
  netif_set_ipaddr(netif, IP_ADDR_ANY);
  netif_set_gw(netif, IP_ADDR_ANY);
  netif_set_netmask(netif, IP_ADDR_ANY);
  /* TODO: netif_down(netif); */
  return result;
}
/**
 * Remove the DHCP client from the interface.
 *
 * @param netif The network interface to stop DHCP on
 */
void dhcp_stop(struct netif *netif)
{
  struct dhcp *dhcp = netif->dhcp;
  DEBUGF(DHCP_DEBUG, ("dhcp_stop()"));
  LWIP_ASSERT("dhcp_stop: dhcp != NULL", dhcp != NULL);
  LWIP_ASSERT("dhcp_stop: dhcp->pcb != NULL", dhcp->pcb != NULL);
  /* netif is DHCP configured? */
  if (dhcp != NULL)
  {
    if (dhcp->pcb != NULL)
    {
      udp_remove(dhcp->pcb);
      dhcp->pcb = NULL;
    }
    if (dhcp->p != NULL)
    {
      pbuf_free(dhcp->p);
      dhcp->p = NULL;
    }
    mem_free((void *)dhcp);
    netif->dhcp = NULL;
  }
}

/*
 * Set the DHCP state of a DHCP client.
 * 
 * If the state changed, reset the number of tries.
 *
 * TODO: we might also want to reset the timeout here?
 */
static void dhcp_set_state(struct dhcp *dhcp, unsigned char new_state)
{
  if (new_state != dhcp->state)
  {
    dhcp->state = new_state;
    dhcp->tries = 0;
  }
}

/*
 * Concatenate an option type and length field to the outgoing
 * DHCP message.
 *
 */
static void dhcp_option(struct dhcp *dhcp, u8_t option_type, u8_t option_len)
{
  LWIP_ASSERT("dhcp_option_short: dhcp->options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN", dhcp->options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = option_type;
  dhcp->msg_out->options[dhcp->options_out_len++] = option_len;
}
/*
 * Concatenate a single byte to the outgoing DHCP message.
 *
 */
static void dhcp_option_byte(struct dhcp *dhcp, u8_t value)
{
  LWIP_ASSERT("dhcp_option_short: dhcp->options_out_len < DHCP_OPTIONS_LEN", dhcp->options_out_len < DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = value;
}                             
static void dhcp_option_short(struct dhcp *dhcp, u16_t value)
{
  LWIP_ASSERT("dhcp_option_short: dhcp->options_out_len + 2 <= DHCP_OPTIONS_LEN", dhcp->options_out_len + 2 <= DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = (value & 0xff00U) >> 8;
  dhcp->msg_out->options[dhcp->options_out_len++] =  value & 0x00ffU;
}
static void dhcp_option_long(struct dhcp *dhcp, u32_t value)
{
  LWIP_ASSERT("dhcp_option_long: dhcp->options_out_len + 4 <= DHCP_OPTIONS_LEN", dhcp->options_out_len + 4 <= DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = (value & 0xff000000UL) >> 24;
  dhcp->msg_out->options[dhcp->options_out_len++] = (value & 0x00ff0000UL) >> 16;
  dhcp->msg_out->options[dhcp->options_out_len++] = (value & 0x0000ff00UL) >> 8;
  dhcp->msg_out->options[dhcp->options_out_len++] = (value & 0x000000ffUL);
}

/**
 * Extract the dhcp_msg and options each into linear pieces of memory.
 *
 * 
 * 
 */
static err_t dhcp_unfold_reply(struct dhcp *dhcp)
{
  struct pbuf *p = dhcp->p;
  u8_t *ptr;
  u16_t i;
  u16_t j = 0;
  dhcp->msg_in = NULL;
  dhcp->options_in = NULL;
  /* options present? */
  if (dhcp->p->tot_len > sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN)
  {
    dhcp->options_in_len = dhcp->p->tot_len - (sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN);
    dhcp->options_in = mem_malloc(dhcp->options_in_len);
    if (dhcp->options_in == NULL)
    {
      DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): could not allocate dhcp->options")); 
      return ERR_MEM;
    }
  }
  dhcp->msg_in = mem_malloc(sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN);
  if (dhcp->msg_in == NULL)
  {
    DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): could not allocate dhcp->msg_in")); 
    mem_free((void *)dhcp->options_in);
    dhcp->options_in = NULL;
    return ERR_MEM;
  }

  ptr = (u8_t *)dhcp->msg_in;
  /* proceed through struct dhcp_msg */
  for (i = 0; i < sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN; i++)
  {
    *ptr++ = ((u8_t *)p->payload)[j++];
    /* reached end of pbuf? */
    if (j == p->len)
    {
      /* proceed to next pbuf in chain */
      p = p->next;
      j = 0;
    }
  }
  DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): copied %u bytes into dhcp->msg_in[]", i)); 
  if (dhcp->options_in != NULL) {
    ptr = (u8_t *)dhcp->options_in;
    /* proceed through options */
    for (i = 0; i < dhcp->options_in_len; i++) {
      *ptr++ = ((u8_t *)p->payload)[j++];
      /* reached end of pbuf? */
      if (j == p->len) {
        /* proceed to next pbuf in chain */
        p = p->next;
        j = 0;
      }
    }
    DEBUGF(DHCP_DEBUG, ("dhcp_unfold_reply(): copied %u bytes to dhcp->options_in[]", i)); 
  }
  return ERR_OK;
}

/**
 * Free the incoming DHCP message including contiguous copy of 
 * its DHCP options.
 *
 */
static void dhcp_free_reply(struct dhcp *dhcp)
{
  if (dhcp->msg_in != NULL) {
    mem_free((void *)dhcp->msg_in);
    dhcp->msg_in = NULL;
  }
  if (dhcp->options_in) {
    mem_free((void *)dhcp->options_in);
    dhcp->options_in = NULL;
    dhcp->options_in_len = 0;
  }
  DEBUGF(DHCP_DEBUG, ("dhcp_free_reply(): freed")); 
}


/**
 * If an incoming DHCP message is in response to use, then trigger the state machine
 */
static void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
  struct netif *netif = (struct netif *)arg;
  struct dhcp *dhcp = netif->dhcp;
  struct dhcp_msg *reply_msg = (struct dhcp_msg *)p->payload;
  u8_t *options_ptr;
  u8_t msg_type;
  u8_t i;
  DEBUGF(DHCP_DEBUG, ("dhcp_recv()"));
  DEBUGF(DHCP_DEBUG, ("pbuf->len = %u", p->len));
  DEBUGF(DHCP_DEBUG, ("pbuf->tot_len = %u", p->tot_len));
  dhcp->p = p;
  if (reply_msg->op != DHCP_BOOTREPLY) {
    DEBUGF(DHCP_DEBUG, ("not a DHCP reply message, but type %u", reply_msg->op));
    pbuf_free(p);
  }
  /* iterate through hardware address and match against DHCP message */
  for (i = 0; i < netif->hwaddr_len; i++) {
    if (netif->hwaddr[i] != reply_msg->chaddr[i]) { 
      DEBUGF(DHCP_DEBUG, ("netif->hwaddr[%u]==%02x != reply_msg->chaddr[%u]==%02x",
        i, netif->hwaddr[i], i, reply_msg->chaddr[i]));
      pbuf_free(p);
      return;
    }
  }
  /* match transaction ID against what we expected */
  if (ntohl(reply_msg->xid) != dhcp->xid) {
    DEBUGF(DHCP_DEBUG, ("transaction id mismatch"));
    pbuf_free(p);
    return;
  }
  /* option fields could be unfold? */
  if (dhcp_unfold_reply(dhcp) != ERR_OK) {
    DEBUGF(DHCP_DEBUG, ("problem unfolding DHCP message - too short on memory?"));
    pbuf_free(p);
    return;
  }
  
  DEBUGF(DHCP_DEBUG, ("searching DHCP_OPTION_MESSAGE_TYPE"));
  /* obtain pointer to DHCP message type */ 
  options_ptr = dhcp_get_option_ptr(dhcp, DHCP_OPTION_MESSAGE_TYPE);
  if (options_ptr == NULL) {
    DEBUGF(DHCP_DEBUG, ("DHCP_OPTION_MESSAGE_TYPE option not found")); 
    pbuf_free(p);
    return;
  }  

  /* read DHCP message type */
  msg_type = dhcp_get_option_byte(options_ptr + 2);
  /* message type is DHCP ACK? */
  if (msg_type == DHCP_ACK) {
    DEBUGF(DHCP_DEBUG, ("DHCP_ACK received")); 
    /* in requesting state? */
    if (dhcp->state == DHCP_REQUESTING) {
      dhcp_handle_ack(dhcp);
      dhcp->request_timeout = 0;
#if DHCP_DOES_ARP_CHECK
      /* check if the acknowledged lease address is already in use */
      dhcp_check(netif);
#else
      /* bind interface to the acknowledged lease address */
      dhcp_bind(netif);
#endif
    }
    /* already bound to the given lease address? */
    else if ((dhcp->state == DHCP_REBOOTING) || (dhcp->state == DHCP_REBINDING) || (dhcp->state == DHCP_RENEWING)) {
      dhcp->request_timeout = 0;
      dhcp_bind(netif);
    }
  }
  /* received a DHCP_NAK in appropriate state? */
  else if ((msg_type == DHCP_NAK) &&
    ((dhcp->state == DHCP_REBOOTING) || (dhcp->state == DHCP_REQUESTING) || 
     (dhcp->state == DHCP_REBINDING) || (dhcp->state == DHCP_RENEWING  ))) {
    DEBUGF(DHCP_DEBUG, ("DHCP_NAK received")); 
    dhcp->request_timeout = 0;
    dhcp_handle_nak(dhcp);
  }
  /* received a DHCP_OFFER in DHCP_SELECTING state? */
  else if ((msg_type == DHCP_OFFER) && (dhcp->state == DHCP_SELECTING)) {
    DEBUGF(DHCP_DEBUG, ("DHCP_OFFER received in DHCP_SELECTING state")); 
    dhcp->request_timeout = 0;
    /* remember offered lease */
    dhcp_handle_offer(dhcp);
  }
  pbuf_free(p);
}


static err_t dhcp_create_request(struct dhcp *dhcp)
{
  u16_t i;
  LWIP_ASSERT("dhcp_create_request: dhcp->p_out == NULL", dhcp->p_out == NULL);
  LWIP_ASSERT("dhcp_create_request: dhcp->msg_out == NULL", dhcp->msg_out == NULL);
  dhcp->p_out = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcp_msg), PBUF_RAM);
  if (dhcp->p_out == NULL) {
    DEBUGF(DHCP_DEBUG, ("dhcp_create_request(): could not allocate pbuf"));
    return ERR_MEM;
  }
  /* give unique transaction identifier to this request */
  dhcp->xid = xid++;  

  dhcp->msg_out = (struct dhcp_msg *)dhcp->p_out->payload;

  dhcp->msg_out->op = DHCP_BOOTREQUEST;
  /* TODO: make link layer independent */  
  dhcp->msg_out->htype = DHCP_HTYPE_ETH;  
  /* TODO: make link layer independent */  
  dhcp->msg_out->hlen = DHCP_HLEN_ETH;  
  dhcp->msg_out->hops = 0;
  dhcp->msg_out->xid = htonl(dhcp->xid);  
  dhcp->msg_out->secs = 0;
  dhcp->msg_out->flags = 0;
  dhcp->msg_out->ciaddr = netif->ip_addr.addr;
  dhcp->msg_out->yiaddr = 0;
  dhcp->msg_out->siaddr = 0;
  dhcp->msg_out->giaddr = 0;
  for (i = 0; i < DHCP_CHADDR_LEN; i++) {
    /* copy netif hardware address, pad with zeroes */
    dhcp->msg_out->chaddr[i] = (i < netif->hwaddr_len) ? netif->hwaddr[i] : 0/* pad byte*/;
  }
  for (i = 0; i < DHCP_SNAME_LEN; i++) dhcp->msg_out->sname[i] = 0;
  for (i = 0; i < DHCP_FILE_LEN; i++) dhcp->msg_out->file[i] = 0;
  dhcp->msg_out->cookie = htonl(0x63825363UL);
  dhcp->options_out_len = 0;
  /* fill options field with an incrementing array (for debugging purposes) */
  for (i = 0; i < DHCP_OPTIONS_LEN; i++) dhcp->msg_out->options[i] = i;
  return ERR_OK;
}

static void dhcp_delete_request(struct dhcp *dhcp)
{
  LWIP_ASSERT("dhcp_free_msg: dhcp->p_out != NULL", dhcp->p_out != NULL);
  LWIP_ASSERT("dhcp_free_msg: dhcp->msg_out != NULL", dhcp->msg_out != NULL);
  pbuf_free(dhcp->p_out);
  dhcp->p_out = NULL;
  dhcp->msg_out = NULL;
}

/**
 * Add a DHCP message trailer
 *
 * Adds the END option to the DHCP message, and if
 * necessary, up to three padding bytes.
 */

static void dhcp_option_trailer(struct dhcp *dhcp)
{
  LWIP_ASSERT("dhcp_option_trailer: dhcp->msg_out != NULL", dhcp->msg_out != NULL);
  LWIP_ASSERT("dhcp_option_trailer: dhcp->options_out_len < DHCP_OPTIONS_LEN", dhcp->options_out_len < DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = DHCP_OPTION_END;
  /* packet is too small, or not 4 byte aligned? */
  while ((dhcp->options_out_len < DHCP_MIN_OPTIONS_LEN) || (dhcp->options_out_len & 3)) {
    /* DEBUGF(DHCP_DEBUG, ("dhcp_option_trailer: dhcp->options_out_len=%u, DHCP_OPTIONS_LEN=%u", dhcp->options_out_len, DHCP_OPTIONS_LEN)); */
    LWIP_ASSERT("dhcp_option_trailer: dhcp->options_out_len < DHCP_OPTIONS_LEN", dhcp->options_out_len < DHCP_OPTIONS_LEN);
    /* add a fill/padding byte */
    dhcp->msg_out->options[dhcp->options_out_len++] = 0;
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
static u8_t *dhcp_get_option_ptr(struct dhcp *dhcp, u8_t option_type)
{
  u8_t overload = DHCP_OVERLOAD_NONE;

  /* options available? */
  if ((dhcp->options_in != NULL) && (dhcp->options_in_len > 0)) {
    /* start with options field */
    u8_t *options = (u8_t *)dhcp->options_in;
    u16_t offset = 0;
    /* at least 1 byte to read and no end marker, then at least 3 bytes to read? */
    while ((offset < dhcp->options_in_len) && (options[offset] != DHCP_OPTION_END)) {
      /* DEBUGF(DHCP_DEBUG, ("msg_offset=%u, q->len=%u", msg_offset, q->len)); */
      /* are the sname and/or file field overloaded with options? */
      if (options[offset] == DHCP_OPTION_OVERLOAD) {
        DEBUGF(DHCP_DEBUG, ("overloaded message detected"));
        /* skip option type and length */
        offset += 2;
        overload = options[offset++];
      }
      /* requested option found */
      else if (options[offset] == option_type) {
        DEBUGF(DHCP_DEBUG, ("option found at offset %u in options", offset));
        return &options[offset];
      /* skip option */
      } else {
         DEBUGF(DHCP_DEBUG, ("skipping option %u in options", options[offset]));
        /* skip option type */
        offset++;
        /* skip option length, and then length bytes */
        offset += 1 + options[offset];
      }
    }
    /* is this an overloaded message? */
    if (overload != DHCP_OVERLOAD_NONE) {
      u16_t field_len;
      if (overload == DHCP_OVERLOAD_FILE) {
        DEBUGF(DHCP_DEBUG, ("overloaded file field"));
        options = (u8_t *)&dhcp->msg_in->file;
        field_len = DHCP_FILE_LEN;
      } else if (overload == DHCP_OVERLOAD_SNAME) {
        DEBUGF(DHCP_DEBUG, ("overloaded sname field"));
        options = (u8_t *)&dhcp->msg_in->sname;
        field_len = DHCP_SNAME_LEN;
      /* TODO: check if else if () is necessary */
      } else {
        DEBUGF(DHCP_DEBUG, ("overloaded sname and file field"));
        options = (u8_t *)&dhcp->msg_in->sname;
        field_len = DHCP_FILE_LEN + DHCP_SNAME_LEN;
      }
      offset = 0;

      /* at least 1 byte to read and no end marker */
      while ((offset < field_len) && (options[offset] != DHCP_OPTION_END)) {
        if (options[offset] == option_type) {
           DEBUGF(DHCP_DEBUG, ("option found at offset=%u", offset));
          return &options[offset];
        /* skip option */
        } else {
          DEBUGF(DHCP_DEBUG, ("skipping option %u", options[offset]));
          /* skip option type */
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
