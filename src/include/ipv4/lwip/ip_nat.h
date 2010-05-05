/***************************************************************************
 * Template - A brief description for this module.
 * Copyright (c) 2008 Christian Walter, © Embedded Solutions, Vienna 2006.
 *
 * $Id: ip_nat.h,v 1.1 2010/05/05 19:34:23 goldsimon Exp $
 ***************************************************************************/

#ifndef __LWIP_NAT_H__
#define __LWIP_NAT_H__

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/opt.h"

#if IP_NAT

/** Timer interval at which to call ip_nat_tmr() */
#define LWIP_NAT_TMR_INTERVAL_SEC        5

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct netif;
struct pbuf;

typedef struct ip_nat_entry
{
  ip_addr_t    source_net;
  ip_addr_t    source_netmask;
  ip_addr_t    dest_net;
  ip_addr_t    dest_netmask;
  struct netif *out_if;
  struct netif *in_if;
} ip_nat_entry_t;

void  ip_nat_init(void);
void  ip_nat_tmr(void);
u8_t  ip_nat_input(struct pbuf *p);
u8_t  ip_nat_out(struct pbuf *p);

err_t ip_nat_add(const ip_nat_entry_t *new_entry);
void  ip_nat_remove(const ip_nat_entry_t *remove_entry);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IP_NAT */

#endif /* __LWIP_NAT_H__ */
