#ifndef __LWIP_EVENT_H__
#define __LWIP_EVENT_H__

#include "lwip/opt.h"

#if LWIP_EVENT_API

#include "lwip/pbuf.h"

enum lwip_event {
  LWIP_EVENT_ACCEPT,
  LWIP_EVENT_SENT,
  LWIP_EVENT_RECV,
  LWIP_EVENT_CONNECTED,
  LWIP_EVENT_POLL,
  LWIP_EVENT_ERR
};

struct tcp_pcb;

err_t lwip_tcp_event(void *arg, struct tcp_pcb *pcb,
		     enum lwip_event,
		     struct pbuf *p,
		     u16_t size,
		     err_t err);

#endif /* LWIP_EVENT_API */

#endif /* __LWIP_EVENT_H__ */
