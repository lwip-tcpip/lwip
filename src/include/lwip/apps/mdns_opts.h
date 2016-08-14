/* 
 * File:   mdns_opts.h
 * Author: dziegel
 *
 * Created on 13. August 2016, 09:17
 */

#ifndef LWIP_HDR_APPS_MDNS_OPTS_H
#define	LWIP_HDR_APPS_MDNS_OPTS_H
/**
 * @defgroup mdns_opts Options
 * @ingroup mdns
 * @{
 */

/**
 * LWIP_MDNS==1: Turn on multicast DNS module. UDP must be available for MDNS
 * transport. IGMP is needed for IPv4 multicast.
 */
#ifndef LWIP_MDNS
#define LWIP_MDNS                       0
#endif /* LWIP_MDNS */

/** The maximum number of services per netif */
#ifndef MDNS_MAX_SERVICES
#define MDNS_MAX_SERVICES               1
#endif

/**
 * MDNS_DEBUG: Enable debugging for multicast DNS.
 */
#ifndef MDNS_DEBUG
#define MDNS_DEBUG                       LWIP_DBG_OFF
#endif

/**
 * @}
 */

#endif	/* LWIP_HDR_APPS_MDNS_OPTS_H */

