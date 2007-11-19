/**
 * lwip DNS resolver header file.

 * Author: Jim Pettinato 
 *   April 2007

 * ported from uIP resolv.c Copyright (c) 2002-2003, Adam Dunkels.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __LWIP_DNS_H__
#define __LWIP_DNS_H__

#include "lwip/opt.h"

#if LWIP_DNS /* don't build if not configured for use in lwipopts.h */

/** The maximum of DNS servers */
#ifndef DNS_MAX_SERVERS
#define DNS_MAX_SERVERS           2
#endif

/** DNS resource record max. TTL (one week as default) */
#ifndef DNS_MAX_TTL
#define DNS_MAX_TTL               604800
#endif

/** DNS timer period */
#define DNS_TMR_INTERVAL          1000

/** DNS message max. size */
#define DNS_MSG_SIZE              512

/** DNS field TYPE used for "Resource Records" */
#define DNS_RRTYPE_A              1     /* a host address */
#define DNS_RRTYPE_NS             2     /* an authoritative name server */
#define DNS_RRTYPE_MD             3     /* a mail destination (Obsolete - use MX) */
#define DNS_RRTYPE_MF             4     /* a mail forwarder (Obsolete - use MX) */
#define DNS_RRTYPE_CNAME          5     /* the canonical name for an alias */
#define DNS_RRTYPE_SOA            6     /* marks the start of a zone of authority */
#define DNS_RRTYPE_MB             7     /* a mailbox domain name (EXPERIMENTAL) */
#define DNS_RRTYPE_MG             8     /* a mail group member (EXPERIMENTAL) */
#define DNS_RRTYPE_MR             9     /* a mail rename domain name (EXPERIMENTAL) */
#define DNS_RRTYPE_NULL           10    /* a null RR (EXPERIMENTAL) */
#define DNS_RRTYPE_WKS            11    /* a well known service description */
#define DNS_RRTYPE_PTR            12    /* a domain name pointer */
#define DNS_RRTYPE_HINFO          13    /* host information */
#define DNS_RRTYPE_MINFO          14    /* mailbox or mail list information */
#define DNS_RRTYPE_MX             15    /* mail exchange */
#define DNS_RRTYPE_TXT            16    /* text strings */

/** DNS field CLASS used for "Resource Records" */
#define DNS_RRCLASS_IN            1     /* the Internet */
#define DNS_RRCLASS_CS            2     /* the CSNET class (Obsolete - used only for examples in some obsolete RFCs) */
#define DNS_RRCLASS_CH            3     /* the CHAOS class */
#define DNS_RRCLASS_HS            4     /* Hesiod [Dyer 87] */
#define DNS_RRCLASS_FLUSH         0x800 /* Flush bit */

/* enumerated list of possible result values returned by dns_gethostname() */
typedef enum dns_result {
  DNS_ERR_MEM,
  DNS_QUERY_INVALID,
  DNS_QUERY_QUEUED,
  DNS_COMPLETE
}DNS_RESULT;


/* initializes the resolver */
err_t dns_init(void);

/* handles requests, retries and timeouts - call every DNS_TMR_INTERVAL tick */
void  dns_tmr(void);

/* initializes DNS server IP address */
void dns_setserver(u8_t numdns, struct ip_addr *dnsserver);

/* returns configured DNS server IP address */
struct ip_addr dns_getserver(u8_t numdns);

/* resolves a host 'name' in ip address */
DNS_RESULT dns_gethostbyname(const char *hostName, struct ip_addr *addr, 
                             void (*found)(const char *name, struct ip_addr *ipaddr, void *arg),
                             void *arg);

/* dns_gethostbyname() - Returns immediately with one of DNS_RESULT return codes
 *                       Return value will be DNS_COMPLETE if hostName is a valid
 *                       IP address string or the host name is already in the local
 *                       names table. Returns DNS_REQUEST_QUEUED and queues a
 *                       request to be sent to the DNS server for resolution if no
 *                       errors are present.
 */

/* dns_found_func() - Callback which is invoked when a hostname is found.
 * This function should be implemented by the application using the DNS resolver.
 *  param 'name'   - pointer to the name that was looked up.
 *  param 'ipaddr' - pointer to a struct ip_addr containing the IP address of the
 *                   hostname, or NULL if the name could not be found.
*/

#endif /* LWIP_DNS */

#endif /* __LWIP_DNS_H__ */
