/**
 * @file
 * DNS - host name to IP address resolver.
 *
 */

/**

 * This file implements a DNS host name to IP address resolver.

 * Port to lwIP from uIP
 * by Jim Pettinato April 2007

 * uIP version Copyright (c) 2002-2003, Adam Dunkels.
 * All rights reserved.
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
 *
 *
 * DNS.C
 *
 * The lwIP DNS resolver functions are used to lookup a host name and
 * map it to a numerical IP address. It maintains a list of resolved
 * hostnames that can be queried with the dns_lookup() function.
 * New hostnames can be resolved using the dns_query() function.
 *
 * The lwIP version of the resolver also adds a non-blocking version of
 * gethostbyname() that will work with a raw API application. This function
 * checks for an IP address string first and converts it if it is valid.
 * gethostbyname() then does a dns_lookup() to see if the name is 
 * already in the table. If so, the IP is returned. If not, a query is 
 * issued and the function returns with a DNS_QUERY_QUEUED status. The app
 * using the dns client must then go into a waiting state.
 *
 * Once a hostname has been resolved (or found to be non-existent),
 * the resolver code calls a specified callback function (which 
 * must be implemented by the module that uses the resolver).
 */

/*-----------------------------------------------------------------------------
 * RFC 1035 - Domain names - implementation and specification
 * RFC 2181 - Clarifications to the DNS Specification
 *----------------------------------------------------------------------------*/

/** @todo: define good default values (rfc compliance) */
/** @todo: secondary server support */
/** @todo: pbuf chain not yet supported */
/** @todo: improve answer parsing, more checkings... */

/*-----------------------------------------------------------------------------
 * Includes
 *----------------------------------------------------------------------------*/

#include "lwip/opt.h"

#if LWIP_DNS /* don't build if not configured for use in lwipopts.h */

#include "lwip/udp.h"
#include "lwip/dns.h"

#include <string.h>

/** DNS server IP address */
#ifndef DNS_SERVER_ADDRESS
#define DNS_SERVER_ADDRESS        inet_addr("208.67.222.222") /* resolver1.opendns.com */
#endif

/** DNS server port address */
#ifndef DNS_SERVER_PORT
#define DNS_SERVER_PORT           53
#endif

/* The maximum number of table entries to maintain locally */
#ifndef DNS_TABLE_SIZE
#define DNS_TABLE_SIZE            4
#endif

/* The maximum length of a host name supported in the name table. */
#ifndef DNS_MAX_NAME_LENGTH
#define DNS_MAX_NAME_LENGTH       256
#endif

/* The maximum number of retries when asking for a name, before "timeout". */
#ifndef DNS_MAX_RETRIES
#define DNS_MAX_RETRIES           8
#endif 

/* DNS entry time to live (in DNS_TMR_INTERVAL ticks) */
#ifndef DNS_TTL_ENTRY
#define DNS_TTL_ENTRY             60
#endif

/* DNS protocol flags */
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03

/* DNS protocol states */
#define DNS_STATE_UNUSED          0
#define DNS_STATE_NEW             1
#define DNS_STATE_ASKING          2
#define DNS_STATE_DONE            3

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
/** DNS message header */
struct dns_hdr {
  u16_t id;
  u8_t flags1;
  u8_t flags2;
  u16_t numquestions;
  u16_t numanswers;
  u16_t numauthrr;
  u16_t numextrarr;
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
/** DNS query message structure */
struct dns_query {
  /* DNS query record starts with either a domain name or a pointer
     to a name already present somewhere in the packet. */
  u16_t type;
  u16_t class;
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
/** DNS answer message structure */
struct dns_answer {
  /* DNS answer record starts with either a domain name or a pointer
     to a name already present somewhere in the packet. */
  u16_t type;
  u16_t class;
  u32_t ttl;
  u16_t len;
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
/** DNS table entry */
struct dns_table_entry {
  u8_t state;
  u8_t tmr;
  u8_t retries;
  u8_t ttl;
  u8_t seqno;
  u8_t err;
  char name[DNS_MAX_NAME_LENGTH];
  struct ip_addr ipaddr;
  void (* found)(const char *name, struct ip_addr *ipaddr, void *arg); /* pointer to callback on DNS query done */
  void *arg;
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

/* forward declarations */
static void dns_recv(void *s, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port);
static void dns_check_entries(void);

/*-----------------------------------------------------------------------------
 * Globales
 *----------------------------------------------------------------------------*/

/* DNS variables */
static struct udp_pcb        *dns_pcb;
static struct dns_table_entry dns_table[DNS_TABLE_SIZE];
static u8_t                   dns_seqno;

/**
 * Initialize the resolver and configure which DNS server to use for queries.
 *
 * param dnsserver A pointer to a 4-byte representation of the IP
 * address of the DNS server to be configured.
 */
err_t
dns_init()
{
  u8_t i;
  struct ip_addr dnsserver = {DNS_SERVER_ADDRESS};

  LWIP_DEBUGF(DNS_DEBUG, ("dns_init: initializing\n"));

  /* if dns client not yet initialized... */
  if (dns_pcb == NULL) {
    dns_pcb = udp_new();

    if (dns_pcb != NULL) {
      /* initialize DNS table */
      for (i=0; i<DNS_TABLE_SIZE; ++i) {
        dns_table[i].state = DNS_STATE_UNUSED;
        dns_table[i].found = NULL;
      }

      /* initialize DNS client */
      udp_bind(dns_pcb, IP_ADDR_ANY, 0);
      udp_recv(dns_pcb, dns_recv, NULL);
      
      /* initialize default DNS primary server */
      dns_setserver(0, &dnsserver);
    }
  }
  return ERR_OK;
}

/**
 * Obtain the currently configured DNS server.
 * return unsigned long encoding of the IP address of
 * the currently configured DNS server or NULL if no DNS server has
 * been configured.
 */
void
dns_setserver(u8_t numdns, struct ip_addr *dnsserver)
{
  LWIP_UNUSED_ARG(numdns);
  if ((dns_pcb != NULL) && (dnsserver != NULL) && (dnsserver->addr !=0 )) {
    udp_connect( dns_pcb, dnsserver, DNS_SERVER_PORT);
  }
}

/**
 * Obtain the currently configured DNS server.
 * return unsigned long encoding of the IP address of
 * the currently configured DNS server or NULL if no DNS server has
 * been configured.
 */
u32_t
dns_getserver(u8_t numdns)
{
  LWIP_UNUSED_ARG(numdns);
  return ((dns_pcb != NULL)?dns_pcb->remote_ip.addr:0);
}

/**
 * The DNS resolver client timer - handle retries and timeouts
 */
void
dns_tmr(void)
{
  if (dns_pcb != NULL) {
    LWIP_DEBUGF(DNS_DEBUG, ("dns_tmr: dns_check_entries\n"));
    dns_check_entries();
  }
}

/**
 * Look up a hostname in the array of known hostnames.
 *
 * \note This function only looks in the internal array of known
 * hostnames, it does not send out a query for the hostname if none
 * was found. The function dns_query() can be used to send a query
 * for a hostname.
 *
 * return A pointer to a 4-byte representation of the hostname's IP
 * address, or NULL if the hostname was not found in the array of
 * hostnames.
 */
u32_t
dns_lookup(const char *name)
{
  u8_t i;

  /* Walk through name list, return entry if found. If not, return NULL. */
  for (i=0; i<DNS_TABLE_SIZE; ++i) {
    if ( (dns_table[i].state==DNS_STATE_DONE) && (strcmp(name, dns_table[i].name)==0) ) {
      LWIP_DEBUGF(DNS_DEBUG, ("dns_lookup: \"%s\": found = ", name));
      ip_addr_debug_print(DNS_DEBUG, (&(dns_table[i].ipaddr)));
      LWIP_DEBUGF(DNS_DEBUG, ("\n"));
      return dns_table[i].ipaddr.addr;
    }
  }

  return 0;
}

/**
 * dns_parse_name() - walk through a compact encoded DNS name and return the end 
 * of the name.
 */
static unsigned char *
dns_parse_name(unsigned char *query)
{
  unsigned char n;

  do {
    n = *query++;
    /** @see RFC 1035 - 4.1.4. Message compression */
    if ((n & 0xc0)==0xc0) {
      /* Compressed name */
      break;
    } else {
      /* Not compressed name */
      while(n > 0) {
        ++query;
        --n;
      };
    }
  } while(*query != 0);

  return query + 1;
}

/**
 * dns_send
 */
static err_t
dns_send(const char* name, u8_t id)
{ 
  struct dns_hdr *hdr;
  struct dns_query *qry;
  struct pbuf *p;
  char *query, *nptr;
  const char *pHostname;
  u8_t n;

  LWIP_DEBUGF(DNS_DEBUG, ("dns_send: \"%s\": request\n", name));

  /* if here, we have either a new query or a retry on a previous query to process */
  p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dns_hdr)+DNS_MAX_NAME_LENGTH+sizeof(struct dns_query), PBUF_RAM);
  if (p) {
    /* fill dns header */
    hdr = (struct dns_hdr *)p->payload;
    memset(hdr, 0, sizeof(struct dns_hdr));
    hdr->id = htons(id);
    hdr->flags1 = DNS_FLAG1_RD;
    hdr->numquestions = htons(1);
    query = (char *)hdr + sizeof(struct dns_hdr);
    pHostname = name;
    --pHostname;

    /* convert hostname into suitable query format. */
    do {
      ++pHostname;
      nptr = query;
      ++query;
      for(n = 0; *pHostname != '.' && *pHostname != 0; ++pHostname) {
        *query = *pHostname;
        ++query;
        ++n;
      }
      *nptr = n;
    } while(*pHostname != 0);
    *query++='\0';

    /* fill dns query */
    qry = (struct dns_query *)query;
    qry->type  = htons(DNS_RRTYPE_A);
    qry->class = htons(DNS_RRCLASS_IN);

    /* resize pbuf to the exact dns query */
    pbuf_realloc(p, (query+sizeof(struct dns_query))-((char*)(p->payload)));

    /* send dns packet */
    udp_send(dns_pcb, p);

    /* free pbuf */
    pbuf_free(p);

    return ERR_OK;
  }

  return ERR_BUF;
}

/**
 * dns_check_entries() - Runs through the list of names to see if there are any 
 * that have not yet been queried and, if so, sends out a query.
 */
static void
dns_check_entries(void)
{
  u8_t i;
  struct dns_table_entry *pEntry;

  for (i = 0; i < DNS_TABLE_SIZE; ++i) {
    pEntry = &dns_table[i];
    switch(pEntry->state) {

      case DNS_STATE_NEW:
      case DNS_STATE_ASKING: {
        if (pEntry->state == DNS_STATE_ASKING) {
          if (--pEntry->tmr == 0) {
            if (++pEntry->retries == DNS_MAX_RETRIES) {
              LWIP_DEBUGF(DNS_DEBUG, ("dns_check_entries: \"%s\": timeout\n", pEntry->name));
              /* call specified callback function if provided */
              if (pEntry->found)
                (*pEntry->found)(pEntry->name, NULL, pEntry->arg);
              /* flush this entry */
              pEntry->state   = DNS_STATE_UNUSED;
              pEntry->found   = NULL;
              continue;
            }
            /* wait longer for the next retry */
            pEntry->tmr = pEntry->retries;
          } else {
            /* Its timer has not run out, so we move on to next entry. */
            continue;
          }
        } else {
          pEntry->state   = DNS_STATE_ASKING;
          pEntry->tmr     = 1;
          pEntry->retries = 0;
        }
        /* send DNS packet for this entry */
        dns_send(pEntry->name, i);
        break;
      }

      case DNS_STATE_DONE: {
        /* if the time to live is nul */
        if (--pEntry->ttl == 0) {
          LWIP_DEBUGF(DNS_DEBUG, ("dns_check_entries: \"%s\": flush\n", pEntry->name));
          /* flush this entry */
          pEntry->state   = DNS_STATE_UNUSED;
          pEntry->found   = NULL;
        }
        break;
      }
    }
  }
}

/**
 * Callback for DNS responses
 */
static void
dns_recv(void *s, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
  u8_t i;
  char *pHostname;
  struct dns_hdr *hdr;
  struct dns_answer *ans;
  struct dns_table_entry *pEntry;
  u8_t nquestions, nanswers;

  LWIP_ASSERT("dns_recv: pbuf chain not yet supported", (p->next==NULL));
  
  hdr = (struct dns_hdr *)p->payload;
  
  /** @todo: check RFC1035 - 7.3. Processing responses */

  /* The ID in the DNS header should be our entry into the name table. */
  i = htons(hdr->id);
  pEntry = &dns_table[i];
  if( (i < DNS_TABLE_SIZE) && (pEntry->state == DNS_STATE_ASKING) ) {
    /* This entry is now completed. */
    pEntry->state = DNS_STATE_DONE;
    pEntry->ttl   = DNS_TTL_ENTRY;
    pEntry->err   = hdr->flags2 & DNS_FLAG2_ERR_MASK;

    /* We only care about the question(s) and the answers. The authrr
       and the extrarr are simply discarded. */
    nquestions = htons(hdr->numquestions);
    nanswers   = htons(hdr->numanswers);

    /* Check for error. If so, call callback to inform. */
    if (((hdr->flags1 & DNS_FLAG1_RESPONSE)==0) ||(pEntry->err != 0) || (nquestions != 1)) {
      LWIP_DEBUGF(DNS_DEBUG, ("dns_recv: \"%s\": error in flags\n", pEntry->name));
      /* call specified callback function if provided */
      if (pEntry->found)
        (*pEntry->found)(pEntry->name, NULL, pEntry->arg);
      /* flush this entry */
      pEntry->state   = DNS_STATE_UNUSED;
      pEntry->found   = NULL;
      return;
    }

    /* Skip the name in the "question" part. This should really be checked
       agains the name in the question, to be sure that they match. */
    pHostname = (char *) dns_parse_name((unsigned char *)p->payload + sizeof(struct dns_hdr)) + sizeof(struct dns_query);

    while(nanswers > 0) {
      /* skip answer resource record's host name */
      pHostname = (char *) dns_parse_name((unsigned char *)pHostname);

      /* Check for IP address type and Internet class. Others are discarded. */
      ans = (struct dns_answer *)pHostname;
      if((ntohs(ans->type) == DNS_RRTYPE_A) && (ntohs(ans->class) == DNS_RRCLASS_IN) && (ntohs(ans->len) == sizeof(struct ip_addr)) ) {
        /* read the IP address after answer resource record's header */
        pEntry->ipaddr =  (*((struct ip_addr*)(ans+1)));
        LWIP_DEBUGF(DNS_DEBUG, ("dns_recv: \"%s\": response = ", pEntry->name));
        ip_addr_debug_print(DNS_DEBUG, (&(pEntry->ipaddr)));
        LWIP_DEBUGF(DNS_DEBUG, ("\n"));
        /* call specified callback function if provided */
        if (pEntry->found)
          (*pEntry->found)(pEntry->name, &pEntry->ipaddr, pEntry->arg);
        return;
      } else {
        pHostname = pHostname + sizeof(struct dns_answer) + htons(ans->len);
      }
      --nanswers;
    }
    LWIP_DEBUGF(DNS_DEBUG, ("dns_recv: \"%s\": error in response\n", pEntry->name));
  }
}

/**
 * Queues a name so that a question for the name will be sent out.
 * param name - The hostname that is to be queried.
 */
static void
dns_query(const char *name, void (*found)(const char *name, struct ip_addr *addr, void *arg), void *arg)
{
  u8_t i;
  u8_t lseq, lseqi;
  struct dns_table_entry *pEntry;

  /* search an unused entry, or the oldest one */
  lseq = lseqi = 0;
  for (i = 0; i < DNS_TABLE_SIZE; ++i) {
    pEntry = &dns_table[i];
    /* is it an unused entry ? */
    if (pEntry->state == DNS_STATE_UNUSED)
      break;

    /* check if this is the oldest entry used */
    if (dns_seqno - pEntry->seqno > lseq) {
      lseq = dns_seqno - pEntry->seqno;
      lseqi = i;
    }
  }

  /* if we don't have found an unused entry, use the oldest one */
  if (i == DNS_TABLE_SIZE) {
    i = lseqi;
    pEntry = &dns_table[i];
    /* since we replace the previous entry, we "unblock" the caller */
    LWIP_DEBUGF(DNS_DEBUG, ("dns_query: \"%s\": replaced by new entry\n", pEntry->name));
    /* call specified callback function if provided */
    if (pEntry->found) 
      (*pEntry->found)(pEntry->name, NULL, pEntry->arg);
  }

  /* fill the entry */
  strcpy(pEntry->name, name);
  pEntry->found = found;
  pEntry->arg   = arg;
  pEntry->state = DNS_STATE_NEW;
  pEntry->seqno = dns_seqno++;
}

/**
 * NON-BLOCKING callback version for use with raw API
 */
DNS_RESULT dns_gethostbyname(const char *hostname, struct ip_addr *addr, 
                             void (*found)(const char *name, struct ip_addr *ipaddr, void *arg),
                             void *arg
                             )
{
  /* not initialized or no valid server yet, or invalid addr pointer */
  if ((dns_pcb == NULL) || (addr == NULL))
    return DNS_QUERY_INVALID;

  /* invalid hostname */
  if ((!hostname) || (!hostname[0]))
    return DNS_QUERY_INVALID;

  /* invalid hostname length */
  if (strlen(hostname) >= DNS_MAX_NAME_LENGTH)
    return DNS_QUERY_INVALID;

  /* host name already in octet notation? set ip addr and return COMPLETE */
  if ((addr->addr = inet_addr(hostname)) != INADDR_NONE)
    return DNS_COMPLETE;

  /* already have this address cached? */
  if ((addr->addr = dns_lookup(hostname)) != 0) 
    return DNS_COMPLETE;

  /* queue query with specified callback */
  dns_query(hostname, found, arg);

  /* force to send request */
  dns_check_entries();
  
  return DNS_QUERY_QUEUED;
}

#endif /* LWIP_DNS */
