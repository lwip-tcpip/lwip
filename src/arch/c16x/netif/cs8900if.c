/** @file
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
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Leon Woestenberg <leon.woestenberg@axon.tv>
 *
 * This is a device driver for the Crystal Semiconductor CS8900
 * chip in combination with the lwIP stack.
 *
 * This is work under development. Please coordinate changes
 * and requests with Leon Woestenberg <leon.woestenberg@axon.tv>
 *
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code under any conditions they seem fit.
 *
 * A quick function roadmap:
 *
 * cs8900_*() are low level, cs8900 hardware specific functions.
 * These are declared static in the device driver source and
 * SHOULD NOT need to be called from outside this source.
 *
 * cs8900if_*() are the lwIP network interface functions.
 * 
 * cs8900_interrupt() is an early interrupt service routine (ISR).
 * It merely sets a flag to indicate the cs8900 needs servicing.
 * (This function MAY be tied to an interrupt vector, IF present).
 *
 * cs8900_service() is the actual interrupt event service routine.
 * It must be called whenever the cs8900 needs servicing. It MAY
 * be polled safely (so, you do NOT NEED interrupt support.)
 *
 * cs8900_init() sets up the cs8900, using its register set. When
 * using the driver on your particular hardware platform, make sure
 * the register setups match.
 * Function is called from cs8900if_init().
 *
 * cs8900_input() transfers a received packet from the chip.
 * Function is called from cs8900if_input().
 *
 * cs8900_output() transfers a packet to the chip for transmission.
 * Function is called from cs8900if_output().
 *
 * cs8900if_init() initializes the lwIP network interface, and
 * calls cs8900_init() to initialize the hardware.
 * Function is called from lwIP.
 * 
 * cs8900if_service() is the service routine, which must be called
 * upon the need for service, or on a regular basis, in order to
 * service the Ethernet chip.
 *
 * cs8900if_input() calls cs8900_input() to get a received packet
 * and then forwards the packet to protocol(s) handler(s).
 * Function is called from cs8900_service().
 *
 * cs8900if_output() resolves the hardware address, then
 * calls cs8900_output() to transfer the packet.
 * Function is called from lwIP.
 *
 * Future development:
 * 
 * Split the generic Ethernet functionality (a lot of the
 * cs8900if_*() functions) and the actual cs8900a dependencies.
 *
 * Enhance the interrupt handler to service the Ethernet
 * chip (to decrease latency); support early packet
 * inspection (during reception) to early drop unwanted
 * packets, minimize chip buffer use and maximize throughput.
 *
 * Statistics gathering, currently under development.
 * SNMP support, currently under development.
 *
 */

#include "lwip/debug.h"

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "netif/etharp.h"

#if 0
// include some debugging help
#  define DBG_LEVEL 1
#  include "leds.h"
#  include "display.h"
//#  include "page.h"
#  define LED_NEED_SERVICE LED_FP1
#else
// no debugging
#  define leds_on()
#  define leds_off()
#endif

#include "cs8900if.h"
#if LWIP_SNMP > 0
#  include "snmp.h"
#endif

// Define those to better describe your network interface
#define IFNAME0 'e'
#define IFNAME1 'n'

static const struct eth_addr ethbroadcast = {{0xffU,0xffU,0xffU,0xffU,0xffU,0xffU}};

// Forward declarations
static err_t cs8900_output(struct netif *netif, struct pbuf *p);
static struct pbuf *cs8900_input(struct netif *netif);
static void cs8900_service(struct netif *netif);
static u32_t cs8900_chksum(void *dataptr, int len);

// Define these to match your hardware setup
#define MEM_BASE 0x00E000
#define IO_BASE 0x800
#define INT_NR 0x00

#define RXTXREG  *((volatile u16_t *)(MEM_BASE + IO_BASE))
#define TXCMD    *((volatile u16_t *)(MEM_BASE + IO_BASE + 0x04))
#define TXLENGTH *((volatile u16_t *)(MEM_BASE + IO_BASE + 0x06))
#define ISQ      *((volatile u16_t *)(MEM_BASE + IO_BASE + 0x08))
#define PACKETPP *((volatile u16_t *)(MEM_BASE + IO_BASE + 0x0A))
#define PPDATA   *((volatile u16_t *)(MEM_BASE + IO_BASE + 0x0C))

// CS8900 PacketPage register offsets 
#define  CS_PP_EISA        0x0000          // EISA Registration number of CS8900
#define  CS_PP_PRODID      0x0002          // Product ID Number
#define  CS_PP_IOBASE      0x0020          // I/O Base Address
#define  CS_PP_INTNUM      0x0022          // Interrupt number (0,1,2, or 3)
#define  CS_PP_RXCFG       0x0102          // Receiver Configuration
#define  CS_PP_RXCTL       0x0104          // Receiver Control
#define  CS_PP_TXCFG       0x0106          // Transmit Configuration
#define  CS_PP_BUFCFG      0x010A          // Buffer Configuration
#define  CS_PP_LINECTL     0x0112          // Line Control Register offset
#define  CS_PP_SELFCTL     0x0114          // Self Control
#define  CS_PP_BUSCTL      0x0116          // Bus Control
#define  CS_PP_TESTCTL     0x0118          // Test Control
#define  CS_PP_ISQ         0x0120          // Interrupt status queue
#define  CS_PP_RXEVENT     0x0124          // Receiver Event
#define  CS_PP_TX_EVENT    0x0128          // Transmitter Event
#define  CS_PP_BUF_EVENT   0x012C          // Buffer Event
#define  CS_PP_RXMISS      0x0130          // Receiver Miss Counter
#define  CS_PP_TXCOL       0x0132          // Transmit Collision Counter
#define  CS_PP_LINESTATUS  0x0134          // Line Status
#define  CS_PP_SELFTEST    0x0136          // Self Status
#define  CS_PP_BUSSTATUS   0x0138          // Bus Status
#define  CS_PP_TXCMD       0x0144          // Transmit Command Request
#define  CS_PP_TXLEN       0x0146          // Transmit Length
#define  CS_PP_IA1         0x0158          // Individual Address (IA)
#define  CS_PP_IA2         0x015A          // Individual Address (IA)
#define  CS_PP_IA3         0x015C          // Individual Address (IA)

#define  CS_PP_RXSTATUS    0x0400          // Receive Status
#define  CS_PP_RXLEN       0x0402          // Receive Length
#define  CS_PP_RXFRAME     0x0404          // Receive Frame Location
#define  CS_PP_TXFRAME     0x0A00          // Transmit Frame Location


// removed interrupt from library
#if 0
// hardware interrupt vector handler 
_interrupt(0x18) void cs8900_interrupt(void)
{
  struct cs8900if *cs8900if = cs8900if_netif->state;
  // network interface is configured?
  if (cs8900if != NULL)
  {
    // chip needs service
    cs8900if->needs_service = 1;
#if (CS8900_STATS > 0)
    cs8900if->interrupts++;
#endif
  }
#ifdef LED_NEED_SERVICE
  leds_on(LED_NEED_SERVICE);
#endif
}
#endif

// cs8900_init()
//
// initializes the CS8900A chip
//
static void cs8900_init(struct netif *netif)
{
#ifdef LED_NEED_SERVICE
  leds_off(LED_NEED_SERVICE);
#endif

  // set RESET bit
  PACKETPP = CS_PP_SELFCTL;
  PPDATA = 0x0055U;

  // { the RESET bit will be cleared by the cs8900a
  //   as a result of the reset }
  // RESET bit cleared?
  while((PPDATA & 0x0040U) != 0); // TODO: add timeout

  // { after full initialization of the cs8900a
  //   the INITD bit will be set }

  PACKETPP = CS_PP_SELFTEST;
  // INITD bit still clear?
  while ((PPDATA & 0x0080U) == 0); // TODO: add timeout
  // { INITD bit is set }

  // SIBUSY bit still set?
  while ((PPDATA & 0x0100U) == 0x0100); // TODO: add timeout
  // { SIBUSY bit clear }

#if 1
  { 
  u16_t dummy;
  // datasheet section 3.3.3 
  dummy = *(u16_t *)(MEM_BASE + IO_BASE + 0x0D);
  // Dummy read, put chip in 16-bit mode
  dummy = *(u16_t *)(MEM_BASE + IO_BASE + 0x0D);
  }
#endif

  // Set MAC address
  PACKETPP = CS_PP_IA1;
  PPDATA = (u16_t)(netif->hwaddr[0]) | (u16_t)(netif->hwaddr[1] << 8U);
  PACKETPP = CS_PP_IA2;
  PPDATA = (u16_t)(netif->hwaddr[2]) | (u16_t)(netif->hwaddr[3] << 8U);
  PACKETPP = CS_PP_IA3;
  PPDATA = (u16_t)(netif->hwaddr[4]) | (u16_t)(netif->hwaddr[5] << 8U);

  // accept valid unicast or broadcast frames
  PACKETPP = CS_PP_RXCTL;
  PPDATA = (0x0005U | 0x0800U/*broadcast*/ | 0x0400U/*individual*/ | 0x0100U/*RxOK*/);
 
  // enable receive interrupt
  PACKETPP = CS_PP_RXCFG;
  PPDATA = (0x0003U | 0x0100U/*RXIRQ*/);

  // disable transmit interrupt (is default)
  PACKETPP = CS_PP_TXCFG;
  PPDATA = (0x0007U | 0);

  // use interrupt number 0
  PACKETPP = CS_PP_INTNUM;
  PPDATA = (0x0000U);

  // generate interrupt event on:
  // - the RxMISS counter reaches 0x200, or
  // - a received frame is lost
  PACKETPP = CS_PP_BUFCFG;
  PPDATA = (0x000bU |
#if (CS8900_STATS > 0) // interrupt before counter overflow 
  (0x2000U/*MissOvfloiE*/ | 0x1000U/*TxColOvfloiE*/) |
#endif
#if (CS8900_STATS > 1) // interrupt on counter increment
  (0x0400U/*RxMissiE*/) |
#endif
  0x0000);

  // enable interrupt generation
  PACKETPP = CS_PP_BUSCTL;
  PPDATA = (0x0017U | 0x8000U/*EnableIRQ*/);

  // enable:
  // - receiver
  // - transmitter
  PACKETPP = CS_PP_LINECTL;
  PPDATA = (0x0013U | 0x0080U/*SerTxOn*/ | 0x0040U/*SerRxOn*/);
}

static err_t cs8900_output(struct netif *netif, struct pbuf *p)
{
	int tries = 0;

  // exit if link has failed
  PACKETPP = CS_PP_LINESTATUS;
  if ((PPDATA & 0x0080U/*LinkOK*/) == 0) return ERR_CONN; // no Ethernet link

  /* issue 'transmit' command to CS8900 */
  TXCMD = 0x00C9U;
  /* send length (in bytes) of packet to send */
  TXLENGTH = p->tot_len;

  PACKETPP = CS_PP_BUSSTATUS;
  // not ready for transmission and still within 100 retries?
  while(((PPDATA & 0x0100U/*Rdy4TxNOW*/) == 0) && (tries++ < 100))
  {
    // throw away the last committed received frame
    PACKETPP = CS_PP_RXCFG;
    PPDATA = (0x0003U | 0x0040U/*Skip_1*/ | 0x0100U/*RxOKiE*/);
    PACKETPP = CS_PP_BUSSTATUS;
    /* cs8900if->dropped++; // CHECK: we do not know if we actually will drop a frame here */ 
  }
  // ready to transmit?
  if((PPDATA & 0x0100U/*Rdy4TxNOW*/) != 0)
  {
    // q traverses through linked list of pbuf's
    struct pbuf *q;
    for(q = p; q != NULL; q = q->next)
    {
      u16_t i;
      u16_t *ptr = (u16_t *)q->payload;
      // Send the data from the pbuf to the interface, one pbuf at a
      // time. The size of the data in each pbuf is kept in the ->len
      // variable.
      for(i = 0; i < q->len; i += 2)
      {
        RXTXREG = *ptr++;
      }
#if (CS8900_STATS > 0)
      ((struct cs8900if *)netif->state)->sentbytes += q->len;
#endif
#if LWIP_SNMP > 0
    snmp_add_ifoutoctets(p->tot_len);
#endif
#if (CS8900_STATS > 0)
    ((struct cs8900if *)netif->state)->sentpackets++;
#endif
    }
  }
  else
  {
    // { not ready to transmit!? }
#if LWIP_SNMP > 0
    snmp_inc_ifoutdiscards();
#endif
  }
  return ERR_OK;
}

/**
 * Move a received packet from the cs8900 into a new pbuf.
 *
 * Must be called after reading an ISQ event containing the
 * "Receiver Event" register, before reading new ISQ events.
 *
 * This function copies a frame from the CS8900A.
 * It is designed failsafe:
 * - It does not assume a frame is actually present.
 * - It checks for non-zero length
 * - It does not overflow the frame buffer
 */
static struct pbuf *cs8900_input(struct netif *netif)
{
  struct pbuf *p = NULL, *q = NULL;
  u16_t len = 0;
  u16_t event_type;
  u16_t i;
  u16_t *ptr = NULL;

  // read RxStatus
  event_type = RXTXREG;

  // correctly received frame, either broadcast or individual address?
  // TODO: maybe defer these conditions to cs8900_input()
  if ((event_type & 0x0100U/*RxOK*/) && (event_type & 0x0c00U/*Broadcast | Individual*/))
  {
#if LWIP_SNMP > 0
    // update number of received MAC-unicast and non-MAC-unicast packets
    if (event_type & 0x0400U/*Individual*/)
    {
      snmp_inc_ifinucastpkts();
    }
    else
    {
      snmp_inc_ifinnucastpkts();
    }
#endif
    event_type = 0; 
    // read RxLength
    len = RXTXREG;
    DEBUGF(NETIF_DEBUG, ("cs8900_input: packet len %u\n", len));
#if LWIP_SNMP > 0    
    snmp_add_ifinoctets(len);
#endif
    // positive length?
    if (len > 0)
    {
      // allocate a pbuf chain with total length 'len' 
      p = pbuf_alloc(PBUF_LINK, len, PBUF_POOL);
      if (p != 0)
      {
        for (q = p; q != 0; q = q->next)
	      {
          DEBUGF(NETIF_DEBUG, ("cs8900_input: pbuf @%p len %u\n", q, q->len));
	        ptr = q->payload;
          // TODO: CHECK: what if q->len is odd? we don't use the last byte?
	        for (i = 0; i < (q->len + 1) / 2; i++)
      	  {
	          *ptr = RXTXREG;
	          ptr++;
      	  }
      	}
      }
      // could not allocate a pbuf
      else
      {
        // skip received frame
        // TODO: maybe do not skip the frame at this point in time?
        PACKETPP = CS_PP_RXCFG;
        PPDATA = (0x0003U | 0x0100U/*RxOKiE*/ | 0x0040U/*Skip_1*/);
#if (CS8900_STATS > 0)
        ((struct cs8900if *)netif->state)->dropped++;
#endif
#if LWIP_SNMP > 0    
        snmp_inc_ifindiscards();
#endif
        len = 0;
      }
    }
    // length was zero
    else
    {
    }
  }
  return p;
}


/**
 * To be called when the cs8900a needs service. Does
 * not assume the cs8900a needs service. Does test the
 * cs8900a whether it needs service. 
 *
 * As such, may be used robustly called as a deferred
 * (or "late") interrupt handler, or may be called in
 * a loop to implement polling, or both.
 *
 * Use cs8900if_service() from your application instead
 * of this function. 
 */
 
static void cs8900_service(struct netif *netif)
{
  // amount of ISQ's to handle (> 0) in one cs8900_service() call
  unsigned char events2service = 1;
  // NOTES:
  // static, so only initialized to zero at program start.
  // irq_status will always hold the last ISQ event register that
  // still needs service. As such, we may leave this function if
  // we encounter an event we cannot service yet, and return later
  // to try to service it.
  static u16_t irq_status = 0x0000U;

  // The "cs8900_needs_service" flag indicates whether any events
  // still need to be serviced.
  // clear flag here. 
  // a receive interrupt can, *concurrently with this function*,
  // set this flag on new ISQ event occurences.
  // we will re-evaluate the correct setting of this flag at
  // function exit (below).
  ((struct cs8900if *)netif->state)->needs_service = 0;
#ifdef LED_NEED_SERVICE
  leds_off(LED_NEED_SERVICE);
#endif
  // no unhandled irq_status left?
  if (irq_status == 0x0000U)
  {
    // read ISQ register
    irq_status = ISQ;
  }
  // ISQ interrupt event, and allowed to service in this loop?
  while ((irq_status != 0x0000U) && (events2service-- > 0))
  {
    // investigate event
    if ((irq_status & 0x003fU) == 0x0004U/*Receiver Event*/)
    {
      // correctly received frame, either broadcast or individual address
      // TODO: think where these checks should appear: here or in cs8900_input()
      if ((irq_status & 0x0100U/*RxOK*/) && (irq_status & 0x0c00U/*Broadcast | Individual*/))
      {
        // read the frame from the cs8900a
        cs8900if_input(netif);
      }
      else
      {
        // skip this frame
        PACKETPP = CS_PP_RXCFG;
        PPDATA |= 0x0040U/*Skip_1*/;
#if (CS8900_STATS > 0)
        ((struct cs8900if *)netif->state)->dropped++;
#endif
      }
    }
#if (CS8900_STATS > 0)
    else if ((irq_status & 0x003fU) == 0x0010U/*RxMISS Event*/)
    {
  	  ((struct cs8900if *)netif->state)->missed += (irq_status >> 6);
  	}
    else if ((irq_status & 0x003fU) == 0x0012U/*TxCOL Event*/)
    {
  	  ((struct cs8900if *)netif->state)->collisions += (irq_status >> 6);
  	}
#endif
    // read ISQ register
    irq_status = ISQ;
  }

  // we did not deplete the ISQ?
  if (irq_status != 0x0000U)
  {
    // the cs8900a still needs service
    ((struct cs8900if *)netif->state)->needs_service = 1;
#ifdef LED_NEED_SERVICE
    leds_on(LED_NEED_SERVICE);
#endif
  }
#if (CS8900_STATS > 1)
  // read RxMiss Counter (zeroes itself upon read)
  PACKETPP = CS_PP_RXMISS;
  ((struct cs8900if *)netif->state)->missed += (PPDATA >> 6);
  // read RxCol Counter (zeroes itself upon read)
  PACKETPP = CS_PP_TXCOL;
  ((struct cs8900if *)netif->state)->collisions += (PPDATA >> 6);
#endif
}

/**
 * Service the CS8900.
 *
 * Can be called in a polling manner, or only after the CS8900 has raised
 * an interrupt request.
 *
 * @param netif The lwIP network interface data structure belonging to this device.
 *
 */
void cs8900if_service(struct netif *netif)
{
  // is there a reason to call the service routine?
  if ((((struct cs8900if *)netif->state)->needs_service) ||
      (((struct cs8900if *)netif->state)->use_polling))
  {
    cs8900_service(netif);
  }
}

/**
 * Writing an IP packet (to be transmitted) to the CS8900.
 *
 * Before writing a frame to the CS8900, the ARP module is asked to resolve the
 * Ethernet MAC address. The ARP module might undertake actions to resolve the
 * address first, and queue this packet for later transmission.
 *
 * @param netif The lwIP network interface data structure belonging to this device.
 * @param p pbuf to be transmitted (or the first pbuf of a chained list of pbufs).
 * @param ipaddr destination IP address.
 *
 * @internal It uses the function cs8900_input() that should handle the actual
 * reception of bytes from the network interface.
 *
 */
err_t cs8900if_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
  struct cs8900if *cs8900if = netif->state;
  p = etharp_output(netif, ipaddr, p);
  /* network hardware address obtained? */
  if (p != NULL)
  {
	  /* send out the packet */
    cs8900_output(netif, p);
	  /* ARP cleanup */
    etharp_output_sent(p);
    p = NULL;
  }
  // { p == NULL }
	else
	{
	  /* we cannot tell if the packet was sent, the packet could have been queued */
    /* on an ARP entry that was already pending. */
	}
  return ERR_OK;
}
/**
 * Read a received packet from the CS8900.
 *
 * This function should be called when a packet is received by the CS8900
 * and is fully available to read. It moves the received packet to a pbuf
 * which is forwarded to the IP network layer or ARP module. It transmits
 * a resulting ARP reply or queued packet.
 *
 * @param netif The lwIP network interface to read from.
 *
 * @internal Uses cs8900_input() to move the packet from the CS8900 to a
 * newly allocated pbuf.
 *
 */
void cs8900if_input(struct netif *netif)
{
  struct cs8900if *cs8900if = netif->state;
  struct eth_hdr *ethhdr = NULL;
  struct pbuf *p = NULL, *q = NULL;

  /* move received packet into a new pbuf */
  p = cs8900_input(netif);
  /* no packet could be read */
  if (p == NULL) {
    /* silently ignore this */
    return;
  }
  /* points to packet payload, which starts with an Ethernet header */
  ethhdr = p->payload;
  
  q = NULL;
  switch(htons(ethhdr->type)) {
  /* IP packet? */
  case ETHTYPE_IP:
    /* update ARP table, obtain first queued packet */
    q = etharp_ip_input(netif, p);
    /* skip Ethernet header */
    pbuf_header(p, -14);
    /* pass to network layer */
    netif->input(p, netif);
    break;
  /* ARP packet? */
  case ETHTYPE_ARP:
    /* pass p to ARP module, get ARP reply or ARP queued packet */
    q = etharp_arp_input(netif, (struct eth_addr *)&netif->hwaddr, p);
    break;
  /* unsupported Ethernet packet type */
  default:
    /* free pbuf */
    pbuf_free(p);
    p = NULL;
    break;
  }
  /* send out the ARP reply or ARP queued packet */
  if (q != NULL) {
    /* q pbuf has been succesfully sent? */
    if (cs8900_output(netif, q) == ERR_OK)
    {
      pbuf_free(q);
      q = NULL;
    }
    else
    {
      /* TODO: re-queue packet in the ARP cache here (?) */
      pbuf_free(q);
      q = NULL;
    }
  }
}
/**
 * Initialize the CS8900 Ethernet MAC/PHY device driver.
 *
 * @param netif The lwIP network interface data structure belonging to this device.
 *
 */
void cs8900if_init(struct netif *netif)
{
  struct cs8900if *cs8900if;

  cs8900if = mem_malloc(sizeof(struct cs8900if));
	if(cs8900if == NULL) return;

  // initialize lwip network interface
  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  netif->output = cs8900if_output;
  netif->linkoutput = cs8900_output;

  // initialize cs8900 specific interface structure
  netif->state = cs8900if;

  // initially assume no ISQ event
  cs8900if->needs_service = 0;
  // set to 1 if polling method is used
  cs8900if->use_polling = 0;

#if (CS8900_STATS > 0)
  // number of interrupt service routine calls
  cs8900if->interrupts = 0;
  cs8900if->missed = 0;
  cs8900if->dropped = 0;
  cs8900if->sentpackets = 0;
  cs8900if->sentbytes = 0;
#endif

  // intialize the cs8900a chip
  cs8900_init(netif);
}

#if 1 
/**
 * Dump an array of bytes inside a UDP message's data field.
 *
 * It is a self-contained function, independent of higher protocol layers or other
 * functions, so it allows you to debug these higher layers, such as lwIP.
 *
 * @param p pointer to an array of bytes, at least with length 'len'
 * @param len number of bytes available at the address pointed to by 'p'
 */
void cs8900_send_debug(unsigned char *p, unsigned int len)
{
	int tries = 0, i;

  // network interface state
  extern struct netif *ethif;

  // exit if link has failed
  PACKETPP = CS_PP_LINESTATUS;
  if ((PPDATA & 0x0080U/*LinkOK*/) == 0) return; // TODO: find a correct error code

  // transmit command
  TXCMD = 0x00C9U;
	// send at least 60 bytes
  TXLENGTH = (14 + 20 + 8 + len < 60) ? 60 : (14 + 20 + 8 + len);

  PACKETPP = CS_PP_BUSSTATUS;
  // not ready for transmission and still within 100 retries?
  while (((PPDATA & 0x0100U/*Rdy4TxNOW*/) == 0) && (tries++ < 100))
  {
    // throw away the last committed received frame
    PACKETPP = CS_PP_RXCFG;
    PPDATA = (0x0003U | 0x0040U/*Skip_1*/ | 0x0100U/*RxOKiE*/);
    PACKETPP = CS_PP_BUSSTATUS;
    /* cs8900if->dropped++; CHECK: we do not know if we actually will drop a frame here, do we? */ 
  }
  // ready to transmit?
  if((PPDATA & 0x0100U/*Rdy4TxNOW*/) != 0)
  { 
    u16_t data, checksum = 0;
    u32_t udp_checksum = 0;
                     
    // destination Ethernet address
    RXTXREG = 0xa000U; 
    RXTXREG = 0xc524U; 
    RXTXREG = 0x6d72U; 
    // source Ethernet address
    RXTXREG = htons(((u16_t)ethif->hwaddr[0] << 8U) | (u16_t)ethif->hwaddr[1]); 
    RXTXREG = htons(((u16_t)ethif->hwaddr[2] << 8U) | (u16_t)ethif->hwaddr[3]); 
    RXTXREG = htons(((u16_t)ethif->hwaddr[4] << 8U) | (u16_t)ethif->hwaddr[5]);
    // frame type
    RXTXREG = htons(0x0800);
    // TOS, version
    RXTXREG = htons(data = ((0x40 | 0x05) << 8) | 0x00); 
    checksum += data;
    // length
    RXTXREG = htons(data = 20 + 8 + len); 
    checksum += data;
    // identifier
    RXTXREG = htons(data = 0); 
    checksum += data;
    // fragment offset
    RXTXREG = htons(data = 0); 
    checksum += data;
    // TTL, UDP protocol
    RXTXREG = htons(data = (255U << 8) | 17U); 
    checksum += data;

    checksum += (htonl(ethif->ip_addr.addr) & 0xffff0000U) >> 16;
    checksum += (htonl(ethif->ip_addr.addr) & 0x0000ffffU);
    checksum += 0xc0a8U;
    checksum += 0x0001U;
    checksum += 6; // LW: kludge/hack: checksum calculation seems to be wrong somehow
    // LW: this seems (?) to fix it
    // checksum
    RXTXREG = htons(~checksum); 

    // source IP
    RXTXREG = htons((htonl(ethif->ip_addr.addr) & 0xffff0000U) >> 16); 
    // source IP           
    RXTXREG = htons( htonl(ethif->ip_addr.addr) & 0x0000ffffU); 
    // destination IP
    RXTXREG = htons(0xc0a8U); 
    // destination IP
    RXTXREG = htons(0x0001U); 
    // source port 3000
    RXTXREG = htons(3000U); 
    // destination port 3000
    RXTXREG = htons(3000U); 
    // UDP length
    RXTXREG = htons(len); 
    // UDP checksum (not present)

    udp_checksum =  (htonl(ethif->ip_addr.addr) & 0xffff0000U) >> 16;
    udp_checksum += (htonl(ethif->ip_addr.addr) & 0x0000ffffU);
    udp_checksum += 0xc0a8U;
    udp_checksum += 0x0001U;
    udp_checksum += 0x0011U;
    udp_checksum += (8 + len);
    udp_checksum += 3000;
    udp_checksum += 3000;
    udp_checksum += (8 + len);
    udp_checksum += cs8900_chksum(p, len);
    while(udp_checksum >> 16) {
      udp_checksum = (udp_checksum & 0xffffUL) + (udp_checksum >> 16);
    }    

    RXTXREG = htons(~(udp_checksum & 0xffff));
	  // UDP data
    for (i = 0; i < len; i += 2)
    {
      RXTXREG = htons((p[i] << 8) | p[i + 1]);
    } 
	  // pad to 60 bytes
	  while (i < 60)
	  {
      RXTXREG = 0;
	    i += 2;
	  }
  }
}

static u32_t cs8900_chksum(void *dataptr, int len)
{
  u32_t acc = 0;
  u16_t *ptr = (u16_t *)dataptr;
    
  for(acc = 0; len > 1; len -= 2) {
    acc += *ptr;
    ptr++;
  }
  /* add up any odd byte */
  if(len == 1) {
    acc += htons((u16_t)((*(u8_t *)ptr) & 0xffU) << 8);
  }
  return acc;
}

#endif