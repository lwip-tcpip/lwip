/*
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
 * All rights reserved. 
 *
 * Copyright (c) 2001, 2002 Xilinx, Inc.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
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
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO 
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS".
 * BY PROVIDING THIS DESIGN, CODE, OR INFORMATION AS ONE POSSIBLE 
 * IMPLEMENTATION OF THIS FEATURE, APPLICATION OR STANDARD, XILINX 
 * IS MAKING NO REPRESENTATION THAT THIS IMPLEMENTATION IS FREE FROM 
 * ANY CLAIMS OF INFRINGEMENT, AND YOU ARE RESPONSIBLE FOR OBTAINING 
 * ANY RIGHTS YOU MAY REQUIRE FOR YOUR IMPLEMENTATION.  XILINX 
 * EXPRESSLY DISCLAIMS ANY WARRANTY WHATSOEVER WITH RESPECT TO THE 
 * ADEQUACY OF THE IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO ANY 
 * WARRANTIES OR REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE 
 * FROM CLAIMS OF INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY 
 * AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Chris Borrelli <chris.borrelli@xilinx.com>
 * 
 * Based on example ethernetif.c, Adam Dunkels <adam@sics.se>
 *
 */

/*---------------------------------------------------------------------------*/
/* V2PDK Include Files                                                       */
/*---------------------------------------------------------------------------*/
#include "xemac.h"
#include "xparameters.h"
#include "xstatus.h"
#include "xintc.h"
#include "exception.h"

/*---------------------------------------------------------------------------*/
/* LWIP Include Files                                                        */
/*---------------------------------------------------------------------------*/
#include "lwip/debug.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "netif/etharp.h"
#include "netif/xemacif.h"

/*---------------------------------------------------------------------------*/
/* Describe network interface                                                */
/*---------------------------------------------------------------------------*/
#define IFNAME0 'e'
#define IFNAME1 '0'

/*---------------------------------------------------------------------------*/
/* Constant Definitions                                                      */
/*---------------------------------------------------------------------------*/
#define EMAC_INTR_ID 28 /* Interrupt ID for EMAC */
#define XEM_MAX_FRAME_SIZE_IN_WORDS ((XEM_MAX_FRAME_SIZE/sizeof(Xuint32))+1)

/*---------------------------------------------------------------------------*/
/* xemacif structure                                                         */
/*    contains the ethernet address and the                                  */
/*    pointer to the instance of the Xilinx                                  */
/*    EMAC driver.                                                           */
/*---------------------------------------------------------------------------*/

struct xemacif {
  struct eth_addr *ethaddr;
  XEmac *instance_ptr;
};

static const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}};
static struct eth_addr mymac              = {{0x00,0x0A,0x35,0x00,0x22,0x20}};

/*---------------------------------------------------------------------------*/
/* Forward declarations                                                      */
/*---------------------------------------------------------------------------*/
static err_t xemacif_output(struct netif *netif, struct pbuf *p,
                struct ip_addr *ipaddr);

#ifdef LWIP_XEMAC_USE_INTMODE
static void FifoSendHandler(void *CallBackRef);
static void ErrorHandler(void *CallBackRef, XStatus Code);
#endif /* LWIP_XEMAC_USE_INTMODE */

/*---------------------------------------------------------------------------*/
/* low_level_init function                                                   */
/*    - hooks up the data structures and sets the mac options and mac        */
/*---------------------------------------------------------------------------*/
static err_t 
low_level_init(struct netif *netif_ptr)
{
   XIntc *IntcInstancePtr;
   
   XEmac * InstancePtr;
   Xuint16 DeviceId = XPAR_EMAC_0_DEVICE_ID; /* from xparameters.h */
#ifdef LWIP_XEMAC_USE_INTMODE
   Xuint16 IntcDeviceId = XPAR_INTC_0_DEVICE_ID;
#endif /* LWIP_XEMAC_USE_INTMODE */
   XStatus Result;
   Xuint32 Options;

   struct xemacif *xemacif_ptr;

   xemacif_ptr = netif_ptr->state;

   /* Get Instance of EMAC Driver */
   xemacif_ptr->instance_ptr = InstancePtr = XEmac_GetInstance(0);

#ifdef LWIP_XEMAC_USE_INTMODE
   /* Get Instance of Interrupt Controller Driver */
   IntcInstancePtr = XIntc_GetInstance(0);
#endif /* LWIP_XEMAC_USE_INTMODE */

   /* Call Initialize Function of EMAC driver */
   Result = XEmac_Initialize(InstancePtr, DeviceId);
   if (Result != XST_SUCCESS) {
      return ERR_MEM;
   }

#ifdef LWIP_XEMAC_USE_INTMODE
   if (XIntc_Initialize(IntcInstancePtr, IntcDeviceId) != XST_SUCCESS) {
      return ERR_MEM;
   }
#endif /* LWIP_XEMAC_USE_INTMODE */

   if (XEmac_IsSgDma(InstancePtr)) {
      /* not configured for direct FIFO access */
      return ERR_MEM;
   }

   Result = XEmac_SelfTest(InstancePtr);
   if (Result != XST_SUCCESS && Result != XST_DEVICE_IS_STARTED) {
      return ERR_MEM;
   }

#ifdef LWIP_XEMAC_USE_INTMODE
   Result = XIntc_SelfTest(IntcInstancePtr);
   if (Result != XST_SUCCESS && Result != XST_DEVICE_IS_STARTED) {
      return ERR_MEM;
   }
#endif /* LWIP_XEMAC_USE_INTMODE */

   /* Stop the EMAC hardware */
   (void) XEmac_Stop(InstancePtr);

   /* Set MAC Address of EMAC */
   Result = XEmac_SetMacAddress(InstancePtr, (Xuint8*) netif_ptr->hwaddr);
   if (Result != XST_SUCCESS) return ERR_MEM;

   /* Set MAC Options - UNICAST and BROADCAST */
#ifdef LWIP_XEMAC_USE_INTMODE
   Options = (XEM_UNICAST_OPTION | XEM_BROADCAST_OPTION);
#else /* LWIP_XEMAC_USE_INTMODE */
   Options = (XEM_UNICAST_OPTION | XEM_BROADCAST_OPTION | XEM_POLLED_OPTION);
#endif /* LWIP_XEMAC_USE_INTMODE */
   
   Result = XEmac_SetOptions(InstancePtr, Options);
   if (Result != XST_SUCCESS) return ERR_MEM;

#ifdef LWIP_XEMAC_USE_INTMODE
   /* Set Callbacks and error handler */
   XEmac_SetFifoSendHandler(InstancePtr, netif_ptr, FifoSendHandler);
   XEmac_SetFifoRecvHandler(InstancePtr, netif_ptr, xemacif_input);
   XEmac_SetErrorHandler(InstancePtr, netif_ptr, ErrorHandler);

   /* Connect to the interrupt controller and enable interrupts */
   XIntc_Connect(IntcInstancePtr, EMAC_INTR_ID, 
         XEmac_GetIntrHandler(InstancePtr), InstancePtr);
#endif /* LWIP_XEMAC_USE_INTMODE */

   /* Start the EMAC hardware */
   Result = XEmac_Start(InstancePtr);
   if (Result != XST_SUCCESS)
      return ERR_MEM;

#ifdef LWIP_XEMAC_USE_INTMODE
   if (XST_SUCCESS != XIntc_Start(IntcInstancePtr))
      return ERR_MEM;

   XIntc_Enable(IntcInstancePtr, EMAC_INTR_ID);
#endif /* LWIP_XEMAC_USE_INTMODE */

   return ERR_OK;
}

#ifdef LWIP_XEMAC_USE_INTMODE
/*---------------------------------------------------------------------------*/
/* FifoSendHandler()                                                         */
/*                                                                           */
/* Checks for Tx Errors                                                      */
/* TODO: Add actions.  Nothing happens if an error is found.                 */
/*                                                                           */
/*---------------------------------------------------------------------------*/
static void FifoSendHandler(void *CallBackRef)
{
   struct netif *netif_ptr = (struct netif *) CallBackRef;
   XEmac *EmacPtr = ((struct xemacif*) netif_ptr->state)->instance_ptr;
   XEmacStats Stats;
    
   /*
   * Check stats for transmission errors (overrun or underrun errors are
   * caught by the asynchronous error handler).
   */
   XEmac_GetStats(EmacPtr, &Stats);
   if (Stats.XmitLateCollisionErrors || Stats.XmitExcessDeferral)
      ;
}

/*---------------------------------------------------------------------------*/
/* ErrorHandler()                                                            */
/*                                                                           */
/* Resets the MAC hardware is an error occurs                                */
/*---------------------------------------------------------------------------*/
static void ErrorHandler(void *CallBackRef, XStatus Code)
{
   struct netif *netif_ptr = (struct netif *) CallBackRef;
   XEmac *EmacPtr = ((struct xemacif*) netif_ptr->state)->instance_ptr;
    
   if (Code == XST_RESET_ERROR) {
      /*
       * A reset error means the application should reset the device because
       * it encountered a reset condition (most likely a FIFO overrun, but
       * can be other reasons).  You can look at the XEmac statistics to
       * see what the error is.
       */
      XEmac_Reset(EmacPtr);
      (void)XEmac_SetMacAddress(EmacPtr, (Xuint8*) netif_ptr->hwaddr);
      (void)XEmac_SetOptions(EmacPtr,XEM_UNICAST_OPTION|XEM_BROADCAST_OPTION);
      (void)XEmac_Start(EmacPtr);
   }
}
#endif /* LWIP_XEMAC_USE_INTMODE */

/*---------------------------------------------------------------------------*/
/* low_level_output()                                                        */
/*                                                                           */
/* Should do the actual transmission of the packet. The packet is            */
/* contained in the pbuf that is passed to the function. This pbuf           */
/* might be chained.                                                         */
/*---------------------------------------------------------------------------*/
static err_t low_level_output(struct xemacif *xemacif_ptr, struct pbuf *p)
{
   struct pbuf *q;
   u32_t frame_buffer[XEM_MAX_FRAME_SIZE_IN_WORDS];  /* word aligned */
   Xuint8 *frame_ptr;
   int payload_size = 0, i;
   XStatus Result;

   frame_ptr = (Xuint8 *) frame_buffer;

   for(q = p; q != NULL; q = q->next) {
      /*
       * Send the data from the pbuf to the interface, one pbuf at a
       * time. The size of the data in each pbuf is kept in the ->len
       * variable.
       */
      for(i = 0 ; i < q->len ; i++) {
         *(frame_ptr++) = (Xuint8) *(((u8_t *) q->payload) + i);
         payload_size++;
      }
   }

#ifdef LWIP_XEMAC_USE_INTMODE

   Result = XEmac_FifoSend(xemacif_ptr->instance_ptr, 
                           (Xuint8 *) frame_buffer,
                           payload_size);

#else /* LWIP_XEMAC_USE_INTMODE */

   Result = XEmac_PollSend(xemacif_ptr->instance_ptr, 
                           (Xuint8 *) frame_buffer,
                           payload_size);

#endif /* LWIP_XEMAC_USE_INTMODE */

   if (Result != XST_SUCCESS) return ERR_MEM;      

#ifdef LINK_STATS
   stats.link.xmit++;
#endif /* LINK_STATS */

   return ERR_OK;
}

/*---------------------------------------------------------------------------*/
/* low_level_input()                                                         */
/*                                                                           */
/* Allocates a pbuf pool and transfers bytes of                              */
/* incoming packet from the interface into the pbuf.                         */
/*---------------------------------------------------------------------------*/
static struct pbuf * low_level_input(struct xemacif *xemacif_ptr)
{
   struct pbuf *p = NULL, *q = NULL;
   XEmac *EmacPtr = (XEmac *) xemacif_ptr->instance_ptr;
   
   Xuint32 RecvBuffer[XEM_MAX_FRAME_SIZE_IN_WORDS];
   Xuint32 FrameLen = XEM_MAX_FRAME_SIZE;
   Xuint32 i;
   u8_t * frame_bytes = (u8_t *) RecvBuffer;
   XStatus Result;

#ifdef CHRIS_DEBUG
   char ascii[2];
#endif /* CHRIS_DEBUG */

#ifdef LWIP_XEMAC_USE_INTMODE
   Result = XEmac_FifoRecv(EmacPtr, (Xuint8 *)RecvBuffer, &FrameLen);
#else
   Result = XEmac_PollRecv(EmacPtr, (Xuint8 *)RecvBuffer, &FrameLen);
#endif /* LWIP_XEMAC_USE_INTMODE */

   if (Result != XST_SUCCESS)
      return p;

#if 0
   printf("\r\n");
   for (i=0 ; i < FrameLen ; i++) {
      printf("%4X", frame_bytes[i]);
      if (! (i%20) && i) printf("\r\n");
      else printf(" ");
   }
   printf ("\r\n");
#endif

   /* Allocate a pbuf chain of pbufs from the pool. */
   p = pbuf_alloc(PBUF_LINK, FrameLen, PBUF_POOL);

   if(p != NULL) {
   /* Iterate over the pbuf chain until we have
    * read the entire packet into the pbuf. */
      for(q = p; q != NULL; q = q->next) {
         /* Read enough bytes to fill this pbuf 
          * in the chain.  The avaliable data in 
          * the pbuf is given by the q->len variable. */
         for (i = 0 ; i < q->len ; i++) {
            ((u8_t *)q->payload)[i] = *(frame_bytes++);
         }
      }

#ifdef LINK_STATS
      stats.link.recv++;
#endif /* LINK_STATS */      

   } else {

#ifdef LINK_STATS
      stats.link.memerr++;
      stats.link.drop++;
#endif /* LINK_STATS */ 
      ;
   }
   return p;  
}

/*---------------------------------------------------------------------------*/
/* xemacif_output():                                                         */
/*                                                                           */
/* This function is called by the TCP/IP stack when an IP packet             */
/* should be sent. It calls the function called low_level_output() to        */
/* do the actuall transmission of the packet.                                */
/*---------------------------------------------------------------------------*/
static err_t xemacif_output(struct netif *netif_ptr,
                            struct pbuf *p,
                            struct ip_addr *ipaddr)
{
   struct xemacif *xemacif_ptr = xemacif_ptr = netif_ptr->state;

   p = etharp_output(netif_ptr, ipaddr, p);
   if (p != NULL)
      return low_level_output(xemacif_ptr, p);
   return ERR_OK;
}

/*---------------------------------------------------------------------------*/
/* xemacif_input():                                                          */
/*                                                                           */
/* This function should be called when a packet is ready to be read          */
/* from the interface. It uses the function low_level_input() that           */
/* should handle the actual reception of bytes from the network              */
/* interface.                                                                */
/*---------------------------------------------------------------------------*/
void xemacif_input(void *CallBackRef)
{
   struct netif * netif_ptr = (struct netif *) CallBackRef;
   struct xemacif * xemacif_ptr;
   struct eth_hdr * ethernet_header;
   struct pbuf *p, *q;

#ifdef LWIP_XEMAC_USE_INTMODE
   /* Disable Interrupts */
   XIntc_Disable(XIntc_GetInstance(0), XPAR_INTC_0_DEVICE_ID);
#endif /* LWIP_XEMAC_USE_INTMODE */

   xemacif_ptr = netif_ptr->state;

   p = low_level_input(xemacif_ptr);

   if(p != NULL) {
      ethernet_header = p->payload;

      q = NULL;
      switch(htons(ethernet_header->type)) {
      case ETHTYPE_IP:
         q = etharp_ip_input(netif_ptr, p);
         pbuf_header(p, -14);
         netif_ptr->input(p, netif_ptr);
         break;
      case ETHTYPE_ARP:
         q = etharp_arp_input(netif_ptr, xemacif_ptr->ethaddr, p);
         break;
      default:
         pbuf_free(p);
         break;
      }

      if(q != NULL) {
         low_level_output(xemacif_ptr, q);
         pbuf_free(q);
      }
   }

#ifdef LWIP_XEMAC_USE_INTMODE
   /* Enable Interrupts again */
   XIntc_Enable(XIntc_GetInstance(0), XPAR_INTC_0_DEVICE_ID);
#endif /* LWIP_XEMAC_USE_INTMODE */
}

/*---------------------------------------------------------------------------*/
/* xemacif_setmac():                                                         */
/*                                                                           */
/* Sets the MAC address of the system.                                       */
/* Note:  Can only be called before xemacif_init is called.                  */
/*---------------------------------------------------------------------------*/
void xemacif_setmac(u8_t *addr)
{
   mymac.addr[0] = addr[0];
   mymac.addr[1] = addr[1];
   mymac.addr[2] = addr[2];
   mymac.addr[3] = addr[3];
   mymac.addr[4] = addr[4];
   mymac.addr[5] = addr[5];
}

/*---------------------------------------------------------------------------*/
/* xemacif_getmac():                                                         */
/*                                                                           */
/* Returns a pointer to the mymac variable (6 bytes in length)               */
/*---------------------------------------------------------------------------*/
u8_t * xemacif_getmac(void) { return &(mymac.addr[0]); }

/*---------------------------------------------------------------------------*/
/* xemacif_init():                                                           */
/*                                                                           */
/* Should be called at the beginning of the program to set up the            */
/* network interface. It calls the function low_level_init() to do the       */
/* actual setup of the hardware.                                             */
/*---------------------------------------------------------------------------*/
void xemacif_init(struct netif *netif_ptr)
{
   struct xemacif *xemacif_ptr;

   xemacif_ptr = mem_malloc(sizeof(struct xemacif));

   netif_ptr->state = xemacif_ptr;
   netif_ptr->hwaddr[0] = mymac.addr[0];
   netif_ptr->hwaddr[1] = mymac.addr[1];
   netif_ptr->hwaddr[2] = mymac.addr[2];
   netif_ptr->hwaddr[3] = mymac.addr[3];
   netif_ptr->hwaddr[4] = mymac.addr[4];
   netif_ptr->hwaddr[5] = mymac.addr[5];
   netif_ptr->name[0] = IFNAME0;
   netif_ptr->name[1] = IFNAME1;
   netif_ptr->output = xemacif_output;
   netif_ptr->linkoutput = NULL;

   /* Copy pointer to netif_ptr->hwaddr into the xemacif_ptr->ethaddr */
   xemacif_ptr->ethaddr = (struct eth_addr *)&(netif_ptr->hwaddr[0]);

   /* Set EXmac instance pointer to NULL. It gets set in low_level_init() */
   xemacif_ptr->instance_ptr = NULL;
   
   low_level_init(netif_ptr);
   etharp_init();
}
