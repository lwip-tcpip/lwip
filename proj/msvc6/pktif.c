/*
 * Copyright (c) 2001,2002 Florian Schulze.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * pktif.c - This file is part of lwIPtest
 *
 ****************************************************************************
 *
 * This file is derived from an example in lwIP with the following license:
 *
 * Copyright (c) 2001, Swedish Institute of Computer Science.
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
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 */

#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <packet32.h>
#include <ntddndis.h>

#include "lwip/debug.h"

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/ip.h"

#include "netif/etharp.h"
#include "netif/tcpdump.h"

#undef NETIF_DEBUG

/* Define those to better describe your network interface. */
#define IFNAME0 'p'
#define IFNAME1 'k'

struct ethernetif {
	struct eth_addr *ethaddr;
	/* Add whatever per-interface state that is needed here. */
};

static const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}};

/* Forward declarations. */
static void  ethernetif_input(struct netif *netif);
static err_t ethernetif_output(struct netif *netif, struct pbuf *p,
			       struct ip_addr *ipaddr);

static struct netif *pktif_netif;

LPADAPTER  lpAdapter;
LPPACKET   lpPacket;
char buffer[256000];  // buffer to hold the data coming from the driver
unsigned char *cur_packet;
int cur_length;

struct eth_addr ethaddr;

/*-----------------------------------------------------------------------------------*/
int init_adapter(void)
{
  #define Max_Num_Adapter 10

  char AdapterList[Max_Num_Adapter][1024];

	int i;
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;

	//unicode strings (winnt)
	WCHAR		AdapterName[8192]; // string that contains a list of the network adapters
	WCHAR		*temp,*temp1;

	//ascii strings (win95)
	char		AdapterNamea[8192]; // string that contains a list of the network adapters
	char		*tempa,*temp1a;

	int			AdapterNum=0;
	ULONG		AdapterLength;

  PPACKET_OID_DATA ppacket_oid_data;
	
	BOOLEAN result;

	// obtain the name of the adapters installed on this machine
	AdapterLength=4096;

  memset(AdapterList,0,sizeof(AdapterList));

  i=0;

	// the data returned by PacketGetAdapterNames is different in Win95 and in WinNT.
	// We have to check the os on which we are running
	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4))
	{  // Windows NT
		if(PacketGetAdapterNames(AdapterName,&AdapterLength)==FALSE){
			printf("Unable to retrieve the list of the adapters!\n");
			return -1;
		}
		temp=AdapterName;
		temp1=AdapterName;
		while ((*temp!='\0')||(*(temp-1)!='\0'))
		{
			if (*temp=='\0') 
			{
				memcpy(AdapterList[i],temp1,(temp-temp1)*2);
				temp1=temp+1;
				i++;
		}
	
		temp++;
		}
	  
		AdapterNum=i;
	}

	else	//windows 95
	{
		if(PacketGetAdapterNames(AdapterNamea,&AdapterLength)==FALSE){
			printf("Unable to retrieve the list of the adapters!\n");
			return -1;
		}
		tempa=AdapterNamea;
		temp1a=AdapterNamea;

		while ((*tempa!='\0')||(*(tempa-1)!='\0'))
		{
			if (*tempa=='\0') 
			{
				memcpy(AdapterList[i],temp1a,tempa-temp1a);
				temp1a=tempa+1;
				i++;
			}
			tempa++;
		}
		  
		AdapterNum=i;
	}

  if (AdapterNum<=0)
    return -1;

  ppacket_oid_data=malloc(sizeof(PACKET_OID_DATA)+6);
  lpAdapter=PacketOpenAdapter(AdapterList[0]);
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	  return -1;
  ppacket_oid_data->Oid=OID_802_3_PERMANENT_ADDRESS;
  ppacket_oid_data->Length=6;
  if (!PacketRequest(lpAdapter,FALSE,ppacket_oid_data))
		return -1;
  memcpy(ppacket_oid_data->Data,&ethaddr,6);
  free(ppacket_oid_data);
	PacketSetBuff(lpAdapter,512000);
	PacketSetReadTimeout(lpAdapter,1);
	PacketSetHwFilter(lpAdapter,NDIS_PACKET_TYPE_ALL_LOCAL);
	if((lpPacket = PacketAllocatePacket())==NULL){
		return (-1);
	}
	PacketInitPacket(lpPacket,(char*)buffer,256000);

	return 0;
}

void shutdown_adapter(void)
{
  struct ethernetif *ethernetif;

  ethernetif = pktif_netif->state;
 
	PacketFreePacket(lpPacket);
	PacketCloseAdapter(lpAdapter);
}

static void open_adapter(struct ethernetif *ethernetif)
{
	memcpy(&ethaddr,ethernetif->ethaddr,6);
}

/*-----------------------------------------------------------------------------------*/
static void
low_level_init(struct netif *netif)
{
	struct ethernetif *ethernetif;

	ethernetif = netif->state;
  
	open_adapter(ethernetif);

#ifdef NETIF_DEBUG
	DEBUGF(NETIF_DEBUG, ("pktif: eth_addr %02X%02X%02X%02X%02X%02X\n",ethernetif->ethaddr->addr[0],ethernetif->ethaddr->addr[1],ethernetif->ethaddr->addr[2],ethernetif->ethaddr->addr[3],ethernetif->ethaddr->addr[4],ethernetif->ethaddr->addr[5]));
#endif /* NETIF_DEBUG */
	/* Do whatever else is needed to initialize interface. */  
	
	pktif_netif=netif;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *ethernetif, struct pbuf *p)
{
  struct pbuf *q;
  unsigned char buffer[1600];
	unsigned char *ptr;
	LPPACKET lpPacket;

  /* initiate transfer(); */
  if (p->tot_len>=1600)
 		return ERR_BUF;
	if((lpPacket = PacketAllocatePacket())==NULL)
 		return ERR_BUF;
	PacketInitPacket(lpPacket,buffer,p->tot_len);
	ptr=buffer;
  for(q = p; q != NULL; q = q->next) {
    /* Send the data from the pbuf to the interface, one pbuf at a
       time. The size of the data in each pbuf is kept in the ->len
       variable. */
    /* send data from(q->payload, q->len); */
#ifdef NETIF_DEBUG
		DEBUGF(NETIF_DEBUG, ("netif: send ptr %p q->payload %p q->len %i q->next %p\n", ptr, q->payload, (int)q->len, q->next));
#endif
		bcopy(q->payload,ptr,q->len);
		ptr+=q->len;
  }

  /* signal that packet should be sent(); */
	
	if (!PacketSendPacket(lpAdapter,lpPacket,TRUE))
		return ERR_BUF;
	PacketFreePacket(lpPacket);

#ifdef LINK_STATS
  lwip_stats.link.xmit++;
#endif /* LINK_STATS */      
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
low_level_input(struct netif *ethernetif)
{
  struct pbuf *p, *q;
  int start, length;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  length = cur_length;
	if (length<=0)
		return NULL;

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_LINK, (u16_t)length, PBUF_POOL);
#ifdef NETIF_DEBUG
	DEBUGF(NETIF_DEBUG, ("netif: recv length %i p->tot_len %i\n", length, (int)p->tot_len));
#endif
	
  if(p != NULL) {
    /* We iterate over the pbuf chain until we have read the entire
       packet into the pbuf. */
		start=0;
    for(q = p; q != NULL; q = q->next) {
      /* Read enough bytes to fill this pbuf in the chain. The
         avaliable data in the pbuf is given by the q->len
         variable. */
      /* read data into(q->payload, q->len); */
#ifdef NETIF_DEBUG
			DEBUGF(NETIF_DEBUG, ("netif: recv start %i length %i q->payload %p q->len %i q->next %p\n", start, length, q->payload, (int)q->len, q->next));
#endif
      bcopy(&cur_packet[start],q->payload,q->len);
			start+=q->len;
			length-=q->len;
			if (length<=0)
				break;
    }
    /* acknowledge that packet has been read(); */
    cur_length=0;
#ifdef LINK_STATS
    lwip_stats.link.recv++;
#endif /* LINK_STATS */      
  } else {
    /* drop packet(); */
    cur_length=0;
#ifdef LINK_STATS
    lwip_stats.link.memerr++;
    lwip_stats.link.drop++;
#endif /* LINK_STATS */      
  }

  return p;  
}
/*-----------------------------------------------------------------------------------*/
/*
 * ethernetif_output():
 *
 * This function is called by the TCP/IP stack when an IP packet
 * should be sent. It calls the function called low_level_output() to
 * do the actuall transmission of the packet.
 *
 */
/*-----------------------------------------------------------------------------------*/
static err_t
ethernetif_output(struct netif *netif, struct pbuf *p,
		  struct ip_addr *ipaddr)
{
  p = etharp_output(netif, ipaddr, p);
  if(p != NULL) {
    return low_level_output(netif, p);
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * ethernetif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
ethernetif_input(struct netif *netif)
{
  struct ethernetif *ethernetif;
  struct eth_hdr *ethhdr;
  struct pbuf *p;


  ethernetif = netif->state;
  
  p = low_level_input(netif);

  if(p != NULL) {

#ifdef LINK_STATS
    lwip_stats.link.recv++;
#endif /* LINK_STATS */

    ethhdr = p->payload;
    
    switch(htons(ethhdr->type)) {
    case ETHTYPE_IP:
      etharp_ip_input(netif, p);
      pbuf_header(p, -14);
			//if(ip_lookup(p->payload, netif)) {
	      netif->input(p, netif);
			//}
      break;
    case ETHTYPE_ARP:
      p = etharp_arp_input(netif, ethernetif->ethaddr, p);
      if(p != NULL) {
				low_level_output(netif, p);
				pbuf_free(p);
      }
      break;
    default:
      pbuf_free(p);
      break;
    }
  }
}
/*-----------------------------------------------------------------------------------*/
static void
arp_timer(void *arg)
{
  etharp_tmr();
  sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, NULL);
}
/*-----------------------------------------------------------------------------------*/
/*
 * ethernetif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
void
ethernetif_init(struct netif *netif)
{
  struct ethernetif *ethernetif;
    
  ethernetif = mem_malloc(sizeof(struct ethernetif));
  netif->state = ethernetif;
  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  netif->output = ethernetif_output;
  
  ethernetif->ethaddr = (struct eth_addr *)&(netif->hwaddr[0]);
  
  low_level_init(netif);
  etharp_init();  
  
  sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, NULL);
}
/*-----------------------------------------------------------------------------------*/
/*
 * pktif_update():
 *
 * Needs to be called periodically to get new packets. This could
 * be done inside a thread.
 */
/*-----------------------------------------------------------------------------------*/
static void ProcessPackets(LPPACKET lpPacket)
{

	ULONG	ulLines, ulBytesReceived;
	char	*base;
	char	*buf;
	u_int off=0;
	u_int tlen,tlen1;
	struct bpf_hdr *hdr;
  struct ethernetif *ethernetif;

  ethernetif = pktif_netif->state;
  
	ulBytesReceived = lpPacket->ulBytesReceived;

	buf = lpPacket->Buffer;

	off=0;

	while(off<ulBytesReceived)
  {	
		//if(kbhit())return;
		hdr=(struct bpf_hdr *)(buf+off);
		tlen1=hdr->bh_datalen;
		cur_length=tlen1;
		tlen=hdr->bh_caplen;
		off+=hdr->bh_hdrlen;

		ulLines = (tlen + 15) / 16;
		if (ulLines > 5) ulLines=5;

		base =(char*)(buf+off);
		cur_packet=base;
		off=Packet_WORDALIGN(off+tlen);

		ethernetif_input(pktif_netif);
	}
} 

void update_adapter(void)
{
  struct ethernetif *ethernetif;

  ethernetif = pktif_netif->state;
  
  if(PacketReceivePacket(lpAdapter,lpPacket,TRUE)==TRUE)
    ProcessPackets(lpPacket);
  cur_length=0;
  cur_packet=NULL;
}

