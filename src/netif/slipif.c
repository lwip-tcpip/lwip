/*
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
 * This file is built upon the file: src/arch/rtxc/netif/sioslip.c
 *
 * Author: Magnus Ivarsson <magnus.ivarsson(at)volvo.com>
 */

#include "netif/slipif.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "netif/sio.h"

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

#define MAX_SIZE     1500
#define SLIPIF_NUM_OF_INTERFACES 2

typedef struct slip_status_t {
	void *sio;
} slip_status_t;

/* yes, this is ugly; TODO: should be dynamicaly allocated instead */
static slip_status_t statusar[SLIPIF_NUM_OF_INTERFACES];

/*-----------------------------------------------------------------------------------*/
err_t slipif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
	slip_status_t *slipState = (slip_status_t *) netif->state;
	struct pbuf *q;
	int i;
	u8_t c;

	/* Send pbuf out on the serial I/O device. */
	sio_send(SLIP_END, slipState->sio);

	for(q = p; q != NULL; q = q->next) {
		for(i = 0; i < q->len; i++) {
			c = ((u8_t *)q->payload)[i];
			switch(c) {
			case SLIP_END:
				sio_send(SLIP_ESC, slipState->sio);
				sio_send(SLIP_ESC_END, slipState->sio);
				break;
			case SLIP_ESC:
				sio_send(SLIP_ESC, slipState->sio);
				sio_send(SLIP_ESC_ESC, slipState->sio);
				break;
			default:
				sio_send(c, slipState->sio);
				break;
			}
		}
	}
	sio_send(SLIP_END, slipState->sio);
	return 0;
}
/*-----------------------------------------------------------------------------------*/

static struct pbuf * slipif_input( struct netif * netif )
{
	slip_status_t *slipState = (slip_status_t *) netif->state;

 	u8_t c;
	struct pbuf *p, *q;
	int recved;
	int i;

	q = p = NULL;
	recved = i = 0;
	c = 0;

	while ( 1 )
	{
		c = sio_recv( slipState->sio );
		switch ( c )
		{
		case SLIP_END:
			if ( p == NULL )
			{
				return slipif_input( netif );
			}
			if ( recved > 0 )
			{
				/* Received whole packet. */
				pbuf_realloc( q, recved );

                    #ifdef LINK_STATS
				stats.link.recv++;
                    #endif /* LINK_STATS */         

				DEBUGF( SLIP_DEBUG, ("slipif: Got packet\n") );
				return q;
			}
			break;

		case SLIP_ESC:
			c = sio_recv( slipState->sio );
			switch ( c ) 
			{
			case SLIP_ESC_END:
				c = SLIP_END;
				break;
			case SLIP_ESC_ESC:
				c = SLIP_ESC;
				break;
			}
			/* FALLTHROUGH */

		default:
			if ( p == NULL )
			{
				DEBUGF( SLIP_DEBUG, ("slipif_input: alloc\n") );
				p = pbuf_alloc( PBUF_LINK, 128, PBUF_POOL );

					#ifdef LINK_STATS           
				if ( p == NULL )
				{
					stats.link.drop++;
					DEBUGF( SLIP_DEBUG, ("slipif_input: no new pbuf! (DROP)\n") );
				}
					#endif /* LINK_STATS */                  

				if ( q != NULL )
				{
					pbuf_chain( q, p );
				}
				else
				{
					q = p;
				}
			}
			if ( p != NULL && recved < MAX_SIZE )
			{
				((u8_t *)p->payload)[i] = c;
				recved++;
				i++;
				if ( i >= p->len )
				{
					i = 0;
					p = NULL;
				}
			}
			break;
		}

	}
	return NULL;
}
/*-----------------------------------------------------------------------------------*/
static void slipif_loop(void *nf)
{
	struct pbuf *p;
	struct netif *netif = (struct netif *) nf;
//	slip_status_t *slipState = (slip_status_t *) netif->state;

	while(1) {
		p = slipif_input( netif );
		netif->input(p, netif);
	}
}			 
/*-----------------------------------------------------------------------------------*/
// void
// sioslipif_init0(struct netif *netif)
// {
//   slip_status_t * ss;
//   printf("slipif_init0: netif->num=%x\n", (int)netif->num);
// 
//   netif->state = &statusar[0];
//   netif->name[0] = 's';
//   netif->name[1] = 'l';
//   netif->output = sioslipif_output;
//   netif->num = 0;
// 
//   sio_open( netif );
// 	ss = (slip_status_t*)(netif->state);
//   printf("slipif_init0: netif=%x sio=0x%x\n", (int)netif, (int)(ss->sio));
//   sys_thread_new((void *)slipif_loop, netif);
// }

/*-----------------------------------------------------------------------------------*/
void slipif_init(struct netif *netif)
{
	slip_status_t *slipState;
	
	DEBUGF(SLIP_DEBUG, ("slipif_init: netif->num=%x\n", (int)netif->num));
	if ( netif->num >= SLIPIF_NUM_OF_INTERFACES )
	{
		DEBUGF( SLIP_DEBUG, ("ERROR: To many slipifs"));
		return;
	}

	/* dynamic allocation would be nice */
	netif->state = &statusar[ netif->num ];
	netif->name[0] = 's';
	netif->name[1] = 'l';
	netif->output = slipif_output;

	slipState = (slip_status_t *) netif->state;
	slipState->sio = sio_open( netif->num );

	sys_thread_new(slipif_loop, netif);
}
/*-----------------------------------------------------------------------------------*/
