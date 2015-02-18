/**
 * @file
 * Network Point to Point Protocol over Serial header file.
 *
 */

/*
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
 */

#include "lwip/opt.h"
#if PPP_SUPPORT && PPPOS_SUPPORT /* don't build if not configured for use in lwipopts.h */

#ifndef PPPOS_H
#define PPPOS_H

#include "lwip/sys.h"
#include "lwip/sio.h"

#include "ppp.h"
#include "vj.h"

/* PPP packet parser states.  Current state indicates operation yet to be
 * completed. */
enum {
  PDIDLE = 0,  /* Idle state - waiting. */
  PDSTART,     /* Process start flag. */
  PDADDRESS,   /* Process address field. */
  PDCONTROL,   /* Process control field. */
  PDPROTOCOL1, /* Process protocol field 1. */
  PDPROTOCOL2, /* Process protocol field 2. */
  PDDATA       /* Process data byte. */
};

/*
 * Extended asyncmap - allows any character to be escaped.
 */
typedef u_char ext_accm[32];

/*
 * PPPoS interface control block.
 */
typedef struct pppos_pcb_s pppos_pcb;
struct pppos_pcb_s {
  /* -- below are data that will NOT be cleared between two sessions */
  pppos_pcb *next;
  ppp_pcb *ppp;                    /* PPP PCB */
  sio_fd_t fd;                     /* File device ID of port. */

  /* -- below are data that will be cleared between two sessions
   *
   * out_accm must be the first member of cleared members, because it is
   * used to know which part must not be cleared.
   */
  ext_accm out_accm;               /* Async-Ctl-Char-Map for output. */

  /* PPPoS rx */
  ext_accm in_accm;                /* Async-Ctl-Char-Map for input. */
  struct pbuf *in_head, *in_tail;  /* The input packet. */
#if VJ_SUPPORT
  struct vjcompress vj_comp;       /* Van Jacobson compression header. */
#endif /* VJ_SUPPORT */
  u16_t in_protocol;               /* The input protocol code. */
  u16_t in_fcs;                    /* Input Frame Check Sequence value. */
  u8_t in_state;                   /* The input process state. */
  u8_t in_escaped;                 /* Escape next character. */
};

/* Create a new PPPoS session. */
ppp_pcb *pppos_create(struct netif *pppif, sio_fd_t fd,
       ppp_link_status_cb_fn link_status_cb, void *ctx_cb);

/* PPP over Serial: this is the input function to be called for received data. */
void pppos_input(ppp_pcb *ppp, u_char* data, int len);


/*
 * Functions called from PPP CORE
 *
 * You may use them if you REALLY know what you are doing.
 */
void pppos_accm_out_config(pppos_pcb *pppos, u32_t accm);
void pppos_accm_in_config(pppos_pcb *pppos, u32_t accm);
sio_fd_t pppos_get_fd(pppos_pcb *pppos);
void pppos_vjc_config(pppos_pcb *pppos, int vjcomp, int cidcomp, int maxcid);
int pppos_vjc_comp(pppos_pcb *pppos, struct pbuf *pb);
int pppos_vjc_uncomp(pppos_pcb *pppos, struct pbuf *pb);

#endif /* PPPOS_H */
#endif /* PPP_SUPPORT && PPPOL2TP_SUPPORT */
