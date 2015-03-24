/*
 * ccp.h - Definitions for PPP Compression Control Protocol.
 *
 * Copyright (c) 1994-2002 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: ccp.h,v 1.12 2004/11/04 10:02:26 paulus Exp $
 */

#include "lwip/opt.h"
#if PPP_SUPPORT && CCP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef CCP_H
#define CCP_H

typedef struct ccp_options {
    unsigned int deflate          :1; /* do Deflate? */
    unsigned int deflate_correct  :1; /* use correct code for deflate? */
    unsigned int deflate_draft    :1; /* use draft RFC code for deflate? */
    unsigned int bsd_compress     :1; /* do BSD Compress? */
    unsigned int predictor_1      :1; /* do Predictor-1? */
    unsigned int predictor_2      :1; /* do Predictor-2? */
    unsigned int                  :2; /* 2 bit of padding to round out to 8 bits */

    u8_t mppe;			/* MPPE bitfield */
    u_short bsd_bits;		/* # bits/code for BSD Compress */
    u_short deflate_size;	/* lg(window size) for Deflate */
    short method;		/* code for chosen compression method */
} ccp_options;

extern const struct protent ccp_protent;

#endif /* CCP_H */
#endif /* PPP_SUPPORT && CCP_SUPPORT */
