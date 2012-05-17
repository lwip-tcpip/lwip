/*
 * magic.h - PPP Magic Number definitions.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: magic.h,v 1.5 2003/06/11 23:56:26 paulus Exp $
 */
/*****************************************************************************
* randm.h - Random number generator header file.
*
* Copyright (c) 2003 by Marc Boucher, Services Informatiques (MBSI) inc.
* Copyright (c) 1998 Global Election Systems Inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 03-01-01 Marc Boucher <marc@mbsi.ca>
*   Ported to lwIP.
* 98-05-29 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*   Extracted from avos.
*****************************************************************************/

#ifndef RANDM_H
#define RANDM_H

/***********************
*** PUBLIC FUNCTIONS ***
***********************/
/*
 * Initialize the random number generator.
 */
void avRandomInit(void);

/*
 * Churn the randomness pool on a random event.  Call this early and often
 * on random and semi-random system events to build randomness in time for
 * usage.  For randomly timed events, pass a null pointer and a zero length
 * and this will use the system timer and other sources to add randomness.
 * If new random data is available, pass a pointer to that and it will be
 * included.
 */
void avChurnRand(char *randData, u32_t randLen);

/*
 * Randomize our random seed value.  To be called for truely random events
 * such as user operations and network traffic.
 */
#if MD5_SUPPORT
#define avRandomize() avChurnRand(NULL, 0)
#else  /* MD5_SUPPORT */
void avRandomize(void);
#endif /* MD5_SUPPORT */

/*
 * Use the random pool to generate random data.  This degrades to pseudo
 * random when used faster than randomness is supplied using churnRand().
 * Thus it's important to make sure that the results of this are not
 * published directly because one could predict the next result to at
 * least some degree.  Also, it's important to get a good seed before
 * the first use.
 */
void avGenRand(char *buf, u32_t bufLen);

/*
 * Return a new random number.
 */
u32_t avRandom(void);


#endif /* RANDM_H */

void magic_init __P((void));	/* Initialize the magic number generator */
u_int32_t magic __P((void));	/* Returns the next magic number */

/* Fill buffer with random bytes */
void random_bytes __P((unsigned char *buf, int len));
