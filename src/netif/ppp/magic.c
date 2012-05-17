/*
 * magic.c - PPP Magic Number routines.
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
 */
/*****************************************************************************
* randm.c - Random number generator program file.
*
* Copyright (c) 2003 by Marc Boucher, Services Informatiques (MBSI) inc.
* Copyright (c) 1998 by Global Election Systems Inc.
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
* 98-06-03 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*   Extracted from avos.
*****************************************************************************/

#include "lwip/opt.h"

#define PPP_SUPPORT 1
#if PPP_SUPPORT /* don't build if not configured for use in lwipopts.h */

#include "md5.h"
#include "magic.h"
#include "pppd.h"
#include "pppmy.h"

/*
 * magic_init - Initialize the magic number generator.
 *
 * Attempts to compute a random number seed which will not repeat.
 * The current method uses the current hostid, current process ID
 * and current time, currently.
 */
void magic_init() {
  avRandomInit();
}

/*
 * magic - Returns the next magic number.
 */
u_int32_t magic() {
    return (u_int32_t)avRandom();
}

#if MD5_SUPPORT /* this module depends on MD5 */
#define RANDPOOLSZ 16   /* Bytes stored in the pool of randomness. */

/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/
static char randPool[RANDPOOLSZ];   /* Pool of randomness. */
static long randCount = 0;      /* Pseudo-random incrementer */


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * Initialize the random number generator.
 *
 * Since this is to be called on power up, we don't have much
 *  system randomess to work with.  Here all we use is the
 *  real-time clock.  We'll accumulate more randomness as soon
 *  as things start happening.
 */
void
avRandomInit()
{
  avChurnRand(NULL, 0);
}

/*
 * Churn the randomness pool on a random event.  Call this early and often
 *  on random and semi-random system events to build randomness in time for
 *  usage.  For randomly timed events, pass a null pointer and a zero length
 *  and this will use the system timer and other sources to add randomness.
 *  If new random data is available, pass a pointer to that and it will be
 *  included.
 *
 * Ref: Applied Cryptography 2nd Ed. by Bruce Schneier p. 427
 */
void
avChurnRand(char *randData, u32_t randLen)
{
  MD5_CTX md5;

  /* LWIP_DEBUGF(LOG_INFO, ("churnRand: %u@%P\n", randLen, randData)); */
  MD5_Init(&md5);
  MD5_Update(&md5, (u_char *)randPool, sizeof(randPool));
  if (randData) {
    MD5_Update(&md5, (u_char *)randData, randLen);
  } else {
    struct {
      /* INCLUDE fields for any system sources of randomness */
      char foobar;
    } sysData;

    /* Load sysData fields here. */
    MD5_Update(&md5, (u_char *)&sysData, sizeof(sysData));
  }
  MD5_Final((u_char *)randPool, &md5);
/*  LWIP_DEBUGF(LOG_INFO, ("churnRand: -> 0\n")); */
}

/*
 * Use the random pool to generate random data.  This degrades to pseudo
 *  random when used faster than randomness is supplied using churnRand().
 * Note: It's important that there be sufficient randomness in randPool
 *  before this is called for otherwise the range of the result may be
 *  narrow enough to make a search feasible.
 *
 * Ref: Applied Cryptography 2nd Ed. by Bruce Schneier p. 427
 *
 * XXX Why does he not just call churnRand() for each block?  Probably
 *  so that you don't ever publish the seed which could possibly help
 *  predict future values.
 * XXX Why don't we preserve md5 between blocks and just update it with
 *  randCount each time?  Probably there is a weakness but I wish that
 *  it was documented.
 */
void
avGenRand(char *buf, u32_t bufLen)
{
  MD5_CTX md5;
  u_char tmp[16];
  u32_t n;

  while (bufLen > 0) {
    n = LWIP_MIN(bufLen, RANDPOOLSZ);
    MD5_Init(&md5);
    MD5_Update(&md5, (u_char *)randPool, sizeof(randPool));
    MD5_Update(&md5, (u_char *)&randCount, sizeof(randCount));
    MD5_Final(tmp, &md5);
    randCount++;
    MEMCPY(buf, tmp, n);
    buf += n;
    bufLen -= n;
  }
}

/*
 * Return a new random number.
 */
u32_t
avRandom()
{
  u32_t newRand;

  avGenRand((char *)&newRand, sizeof(newRand));

  return newRand;
}

/*
 * random_bytes - Fill a buffer with random bytes.
 */
void
random_bytes(unsigned char *buf, int len)
{
  avGenRand(buf, len);
}

#else /* MD5_SUPPORT */

/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/
static int  avRandomized = 0;       /* Set when truely randomized. */
static u32_t avRandomSeed = 0;      /* Seed used for random number generation. */


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * Initialize the random number generator.
 *
 * Here we attempt to compute a random number seed but even if
 * it isn't random, we'll randomize it later.
 *
 * The current method uses the fields from the real time clock,
 * the idle process counter, the millisecond counter, and the
 * hardware timer tick counter.  When this is invoked
 * in startup(), then the idle counter and timer values may
 * repeat after each boot and the real time clock may not be
 * operational.  Thus we call it again on the first random
 * event.
 */
void
avRandomInit()
{
#if 0
  /* Get a pointer into the last 4 bytes of clockBuf. */
  u32_t *lptr1 = (u32_t *)((char *)&clockBuf[3]);

  /*
   * Initialize our seed using the real-time clock, the idle
   * counter, the millisecond timer, and the hardware timer
   * tick counter.  The real-time clock and the hardware
   * tick counter are the best sources of randomness but
   * since the tick counter is only 16 bit (and truncated
   * at that), the idle counter and millisecond timer
   * (which may be small values) are added to help
   * randomize the lower 16 bits of the seed.
   */
  readClk();
  avRandomSeed += *(u32_t *)clockBuf + *lptr1 + OSIdleCtr
           + ppp_mtime() + ((u32_t)TM1 << 16) + TM1;
#else
  avRandomSeed += sys_jiffies(); /* XXX */
#endif

  /* Initialize the Borland random number generator. */
  srand((unsigned)avRandomSeed);
}

/*
 * Randomize our random seed value.  Here we use the fact that
 * this function is called at *truely random* times by the polling
 * and network functions.  Here we only get 16 bits of new random
 * value but we use the previous value to randomize the other 16
 * bits.
 */
void
avRandomize(void)
{
  static u32_t last_jiffies;

  if (!avRandomized) {
    avRandomized = !0;
    avRandomInit();
    /* The initialization function also updates the seed. */
  } else {
    /* avRandomSeed += (avRandomSeed << 16) + TM1; */
    avRandomSeed += (sys_jiffies() - last_jiffies); /* XXX */
  }
  last_jiffies = sys_jiffies();
}

/*
 * Return a new random number.
 * Here we use the Borland rand() function to supply a pseudo random
 * number which we make truely random by combining it with our own
 * seed which is randomized by truely random events.
 * Thus the numbers will be truely random unless there have been no
 * operator or network events in which case it will be pseudo random
 * seeded by the real time clock.
 */
u32_t
avRandom()
{
  return ((((u32_t)rand() << 16) + rand()) + avRandomSeed);
}

#endif /* MD5_SUPPORT */

#endif /* PPP_SUPPORT */
