/*
 * mppe.c - interface MPPE to the PPP code.
 *
 * By Frank Cusack <fcusack@fcusack.com>.
 * Copyright (c) 2002,2003,2004 Google, Inc.
 * All rights reserved.
 *
 * License:
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied.
 *
 * Changelog:
 *      08/12/05 - Matt Domsch <Matt_Domsch@dell.com>
 *                 Only need extra skb padding on transmit, not receive.
 *      06/18/04 - Matt Domsch <Matt_Domsch@dell.com>, Oleg Makarenko <mole@quadra.ru>
 *                 Use Linux kernel 2.6 arc4 and sha1 routines rather than
 *                 providing our own.
 *      2/15/04 - TS: added #include <version.h> and testing for Kernel
 *                    version before using
 *                    MOD_DEC_USAGE_COUNT/MOD_INC_USAGE_COUNT which are
 *                    deprecated in 2.6
 */

#include "lwip/opt.h"
#if PPP_SUPPORT && MPPE_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#include <string.h>

#include "lwip/err.h"

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/ccp.h"
#include "netif/ppp/mppe.h"
#include "netif/ppp/pppdebug.h"

#if LWIP_INCLUDED_POLARSSL_SHA1
#include "netif/ppp/polarssl/sha1.h"
#else
#include "polarssl/sha1.h"
#endif

#if LWIP_INCLUDED_POLARSSL_ARC4
#include "netif/ppp/polarssl/arc4.h"
#else
#include "polarssl/arc4.h"
#endif

#define SHA1_SIGNATURE_SIZE 20
#define SHA1_PAD_SIZE 40

/*
 * State for an MPPE (de)compressor.
 */
struct ppp_mppe_state {
	arc4_context arc4;
	u8_t sha1_digest[SHA1_SIGNATURE_SIZE];
	unsigned char master_key[MPPE_MAX_KEY_LEN];
	unsigned char session_key[MPPE_MAX_KEY_LEN];
	unsigned keylen;	/* key length in bytes             */
	/* NB: 128-bit == 16, 40-bit == 8! */
	/* If we want to support 56-bit,   */
	/* the unit has to change to bits  */
	unsigned char bits;	/* MPPE control bits */
	unsigned ccount;	/* 12-bit coherency count (seqno)  */
	unsigned stateful;	/* stateful mode flag */
	int discard;		/* stateful mode packet loss flag */
	int sanity_errors;	/* take down LCP if too many */
	int unit;
	int debug;
};

/* struct ppp_mppe_state.bits definitions */
#define MPPE_BIT_A	0x80	/* Encryption table were (re)inititalized */
#define MPPE_BIT_B	0x40	/* MPPC only (not implemented) */
#define MPPE_BIT_C	0x20	/* MPPC only (not implemented) */
#define MPPE_BIT_D	0x10	/* This is an encrypted frame */

#define MPPE_BIT_FLUSHED	MPPE_BIT_A
#define MPPE_BIT_ENCRYPTED	MPPE_BIT_D

#define MPPE_BITS(p) ((p)[4] & 0xf0)
#define MPPE_CCOUNT(p) ((((p)[4] & 0x0f) << 8) + (p)[5])
#define MPPE_CCOUNT_SPACE 0x1000	/* The size of the ccount space */

#define MPPE_OVHD	2	/* MPPE overhead/packet */
#define SANITY_MAX	1600	/* Max bogon factor we will tolerate */

/*
 * Key Derivation, from RFC 3078, RFC 3079.
 * Equivalent to Get_Key() for MS-CHAP as described in RFC 3079.
 */
static void get_new_key_from_sha(struct ppp_mppe_state * state)
{
  sha1_context sha1;
  /* sha1 is faster when using 64 byte chunks */
  u8_t pad[64];
  u8_t i;

  sha1_starts(&sha1);
  sha1_update(&sha1, state->master_key, state->keylen);

  /* first padding, 256 bytes of 0x00 */
  memset(pad, 0x00, sizeof(pad));
  for (i = 0; i < 4; i++) {
    sha1_update(&sha1, pad, sizeof(pad));
  }

  sha1_update(&sha1, state->session_key, state->keylen);

  /* second padding, 256 bytes of 0xf2 */
  memset(pad, 0xf2, sizeof(pad));
  for (i = 0; i < 4; i++) {
    sha1_update(&sha1, pad, sizeof(pad));
  }

  sha1_finish(&sha1, state->sha1_digest);
}

/*
 * Perform the MPPE rekey algorithm, from RFC 3078, sec. 7.3.
 * Well, not what's written there, but rather what they meant.
 */
static void mppe_rekey(struct ppp_mppe_state * state, int initial_key)
{
	get_new_key_from_sha(state);
	if (!initial_key) {
		arc4_setup(&state->arc4, state->sha1_digest, state->keylen);
		MEMCPY(state->session_key, state->sha1_digest, state->keylen);
		arc4_crypt(&state->arc4, state->session_key, state->keylen);
	} else {
		memcpy(state->session_key, state->sha1_digest, state->keylen);
	}
	if (state->keylen == 8) {
		/* See RFC 3078 */
		state->session_key[0] = 0xd1;
		state->session_key[1] = 0x26;
		state->session_key[2] = 0x9e;
	}
	arc4_crypt(&state->arc4, state->session_key, state->keylen);
}

/*
 * Allocate space for a (de)compressor.
 */
void *mppe_alloc(unsigned char *options, int optlen)
{
	struct ppp_mppe_state *state;

	if (optlen != CILEN_MPPE + sizeof(state->master_key) ||
	    options[0] != CI_MPPE || options[1] != CILEN_MPPE)
		goto out;

	/* FIXME: remove malloc() */
	state = (struct ppp_mppe_state *)malloc(sizeof(*state));
	if (state == NULL)
		goto out;

	/* Save keys. */
	memcpy(state->master_key, &options[CILEN_MPPE],
	       sizeof(state->master_key));
	memcpy(state->session_key, state->master_key,
	       sizeof(state->master_key));

	/*
	 * We defer initial key generation until mppe_init(), as mppe_alloc()
	 * is called frequently during negotiation.
	 */

	return (void *)state;

out:
	return NULL;
}

/*
 * Deallocate space for a (de)compressor.
 */
void mppe_free(void *arg)
{
	struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;
	if (state) {
	    free(state);
	}
}

/*
 * Initialize (de)compressor state.
 */
static int
mppe_init(void *arg, unsigned char *options, int optlen, int unit, int debug,
	  const char *debugstr)
{
	struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;
	unsigned char mppe_opts;

	if (optlen != CILEN_MPPE ||
	    options[0] != CI_MPPE || options[1] != CILEN_MPPE)
		return 0;

	MPPE_CI_TO_OPTS(&options[2], mppe_opts);
	if (mppe_opts & MPPE_OPT_128)
		state->keylen = 16;
	else if (mppe_opts & MPPE_OPT_40)
		state->keylen = 8;
	else {
		PPPDEBUG(LOG_DEBUG, ("%s[%d]: unknown key length\n", debugstr,
		       unit));
		return 0;
	}
	if (mppe_opts & MPPE_OPT_STATEFUL)
		state->stateful = 1;

	/* Generate the initial session key. */
	mppe_rekey(state, 1);

	if (debug) {
		int i;
		char mkey[sizeof(state->master_key) * 2 + 1];
		char skey[sizeof(state->session_key) * 2 + 1];

		PPPDEBUG(LOG_DEBUG, ("%s[%d]: initialized with %d-bit %s mode\n",
		       debugstr, unit, (state->keylen == 16) ? 128 : 40,
		       (state->stateful) ? "stateful" : "stateless"));

		for (i = 0; i < (int)sizeof(state->master_key); i++)
			sprintf(mkey + i * 2, "%02x", state->master_key[i]);
		for (i = 0; i < (int)sizeof(state->session_key); i++)
			sprintf(skey + i * 2, "%02x", state->session_key[i]);
		PPPDEBUG(LOG_DEBUG,
		       ("%s[%d]: keys: master: %s initial session: %s\n",
		       debugstr, unit, mkey, skey));
	}

	/*
	 * Initialize the coherency count.  The initial value is not specified
	 * in RFC 3078, but we can make a reasonable assumption that it will
	 * start at 0.  Setting it to the max here makes the comp/decomp code
	 * do the right thing (determined through experiment).
	 */
	state->ccount = MPPE_CCOUNT_SPACE - 1;

	/*
	 * Note that even though we have initialized the key table, we don't
	 * set the FLUSHED bit.  This is contrary to RFC 3078, sec. 3.1.
	 */
	state->bits = MPPE_BIT_ENCRYPTED;

	state->unit = unit;
	state->debug = debug;

	return 1;
}

int
mppe_comp_init(void *arg, unsigned char *options, int optlen, int unit,
	       int hdrlen, int debug)
{
	LWIP_UNUSED_ARG(hdrlen);
	return mppe_init(arg, options, optlen, unit, debug, "mppe_comp_init");
}

/*
 * We received a CCP Reset-Request (actually, we are sending a Reset-Ack),
 * tell the compressor to rekey.  Note that we MUST NOT rekey for
 * every CCP Reset-Request; we only rekey on the next xmit packet.
 * We might get multiple CCP Reset-Requests if our CCP Reset-Ack is lost.
 * So, rekeying for every CCP Reset-Request is broken as the peer will not
 * know how many times we've rekeyed.  (If we rekey and THEN get another
 * CCP Reset-Request, we must rekey again.)
 */
void mppe_comp_reset(void *arg)
{
	struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;

	state->bits |= MPPE_BIT_FLUSHED;
}

/*
 * Compress (encrypt) a packet.
 * It's strange to call this a compressor, since the output is always
 * MPPE_OVHD + 2 bytes larger than the input.
 */
int
mppe_compress(void *arg, unsigned char *ibuf, unsigned char *obuf,
	      int isize, int osize)
{
	struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;
	int proto;

	/*
	 * Check that the protocol is in the range we handle.
	 */
	proto = PPP_PROTOCOL(ibuf);
	if (proto < 0x0021 || proto > 0x00fa)
		return 0;

	/* Make sure we have enough room to generate an encrypted packet. */
	if (osize < isize + MPPE_OVHD + 2) {
		/* Drop the packet if we should encrypt it, but can't. */
		PPPDEBUG(LOG_DEBUG, ("mppe_compress[%d]: osize too small! "
		       "(have: %d need: %d)\n", state->unit,
		       osize, osize + MPPE_OVHD + 2));
		return -1;
	}

	osize = isize + MPPE_OVHD + 2;


	/*
	 * Copy over the PPP header and set control bits.
	 */
	/* FIXME: use PUT* macros */
	obuf[0] = PPP_ADDRESS(ibuf);
	obuf[1] = PPP_CONTROL(ibuf);
	obuf[2] = PPP_COMP>>8;
	obuf[3] = PPP_COMP;
	obuf += PPP_HDRLEN;

	state->ccount = (state->ccount + 1) % MPPE_CCOUNT_SPACE;
	if (state->debug >= 7)
		PPPDEBUG(LOG_DEBUG, ("mppe_compress[%d]: ccount %d\n", state->unit,
		       state->ccount));
	/* FIXME: use PUT* macros */
	obuf[0] = state->ccount>>8;
	obuf[1] = state->ccount;

	if (!state->stateful ||	/* stateless mode     */
	    ((state->ccount & 0xff) == 0xff) ||	/* "flag" packet      */
	    (state->bits & MPPE_BIT_FLUSHED)) {	/* CCP Reset-Request  */
		/* We must rekey */
		if (state->debug && state->stateful)
			PPPDEBUG(LOG_DEBUG, ("mppe_compress[%d]: rekeying\n",
			       state->unit));
		mppe_rekey(state, 0);
		state->bits |= MPPE_BIT_FLUSHED;
	}
	obuf[0] |= state->bits;
	state->bits &= ~MPPE_BIT_FLUSHED;	/* reset for next xmit */

	obuf += MPPE_OVHD;
	ibuf += 2;		/* skip to proto field */
	isize -= 2;

	/* Encrypt packet */
	MEMCPY(obuf, ibuf, isize);
	arc4_crypt(&state->arc4, obuf, isize);
	return osize;
}

int
mppe_decomp_init(void *arg, unsigned char *options, int optlen, int unit,
		 int hdrlen, int mru, int debug)
{
	LWIP_UNUSED_ARG(hdrlen);
	LWIP_UNUSED_ARG(mru);
	return mppe_init(arg, options, optlen, unit, debug, "mppe_decomp_init");
}

/*
 * We received a CCP Reset-Ack.  Just ignore it.
 */
void mppe_decomp_reset(void *arg)
{
	LWIP_UNUSED_ARG(arg);
	return;
}

/*
 * Decompress (decrypt) an MPPE packet.
 */
int
mppe_decompress(void *arg, unsigned char *ibuf, int isize, unsigned char *obuf,
		int osize)
{
	struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;
	unsigned ccount;
	int flushed = MPPE_BITS(ibuf) & MPPE_BIT_FLUSHED;
	int sanity = 0;

	if (isize <= PPP_HDRLEN + MPPE_OVHD) {
		if (state->debug)
			PPPDEBUG(LOG_DEBUG,
			       ("mppe_decompress[%d]: short pkt (%d)\n",
			       state->unit, isize));
		return ERR_BUF;
	}

	/*
	 * Make sure we have enough room to decrypt the packet.
	 * Note that for our test we only subtract 1 byte whereas in
	 * mppe_compress() we added 2 bytes (+MPPE_OVHD);
	 * this is to account for possible PFC.
	 */
	if (osize < isize - MPPE_OVHD - 1) {
		PPPDEBUG(LOG_DEBUG, ("mppe_decompress[%d]: osize too small! "
		       "(have: %d need: %d)\n", state->unit,
		       osize, isize - MPPE_OVHD - 1));
		return ERR_BUF;
	}
	osize = isize - MPPE_OVHD - 2;	/* assume no PFC */

	ccount = MPPE_CCOUNT(ibuf);
	if (state->debug >= 7)
		PPPDEBUG(LOG_DEBUG, ("mppe_decompress[%d]: ccount %d\n",
		       state->unit, ccount));

	/* sanity checks -- terminate with extreme prejudice */
	if (!(MPPE_BITS(ibuf) & MPPE_BIT_ENCRYPTED)) {
		PPPDEBUG(LOG_DEBUG,
		       ("mppe_decompress[%d]: ENCRYPTED bit not set!\n",
		       state->unit));
		state->sanity_errors += 100;
		sanity = 1;
	}
	if (!state->stateful && !flushed) {
		PPPDEBUG(LOG_DEBUG, ("mppe_decompress[%d]: FLUSHED bit not set in "
		       "stateless mode!\n", state->unit));
		state->sanity_errors += 100;
		sanity = 1;
	}
	if (state->stateful && ((ccount & 0xff) == 0xff) && !flushed) {
		PPPDEBUG(LOG_DEBUG, ("mppe_decompress[%d]: FLUSHED bit not set on "
		       "flag packet!\n", state->unit));
		state->sanity_errors += 100;
		sanity = 1;
	}

	if (sanity) {
		if (state->sanity_errors < SANITY_MAX)
			return ERR_BUF;
		else
			/*
			 * Take LCP down if the peer is sending too many bogons.
			 * We don't want to do this for a single or just a few
			 * instances since it could just be due to packet corruption.
			 */
			/* FIXME: call lcp_close() here */
			return ERR_BUF;
	}

	/*
	 * Check the coherency count.
	 */

	if (!state->stateful) {
		/* RFC 3078, sec 8.1.  Rekey for every packet. */
		while (state->ccount != ccount) {
			mppe_rekey(state, 0);
			state->ccount = (state->ccount + 1) % MPPE_CCOUNT_SPACE;
		}
	} else {
		/* RFC 3078, sec 8.2. */
		if (!state->discard) {
			/* normal state */
			state->ccount = (state->ccount + 1) % MPPE_CCOUNT_SPACE;
			if (ccount != state->ccount) {
				/*
				 * (ccount > state->ccount)
				 * Packet loss detected, enter the discard state.
				 * Signal the peer to rekey (by sending a CCP Reset-Request).
				 */
				state->discard = 1;
				return ERR_BUF;
			}
		} else {
			/* discard state */
			if (!flushed) {
				/* ccp.c will be silent (no additional CCP Reset-Requests). */
				return ERR_BUF;
			} else {
				/* Rekey for every missed "flag" packet. */
				while ((ccount & ~0xff) !=
				       (state->ccount & ~0xff)) {
					mppe_rekey(state, 0);
					state->ccount =
					    (state->ccount +
					     256) % MPPE_CCOUNT_SPACE;
				}

				/* reset */
				state->discard = 0;
				state->ccount = ccount;
				/*
				 * Another problem with RFC 3078 here.  It implies that the
				 * peer need not send a Reset-Ack packet.  But RFC 1962
				 * requires it.  Hopefully, M$ does send a Reset-Ack; even
				 * though it isn't required for MPPE synchronization, it is
				 * required to reset CCP state.
				 */
			}
		}
		if (flushed)
			mppe_rekey(state, 0);
	}

	/*
	 * Fill in the first part of the PPP header.  The protocol field
	 * comes from the decrypted data.
	 */
	obuf[0] = PPP_ADDRESS(ibuf);	/* +1 */
	obuf[1] = PPP_CONTROL(ibuf);	/* +1 */
	obuf += 2;
	ibuf += PPP_HDRLEN + MPPE_OVHD;
	isize -= PPP_HDRLEN + MPPE_OVHD;	/* -6 */
	/* net osize: isize-4 */

	/*
	 * Decrypt the first byte in order to check if it is
	 * a compressed or uncompressed protocol field.
	 */
	obuf[0] = ibuf[0];
	arc4_crypt(&state->arc4, obuf, 1);

	/*
	 * Do PFC decompression.
	 * This would be nicer if we were given the actual sk_buff
	 * instead of a char *.
	 */
	if ((obuf[0] & 0x01) != 0) {
		obuf[1] = obuf[0];
		obuf[0] = 0;
		obuf++;
		osize++;
	}

	/* And finally, decrypt the rest of the packet. */
	MEMCPY(obuf+1, ibuf+1, isize-1);
	arc4_crypt(&state->arc4, obuf+1, isize-1);

	/* good packet credit */
	state->sanity_errors >>= 1;

	return osize;
}

/*
 * Incompressible data has arrived (this should never happen!).
 * We should probably drop the link if the protocol is in the range
 * of what should be encrypted.  At the least, we should drop this
 * packet.  (How to do this?)
 */
void mppe_incomp(void *arg, unsigned char *ibuf, int icnt)
{
	struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;
	LWIP_UNUSED_ARG(icnt);

	if (state->debug &&
	    (PPP_PROTOCOL(ibuf) >= 0x0021 && PPP_PROTOCOL(ibuf) <= 0x00fa))
		PPPDEBUG(LOG_DEBUG,
		       ("mppe_incomp[%d]: incompressible (unencrypted) data! "
		       "(proto %04x)\n", state->unit, PPP_PROTOCOL(ibuf)));
}

#if 0
/*************************************************************
 * Module interface table
 *************************************************************/

/*
 * Procedures exported to if_ppp.c.
 */
static struct compressor ppp_mppe = {
	.compress_proto = CI_MPPE,
	.comp_alloc     = mppe_alloc,
	.comp_free      = mppe_free,
	.comp_init      = mppe_comp_init,
	.comp_reset     = mppe_comp_reset,
	.compress       = mppe_compress,
	.decomp_alloc   = mppe_alloc,
	.decomp_free    = mppe_free,
	.decomp_init    = mppe_decomp_init,
	.decomp_reset   = mppe_decomp_reset,
	.decompress     = mppe_decompress,
	.incomp         = mppe_incomp,
	.comp_extra     = MPPE_PAD,
};
#endif /* 0 */

#endif /* PPP_SUPPORT && MPPE_SUPPORT */
