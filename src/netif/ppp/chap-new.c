/*
 * chap-new.c - New CHAP implementation.
 *
 * Copyright (c) 2003 Paul Mackerras. All rights reserved.
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
 */

#include "lwip/opt.h"
#if PPP_SUPPORT && CHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#if 0 /* UNUSED */
#include <stdlib.h>
#include <string.h>
#endif /* UNUSED */

#include "ppp_impl.h"

#if 0 /* UNUSED */
#include "session.h"
#endif /* UNUSED */

#include "chap-new.h"
#include "chap-md5.h"

#if MSCHAP_SUPPORT
#include "chap_ms.h"
#define MDTYPE_ALL (MDTYPE_MICROSOFT_V2 | MDTYPE_MICROSOFT | MDTYPE_MD5)
#else
#define MDTYPE_ALL (MDTYPE_MD5)
#endif

/* Hook for a plugin to validate CHAP challenge */
int (*chap_verify_hook)(char *name, char *ourname, int id,
			struct chap_digest_type *digest,
			unsigned char *challenge, unsigned char *response,
			char *message, int message_space) = NULL;

#if PPP_OPTIONS
/*
 * Command-line options.
 */
static option_t chap_option_list[] = {
	{ "chap-restart", o_int, &chap_timeout_time,
	  "Set timeout for CHAP", OPT_PRIO },
	{ "chap-max-challenge", o_int, &pcb->settings.chap_max_transmits,
	  "Set max #xmits for challenge", OPT_PRIO },
	{ "chap-interval", o_int, &pcb->settings.chap_rechallenge_time,
	  "Set interval for rechallenge", OPT_PRIO },
	{ NULL }
};
#endif /* PPP_OPTIONS */

/*
 * These limits apply to challenge and response packets we send.
 * The +4 is the +1 that we actually need rounded up.
 */
#define CHAL_MAX_PKTLEN	(PPP_HDRLEN + CHAP_HDRLEN + 4 + MAX_CHALLENGE_LEN + MAXNAMELEN)
#define RESP_MAX_PKTLEN	(PPP_HDRLEN + CHAP_HDRLEN + 4 + MAX_RESPONSE_LEN + MAXNAMELEN)

/* Values for flags in chap_client_state and chap_server_state */
#define LOWERUP			1
#define AUTH_STARTED		2
#define AUTH_DONE		4
#define AUTH_FAILED		8
#define TIMEOUT_PENDING		0x10
#define CHALLENGE_VALID		0x20

/*
 * Prototypes.
 */
static void chap_init(ppp_pcb *pcb);
static void chap_lowerup(ppp_pcb *pcb);
static void chap_lowerdown(ppp_pcb *pcb);
#if PPP_SERVER
static void chap_timeout(void *arg);
static void chap_generate_challenge(ppp_pcb *pcb);
static void chap_handle_response(ppp_pcb *pcb, int code,
		unsigned char *pkt, int len);
static int chap_verify_response(char *name, char *ourname, int id,
		struct chap_digest_type *digest,
		unsigned char *challenge, unsigned char *response,
		char *message, int message_space);
#endif /* PPP_SERVER */
static void chap_respond(ppp_pcb *pcb, int id,
		unsigned char *pkt, int len);
static void chap_handle_status(ppp_pcb *pcb, int code, int id,
		unsigned char *pkt, int len);
static void chap_protrej(ppp_pcb *pcb);
static void chap_input(ppp_pcb *pcb, unsigned char *pkt, int pktlen);
#if PRINTPKT_SUPPORT
static int chap_print_pkt(unsigned char *p, int plen,
		void (*printer) (void *, char *, ...), void *arg);
#endif /* PRINTPKT_SUPPORT */

/* List of digest types that we know about */
static struct chap_digest_type *chap_digests;

/*
 * chap_init - reset to initial state.
 */
static void chap_init(ppp_pcb *pcb) {

	memset(&pcb->chap_client, 0, sizeof(chap_client_state));
#if PPP_SERVER
	memset(&pcb->chap_server, 0, sizeof(chap_server_state));
#endif /* PPP_SERVER */

	pcb->chap_mdtype_all = MDTYPE_ALL;

	chap_md5_init();
#if MSCHAP_SUPPORT
	chapms_init();
#endif
}

/*
 * Add a new digest type to the list.
 */
void chap_register_digest(struct chap_digest_type *dp) {
	dp->next = chap_digests;
	chap_digests = dp;
}

/*
 * chap_lowerup - we can start doing stuff now.
 */
static void chap_lowerup(ppp_pcb *pcb) {

	pcb->chap_client.flags |= LOWERUP;
#if PPP_SERVER
	pcb->chap_server.flags |= LOWERUP;
	if (pcb->chap_server.flags & AUTH_STARTED)
		chap_timeout(pcb);
#endif /* PPP_SERVER */
}

static void chap_lowerdown(ppp_pcb *pcb) {

	pcb->chap_client.flags = 0;
#if PPP_SERVER
	if (pcb->chap_server.flags & TIMEOUT_PENDING)
		UNTIMEOUT(chap_timeout, pcb);
	pcb->chap_server.flags = 0;
#endif /* PPP_SERVER */
}

#if PPP_SERVER
/*
 * chap_auth_peer - Start authenticating the peer.
 * If the lower layer is already up, we start sending challenges,
 * otherwise we wait for the lower layer to come up.
 */
void chap_auth_peer(ppp_pcb *pcb, char *our_name, int digest_code) {
	struct chap_server_state *ss = &server;
	struct chap_digest_type *dp;

	if (pcb->chap_server.flags & AUTH_STARTED) {
		error("CHAP: peer authentication already started!");
		return;
	}
	for (dp = chap_digests; dp != NULL; dp = dp->next)
		if (dp->code == digest_code)
			break;
	if (dp == NULL)
		fatal("CHAP digest 0x%x requested but not available",
		      digest_code);

	pcb->chap_server.digest = dp;
	pcb->chap_server.name = our_name;
	/* Start with a random ID value */
	pcb->chap_server.id = (unsigned char)(drand48() * 256);
	pcb->chap_server.flags |= AUTH_STARTED;
	if (pcb->chap_server.flags & LOWERUP)
		chap_timeout(ss);
}
#endif /* PPP_SERVER */

/*
 * chap_auth_with_peer - Prepare to authenticate ourselves to the peer.
 * There isn't much to do until we receive a challenge.
 */
void chap_auth_with_peer(ppp_pcb *pcb, char *our_name, int digest_code) {
	struct chap_digest_type *dp;

	if (pcb->chap_client.flags & AUTH_STARTED) {
		error("CHAP: authentication with peer already started!");
		return;
	}
	for (dp = chap_digests; dp != NULL; dp = dp->next)
		if (dp->code == digest_code)
			break;
	if (dp == NULL)
		fatal("CHAP digest 0x%x requested but not available",
		      digest_code);

	pcb->chap_client.digest = dp;
	pcb->chap_client.name = our_name;
	pcb->chap_client.flags |= AUTH_STARTED;
}

# if PPP_SERVER
/*
 * chap_timeout - It's time to send another challenge to the peer.
 * This could be either a retransmission of a previous challenge,
 * or a new challenge to start re-authentication.
 */
static void chap_timeout(void *arg) {
	ppp_pcb *pcb = (ppp_pcb*)arg;

	pcb->chap_server.flags &= ~TIMEOUT_PENDING;
	if ((pcb->chap_server.flags & CHALLENGE_VALID) == 0) {
		pcb->chap_server.challenge_xmits = 0;
		chap_generate_challenge(pcb);
		pcb->chap_server.flags |= CHALLENGE_VALID;
	} else if (pcb->chap_server.challenge_xmits >= pcb->settings.chap_max_transmits) {
		pcb->chap_server.flags &= ~CHALLENGE_VALID;
		pcb->chap_server.flags |= AUTH_DONE | AUTH_FAILED;
		auth_peer_fail(pcb, PPP_CHAP);
		return;
	}

	ppp_write(pcb, pcb->chap_server.challenge, pcb->chap_server.challenge_pktlen);
	++pcb->chap_server.challenge_xmits;
	pcb->chap_server.flags |= TIMEOUT_PENDING;
	TIMEOUT(chap_timeout, arg, pcb->settings.chap_timeout_time);
}

/*
 * chap_generate_challenge - generate a challenge string and format
 * the challenge packet in pcb->chap_server.challenge_pkt.
 */
static void chap_generate_challenge(ppp_pcb *pcb) {
	int clen = 1, nlen, len;
	unsigned char *p;

	p = pcb->chap_server.challenge;
	MAKEHEADER(p, PPP_CHAP);
	p += CHAP_HDRLEN;
	pcb->chap_server.digest->generate_challenge(p);
	clen = *p;
	nlen = strlen(pcb->chap_server.name);
	memcpy(p + 1 + clen, pcb->chap_server.name, nlen);

	len = CHAP_HDRLEN + 1 + clen + nlen;
	pcb->chap_server.challenge_pktlen = PPP_HDRLEN + len;

	p = pcb->chap_server.challenge + PPP_HDRLEN;
	p[0] = CHAP_CHALLENGE;
	p[1] = ++pcb->chap_server.id;
	p[2] = len >> 8;
	p[3] = len;
}

/*
 * chap_handle_response - check the response to our challenge.
 */
static void  chap_handle_response(ppp_pcb *pcb, int id,
		     unsigned char *pkt, int len) {
	int response_len, ok, mlen;
	unsigned char *response, *p;
	char *name = NULL;	/* initialized to shut gcc up */
	int (*verifier)(char *, char *, int, struct chap_digest_type *,
		unsigned char *, unsigned char *, char *, int);
	char rname[MAXNAMELEN+1];

	if ((pcb->chap_server.flags & LOWERUP) == 0)
		return;
	if (id != pcb->chap_server.challenge[PPP_HDRLEN+1] || len < 2)
		return;
	if (pcb->chap_server.flags & CHALLENGE_VALID) {
		response = pkt;
		GETCHAR(response_len, pkt);
		len -= response_len + 1;	/* length of name */
		name = (char *)pkt + response_len;
		if (len < 0)
			return;

		if (pcb->chap_server.flags & TIMEOUT_PENDING) {
			pcb->chap_server.flags &= ~TIMEOUT_PENDING;
			UNTIMEOUT(chap_timeout, pcb);
		}

		if (explicit_remote) {
			name = remote_name;
		} else {
			/* Null terminate and clean remote name. */
			slprintf(rname, sizeof(rname), "%.*v", len, name);
			name = rname;
		}

		if (chap_verify_hook)
			verifier = chap_verify_hook;
		else
			verifier = chap_verify_response;
		ok = (*verifier)(name, pcb->chap_server.name, id, pcb->chap_server.digest,
				 pcb->chap_server.challenge + PPP_HDRLEN + CHAP_HDRLEN,
				 response, pcb->chap_server.message, sizeof(pcb->chap_server.message));
#if 0 /* UNUSED */
		if (!ok || !auth_number()) {
#endif /* UNUSED */
		if (!ok) {
			pcb->chap_server.flags |= AUTH_FAILED;
			warn("Peer %q failed CHAP authentication", name);
		}
	} else if ((pcb->chap_server.flags & AUTH_DONE) == 0)
		return;

	/* send the response */
	p = pcb->outpacket_buf;
	MAKEHEADER(p, PPP_CHAP);
	mlen = strlen(pcb->chap_server.message);
	len = CHAP_HDRLEN + mlen;
	p[0] = (pcb->chap_server.flags & AUTH_FAILED)? CHAP_FAILURE: CHAP_SUCCESS;
	p[1] = id;
	p[2] = len >> 8;
	p[3] = len;
	if (mlen > 0)
		memcpy(p + CHAP_HDRLEN, pcb->chap_server.message, mlen);
	ppp_write(pcb, pcb->outpacket_buf, PPP_HDRLEN + len);

	if (pcb->chap_server.flags & CHALLENGE_VALID) {
		pcb->chap_server.flags &= ~CHALLENGE_VALID;
		if (!(pcb->chap_server.flags & AUTH_DONE) && !(pcb->chap_server.flags & AUTH_FAILED)) {

#if 0 /* UNUSED */
		    /*
		     * Auth is OK, so now we need to check session restrictions
		     * to ensure everything is OK, but only if we used a
		     * plugin, and only if we're configured to check.  This
		     * allows us to do PAM checks on PPP servers that
		     * authenticate against ActiveDirectory, and use AD for
		     * account info (like when using Winbind integrated with
		     * PAM).
		     */
		    if (session_mgmt &&
			session_check(name, NULL, devnam, NULL) == 0) {
			pcb->chap_server.flags |= AUTH_FAILED;
			warn("Peer %q failed CHAP Session verification", name);
		    }
#endif /* UNUSED */

		}
		if (pcb->chap_server.flags & AUTH_FAILED) {
			auth_peer_fail(pcb, PPP_CHAP);
		} else {
			if ((pcb->chap_server.flags & AUTH_DONE) == 0)
				auth_peer_success(pcb, PPP_CHAP,
						  pcb->chap_server.digest->code,
						  name, strlen(name));
			if (pcb->settings.chap_rechallenge_time) {
				pcb->chap_server.flags |= TIMEOUT_PENDING;
				TIMEOUT(chap_timeout, pcb,
					pcb->settings.chap_rechallenge_time);
			}
		}
		pcb->chap_server.flags |= AUTH_DONE;
	}
}

/*
 * chap_verify_response - check whether the peer's response matches
 * what we think it should be.  Returns 1 if it does (authentication
 * succeeded), or 0 if it doesn't.
 */
static int chap_verify_response(char *name, char *ourname, int id,
		     struct chap_digest_type *digest,
		     unsigned char *challenge, unsigned char *response,
		     char *message, int message_space) {
	int ok;
	unsigned char secret[MAXSECRETLEN];
	int secret_len;

	/* Get the secret that the peer is supposed to know */
	if (!get_secret(pcb, name, ourname, (char *)secret, &secret_len, 1)) {
		error("No CHAP secret found for authenticating %q", name);
		return 0;
	}

	ok = digest->verify_response(id, name, secret, secret_len, challenge,
				     response, message, message_space);
	memset(secret, 0, sizeof(secret));

	return ok;
}
#endif /* PPP_SERVER */

/*
 * chap_respond - Generate and send a response to a challenge.
 */
static void chap_respond(ppp_pcb *pcb, int id,
	     unsigned char *pkt, int len) {
	int clen, nlen;
	int secret_len;
	unsigned char *p;
	unsigned char response[RESP_MAX_PKTLEN];
	char rname[MAXNAMELEN+1];
	char secret[MAXSECRETLEN+1];
	ppp_pcb *pc = &ppp_pcb_list[0];

	if ((pcb->chap_client.flags & (LOWERUP | AUTH_STARTED)) != (LOWERUP | AUTH_STARTED))
		return;		/* not ready */
	if (len < 2 || len < pkt[0] + 1)
		return;		/* too short */
	clen = pkt[0];
	nlen = len - (clen + 1);

	/* Null terminate and clean remote name. */
	slprintf(rname, sizeof(rname), "%.*v", nlen, pkt + clen + 1);

	/* Microsoft doesn't send their name back in the PPP packet */
	if (pc->settings.explicit_remote || (pc->settings.remote_name[0] != 0 && rname[0] == 0))
		strlcpy(rname, pc->settings.remote_name, sizeof(rname));

	/* get secret for authenticating ourselves with the specified host */
	if (!get_secret(pcb, pcb->chap_client.name, rname, secret, &secret_len, 0)) {
		secret_len = 0;	/* assume null secret if can't find one */
		warn("No CHAP secret found for authenticating us to %q", rname);
	}

	p = response;
	MAKEHEADER(p, PPP_CHAP);
	p += CHAP_HDRLEN;

	pcb->chap_client.digest->make_response(p, id, pcb->chap_client.name, pkt,
				  secret, secret_len, pcb->chap_client.priv);
	memset(secret, 0, secret_len);

	clen = *p;
	nlen = strlen(pcb->chap_client.name);
	memcpy(p + clen + 1, pcb->chap_client.name, nlen);

	p = response + PPP_HDRLEN;
	len = CHAP_HDRLEN + clen + 1 + nlen;
	p[0] = CHAP_RESPONSE;
	p[1] = id;
	p[2] = len >> 8;
	p[3] = len;

	ppp_write(pcb, response, PPP_HDRLEN + len);
}

static void chap_handle_status(ppp_pcb *pcb, int code, int id,
		   unsigned char *pkt, int len) {
	const char *msg = NULL;

	if ((pcb->chap_client.flags & (AUTH_DONE|AUTH_STARTED|LOWERUP))
	    != (AUTH_STARTED|LOWERUP))
		return;
	pcb->chap_client.flags |= AUTH_DONE;

	if (code == CHAP_SUCCESS) {
		/* used for MS-CHAP v2 mutual auth, yuck */
		if (pcb->chap_client.digest->check_success != NULL) {
			if (!(*pcb->chap_client.digest->check_success)(pkt, len, pcb->chap_client.priv))
				code = CHAP_FAILURE;
		} else
			msg = "CHAP authentication succeeded";
	} else {
		if (pcb->chap_client.digest->handle_failure != NULL)
			(*pcb->chap_client.digest->handle_failure)(pkt, len);
		else
			msg = "CHAP authentication failed";
	}
	if (msg) {
		if (len > 0)
			info("%s: %.*v", msg, len, pkt);
		else
			info("%s", msg);
	}
	if (code == CHAP_SUCCESS)
		auth_withpeer_success(pcb, PPP_CHAP, pcb->chap_client.digest->code);
	else {
		pcb->chap_client.flags |= AUTH_FAILED;
		error("CHAP authentication failed");
		auth_withpeer_fail(pcb, PPP_CHAP);
	}
}

static void chap_input(ppp_pcb *pcb, unsigned char *pkt, int pktlen) {
	unsigned char code, id;
	int len;

	if (pktlen < CHAP_HDRLEN)
		return;
	GETCHAR(code, pkt);
	GETCHAR(id, pkt);
	GETSHORT(len, pkt);
	if (len < CHAP_HDRLEN || len > pktlen)
		return;
	len -= CHAP_HDRLEN;

	switch (code) {
	case CHAP_CHALLENGE:
		chap_respond(pcb, id, pkt, len);
		break;
#if PPP_SERVER
	case CHAP_RESPONSE:
		chap_handle_response(pcb, id, pkt, len);
		break;
#endif /* PPP_SERVER */
	case CHAP_FAILURE:
	case CHAP_SUCCESS:
		chap_handle_status(pcb, code, id, pkt, len);
		break;
	}
}

static void chap_protrej(ppp_pcb *pcb) {

#if PPP_SERVER
	if (pcb->chap_server.flags & TIMEOUT_PENDING) {
		pcb->chap_server.flags &= ~TIMEOUT_PENDING;
		UNTIMEOUT(chap_timeout, pcb);
	}
	if (pcb->chap_server.flags & AUTH_STARTED) {
		pcb->chap_server.flags = 0;
		auth_peer_fail(pcb, PPP_CHAP);
	}
#endif /* PPP_SERVER */
	if ((pcb->chap_client.flags & (AUTH_STARTED|AUTH_DONE)) == AUTH_STARTED) {
		pcb->chap_client.flags &= ~AUTH_STARTED;
		error("CHAP authentication failed due to protocol-reject");
		auth_withpeer_fail(pcb, PPP_CHAP);
	}
}

#if PRINTPKT_SUPPORT
/*
 * chap_print_pkt - print the contents of a CHAP packet.
 */
static char *chap_code_names[] = {
	"Challenge", "Response", "Success", "Failure"
};

static int chap_print_pkt(unsigned char *p, int plen,
	       void (*printer) (void *, char *, ...), void *arg) {
	int code, id, len;
	int clen, nlen;
	unsigned char x;

	if (plen < CHAP_HDRLEN)
		return 0;
	GETCHAR(code, p);
	GETCHAR(id, p);
	GETSHORT(len, p);
	if (len < CHAP_HDRLEN || len > plen)
		return 0;

	if (code >= 1 && code <= sizeof(chap_code_names) / sizeof(char *))
		printer(arg, " %s", chap_code_names[code-1]);
	else
		printer(arg, " code=0x%x", code);
	printer(arg, " id=0x%x", id);
	len -= CHAP_HDRLEN;
	switch (code) {
	case CHAP_CHALLENGE:
	case CHAP_RESPONSE:
		if (len < 1)
			break;
		clen = p[0];
		if (len < clen + 1)
			break;
		++p;
		nlen = len - clen - 1;
		printer(arg, " <");
		for (; clen > 0; --clen) {
			GETCHAR(x, p);
			printer(arg, "%.2x", x);
		}
		printer(arg, ">, name = ");
		print_string((char *)p, nlen, printer, arg);
		break;
	case CHAP_FAILURE:
	case CHAP_SUCCESS:
		printer(arg, " ");
		print_string((char *)p, len, printer, arg);
		break;
	default:
		for (clen = len; clen > 0; --clen) {
			GETCHAR(x, p);
			printer(arg, " %.2x", x);
		}
		/* no break */
	}

	return len + CHAP_HDRLEN;
}
#endif /* PRINTPKT_SUPPORT */

struct protent chap_protent = {
	PPP_CHAP,
	chap_init,
	chap_input,
	chap_protrej,
	chap_lowerup,
	chap_lowerdown,
	NULL,		/* open */
	NULL,		/* close */
#if PRINTPKT_SUPPORT
	chap_print_pkt,
#endif /* PRINTPKT_SUPPORT */
	NULL,		/* datainput */
	1,		/* enabled_flag */
#if PRINTPKT_SUPPORT
	"CHAP",		/* name */
	NULL,		/* data_name */
#endif /* PRINTPKT_SUPPORT */
#if PPP_OPTIONS
	chap_option_list,
	NULL,		/* check_options */
#endif /* PPP_OPTIONS */
#if DEMAND_SUPPORT
	NULL,
	NULL
#endif /* DEMAND_SUPPORT */
};

#endif /* PPP_SUPPORT && CHAP_SUPPORT */
