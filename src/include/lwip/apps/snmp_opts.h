/*
 * Copyright (c) 2015 Dirk Ziegelmeier
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
 * Author: Dirk Ziegelmeier
 *
 */

#ifndef LWIP_HDR_APPS_SNMP_OPTS_H
#define LWIP_HDR_APPS_SNMP_OPTS_H

#include "lwip/opt.h"

/*
   ----------------------------------
   ---------- SNMP options ----------
   ----------------------------------
*/
/**
 * LWIP_SNMP==1: This enables the lwIP SNMP agent. UDP must be available
 * for SNMP transport.
 * If you want to use your own SNMP agent, leave this disabled.
 * To integrate MIB2 of an external agent, you need to enable
 * LWIP_MIB2_CALLBACKS and MIB2_STATS. This will give you the callbacks
 * and statistics counters you need to get MIB2 working.
 */
#ifndef LWIP_SNMP
#define LWIP_SNMP                       0
#endif

/**
 * SNMP_CONCURRENT_REQUESTS: Number of concurrent requests the module will
 * allow. At least one request buffer is required.
 * Does not have to be changed unless external MIBs answer request asynchronously
 */
#ifndef SNMP_CONCURRENT_REQUESTS
#define SNMP_CONCURRENT_REQUESTS        1
#endif

/**
 * SNMP_TRAP_DESTINATIONS: Number of trap destinations. At least one trap
 * destination is required
 */
#ifndef SNMP_TRAP_DESTINATIONS
#define SNMP_TRAP_DESTINATIONS          1
#endif

/**
 * SNMP_PRIVATE_MIB:
 * When using a private MIB, you have to create a file 'private_mib.h' that contains
 * a 'struct mib_array_node mib_private' which contains your MIB.
 */
#ifndef SNMP_PRIVATE_MIB
#define SNMP_PRIVATE_MIB                0
#endif

/**
 * Only allow SNMP write actions that are 'safe' (e.g. disabling netifs is not
 * a safe action and disabled when SNMP_SAFE_REQUESTS = 1).
 * Unsafe requests are disabled by default!
 */
#ifndef SNMP_SAFE_REQUESTS
#define SNMP_SAFE_REQUESTS              1
#endif

/**
 * The maximum length of strings used. This affects the size of
 * MEMP_SNMP_VALUE elements.
 */
#ifndef SNMP_MAX_OCTET_STRING_LEN
#define SNMP_MAX_OCTET_STRING_LEN       127
#endif

/**
 * The maximum depth of the SNMP tree.
 * With private MIBs enabled, this depends on your MIB!
 * This affects the size of MEMP_SNMP_VALUE elements.
 */
#ifndef SNMP_MAX_TREE_DEPTH
#define SNMP_MAX_TREE_DEPTH             15
#endif

/**
 * The size of the MEMP_SNMP_VALUE elements, normally calculated from
 * SNMP_MAX_OCTET_STRING_LEN and SNMP_MAX_TREE_DEPTH.
 */
#ifndef SNMP_MAX_VALUE_SIZE
#define SNMP_MAX_VALUE_SIZE             LWIP_MAX((SNMP_MAX_OCTET_STRING_LEN)+1, sizeof(s32_t)*(SNMP_MAX_TREE_DEPTH))
#endif

/**
 * The snmp read-access community. Used for write-access and traps, too
 * unless SNMP_COMMUNITY_WRITE or SNMP_COMMUNITY_TRAP are enabled, respectively.
 */
#ifndef SNMP_COMMUNITY
#define SNMP_COMMUNITY                  "public"
#endif

/**
 * Set this to 1 to enable support for dedicated write-access and trap communities.
 */
#ifndef SNMP_COMMUNITY_EXT
#define SNMP_COMMUNITY_EXT              0
#endif

#if SNMP_COMMUNITY_EXT
/**
 * The snmp write-access community.
 */
#ifndef SNMP_COMMUNITY_WRITE
#define SNMP_COMMUNITY_WRITE            "private"
#endif

/**
 * The snmp community used for sending traps.
 */
#ifndef SNMP_COMMUNITY_TRAP
#define SNMP_COMMUNITY_TRAP             "public"
#endif
#endif /* SNMP_COMMUNITY_EXT */

/**
 * SNMP_NUM_NODE: the number of leafs in the SNMP tree.
 */
#ifndef SNMP_NUM_NODE
#define SNMP_NUM_NODE              50
#endif

/**
 * SNMP_NUM_ROOTNODE: the number of branches in the SNMP tree.
 * Every branch has one leaf (MEMP_NUM_SNMP_NODE) at least!
 */
#ifndef SNMP_NUM_ROOTNODE
#define SNMP_NUM_ROOTNODE          30
#endif

/**
 * SNMP_NUM_VARBIND: influences the number of concurrent requests:
 * 2 of these are used per request (1 for input, 1 for output), so this needs
 * to be increased only if you want to support concurrent requests or multiple
 * variables per request/response.
 */
#ifndef SNMP_NUM_VARBIND
#define SNMP_NUM_VARBIND           2
#endif

/**
 * SNMP_NUM_VALUE: the number of OID or values concurrently used
 * (does not have to be changed normally) - >=3 of these are used per request
 * (1 for the value read and 2 for OIDs - input and output on getnext, or more
 * if you want to support multiple varibles per request/response)
 */
#ifndef SNMP_NUM_VALUE
#define SNMP_NUM_VALUE             3
#endif

/**
 * SNMP_MSG_DEBUG: Enable debugging for SNMP messages.
 */
#ifndef SNMP_MSG_DEBUG
#define SNMP_MSG_DEBUG                  LWIP_DBG_OFF
#endif

/**
 * SNMP_MIB_DEBUG: Enable debugging for SNMP MIBs.
 */
#ifndef SNMP_MIB_DEBUG
#define SNMP_MIB_DEBUG                  LWIP_DBG_OFF
#endif

#endif	/* LWIP_HDR_APPS_SNMP_OPTS_H */
