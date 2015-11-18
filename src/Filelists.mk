#
# Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
# All rights reserved. 
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission. 
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
# SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
# OF SUCH DAMAGE.
#
# This file is part of the lwIP TCP/IP stack.
# 
# Author: Adam Dunkels <adam@sics.se>
#

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.
COREFILES=$(LWIPDIR)/core/def.c \
	$(LWIPDIR)/core/dns.c \
	$(LWIPDIR)/core/inet_chksum.c \
	$(LWIPDIR)/core/init.c \
	$(LWIPDIR)/core/mem.c \
	$(LWIPDIR)/core/memp.c \
	$(LWIPDIR)/core/netif.c \
	$(LWIPDIR)/core/pbuf.c \
	$(LWIPDIR)/core/raw.c \
	$(LWIPDIR)/core/stats.c \
	$(LWIPDIR)/core/sys.c \
	$(LWIPDIR)/core/tcp.c \
	$(LWIPDIR)/core/tcp_in.c \
	$(LWIPDIR)/core/tcp_out.c \
	$(LWIPDIR)/core/timers.c \
	$(LWIPDIR)/core/udp.c

CORE4FILES=$(LWIPDIR)/core/ipv4/autoip.c \
	$(LWIPDIR)/core/ipv4/dhcp.c \
	$(LWIPDIR)/core/ipv4/icmp.c \
	$(LWIPDIR)/core/ipv4/igmp.c \
	$(LWIPDIR)/core/ipv4/ip_frag.c \
	$(LWIPDIR)/core/ipv4/ip4.c \
	$(LWIPDIR)/core/ipv4/ip4_addr.c

CORE6FILES=$(LWIPDIR)/core/ipv6/dhcp6.c \
	$(LWIPDIR)/core/ipv6/ethip6.c \
	$(LWIPDIR)/core/ipv6/icmp6.c \
	$(LWIPDIR)/core/ipv6/ip6.c \
	$(LWIPDIR)/core/ipv6/ip6_addr.c \
	$(LWIPDIR)/core/ipv6/ip6_frag.c \
	$(LWIPDIR)/core/ipv6/mld6.c \
	$(LWIPDIR)/core/ipv6/nd6.c

# APIFILES: The files which implement the sequential and socket APIs.
APIFILES=$(LWIPDIR)/api/api_lib.c \
	$(LWIPDIR)/api/api_msg.c \
	$(LWIPDIR)/api/err.c \
	$(LWIPDIR)/api/netbuf.c \
	$(LWIPDIR)/api/netdb.c \
	$(LWIPDIR)/api/netifapi.c \
	$(LWIPDIR)/api/pppapi.c \
	$(LWIPDIR)/api/sockets.c \
	$(LWIPDIR)/api/tcpip.c

# NETIFFILES: Files implementing various generic network interface functions
NETIFFILES=$(LWIPDIR)/netif/etharp.c \
	$(LWIPDIR)/netif/slipif.c

# PPPFILES: PPP
PPPFILES=$(LWIPDIR)/netif/ppp/auth.c \
	$(LWIPDIR)/netif/ppp/ccp.c \
	$(LWIPDIR)/netif/ppp/chap-md5.c \
	$(LWIPDIR)/netif/ppp/chap_ms.c \
	$(LWIPDIR)/netif/ppp/chap-new.c \
	$(LWIPDIR)/netif/ppp/demand.c \
	$(LWIPDIR)/netif/ppp/eap.c \
	$(LWIPDIR)/netif/ppp/ecp.c \
	$(LWIPDIR)/netif/ppp/eui64.c \
	$(LWIPDIR)/netif/ppp/fsm.c \
	$(LWIPDIR)/netif/ppp/ipcp.c \
	$(LWIPDIR)/netif/ppp/ipv6cp.c \
	$(LWIPDIR)/netif/ppp/lcp.c \
	$(LWIPDIR)/netif/ppp/magic.c \
	$(LWIPDIR)/netif/ppp/mppe.c \
	$(LWIPDIR)/netif/ppp/multilink.c \
	$(LWIPDIR)/netif/ppp/ppp.c \
	$(LWIPDIR)/netif/ppp/pppcrypt.c \
	$(LWIPDIR)/netif/ppp/pppoe.c \
	$(LWIPDIR)/netif/ppp/pppol2tp.c \
	$(LWIPDIR)/netif/ppp/pppos.c \
	$(LWIPDIR)/netif/ppp/upap.c \
	$(LWIPDIR)/netif/ppp/utils.c \
	$(LWIPDIR)/netif/ppp/vj.c \
	$(LWIPDIR)/netif/ppp/polarssl/arc4.c \
	$(LWIPDIR)/netif/ppp/polarssl/des.c \
	$(LWIPDIR)/netif/ppp/polarssl/md4.c \
	$(LWIPDIR)/netif/ppp/polarssl/md5.c \
	$(LWIPDIR)/netif/ppp/polarssl/sha1.c

# LWIPNOAPPSFILES: All LWIP files without apps
LWIPNOAPPSFILES=$(COREFILES) \
	$(CORE4FILES) \
	$(CORE6FILES) \
	$(APIFILES) \
	$(NETIFFILES) \
	$(PPPFILES)

# SNMPFILES: SNMPv1 agent
SNMPFILES=$(LWIPDIR)/apps/snmp/asn1_dec.c \
	$(LWIPDIR)/apps/snmp/asn1_enc.c \
	$(LWIPDIR)/apps/snmp/mib2.c \
	$(LWIPDIR)/apps/snmp/mib_structs.c \
	$(LWIPDIR)/apps/snmp/msg_in.c \
	$(LWIPDIR)/apps/snmp/msg_out.c

# HTTPDFILES: HTTP server
HTTPDFILES=$(LWIPDIR)/apps/httpd/fs.c \
	$(LWIPDIR)/apps/httpd/httpd.c

# LWIPERFFILES: IPERF server
LWIPERFFILES=$(LWIPDIR)/apps/lwiperf/lwiperf.c

# SNTPFILES: SNTP client
SNTPFILES=$(LWIPDIR)/apps/sntp/sntp.c

# NETBIOSNSFILES: NetBIOS name server
NETBIOSNSFILES=$(LWIPDIR)/apps/netbiosns/netbiosns.c

# LWIPAPPFILES: All LWIP APPs
LWIPAPPFILES=$(SNMPFILES) \
	$(HTTPDFILES) \
	$(LWIPERFFILES) \
	$(SNTPFILES) \
	$(NETBIOSNSFILES)
