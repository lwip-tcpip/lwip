# Copyright (c) 2001, Swedish Institute of Computer Science.
# All rights reserved. 
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions 
# are met: 
#
# 1. Redistributions of source code must retain the above copyright 
#    notice, this list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in the 
#    documentation and/or other materials provided with the distribution. 
# 3. Neither the name of the Institute nor the names of its contributors 
#    may be used to endorse or promote products derived from this software 
#    without specific prior written permission. 
#
# THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
# SUCH DAMAGE. 
#
# This file is part of the lwIP TCP/IP stack.
# 
# Author: Adam Dunkels <adam@sics.se>
#
# $Id: Makefile,v 1.1.1.1 2002/10/19 12:59:37 likewise Exp $

CCDEP=gcc
CC=gcc
CFLAGS=-g -Wall -DIPv4 -DLWIP_DEBUG -pedantic
LDFLAGS=-lpcap
LWIPARCH=unix
ARFLAGS=rs
LWIPDIR=../../src

CFLAGS:=$(CFLAGS) \
	-I$(LWIPDIR)/include -I$(LWIPDIR)/arch/$(LWIPARCH)/include -I$(LWIPDIR)/include/ipv4 \
	-Iapps -I.

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.
COREFILES=$(LWIPDIR)/core/mem.c $(LWIPDIR)/core/memp.c $(LWIPDIR)/core/netif.c \
	$(LWIPDIR)/core/pbuf.c $(LWIPDIR)/core/stats.c $(LWIPDIR)/core/sys.c \
        $(LWIPDIR)/core/tcp.c $(LWIPDIR)/core/tcp_input.c \
        $(LWIPDIR)/core/tcp_output.c $(LWIPDIR)/core/udp.c 
CORE4FILES=$(LWIPDIR)/core/ipv4/icmp.c $(LWIPDIR)/core/ipv4/ip.c \
	$(LWIPDIR)/core/inet.c $(LWIPDIR)/core/ipv4/ip_addr.c


# APIFILES: The files which implement the sequential and socket APIs.
APIFILES=$(LWIPDIR)/api/api_lib.c $(LWIPDIR)/api/api_msg.c $(LWIPDIR)/api/tcpip.c \
	$(LWIPDIR)/api/err.c $(LWIPDIR)/api/sockets.c 

# NETIFFILES: Files implementing various generic network interface functions.'
NETIFFILES=$(LWIPDIR)/netif/loopif.c \
	$(LWIPDIR)/netif/tcpdump.c $(LWIPDIR)/netif/etharp.c

# ARCHFILES: Archiecture specific files.
ARCHFILES=$(wildcard $(LWIPDIR)/arch/$(LWIPARCH)/*.c $(LWIPDIR)/arch/$(LWIPARCH)/netif/*.c)

# APPFILES: Applications.
APPFILES=apps/fs.c apps/httpd.c \
	apps/udpecho.c apps/tcpecho.c \
	apps/shell.c 

# LWIPFILES: All the above.
LWIPFILES=$(COREFILES) $(CORE4FILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES)
LWIPFILESW=$(wildcard $(LWIPFILES))
LWIPOBJS=$(notdir $(LWIPFILESW:.c=.o))

LWIPLIB=liblwip4.a
APPLIB=liblwipapps.a
APPOBJS=$(notdir $(APPFILES:.c=.o))

%.o:
	$(CC) $(CFLAGS) -c $(<:.o=.c)

all ipv4 compile: simhost simnode simrouter
.PHONY: all

clean:
	rm -f *.o $(LWIPLIB) $(APPLIB) simhost simnode simrouter *.s .depend* *.core core

depend dep: .depend

include .depend

$(APPLIB): $(APPOBJS)
	$(AR) $(ARFLAGS) $(APPLIB) $?

$(LWIPLIB): $(LWIPOBJS)
	$(AR) $(ARFLAGS) $(LWIPLIB) $?

.depend: simhost.c simnode.c simrouter.c $(LWIPFILES) $(APPFILES)
	$(CCDEP) $(CFLAGS) -MM $^ > .depend || rm -f .depend

simhost: .depend $(LWIPLIB) $(APPLIB) simhost.o $(APPFILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread -o simhost simhost.o $(APPLIB) $(LWIPLIB)

simrouter: .depend $(LWIPLIB) $(APPLIB) simrouter.o
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread -o simrouter simrouter.o $(APPLIB) $(LWIPLIB) 

simnode: .depend $(LWIPLIB) $(APPLIB) simnode.o 
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread -o simnode simnode.o $(APPLIB) $(LWIPLIB)

