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
 
CCDEP=gcc
CC=gcc
CFLAGS=-g -Wall -DIPv4 -Os -fpack-struct
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

# NETIFFILES: Files implementing various generic network interface functions.'
NETIFFILES=$(LWIPDIR)/netif/etharp.c mintapif.c

# LWIPFILES: All the above.
LWIPFILES=$(COREFILES) $(CORE4FILES) $(NETIFFILES)
LWIPFILESW=$(wildcard $(LWIPFILES))
LWIPOBJS=$(notdir $(LWIPFILESW:.c=.o))

# APPFILES
APPFILES=echo.c 

LWIPLIB=liblwip4.a
APPLIB=liblwipapps.a
APPOBJS=$(notdir $(APPFILES:.c=.o))

%.o:
	$(CC) $(CFLAGS) -c $(<:.o=.c)

all ipv4 compile: minimal
.PHONY: all

clean:
	rm -f *.o $(LWIPLIB) $(APPLIB) minimal .depend* *.core core

depend dep: .depend

include .depend

$(APPLIB): $(APPOBJS)
	$(AR) $(ARFLAGS) $(APPLIB) $?

$(LWIPLIB): $(LWIPOBJS)
	$(AR) $(ARFLAGS) $(LWIPLIB) $?

.depend: main.c $(LWIPFILES) $(APPFILES)
	$(CCDEP) $(CFLAGS) -MM $^ > .depend || rm -f .depend

minimal: .depend $(LWIPLIB) $(APPLIB) main.o $(APPFILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o minimal main.o $(APPLIB) $(LWIPLIB)


