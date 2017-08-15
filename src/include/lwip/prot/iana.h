/**
 * @file
 * IANA assigned numbers (RFC 1700 and successors)
 *
 * @defgroup iana IANA assigned numbers
 * @ingroup infrastructure
 */

/*
 * Copyright (c) 2017 Dirk Ziegelmeier.
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 *
 */

#ifndef LWIP_HDR_PROT_IANA_H
#define LWIP_HDR_PROT_IANA_H

/**
 * @ingroup iana
 * Hardware types
 */
enum lwip_iana_hwtype {
  /** Ethernet */
  LWIP_IANA_HWTYPE_ETHERNET = 1
};

/**
 * @ingroup iana
 * Port numbers
 * https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
 */
enum lwip_iana_port_number {
  /** SMTP */
  LWIP_IANA_PORT_SMTP        = 25,
  /** DHCP server */
  LWIP_IANA_PORT_DHCP_SERVER = 67,
  /** DHCP client */
  LWIP_IANA_PORT_DHCP_CLIENT = 68,
  /** TFTP */
  LWIP_IANA_PORT_TFTP        = 69,
  /** HTTP */
  LWIP_IANA_PORT_HTTP        = 80,
  /** SNTP */
  LWIP_IANA_PORT_SNTP        = 123,
  /** NETBIOS */
  LWIP_IANA_PORT_NETBIOS     = 137,
  /** SNMP */
  LWIP_IANA_PORT_SNMP        = 161,
  /** SNMP traps */
  LWIP_IANA_PORT_SNMP_TRAP   = 162,
  /** HTTPS */
  LWIP_IANA_PORT_HTTPS       = 443,
  /** SMTPS */
  LWIP_IANA_PORT_SMTPS       = 465,
  /** MQTT */
  LWIP_IANA_PORT_MQTT        = 1883,
  /** MDNS */
  LWIP_IANA_PORT_MDNS        = 5353,
  /** Secure MQTT */
  LWIP_IANA_PORT_SEQURE_MQTT = 8883
};

/**
 * @ingroup iana
 * A list of often ethtypes (although lwIP does not use all of them).
 * https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
 */
enum eth_type {
  /** Internet protocol v4 */
  ETHTYPE_IP        = 0x0800U,
  /** Address resolution protocol */
  ETHTYPE_ARP       = 0x0806U, 
  /** Wake on lan */
  ETHTYPE_WOL       = 0x0842U,
  /** RARP */
  ETHTYPE_RARP      = 0x8035U,
  /** Virtual local area network */
  ETHTYPE_VLAN      = 0x8100U,
  /** Internet protocol v6 */
  ETHTYPE_IPV6      = 0x86DDU,
  /** PPP Over Ethernet Discovery Stage */
  ETHTYPE_PPPOEDISC = 0x8863U,
  /** PPP Over Ethernet Session Stage */
  ETHTYPE_PPPOE     = 0x8864U,
  /** Jumbo Frames */
  ETHTYPE_JUMBO     = 0x8870U,
  /** Process field network */
  ETHTYPE_PROFINET  = 0x8892U,
  /** Ethernet for control automation technology */
  ETHTYPE_ETHERCAT  = 0x88A4U,
  /** Link layer discovery protocol */
  ETHTYPE_LLDP      = 0x88CCU,
  /** Serial real-time communication system */
  ETHTYPE_SERCOS    = 0x88CDU,
  /** Media redundancy protocol */
  ETHTYPE_MRP       = 0x88E3U,
  /** Precision time protocol */
  ETHTYPE_PTP       = 0x88F7U,
  /** Q-in-Q, 802.1ad */
  ETHTYPE_QINQ      = 0x9100U
};

#endif /* LWIP_HDR_PROT_IANA_H */
