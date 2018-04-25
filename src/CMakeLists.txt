set(LWIP_VERSION_MAJOR    "2")
set(LWIP_VERSION_MINOR    "0")
set(LWIP_VERSION_REVISION "3")
# LWIP_VERSION_RC is set to LWIP_RC_RELEASE for official releases */
# LWIP_VERSION_RC is set to LWIP_RC_DEVELOPMENT for Git versions */
set(LWIP_VERSION_RC       "LWIP_RC_DEVELOPMENT")

set(LWIP_VERSION_STRING
    "${LWIP_VERSION_MAJOR}.${LWIP_VERSION_MINOR}.${LWIP_VERSION_REVISION}"
)

# The minimum set of files needed for lwIP.
set(lwipcore_SRCS
    core/init.c
    core/def.c
    core/dns.c
    core/inet_chksum.c
    core/ip.c
    core/mem.c
    core/memp.c
    core/netif.c
    core/pbuf.c
    core/raw.c
    core/stats.c
    core/sys.c
    core/altcp.c
    core/altcp_alloc.c
    core/altcp_tcp.c
    core/tcp.c
    core/tcp_in.c
    core/tcp_out.c
    core/timeouts.c
    core/udp.c
)
set(lwipcore4_SRCS
    core/ipv4/autoip.c
    core/ipv4/dhcp.c
    core/ipv4/etharp.c
    core/ipv4/icmp.c
    core/ipv4/igmp.c
    core/ipv4/ip4_frag.c
    core/ipv4/ip4.c
    core/ipv4/ip4_addr.c
)
set(lwipcore6_SRCS
    core/ipv6/dhcp6.c
    core/ipv6/ethip6.c
    core/ipv6/icmp6.c
    core/ipv6/inet6.c
    core/ipv6/ip6.c
    core/ipv6/ip6_addr.c
    core/ipv6/ip6_frag.c
    core/ipv6/mld6.c
    core/ipv6/nd6.c
)

# APIFILES: The files which implement the sequential and socket APIs.
set(lwipapi_SRCS
    api/api_lib.c
    api/api_msg.c
    api/err.c
    api/if_api.c
    api/netbuf.c
    api/netdb.c
    api/netifapi.c
    api/sockets.c
    api/tcpip.c
)

# Files implementing various generic network interface functions
set(lwipnetif_SRCS
    netif/ethernet.c
    netif/bridgeif.c
    netif/bridgeif_fdb.c
    netif/slipif.c
)

# 6LoWPAN
set(lwipsixlowpan_SRCS
    netif/lowpan6_common.c
    netif/lowpan6.c
    netif/lowpan6_ble.c
    netif/zepif.c
)

# PPP
set(lwipppp_SRCS
    netif/ppp/auth.c
    netif/ppp/ccp.c
    netif/ppp/chap-md5.c
    netif/ppp/chap_ms.c
    netif/ppp/chap-new.c
    netif/ppp/demand.c
    netif/ppp/eap.c
    netif/ppp/ecp.c
    netif/ppp/eui64.c
    netif/ppp/fsm.c
    netif/ppp/ipcp.c
    netif/ppp/ipv6cp.c
    netif/ppp/lcp.c
    netif/ppp/magic.c
    netif/ppp/mppe.c
    netif/ppp/multilink.c
    netif/ppp/ppp.c
    netif/ppp/pppapi.c
    netif/ppp/pppcrypt.c
    netif/ppp/pppoe.c
    netif/ppp/pppol2tp.c
    netif/ppp/pppos.c
    netif/ppp/upap.c
    netif/ppp/utils.c
    netif/ppp/vj.c
    netif/ppp/polarssl/arc4.c
    netif/ppp/polarssl/des.c
    netif/ppp/polarssl/md4.c
    netif/ppp/polarssl/md5.c
    netif/ppp/polarssl/sha1.c
)

# SNMPv3 agent
set(lwipsnmp_SRCS
    apps/snmp/snmp_asn1.c
    apps/snmp/snmp_core.c
    apps/snmp/snmp_mib2.c
    apps/snmp/snmp_mib2_icmp.c
    apps/snmp/snmp_mib2_interfaces.c
    apps/snmp/snmp_mib2_ip.c
    apps/snmp/snmp_mib2_snmp.c
    apps/snmp/snmp_mib2_system.c
    apps/snmp/snmp_mib2_tcp.c
    apps/snmp/snmp_mib2_udp.c
    apps/snmp/snmp_snmpv2_framework.c
    apps/snmp/snmp_snmpv2_usm.c
    apps/snmp/snmp_msg.c
    apps/snmp/snmpv3.c
    apps/snmp/snmp_netconn.c
    apps/snmp/snmp_pbuf_stream.c
    apps/snmp/snmp_raw.c
    apps/snmp/snmp_scalar.c
    apps/snmp/snmp_table.c
    apps/snmp/snmp_threadsync.c
    apps/snmp/snmp_traps.c
)

# HTTP server + client
set(lwiphttp_SRCS
    apps/http/altcp_proxyconnect.c
    apps/http/fs.c
    apps/http/http_client.c
    apps/http/httpd.c
)

# MAKEFSDATA HTTP server host utility
set(lwipmakefsdata_SRCS
    apps/http/makefsdata/makefsdata.c
)

# IPERF server
set(lwipiperf_SRCS
    apps/lwiperf/lwiperf.c
)

# SMTP client
set(lwipsmtp_SRCS
    apps/smtp/smtp.c
)

# SNTP client
set(lwipsntp_SRCS
    apps/sntp/sntp.c
)

# MDNS responder
set(lwipmdns_SRCS
    apps/mdns/mdns.c
)

# NetBIOS name server
set(lwipnetbios_SRCS
    apps/netbiosns/netbiosns.c
)

# TFTP server files
set(lwiptftp_SRCS
    apps/tftp/tftp_server.c
)

# MQTT client files
set(lwipmqtt_SRCS
    apps/mqtt/mqtt.c
)

# ARM MBEDTLS related files of lwIP rep
set(lwipmbedtls_SRCS
    apps/altcp_tls/altcp_tls_mbedtls.c
    apps/altcp_tls/altcp_tls_mbedtls_mem.c
    apps/snmp/snmpv3_mbedtls.c
)

# All LWIP files without apps
set(lwipnoapps_SRCS
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipcore6_SRCS}
    ${lwipapi_SRCS}
    ${lwipnetif_SRCS}
    ${lwipsixlowpan_SRCS}
    ${lwipppp_SRCS}
)

# LWIPAPPFILES: All LWIP APPs
set(lwipallapps_SRCS
    ${lwipsnmp_SRCS}
    ${lwiphttp_SRCS}
    ${lwipiperf_SRCS}
    ${lwipsmtp_SRCS}
    ${lwipsntp_SRCS}
    ${lwipmdns_SRCS}
    ${lwipnetbios_SRCS}
    ${lwiptftp_SRCS}
    ${lwipmqtt_SRCS}
    ${lwipmbedtls_SRCS}
)

# Documentation
option(LWIP_BUILD_DOCUMENTATION "Build documentation" OFF)
if(LWIP_BUILD_DOCUMENTATION)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        set(DOXYGEN_IN  ../doc/doxygen/lwip.Doxyfile.cmake.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_SOURCE_DIR}/../doc/doxygen/lwip.Doxyfile)

        # configure the file (version info)
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT})
        message("Doxygen build started")

        # note the option ALL which allows to build the docs together with the application
        add_custom_target(lwipdocs ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../doc/doxygen
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM )
    else (DOXYGEN_FOUND)
        message("Doxygen need to be installed to generate the doxygen documentation")
    endif (DOXYGEN_FOUND)
endif(LWIP_BUILD_DOCUMENTATION)

option(LWIP_CONFIGURE_FILES "Generate files configured by CMAKE (usually done by lwIP developers)" OFF)
if(LWIP_CONFIGURE_FILES)
    # Generate Filelists.mk via cmake
    function(lwip_gen_filelist_entries var_name filelist_var_name)
        foreach(srcfile ${${filelist_var_name}})
           set(tmp "${tmp}$(LWIPDIR)/${srcfile} ")
        endforeach()
        set(${var_name} "${tmp}" PARENT_SCOPE)
    endfunction(lwip_gen_filelist_entries)
    
    lwip_gen_filelist_entries("filelist_mk_COREFILES" "lwipcore_SRCS")
    lwip_gen_filelist_entries("filelist_mk_CORE4FILES" "lwipcore4_SRCS")
    lwip_gen_filelist_entries("filelist_mk_CORE6FILES" "lwipcore6_SRCS")
    lwip_gen_filelist_entries("filelist_mk_APIFILES" "lwipapi_SRCS")
    lwip_gen_filelist_entries("filelist_mk_NETIFFILES" "lwipnetif_SRCS")
    lwip_gen_filelist_entries("filelist_mk_SIXLOWPANFILES" "lwipsixlowpan_SRCS")
    lwip_gen_filelist_entries("filelist_mk_PPPFILES" "lwipppp_SRCS")
    
    lwip_gen_filelist_entries("filelist_mk_SNMPFILES" "lwipsnmp_SRCS")
    lwip_gen_filelist_entries("filelist_mk_HTTPFILES" "lwiphttp_SRCS")
    lwip_gen_filelist_entries("filelist_mk_MKFSDATAFILES" "lwipmakefsdata_SRCS")
    lwip_gen_filelist_entries("filelist_mk_IPERFFILES" "lwipiperf_SRCS")
    lwip_gen_filelist_entries("filelist_mk_SMTPFILES" "lwipsmtp_SRCS")
    lwip_gen_filelist_entries("filelist_mk_SNTPFILES" "lwipsntp_SRCS")
    lwip_gen_filelist_entries("filelist_mk_MDNSFILES" "lwipmdns_SRCS")
    lwip_gen_filelist_entries("filelist_mk_NETBIOSFILES" "lwipnetbios_SRCS")
    lwip_gen_filelist_entries("filelist_mk_TFTPFILES" "lwiptftp_SRCS")
    lwip_gen_filelist_entries("filelist_mk_MQTTFILES" "lwipmqtt_SRCS")
    lwip_gen_filelist_entries("filelist_mk_MBEDTLSFILES" "lwipmbedtls_SRCS")
    
    configure_file(Filelists.mk.cmake.in
        ${CMAKE_CURRENT_SOURCE_DIR}/Filelists.mk)
    
    # Generate lwip/init.h (version info)
    configure_file(include/lwip/init.h.cmake.in
        ${CMAKE_CURRENT_SOURCE_DIR}/include/lwip/init.h)
endif(LWIP_CONFIGURE_FILES)

add_library(lwip EXCLUDE_FROM_ALL ${lwipnoapps_SRCS} ${lwipallapps_SRCS})

add_executable(makefsdata EXCLUDE_FROM_ALL ${lwipmakefsdata_SRCS})
