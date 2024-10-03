include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/api/api.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/arch/arch.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/core/core.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/dhcp/dhcp.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/etharp/etharp.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ip4/ip4.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ip6/ip6.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/mdns/mdns.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/mqtt/mqtt.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ppp/ppp.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/tcp/tcp.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/udp/udp.mk

UNIT_INC := 
UNIT_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit
UNIT_INC += $(API_INC)
UNIT_INC += $(ARCH_INC)
UNIT_INC += $(CORE_INC)
UNIT_INC += $(DHCP_INC)
UNIT_INC += $(ETHARP_INC)
UNIT_INC += $(IP4_INC)
UNIT_INC += $(IP6_INC)
UNIT_INC += $(MDNS_INC)
UNIT_INC += $(MQTT_INC)
UNIT_INC += $(PPP_INC)
UNIT_INC += $(TCP_INC)
UNIT_INC += $(UDP_INC)

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/*.c)








HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/*.c)