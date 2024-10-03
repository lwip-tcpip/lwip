include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/compat.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/lwip/lwip.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/netif/netif.mk

INCLUDE_INC := 
INCLUDE_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include
INCLUDE_INC += $(COMPAT_INC)
INCLUDE_INC += $(LWIP_INC)
INCLUDE_INC += $(NETIF_INC)