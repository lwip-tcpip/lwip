include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/lwip/apps/apps.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/lwip/priv/priv.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/lwip/prot/prot.mk

LWIP_INC := 
LWIP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/lwip
LWIP_INC += $(APPS_INC)
LWIP_INC += $(PRIV_INC)
LWIP_INC += $(PROT_INC)