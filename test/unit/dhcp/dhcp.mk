DHCP_INC := 
DHCP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/dhcp

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/dhcp/*.c)