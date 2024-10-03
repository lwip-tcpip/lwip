ETHARP_INC := 
ETHARP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/etharp

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/etharp/*.c)