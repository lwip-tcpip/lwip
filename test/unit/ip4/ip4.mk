IP4_INC := 
IP4_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ip4

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ip4/*.c)