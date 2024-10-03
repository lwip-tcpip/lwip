IP6_INC := 
IP6_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ip6

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ip6/*.c)