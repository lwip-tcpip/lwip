PPP_INC := 
PPP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ppp

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/ppp/*.c)