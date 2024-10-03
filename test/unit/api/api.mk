API_INC := 
API_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/api

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/api/*.c)