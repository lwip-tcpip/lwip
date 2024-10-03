CORE_INC := 
CORE_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/core

HOSTCOM_SRC += $(wildcard $(HOSTCOM_SRC)/src/3rd_party/lwip/test/unit/core/*.c)