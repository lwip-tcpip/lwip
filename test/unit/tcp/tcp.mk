TCP_INC := 
TCP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/tcp

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/tcp/*.c)