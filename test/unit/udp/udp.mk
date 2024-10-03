UDP_INC := 
UDP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/udp

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/udp/*.c)