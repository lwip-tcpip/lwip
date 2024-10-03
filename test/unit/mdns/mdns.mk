MDNS_INC := 
MDNS_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/mdns

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/mdns/*.c)