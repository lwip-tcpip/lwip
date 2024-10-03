MQTT_INC := 
MQTT_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/mqtt

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/mqtt/*.c)