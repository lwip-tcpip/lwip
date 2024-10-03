ARCH_INC := 
ARCH_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/arch

HOSTCOM_SRC += $(wildcard $(HOSTCOM_ROOT)/src/3rd_party/lwip/test/unit/arch/*.c)