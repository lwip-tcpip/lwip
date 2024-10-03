include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/posix/arpa/arpa.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/posix/net/net.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/posix/sys/sys.mk

POSIX_INC := 
POSIX_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/posix
POSIX_INC += $(ARPA_INC)
POSIX_INC += $(NET_INC)
POSIX_INC += $(SYS_INC)