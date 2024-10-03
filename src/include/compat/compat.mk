include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/posix/posix.mk
include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat/stdc/stdc.mk

COMPAT_INC := 
COMPAT_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/compat
COMPAT_INC += $(POSIX_INC)
COMPAT_INC += $(STDC_INC)