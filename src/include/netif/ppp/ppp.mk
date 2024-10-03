include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/netif/ppp/polarssl/polarssl.mk

PPP_INC := 
PPP_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/netif/ppp
PPP_INC += $(POLARSSL_INC)