include $(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/netif/ppp/ppp.mk

NETIF_INC := 
NETIF_INC += -I$(HOSTCOM_ROOT)/src/3rd_party/lwip/src/include/netif
NETIF_INC += $(PPP_INC)