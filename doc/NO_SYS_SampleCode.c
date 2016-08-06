void eth_mac_irq()
{
  /* Service MAC IRQ here */

  /* Allocate pbuf from pool (avoid using heap in interrupts) */
  struct pbuf* p = pbuf_alloc(PBUF_RAW, eth_data_count, PBUF_POOL);

  if(p != NULL) {
    /* Copy ethernet frame into pbuf */
    pbuf_take(p, eth_data, eth_data_count);

    /* Put in a queue which is processed in main loop */
    if(!queue->tryPut(p)) {
      /* queue is full -> packet loss */
      pbuf_free(p);
    }
  }
}

static err_t netif_output(struct netif *netif, struct pbuf *p)
{
  LINK_STATS_INC(link.xmit);

  /* Update SNMP stats (only if you use SNMP) */
  MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
  int unicast = ((p->payload[0] & 0x01) == 0);
  if (unicast) {
    MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
  } else {
    MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
  }

  LockInterrupts();
  pbuf_copy_partial(p, mac_send_buffer, p->tot_len, 0);
  /* Start MAC transmit here */
  UnlockInterrupts();

  return ERR_OK;
}

static void netif_status_callback(struct netif *netif)
{
  printf("netif status changed %s\n", ip4addr_ntoa(netif_ip4_addr(netif)));
}

static err_t netif_init(struct netif *netif)
{
  netif->linkoutput = netif_output;
  netif->output = etharp_output;
  netif->name[0] = 'e';
  netif->name[1] = '0';
  netif->mtu = ETHERNET_MTU;

  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP;
  MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 100000000);

  memcpy(netif->hwaddr, your_mac_address_goes_here, sizeof(netif->hwaddr));
  netif->hwaddr_len = sizeof(netif->hwaddr);

  return ERR_OK;
}

void main(void)
{
  struct netif netif;

  lwip_init();

  netif_add(&netif, IPADDR_ANY, IPADDR_ANY, IPADDR_ANY, NULL, netif_init, netif_input);
  netif_set_status_callback(&netif, netif_status_callback);
  netif_set_default(&netif);
  netif_set_up(&netif);
  
  /* Start DHCP */
  dhcp_init();

  while(1) {
    /* Check link state, e.g. via MDIO communication with PHY */
    if(linkStateChanged()) {
      if(linkIsUp()) {
        netif_set_link_up(&netif);
      } else {
        netif_set_link_down(&netif);
      }
    }

    /* Check for received frames, feed them to lwIP */
    LockInterrupts();
    struct pbuf* p = queue->tryGet();
    UnlockInterrupts();

    if(p != NULL) {
      LINK_STATS_INC(link.recv);
 
      /* Update SNMP stats (only if you use SNMP) */
      MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);
      int unicast = ((p->payload[0] & 0x01) == 0);
      if (unicast) {
        MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
      } else {
        MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
      }

      if(netif.input(p, &netif) != ERR_OK) {
        pbuf_free(p);
      }
    }
     
    /* Cyclic lwIP timers check */
    sys_check_timeouts();
     
    /* your application goes here */
  }
}
