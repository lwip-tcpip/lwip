/*
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/debug.h"

#include <unistd.h>


#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"

#include "lwip/stats.h"


#include "lwip/tcpip.h"


#include "netif/unixif.h"
#include "netif/dropif.h"

#include "netif/loopif.h"

#include "netif/tcpdump.h"

#include "lwip/ip_addr.h"

#include "arch/perf.h"

#include "httpd.h"
#include "udpecho.h"
#include "tcpecho.h"
#include "shell.h"

/*-----------------------------------------------------------------------------------*/
static void
tcp_timeout(void *data)
{
#if TCP_DEBUG
  tcp_debug_print_pcbs();
#endif /* TCP_DEBUG */
  sys_timeout(5000, tcp_timeout, NULL);
}
/*-----------------------------------------------------------------------------------*/
static void
tcpip_init_done(void *arg)
{
  sys_sem_t *sem;
  sem = arg;
  sys_sem_signal(*sem);
}
/*-----------------------------------------------------------------------------------*/
static void
main_thread(void *arg)
{
  struct ip_addr ipaddr, netmask, gw;
  sys_sem_t sem;

    
  IP4_ADDR(&gw, 192,168,1,1);
  IP4_ADDR(&ipaddr, 192,168,1,2);
  IP4_ADDR(&netmask, 255,255,255,0);

  netif_set_default(netif_add(&ipaddr, &netmask, &gw, unixif_init_client,
			      tcpip_input));
  /*  netif_set_default(netif_add(&ipaddr, &netmask, &gw, sioslipif_init1,
			      tcpip_input)); */

  
  sem = sys_sem_new(0);
  tcpip_init(tcpip_init_done, &sem);
  sys_sem_wait(sem);
  sys_sem_free(sem);
  printf("TCP/IP initialized.\n");

  tcpecho_init();
  shell_init();
  httpd_init();
  udpecho_init();

  printf("Applications started.\n");
    
  sys_timeout(5000, tcp_timeout, NULL);

#ifdef MEM_PERF
  mem_perf_init("/tmp/memstats.client");
#endif /* MEM_PERF */

  sem = sys_sem_new(0);
  sys_sem_wait(sem);

}
/*-----------------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
#ifdef PERF
  perf_init("/tmp/client.perf");
#endif /* PERF */
#ifdef STATS
  stats_init();
#endif /* STATS */
  sys_init();
  mem_init();
  memp_init();
  pbuf_init();

  tcpdump_init();

  
  printf("System initialized.\n");
    
  sys_thread_new((void *)(main_thread), NULL);
  pause();
  return 0;
}
/*-----------------------------------------------------------------------------------*/








