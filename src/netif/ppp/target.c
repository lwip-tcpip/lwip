#include "ppp.h"

void ppp_panic(char * msg)
{
	LWIP_ASSERT("PPP panic: %s\n", msg);
}

void
ppp_msleep(unsigned long ms)
{
	sys_sem_t delaysem = sys_sem_new(0);

	sys_sem_wait_timeout(delaysem, ms);

	sys_sem_free(delaysem);
}

/*
 * Make a string representation of a network IP address.
 * WARNING: NOT RE-ENTRANT!
 */
char *ip_ntoa(u32_t ipaddr)
{
    static char b[20];
    
    ipaddr = ntohl(ipaddr);
#if 0 
//    FIXME
    sprintf(b, "%d.%d.%d.%d",
            (u_char)(ipaddr >> 24),
            (u_char)(ipaddr >> 16),
            (u_char)(ipaddr >> 8),
            (u_char)(ipaddr));
#endif
    return b;
}


