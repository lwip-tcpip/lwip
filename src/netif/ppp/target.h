#ifndef TARGET_H_
#define TARGET_H_

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/api.h"
#include "lwip/sockets.h"
#include "lwip/stats.h"
#include "lwip/mem.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"



/* the following is temporary until sio_common.h defines SIO_ERROR */
#if defined(ERROR) && !defined(SIO_ERROR)
#define SIO_ERROR ERROR
#endif

#define TIMEOUT(f, a, t)	sys_untimeout((f), (a)), sys_timeout((t)*1000, (f), (a))
#define UNTIMEOUT(f, a)		sys_untimeout((f), (a))



/* Type definitions for BSD code. */
typedef unsigned long u_long;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;


/*
 * Sleep ms milliseconds.  Note that this only has a (close to) 1 Jiffy 
 *  resolution.
 * Note: Since there may me less than a ms left before the next clock
 *  tick, 1 tick is added to ensure we delay at least ms time.
 */
void ppp_msleep(unsigned long ms);

/*
 * Return the number of jiffies that have passed since power up.
 */
unsigned long ppp_jiffies(void);

/* Display a panic message and HALT the system. */
void ppp_panic(char *msg);

/*
 * Make a string representation of a network IP address.
 * WARNING: NOT RE-ENTRANT!
 */
char *ip_ntoa(u32_t ipaddr);

typedef void * ppp_sio_fd_t;

/*FIXME */
#define sio_read_abort(fd) do { \
} while (0)


#endif /* TARGET_H */
