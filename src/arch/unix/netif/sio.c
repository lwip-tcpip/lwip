/* Author: Magnus Ivarsson <magnus.ivarsson@volvo.com> */

#include "netif/sio.h" 
#include "netif/fifo.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/sys.h"
#include "lwip/arch.h"

/* Following #undefs are here to keep compiler from issuing warnings
   about them being double defined. (They are defined in lwip/inet.h
   as well as the Unix #includes below.) */
#undef htonl
#undef ntohl
#undef htons
#undef ntohs
#undef HTONL
#undef NTOHL
#undef HTONS
#undef NTOHS

#include <stdlib.h>
#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/types.h>

//#define BAUDRATE B19200 
//#define BAUDRATE B57600
#define BAUDRATE B115200

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* for all of you who dont define SIO_DEBUG in debug.h */
#ifndef SIO_DEBUG
#define SIO_DEBUG 0
#endif


// typedef struct siostruct_t
// { 
// 	sio_status_t *sio;
// } siostruct_t;

/** array of ((siostruct*)netif->state)->sio structs */
static sio_status_t statusar[2];

/* --private-functions----------------------------------------------------------------- */
/** 
 * Signal handler for ttyXX0 to indicate bytes received 
 * one per interface is needed since we cannot send a instance number / pointer as callback argument (?)
 */
static void	signal_handler_IO_0( int status )
{
	DEBUGF(SIO_DEBUG, ("SigHand: rxSignal chanel 0"));
	fifoPut( &statusar[0].myfifo, statusar[0].fd );
}

/**
 * Signal handler for ttyXX1 to indicate bytes received 
 * one per interface is needed since we cannot send a instance number / pointer as callback argument (?)
 */
static void signal_handler_IO_1( int status )
{
	DEBUGF(SIO_DEBUG, ("SigHand: rxSignal channel 1"));
	fifoPut( &statusar[1].myfifo, statusar[1].fd );
}

/**
* Initiation of serial device 
* @param device : string with the device name and path, eg. "/dev/ttyS0"
* @param netif  : netinterface struct, contains interface instance data
* @return file handle to serial dev.
*/
static int sio_init( char * device, int devnum, sio_status_t * siostat )
{
	struct termios oldtio,newtio;
	struct sigaction saio;           /* definition of signal action */
	int fd;

	/* open the device to be non-blocking (read will return immediatly) */
	fd = open( device, O_RDWR | O_NOCTTY | O_NONBLOCK );
	if ( fd < 0 )
	{
		perror( device );
		exit( -1 );
	}

	/* install the signal handler before making the device asynchronous */
	switch ( devnum )
	{
		case 0:
			DEBUGF( SIO_DEBUG, ("sioinit, signal_handler_IO_0\r\n") );
			saio.sa_handler = signal_handler_IO_0;
			break;
		case 1:
			DEBUGF( SIO_DEBUG, ("sioinit, signal_handler_IO_1\r\n") );
			saio.sa_handler = signal_handler_IO_1;
			break;
		default:
			DEBUGF( SIO_DEBUG,("sioinit, devnum not allowed\r\n") );
			break;
	}

	saio.sa_flags = 0;
#if linux
	saio.sa_restorer = NULL;
#endif /* linux */
	sigaction( SIGIO,&saio,NULL );

	/* allow the process to receive SIGIO */
	fcntl( fd, F_SETOWN, getpid( ) );
	/* Make the file descriptor asynchronous (the manual page says only
	O_APPEND and O_NONBLOCK, will work with F_SETFL...) */
	fcntl( fd, F_SETFL, FASYNC );

	tcgetattr( fd,&oldtio ); /* save current port settings */
	/* set new port settings */
	/* see 'man termios' for further settings */
	newtio.c_cflag = BAUDRATE | CS8 | CLOCAL | CREAD; // | CRTSCTS;
	newtio.c_iflag = 0;
	newtio.c_oflag = 0;
	newtio.c_lflag = 0; //ECHO;
	newtio.c_cc[VMIN] = 1; /* Read 1 byte at a time, no timer */
	newtio.c_cc[VTIME] = 0;

	tcsetattr( fd,TCSANOW,&newtio );
	tcflush( fd, TCIOFLUSH );

	return fd;
}

/**
*
*/
static void sio_speed( int fd, int speed )
{
	struct termios oldtio,newtio;
	//  int fd;

	DEBUGF( 1,("sio_speed: baudcode:%d  enter\n",speed ) );

	if ( fd < 0 )
	{
		DEBUGF(SIO_DEBUG, ( "sio_speed: fd ERROR\n" ));
		exit( -1 );
	}

	tcgetattr( fd,&oldtio ); /* get current port settings */

	/* set new port settings 
	* see 'man termios' for further settings */
	newtio.c_cflag = speed | CS8 | CLOCAL | CREAD; //§ | CRTSCTS;
	newtio.c_iflag = 0;
	newtio.c_oflag = 0;
	newtio.c_lflag = 0; //ECHO;
	newtio.c_cc[VMIN] = 1; /* Read 1 byte at a time, no timer */
	newtio.c_cc[VTIME] = 0;

	tcsetattr( fd,TCSANOW,&newtio );
	tcflush( fd, TCIOFLUSH );

	DEBUGF( SIO_DEBUG ,("sio_speed: leave\n" ));
}

/* --public-functions----------------------------------------------------------------------------- */
void sio_send( u8_t c, sio_status_t * siostat )
{
//	sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;

	if ( write( siostat->fd, &c, 1 ) <= 0 )
	{
		DEBUGF( SIO_DEBUG,("sio_send: write refused") );
	}
}

void sio_send_string( u8_t *str, sio_status_t * siostat )
{
//	sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;
	int len = strlen( (const char *)str );

	if ( write( siostat->fd, str, len ) <= 0 )
	{
		DEBUGF( SIO_DEBUG,("sio_send_string: write refused") );
	}
	DEBUGF( (PPP_DEBUG | SIO_DEBUG),("sent:%s",str ) );
}


void sio_flush( sio_status_t * siostat )
{
	/* not implemented in unix as it is not needed */
 	//sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;
}


//u8_t sio_recv( struct netif * netif )
u8_t sio_recv( sio_status_t * siostat )
{
//	sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;
	return fifoGet( &(siostat->myfifo) );
}

s16_t sio_poll(sio_status_t * siostat)
{
//	sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;
	return fifoGetNonBlock( &(siostat->myfifo) );
}


void sio_expect_string( u8_t *str, sio_status_t * siostat )
{
//	sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;
	u8_t c;
 	int finger=0;
  
	DEBUGF( (PPP_DEBUG | SIO_DEBUG), ("expect:%s\n",str) );
	while ( 1 )
	{
		c=fifoGet( &(siostat->myfifo) );
		DEBUGF( (PPP_DEBUG | SIO_DEBUG), ("_%c",c) );
		if ( c==str[finger] )
		{
			finger++;
		} else if ( finger > 0 )
		{
			//it might fit in the beginning?
			if ( str[0] == c )
			{
				finger = 1;
			}
		}
		if ( 0 == str[finger] ) 
			break;	// done, we have a match
	}
	DEBUGF( (PPP_DEBUG | SIO_DEBUG), ("[match]\n") );
}


sio_status_t * sio_open( int devnum )
{
	char dev[20];

	/* would be nice with dynamic memory alloc */
	sio_status_t * siostate = &statusar[ devnum ];
// 	siostruct_t * tmp;
// 
// 
// 	tmp = (siostruct_t*)(netif->state);
// 	tmp->sio = siostate;
// 
// 	tmp = (siostruct_t*)(netif->state);
// 
// 	((sio_status_t*)(tmp->sio))->fd = 0;

	fifoInit( &siostate->myfifo );

	sprintf( dev, "/dev/ttyS%d", devnum );

	if ( (devnum == 1) || (devnum == 0) )
	{
		if ( ( siostate->fd = sio_init( dev, devnum, siostate ) ) == 0 )
		{
			DEBUGF(SIO_DEBUG, ( "sio_open: ERROR opening serial device" ));
			abort( );
			return NULL;
		}
	} 
	else
	{
		DEBUGF(SIO_DEBUG, ( "sio_open: device %s (%d) is not supported", dev, devnum ));
		return NULL;
	}
	DEBUGF( 1,("sio_open: dev=%s open.\n", dev ));

	return siostate;
}

/**
*
*/
void sio_change_baud( sioBaudrates baud, sio_status_t * siostat )
{
//	sio_status_t * siostat = ((siostruct_t*)netif->state)->sio;

	DEBUGF( 1,("sio_change_baud\n" ));

	switch ( baud )
	{
		case SIO_BAUD_9600:
			sio_speed( siostat->fd, B9600 );
			break;
		case SIO_BAUD_19200:
			sio_speed( siostat->fd, B19200 );
			break;
		case SIO_BAUD_38400:
			sio_speed( siostat->fd, B38400 );
			break;
		case SIO_BAUD_57600:
			sio_speed( siostat->fd, B57600 );
			break;
		case SIO_BAUD_115200:
			sio_speed( siostat->fd, B115200 );
			break;

		default:
			DEBUGF( 1,("sio_change_baud: Unknown baudrate, code:%d", baud ));
			break;
	}
}

