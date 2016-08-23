/**
 * @defgroup lwip lwIP
 *
 * @defgroup infrastructure Infrastructure
 *
 * @defgroup callbackstyle_api Callback-style APIs
 * Non thread-safe APIs, callback style for maximum performance and minimum
 * memory footprint.
 * 
 * @defgroup threadsafe_api Thread-safe APIs
 * Thread-safe APIs, blocking functions. More overhead, but can be called
 * from any thread except TCPIP thread.
 * 
 * @defgroup addons Addons
 * 
 * @defgroup apps Applications
 */

/**
 * @mainpage Overview
 * @verbinclude "README"
 */

/**
 * @page upgrading Upgrading
 * @verbinclude "UPGRADING"
 */

/**
 * @page contrib How to contribute to lwIP
 * @verbinclude "contrib.txt"
 */

/**
 * @page bugs Reporting bugs
 * Please report bugs in the lwIP bug tracker at savannah.\n
 * BEFORE submitting, please check if the bug has already been reported!\n
 * https://savannah.nongnu.org/bugs/?group=lwip
 */

/**
 * @defgroup lwip_nosys Mainloop mode ("NO_SYS")
 * @ingroup lwip
 * Use this mode if you do not run an OS on your system. \#define NO_SYS to 1.
 * Feed incoming packets to netif->input(pbuf, netif) function from mainloop,
 * *not* *from* *interrupt* *context*. You can allocate a @ref pbuf in interrupt
 * context and put them into a queue which is processed from mainloop.\n
 * Call sys_check_timeouts() periodically in the mainloop.\n
 * Porting: implement all functions in @ref sys_time and @ref sys_prot.\n
 * You can only use @ref callbackstyle_api in this mode.\n
 * Sample code:\n
 * @verbinclude NO_SYS_SampleCode.c
 */

/**
 * @defgroup lwip_os OS mode (TCPIP thread)
 * @ingroup lwip
 * Use this mode if you run an OS on your system. It is recommended to
 * use an RTOS that correctly handles priority inversion and
 * to use @ref LWIP_TCPIP_CORE_LOCKING.\n
 * Porting: implement all functions in @ref sys_layer.\n
 * You can use @ref callbackstyle_api together with @ref tcpip_callback,
 * and all @ref threadsafe_api.
 */

/**
 * @page raw_api lwIP API
 * @verbinclude "rawapi.txt"
 */
