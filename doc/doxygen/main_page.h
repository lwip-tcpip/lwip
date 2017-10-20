/**
 * @defgroup lwip lwIP
 *
 * @defgroup infrastructure Infrastructure
 * 
 * @defgroup api APIs
 * lwIP provides three Application Program's Interfaces (APIs) for programs
 * to use for communication with the TCP/IP code:
 * - low-level "core" / "callback" or @ref callbackstyle_api.
 * - higher-level @ref sequential_api.
 * - BSD-style @ref socket.
 * 
 * The raw TCP/IP interface allows the application program to integrate
 * better with the TCP/IP code. Program execution is event based by
 * having callback functions being called from within the TCP/IP
 * code. The TCP/IP code and the application program both run in the same
 * thread. The sequential API has a much higher overhead and is not very
 * well suited for small systems since it forces a multithreaded paradigm
 * on the application.
 * 
 * The raw TCP/IP interface is not only faster in terms of code execution
 * time but is also less memory intensive. The drawback is that program
 * development is somewhat harder and application programs written for
 * the raw TCP/IP interface are more difficult to understand. Still, this
 * is the preferred way of writing applications that should be small in
 * code size and memory usage.
 * 
 * All APIs can be used simultaneously by different application
 * programs. In fact, the sequential API is implemented as an application
 * program using the raw TCP/IP interface.
 * 
 * Do not confuse the lwIP raw API with raw Ethernet or IP sockets.
 * The former is a way of interfacing the lwIP network stack (including
 * TCP and UDP), the latter refers to processing raw Ethernet or IP data
 * instead of TCP connections or UDP packets.
 * 
 * Raw API applications may never block since all packet processing
 * (input and output) as well as timer processing (TCP mainly) is done
 * in a single execution context.
 * 
 * Multithreading
 * --------------
 * lwIP started targeting single-threaded environments. When adding multi-
 * threading support, instead of making the core thread-safe, another
 * approach was chosen: there is one main thread running the lwIP core
 * (also known as the "tcpip_thread"). When running in a multithreaded
 * environment, raw API functions MUST only be called from the core thread
 * since raw API functions are not protected from concurrent access (aside
 * from pbuf- and memory management functions). Application threads using
 * the sequential- or socket API communicate with this main thread through
 * message passing.
 * 
 * As such, the list of functions that may be called from
 * other threads or an ISR is very limited! Only functions
 * from these API header files are thread-safe:
 * - api.h
 * - netbuf.h
 * - netdb.h
 * - netifapi.h
 * - pppapi.h
 * - sockets.h
 * - sys.h
 * 
 * Additionaly, memory (de-)allocation functions may be
 * called from multiple threads (not ISR!) with NO_SYS=0
 * since they are protected by SYS_LIGHTWEIGHT_PROT and/or
 * semaphores.
 * 
 * Netconn or Socket API functions are thread safe against the
 * core thread but they are not reentrant at the control block
 * granularity level. That is, a UDP or TCP control block must
 * not be shared among multiple threads without proper locking.
 * 
 * If SYS_LIGHTWEIGHT_PROT is set to 1 and
 * LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT is set to 1,
 * pbuf_free() may also be called from another thread or
 * an ISR (since only then, mem_free - for PBUF_RAM - may
 * be called from an ISR: otherwise, the HEAP is only
 * protected by semaphores).
 *
 * @defgroup callbackstyle_api "raw" APIs
 * @ingroup api
 * Non thread-safe APIs, callback style for maximum performance and minimum
 * memory footprint.
 * Program execution is driven by callbacks functions, which are then
 * invoked by the lwIP core when activity related to that application
 * occurs. A particular application may register to be notified via a
 * callback function for events such as incoming data available, outgoing
 * data sent, error notifications, poll timer expiration, connection
 * closed, etc. An application can provide a callback function to perform
 * processing for any or all of these events. Each callback is an ordinary
 * C function that is called from within the TCP/IP code. Every callback
 * function is passed the current TCP or UDP connection state as an
 * argument. Also, in order to be able to keep program specific state,
 * the callback functions are called with a program specified argument
 * that is independent of the TCP/IP state.
 * The raw API (sometimes called native API) is an event-driven API designed
 * to be used without an operating system that implements zero-copy send and
 * receive. This API is also used by the core stack for interaction between
 * the various protocols. It is the only API available when running lwIP
 * without an operating system.
 * 
 * @defgroup sequential_api Sequential-style APIs
 * @ingroup api
 * Sequential-style APIs, blocking functions. More overhead, but can be called
 * from any thread except TCPIP thread.
 * The sequential API provides a way for ordinary, sequential, programs
 * to use the lwIP stack. It is quite similar to the BSD socket API. The
 * model of execution is based on the blocking open-read-write-close
 * paradigm. Since the TCP/IP stack is event based by nature, the TCP/IP
 * code and the application program must reside in different execution
 * contexts (threads).
 * 
 * @defgroup socket Socket API
 * @ingroup api
 * BSD-style socket API.\n
 * Thread-safe, to be called from non-TCPIP threads only.\n
 * Can be activated by defining @ref LWIP_SOCKET to 1.\n
 * Header is in posix/sys/socket.h\n
 * The socket API is a compatibility API for existing applications,
 * currently it is built on top of the sequential API. It is meant to
 * provide all functions needed to run socket API applications running
 * on other platforms (e.g. unix / windows etc.). However, due to limitations
 * in the specification of this API, there might be incompatibilities
 * that require small modifications of existing programs.
 * 
 * @defgroup netifs NETIFs
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
 * @page changelog Changelog
 * @verbinclude "CHANGELOG"
 */

/**
 * @page contrib How to contribute to lwIP
 * @verbinclude "contrib.txt"
 */

/**
 * @page pitfalls Common pitfalls
 *
 * Multiple Execution Contexts in lwIP code
 * ========================================
 *
 * The most common source of lwIP problems is to have multiple execution contexts
 * inside the lwIP code.
 * 
 * lwIP can be used in two basic modes: @ref lwip_nosys (no OS/RTOS 
 * running on target system) or @ref lwip_os (there is an OS running
 * on the target system).
 *
 * Mainloop Mode
 * -------------
 * In mainloop mode, only @ref callbackstyle_api can be used.
 * The user has two possibilities to ensure there is only one 
 * exection context at a time in lwIP:
 *
 * 1) Deliver RX ethernet packets directly in interrupt context to lwIP
 *    by calling netif->input directly in interrupt. This implies all lwIP 
 *    callback functions are called in IRQ context, which may cause further
 *    problems in application code: IRQ is blocked for a long time, multiple
 *    execution contexts in application code etc. When the application wants
 *    to call lwIP, it only needs to disable interrupts during the call.
 *    If timers are involved, even more locking code is needed to lock out
 *    timer IRQ and ethernet IRQ from each other, assuming these may be nested.
 *
 * 2) Run lwIP in a mainloop. There is example code here: @ref lwip_nosys.
 *    lwIP is _ONLY_ called from mainloop callstacks here. The ethernet IRQ
 *    has to put received telegrams into a queue which is polled in the
 *    mainloop. Ensure lwIP is _NEVER_ called from an interrupt, e.g.
 *    some SPI IRQ wants to forward data to udp_send() or tcp_write()!
 *
 * OS Mode
 * -------
 * In OS mode, @ref callbackstyle_api AND @ref sequential_api can be used.
 * @ref sequential_api are designed to be called from threads other than
 * the TCPIP thread, so there is nothing to consider here.
 * But @ref callbackstyle_api functions must _ONLY_ be called from
 * TCPIP thread. It is a common error to call these from other threads
 * or from IRQ contexts. ​Ethernet RX needs to deliver incoming packets
 * in the correct way by sending a message to TCPIP thread, this is
 * implemented in tcpip_input().​​
 * Again, ensure lwIP is _NEVER_ called from an interrupt, e.g.
 * some SPI IRQ wants to forward data to udp_send() or tcp_write()!
 * 
 * 1) tcpip_callback() can be used get called back from TCPIP thread,
 *    it is safe to call any @ref callbackstyle_api from there.
 *
 * 2) Use @ref LWIP_TCPIP_CORE_LOCKING. All @ref callbackstyle_api
 *    functions can be called when lwIP core lock is aquired, see
 *    @ref LOCK_TCPIP_CORE() and @ref UNLOCK_TCPIP_CORE().
 *    These macros cannot be used in an interrupt context!
 *    Note the OS must correctly handle priority inversion for this.
 */

/**
 * @page bugs Reporting bugs
 * Please report bugs in the lwIP bug tracker at savannah.\n
 * BEFORE submitting, please check if the bug has already been reported!\n
 * https://savannah.nongnu.org/bugs/?group=lwip
 */

/**
 * @page zerocopyrx Zero-copy RX
 * The following code is an example for zero-copy RX ethernet driver:
 * @include ZeroCopyRx.c
 */

/**
 * @defgroup lwip_nosys Mainloop mode ("NO_SYS")
 * @ingroup lwip
 * Use this mode if you do not run an OS on your system. \#define NO_SYS to 1.
 * Feed incoming packets to netif->input(pbuf, netif) function from mainloop,
 * *not* *from* *interrupt* *context*. You can allocate a @ref pbuf in interrupt
 * context and put them into a queue which is processed from mainloop.\n
 * Call sys_check_timeouts() periodically in the mainloop.\n
 * Porting: implement all functions in @ref sys_time, @ref sys_prot and 
 * @ref compiler_abstraction.\n
 * You can only use @ref callbackstyle_api in this mode.\n
 * Sample code:\n
 * @include NO_SYS_SampleCode.c
 */

/**
 * @defgroup lwip_os OS mode (TCPIP thread)
 * @ingroup lwip
 * Use this mode if you run an OS on your system. It is recommended to
 * use an RTOS that correctly handles priority inversion and
 * to use @ref LWIP_TCPIP_CORE_LOCKING.\n
 * Porting: implement all functions in @ref sys_layer.\n
 * You can use @ref callbackstyle_api together with @ref tcpip_callback,
 * and all @ref sequential_api.
 */

/**
 * @page raw_api lwIP API
 * @verbinclude "rawapi.txt"
 */
