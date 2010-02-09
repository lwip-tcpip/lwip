/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
#ifndef __LWIP_SYS_H__
#define __LWIP_SYS_H__

#include "lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NO_SYS

/* For a totally minimal and standalone system, we provide null
   definitions of the sys_ functions. */
typedef u8_t sys_sem_t;
typedef u8_t sys_mbox_t;

#define sys_sem_new(c) ((sys_sem_t)c)
#define sys_sem_signal(s)
#define sys_sem_wait(s)
#define sys_arch_sem_wait(s,t)
#define sys_sem_free(s)
#define sys_mbox_new(s) 0
#define sys_mbox_fetch(m,d)
#define sys_mbox_tryfetch(m,d)
#define sys_mbox_post(m,d)
#define sys_mbox_trypost(m,d)
#define sys_mbox_free(m)

#define sys_thread_new(n,t,a,s,p)

#define sys_msleep(t)

#else /* NO_SYS */

/** Return code for timeouts from sys_arch_mbox_fetch and sys_arch_sem_wait */
#define SYS_ARCH_TIMEOUT 0xffffffffUL

/** sys_mbox_tryfetch() returns SYS_MBOX_EMPTY if appropriate.
 * For now we use the same magic value, but we allow this to change in future.
 */
#define SYS_MBOX_EMPTY SYS_ARCH_TIMEOUT 

#include "lwip/err.h"
#include "arch/sys_arch.h"

/** Function prototype for thread functions */
typedef void (*lwip_thread_fn)(void *arg);

/* Function prototypes for functions to be implemented by platform ports
   (in sys_arch.c) */

/* Semaphore functions: */

/** Create a new semaphore
 * @param count initial count of the semaphore
 * @return a new semaphore */
sys_sem_t sys_sem_new(u8_t count);
/** Signals a semaphore
 * @param sem the semaphore to signal */
void sys_sem_signal(sys_sem_t sem);
/** Wait for a semaphore for the specified timeout
 * @param sem the semaphore to wait for
 * @param timeout timeout in miliseconds to wait (0 = wait forever)
 * @return time (in miliseconds) waited for the semaphore
 *         or SYS_ARCH_TIMEOUT on timeout */
u32_t sys_arch_sem_wait(sys_sem_t sem, u32_t timeout);
/** Delete a semaphore
 * @param sem semaphore to delete */
void sys_sem_free(sys_sem_t sem);
/** Wait for a semaphore - forever/no timeout */
#define sys_sem_wait(sem)                  sys_arch_sem_wait(sem, 0)

/* Time functions. */
#ifndef sys_msleep
void sys_msleep(u32_t ms); /* only has a (close to) 1 jiffy resolution. */
#endif

/* Mailbox functions. */

/** Create a new mbox of specified size
 * @param size (miminum) number of messages in this mbox
 * @return a new mbox */
sys_mbox_t sys_mbox_new(int size);
/** Post a message to an mbox - may not fail
 * -> blocks if full, only used from tasks not from ISR
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL) */
void sys_mbox_post(sys_mbox_t mbox, void *msg);
/** Try to post a message to an mbox - may fail if full or ISR
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL) */
err_t sys_mbox_trypost(sys_mbox_t mbox, void *msg);
/** Wait for a new message to arrive in the mbox
 * @param mbox mbox to get a message from
 * @param msg pointer where the message is stored
 * @param timeout maximum time (in miliseconds) to wait for a message
 * @return time (in miliseconds) waited for a message, may be 0 if not waited
           or SYS_ARCH_TIMEOUT on timeout
 *         The returned time has to be accurate to prevent timer jitter! */
u32_t sys_arch_mbox_fetch(sys_mbox_t mbox, void **msg, u32_t timeout);
/* Allow port to override with a macro, e.g. special timout for sys_arch_mbox_fetch() */
#ifndef sys_arch_mbox_tryfetch
/** Wait for a new message to arrive in the mbox
 * @param mbox mbox to get a message from
 * @param msg pointer where the message is stored
 * @param timeout maximum time (in miliseconds) to wait for a message
 * @return 0 (miliseconds) if a message has been received
 *         or SYS_MBOX_EMPTY if the mailbox is empty */
u32_t sys_arch_mbox_tryfetch(sys_mbox_t mbox, void **msg);
#endif
/** For now, we map straight to sys_arch implementation. */
#define sys_mbox_tryfetch(mbox, msg) sys_arch_mbox_tryfetch(mbox, msg)
/** Delete an mbox
 * @param mbox mbox to delete */
void sys_mbox_free(sys_mbox_t mbox);
#define sys_mbox_fetch(mbox, msg) sys_arch_mbox_fetch(mbox, msg, 0)

/** The only thread function:
 * Creates a new thread
 * @param name human-readable name for the thread (used for debugging purposes)
 * @param thread thread-function
 * @param arg parameter passed to 'thread'
 * @param stacksize stack size in bytes for the new thread (may be ignored by ports)
 * @param prio priority of the new thread (may be ignored by ports) */
sys_thread_t sys_thread_new(char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio);

#endif /* NO_SYS */

/* sys_init() must be called before anthing else. */
void sys_init(void);

#ifndef sys_jiffies
/** Ticks/jiffies since power up. */
u32_t sys_jiffies(void);
#endif

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t sys_now(void);

/* Critical Region Protection */
/* These functions must be implemented in the sys_arch.c file.
   In some implementations they can provide a more light-weight protection
   mechanism than using semaphores. Otherwise semaphores can be used for
   implementation */
#ifndef SYS_ARCH_PROTECT
/** SYS_LIGHTWEIGHT_PROT
 * define SYS_LIGHTWEIGHT_PROT in lwipopts.h if you want inter-task protection
 * for certain critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */
#if SYS_LIGHTWEIGHT_PROT

/** SYS_ARCH_DECL_PROTECT
 * declare a protection variable. This macro will default to defining a variable of
 * type sys_prot_t. If a particular port needs a different implementation, then
 * this macro may be defined in sys_arch.h.
 */
#define SYS_ARCH_DECL_PROTECT(lev) sys_prot_t lev
/** SYS_ARCH_PROTECT
 * Perform a "fast" protect. This could be implemented by
 * disabling interrupts for an embedded system or by using a semaphore or
 * mutex. The implementation should allow calling SYS_ARCH_PROTECT when
 * already protected. The old protection level is returned in the variable
 * "lev". This macro will default to calling the sys_arch_protect() function
 * which should be implemented in sys_arch.c. If a particular port needs a
 * different implementation, then this macro may be defined in sys_arch.h
 */
#define SYS_ARCH_PROTECT(lev) lev = sys_arch_protect()
/** SYS_ARCH_UNPROTECT
 * Perform a "fast" set of the protection level to "lev". This could be
 * implemented by setting the interrupt level to "lev" within the MACRO or by
 * using a semaphore or mutex.  This macro will default to calling the
 * sys_arch_unprotect() function which should be implemented in
 * sys_arch.c. If a particular port needs a different implementation, then
 * this macro may be defined in sys_arch.h
 */
#define SYS_ARCH_UNPROTECT(lev) sys_arch_unprotect(lev)
sys_prot_t sys_arch_protect(void);
void sys_arch_unprotect(sys_prot_t pval);

#else

#define SYS_ARCH_DECL_PROTECT(lev)
#define SYS_ARCH_PROTECT(lev)
#define SYS_ARCH_UNPROTECT(lev)

#endif /* SYS_LIGHTWEIGHT_PROT */

#endif /* SYS_ARCH_PROTECT */

/*
 * Macros to set/get and increase/decrease variables in a thread-safe way.
 * Use these for accessing variable that are used from more than one thread.
 */

#ifndef SYS_ARCH_INC
#define SYS_ARCH_INC(var, val) do { \
                                SYS_ARCH_DECL_PROTECT(old_level); \
                                SYS_ARCH_PROTECT(old_level); \
                                var += val; \
                                SYS_ARCH_UNPROTECT(old_level); \
                              } while(0)
#endif /* SYS_ARCH_INC */

#ifndef SYS_ARCH_DEC
#define SYS_ARCH_DEC(var, val) do { \
                                SYS_ARCH_DECL_PROTECT(old_level); \
                                SYS_ARCH_PROTECT(old_level); \
                                var -= val; \
                                SYS_ARCH_UNPROTECT(old_level); \
                              } while(0)
#endif /* SYS_ARCH_DEC */

#ifndef SYS_ARCH_GET
#define SYS_ARCH_GET(var, ret) do { \
                                SYS_ARCH_DECL_PROTECT(old_level); \
                                SYS_ARCH_PROTECT(old_level); \
                                ret = var; \
                                SYS_ARCH_UNPROTECT(old_level); \
                              } while(0)
#endif /* SYS_ARCH_GET */

#ifndef SYS_ARCH_SET
#define SYS_ARCH_SET(var, val) do { \
                                SYS_ARCH_DECL_PROTECT(old_level); \
                                SYS_ARCH_PROTECT(old_level); \
                                var = val; \
                                SYS_ARCH_UNPROTECT(old_level); \
                              } while(0)
#endif /* SYS_ARCH_SET */


#ifdef __cplusplus
}
#endif

#endif /* __LWIP_SYS_H__ */
