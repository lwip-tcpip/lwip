/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
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

#include "arch/cc.h"

#include "lwip/opt.h"

#if NO_SYS

/* For a totally minimal and standalone system, we provide null
   definitions of the sys_ functions. */
typedef u8_t sys_sem_t;
typedef u8_t sys_mbox_t;
struct sys_timeout {u8_t dummy;};

#define sys_init()
#define sys_timeout(m,h,a)
#define sys_sem_new(c) c
#define sys_sem_signal(s)
#define sys_sem_wait(s)
#define sys_sem_free(s)
#define sys_mbox_new() 0
#define sys_mbox_fetch(m,d)
#define sys_mbox_post(m,d)
#define sys_mbox_free(m)

#define sys_thread_new(t,a)

#else /* NO_SYS */

#include "arch/sys_arch.h"

typedef void (* sys_timeout_handler)(void *arg);

struct sys_timeout {
  struct sys_timeout *next;
  u32_t time;
  sys_timeout_handler h;
  void *arg;
};

struct sys_timeouts {
  struct sys_timeout *next;
};

/* sys_init() must be called before anthing else. */
void sys_init(void);

/*
 * sys_timeout():
 *
 * Schedule a timeout a specified amount of milliseconds in the
 * future. When the timeout occurs, the specified timeout handler will
 * be called. The handler will be passed the "arg" argument when
 * called.
 *
 */
void sys_timeout(u32_t msecs, sys_timeout_handler h, void *arg);
struct sys_timeouts *sys_arch_timeouts(void);

/* Semaphore functions. */
sys_sem_t sys_sem_new(u8_t count);
void sys_sem_signal(sys_sem_t sem);
u32_t sys_arch_sem_wait(sys_sem_t sem, u32_t timeout);
void sys_sem_free(sys_sem_t sem);
void sys_sem_wait(sys_sem_t sem);

/* Mailbox functions. */
sys_mbox_t sys_mbox_new(void);
void sys_mbox_post(sys_mbox_t mbox, void *msg);
u32_t sys_arch_mbox_fetch(sys_mbox_t mbox, void **msg, u32_t timeout);
void sys_mbox_free(sys_mbox_t mbox);
void sys_mbox_fetch(sys_mbox_t mbox, void **msg);

/* Thread functions. */
void sys_thread_new(void (* thread)(void *arg), void *arg);

/* The following functions are used only in Unix code, and
   can be omitted when porting the stack. */
/* Returns the current time in microseconds. */
unsigned long sys_now(void);

#endif /* NO_SYS */

#endif /* __LWIP_SYS_H__ */
