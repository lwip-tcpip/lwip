/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 * $Id: sys_arch.c,v 1.1 2002/11/29 11:03:34 likewise Exp $
 */

#include "lwip/def.h"
#include "lwip/sys.h"
#include "lwip/mem.h"

//#include "timers.h"

static struct sys_timeouts timeouts;

/*-----------------------------------------------------------------------------------*/
sys_mbox_t
sys_mbox_new(void)
{
  return SYS_MBOX_NULL;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_free(sys_mbox_t mbox)
{
  if (mbox); // LEON: prevent warning
  return;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_post(sys_mbox_t mbox, void *data)
{
  if (mbox); // LEON: prevent warning
  if (data); // LEON: prevent warning
  return;
}

u16_t
sys_arch_mbox_fetch(sys_mbox_t mbox, void **msg, u16_t timeout)
{
  if (mbox); // LEON: prevent warning
  if (msg); // LEON: prevent warning
  if (timeout); // LEON: prevent warning
  return 0;
}
/*-----------------------------------------------------------------------------------*/
sys_sem_t
sys_sem_new(u8_t count)
{
  if (count);
  return 0;
}
/*-----------------------------------------------------------------------------------*/
u16_t
sys_arch_sem_wait(sys_sem_t sem, u16_t timeout)
{
  if (sem);
  return 0;
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_signal(sys_sem_t sem)
{
  if (sem);
  return;
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_free(sys_sem_t sem)
{
  if (sem);
  return;
}

void
sys_init(void)
{
  timeouts.next = NULL;
  return;
}

struct sys_timeouts *
sys_arch_timeouts(void)
{
  return &timeouts;
}

u8_t			
sys_timeout_u32_t(u32_t msecs, sys_timeout_handler h, void *data) // LEON: arg 1 was unsigned int
{
  return 0;
  // WAS: return timer_obtain(msecs, h, data);
  // RE-ENABLE IF DHCP_TIMER_CALLBACKS
#if DHCP_TIMER_CALLBACKS
#error DHCP_TIMER_CALLBACKS not supported!
#endif
}

void
sys_thread_new(void (* function)(void *arg), void *arg)
{
  if (arg); // LW
}
/*-----------------------------------------------------------------------------------*/
void
sys_main(void)
{
}
/*-----------------------------------------------------------------------------------*/
