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

#include <c64.h>
#include <time.h>

#include "lwip/sys.h"
#include "lwip/def.h"

struct sys_timeouts timeouts;

/*-----------------------------------------------------------------------------------*/
void
sys_arch_block(u16_t time)
{
  u16_t ticks;
  
  ticks = time * (CLK_TCK / 1000) + clock();
  printf("ticks %d\n", ticks);

  while(clock() != ticks);  
}
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
  return;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_post(sys_mbox_t mbox, void *data)
{
  return;
}
/*-----------------------------------------------------------------------------------*/
u16_t 
sys_arch_mbox_fetch(sys_mbox_t mbox, void **data, u16_t timeout)
{
  sys_arch_block(timeout);
  return 0;
}
/*-----------------------------------------------------------------------------------*/
sys_sem_t
sys_sem_new(u8_t count)
{
  return 0;
}
/*-----------------------------------------------------------------------------------*/
u16_t
sys_arch_sem_wait(sys_sem_t sem, u16_t timeout)
{
  sys_arch_block(timeout);
  return 0;
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_signal(sys_sem_t sem)
{
  return;
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_free(sys_sem_t sem)
{
  return;
}
/*-----------------------------------------------------------------------------------*/
void
sys_init(void)
{
  timeouts.next = NULL;
  return;
}
/*-----------------------------------------------------------------------------------*/
struct sys_timeouts *
sys_arch_timeouts(void)
{
  return &timeouts;
}
/*-----------------------------------------------------------------------------------*/
void
sys_thread_new(void (* function)(void *arg), void *arg)
{
}
/*-----------------------------------------------------------------------------------*/
