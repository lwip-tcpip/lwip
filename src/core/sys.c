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

#include "lwip/sys.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/memp.h"

#ifndef NO_SYS
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_fetch(sys_mbox_t mbox, void **msg)
{
  u16_t time;
  struct sys_timeouts *timeouts;
  struct sys_timeout *tmptimeout;
  sys_timeout_handler h;
  void *arg;

    
 again:
  timeouts = sys_arch_timeouts();
    
  if(timeouts->next == NULL) {
    sys_arch_mbox_fetch(mbox, msg, 0);
  } else {
    if(timeouts->next->time > 0) {
      time = sys_arch_mbox_fetch(mbox, msg, timeouts->next->time);
    } else {
      time = 0;
    }

    if(time == 0) {
      /* If time == 0, a timeout occured before a message could be
	 fetched. We should now call the timeout handler and
	 deallocate the memory allocated for the timeout. */
      tmptimeout = timeouts->next;
      timeouts->next = tmptimeout->next;
      h = tmptimeout->h;
      arg = tmptimeout->arg;
      memp_free(MEMP_SYS_TIMEOUT, tmptimeout);
      h(arg);
      
      /* We try again to fetch a message from the mbox. */
      goto again;
    } else {
      /* If time > 0, a message was received before the timeout
	 occured. The time variable is set to the number of
	 microseconds we waited for the message. */
      if(time <= timeouts->next->time) {
	timeouts->next->time -= time;
      } else {
	timeouts->next->time = 0;
      }
    }
    
  }
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_wait(sys_sem_t sem)
{
  u16_t time;
  struct sys_timeouts *timeouts;
  struct sys_timeout *tmptimeout;
  sys_timeout_handler h;
  void *arg;
  
  /*  while(sys_arch_sem_wait(sem, 1000) == 0);
      return;*/

 again:
  
  timeouts = sys_arch_timeouts();
  
  if(timeouts->next == NULL) {
    sys_arch_sem_wait(sem, 0);
  } else {
    if(timeouts->next->time > 0) {
      time = sys_arch_sem_wait(sem, timeouts->next->time);
    } else {
      time = 0;
    }

    if(time == 0) {
      /* If time == 0, a timeout occured before a message could be
	 fetched. We should now call the timeout handler and
	 deallocate the memory allocated for the timeout. */
      tmptimeout = timeouts->next;
      timeouts->next = tmptimeout->next;
      h = tmptimeout->h;
      arg = tmptimeout->arg;
      memp_free(MEMP_SYS_TIMEOUT, tmptimeout);
      h(arg);
	    
      
      /* We try again to fetch a message from the mbox. */
      goto again;
    } else {
      /* If time > 0, a message was received before the timeout
	 occured. The time variable is set to the number of
	 microseconds we waited for the message. */
      if(time <= timeouts->next->time) {
	timeouts->next->time -= time;
      } else {
	timeouts->next->time = 0;
      }
    }
    
  }
}
/*-----------------------------------------------------------------------------------*/
void
sys_timeout(u16_t msecs, sys_timeout_handler h, void *arg)
{
  struct sys_timeouts *timeouts;
  struct sys_timeout *timeout, *t;

  timeout = memp_malloc(MEMP_SYS_TIMEOUT);
  if(timeout == NULL) {
    return;
  }
  timeout->next = NULL;
  timeout->h = h;
  timeout->arg = arg;
  timeout->time = msecs;
  
  timeouts = sys_arch_timeouts();
  
  if(timeouts->next == NULL) {
    timeouts->next = timeout;
    return;
  }  
  
  if(timeouts->next->time > msecs) {
    timeouts->next->time -= msecs;
    timeout->next = timeouts->next;
    timeouts->next = timeout;
  } else {
    for(t = timeouts->next; t != NULL; t = t->next) {
      timeout->time -= t->time;
      if(t->next == NULL ||
	 t->next->time > timeout->time) {
	if(t->next != NULL) {
	  t->next->time -= timeout->time;
	}
	timeout->next = t->next;
	t->next = timeout;
	break;
      }
    }
  }
  
}
/*-----------------------------------------------------------------------------------*/
#endif /* NO_SYS */
