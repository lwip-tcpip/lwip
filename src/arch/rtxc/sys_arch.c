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

#include "lwip/debug.h"

#include "lwip/def.h"
#include "lwip/sys.h"
#include "lwip/mem.h"

#include "rtxcapi.h"
#include "csema.h"
#include "cclock.h"
#include "cqueue.h"
#include "cres.h"
#include "cpart.h"
#include "ctask.h"

struct timeoutlist {
  struct sys_timeouts timeouts;
  TASK pid;
};

#define SYS_THREAD_MAX 2

static struct timeoutlist timeoutlist[SYS_THREAD_MAX];
static u16_t nextthread = 0;

/*-----------------------------------------------------------------------------------*/
sys_mbox_t
sys_mbox_new(void)
{
  QUEUE mbox;  
  KS_dequeuew(IP_MBOXQ, &mbox);
  KS_purgequeue(mbox);
  return mbox;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_free(sys_mbox_t mbox)
{
  KS_enqueue(IP_MBOXQ, &mbox);
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_post(sys_mbox_t mbox, void *data)
{
  if(KS_enqueue(mbox, &data) != RC_GOOD) {
  }
}
/*-----------------------------------------------------------------------------------*/
u16_t
sys_arch_mbox_fetch(sys_mbox_t mbox, void **data, u16_t timeout)
{
  KSRC ret;
  u16_t wtime = 1;
  
  if(timeout == 0) {
    DEBUGF(SYS_DEBUG, ("PID: %d sys_mbox_fetch: without timeouts\n",KS_inqtask()));
    KS_dequeuew(mbox, data);
    
  } else { 
  
    ret = KS_dequeuet(mbox, data, (TICKS)timeout/CLKTICK);
    if(ret == RC_TIMEOUT) {
      /* The call timed out, so we return 0. */
      wtime = 0;
    } else {
      /* Calculate time we waited for the message to arrive. */
      
      /* XXX: we cheat and just pretend that we waited for half the timeout value! */
      wtime = timeout / 2;
      
      /* Make sure we don't return 0 here. */
      if(wtime == 0) {
	wtime = 1;
      }
    }
  }
  return wtime;
}
/*-----------------------------------------------------------------------------------*/
sys_sem_t
sys_sem_new(u8_t count)
{
  SEMA sem;
  KS_dequeuew(IP_SEMQ, &sem);
  KS_pend(sem);
  if(count > 0) {
    KS_signal(sem);
  }
  return sem;
}
/*-----------------------------------------------------------------------------------*/
u16_t
sys_arch_sem_wait(sys_sem_t sem, u16_t timeout)
{
  KSRC ret;
  u16_t wtime = 1;
  
  if(timeout == 0) {
    DEBUGF(SYS_DEBUG, ("PID: %d sys_mbox_fetch: without timeouts\n",KS_inqtask()));
    KS_wait(sem);
    
  } else { 
    ret = KS_waitt(sem, (TICKS)timeout/CLKTICK);  
    if(ret == RC_TIMEOUT) {
      /* The call timed out, so we return 0. */
      wtime = 0;
    } else {
      /* Calculate time we waited for the message to arrive. */
      
      /* XXX: we cheat and just pretend that we waited for half the timeout value! */
      wtime = timeout / 2;
      
      /* Make sure we don't return 0 here. */
      if(wtime == 0) {
	wtime = 1;
      }
    }
  }
  return wtime;

}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_signal(sys_sem_t sem)
{
  KS_signal(sem);
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_free(sys_sem_t sem)
{
  KS_enqueue(IP_SEMQ, &sem);
}
/*-----------------------------------------------------------------------------------*/
void
sys_init(void)
{
  /* posta in alla semaforer i IP_SEMQ, posta in alla mboxar i
     IP_MBOXQ */
  QUEUE mbox;
  SEMA  sem;
  
  mbox = IP_Q_01; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_02; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_03; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_04; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_05; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_06; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_07; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_08; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_09; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_10; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_11; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_12; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_13; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_14; KS_enqueue(IP_MBOXQ, &mbox);
  mbox = IP_Q_15; KS_enqueue(IP_MBOXQ, &mbox);
  sem  = IP_S_01; KS_enqueue(IP_SEMQ,  &sem);
  sem  = IP_S_02; KS_enqueue(IP_SEMQ,  &sem);
  sem  = IP_S_03; KS_enqueue(IP_SEMQ,  &sem);
}
/*-----------------------------------------------------------------------------------*/
struct sys_timeouts *
sys_arch_timeouts(void)
{
  int i;
  TASK pid;
  struct timeoutlist *tl;  
  
  DEBUGF(SYS_DEBUG, ("PID: %d sys_mbox_fetch: timeoutlist not empty\n",KS_inqtask()));
  pid = KS_inqtask();
  for(i = 0; i < nextthread; i++) {
    tl = &timeoutlist[i];
    if(tl->pid == pid) {
      DEBUGF(SYS_DEBUG, ("PID: %d sys_mbox_fetch: corresponding pid found!\n",KS_inqtask()));
      return &(tl->timeouts);
    }
  }

  /* Error! */
  return NULL;
}
/*-----------------------------------------------------------------------------------*/
struct sys_thread_arg {
  void (* thread)(void *);
  void *threadarg;
  SEMA sem;
};
/*-----------------------------------------------------------------------------------*/
static void
sys_thread(void)
{
  struct sys_thread_arg *arg;
  void (* thread)(void *);
  void *threadarg;
  
  arg = KS_inqtask_arg(0);
  if(arg != NULL) {

    timeoutlist[nextthread].timeouts.next = NULL;
    timeoutlist[nextthread].pid = KS_inqtask();

    ++nextthread;
    
    thread = arg->thread;
    threadarg = arg->threadarg;
    KS_signal(arg->sem);
    thread(threadarg);
  }
  KS_terminate(0);
}
/*-----------------------------------------------------------------------------------*/
void
sys_thread_new(void (* function)(void *arg), void *arg) 
{
  TASK newtask;
  PRIORITY pri = 2;       /* This may have to be changed. */
  char *stack;
  int stacksize = 512;   /* This may have to be changed. */
  struct sys_thread_arg threadarg;
  
  
  newtask = KS_alloc_task();
  stack = KS_allocw(MAP512);
  
  KS_deftask(newtask, pri, (char ks_stk *)stack, (size_t)stacksize, (void (*)(void))sys_thread);
  
  threadarg.thread = function;
  threadarg.threadarg = arg;
  threadarg.sem = THRDSYNC;
  KS_deftask_arg(newtask, &threadarg);    
  KS_execute(newtask);
  KS_wait(THRDSYNC);
}






