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

/*
 * Wed Apr 17 16:05:29 EDT 2002 (James Roth)
 *
 *  - Fixed an unlikely sys_thread_new() race condition.
 *
 *  - Made current_thread() work with threads which where
 *    not created with sys_thread_new().  This includes
 *    the main thread and threads made with pthread_create().
 *
 *  - Catch overflows where more than SYS_MBOX_SIZE messages
 *    are waiting to be read.  The sys_mbox_post() routine
 *    will block until there is more room instead of just
 *    leaking messages.
 */
#include "lwip/debug.h"

#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "lwip/sys.h"
#include "lwip/opt.h"
#include "lwip/stats.h"

#define UMAX(a, b)      ((a) > (b) ? (a) : (b))

static struct sys_thread *threads = NULL;
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;

struct sys_mbox_msg {
  struct sys_mbox_msg *next;
  void *msg;
};

#define SYS_MBOX_SIZE 128

struct sys_mbox {
  int first, last;
  void *msgs[SYS_MBOX_SIZE];
  struct sys_sem *mail;
  struct sys_sem *mutex;
  int wait_send;
};

struct sys_sem {
  unsigned int c;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
};

struct sys_thread {
  struct sys_thread *next;
  struct sys_timeouts timeouts;
  pthread_t pthread;
};


static struct timeval starttime;

static struct sys_sem *sys_sem_new_(u8_t count);
static void sys_sem_free_(struct sys_sem *sem);

static u16_t cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex,
		       u16_t timeout);

/*-----------------------------------------------------------------------------------*/
static struct sys_thread * 
introduce_thread(pthread_t id)
{
  struct sys_thread *thread;
  
  thread = malloc(sizeof(struct sys_thread));
    
  if(thread) {
    pthread_mutex_lock(&threads_mutex);
    thread->next = threads;
    thread->timeouts.next = NULL;
    thread->pthread = id;
    threads = thread;
    pthread_mutex_unlock(&threads_mutex);
  }
    
  return thread;
}
/*-----------------------------------------------------------------------------------*/
static struct sys_thread *
current_thread(void)
{
  struct sys_thread *st;
  pthread_t pt;
  pt = pthread_self();
  pthread_mutex_lock(&threads_mutex);

  for(st = threads; st != NULL; st = st->next) {    
    if(pthread_equal(st->pthread, pt)) {
      pthread_mutex_unlock(&threads_mutex);
      
      return st;
    }
  }

  pthread_mutex_unlock(&threads_mutex);

  st = introduce_thread(pt);

  if(!st) {
    printf("current_thread???\n");
    abort();
  }

  return st;
}
/*-----------------------------------------------------------------------------------*/
void
sys_thread_new(void (*function)(void *arg), void *arg)
{
  int code;
  pthread_t tmp;
  struct sys_thread *st = NULL;
  
  code = pthread_create(&tmp,
			NULL, 
			(void *(*)(void *)) 
			function, 
			arg);
  
  if(0 == code) {
    st = introduce_thread(tmp);
  }
  
  if(NULL == st) {
    DEBUGF(SYS_DEBUG, ("sys_thread_new: pthread_create %d, st = 0x%x",
		       code, (int)st));
    abort();
  }
}
/*-----------------------------------------------------------------------------------*/
struct sys_mbox *
sys_mbox_new()
{
  struct sys_mbox *mbox;
  
  mbox = malloc(sizeof(struct sys_mbox));
  mbox->first = mbox->last = 0;
  mbox->mail = sys_sem_new_(0);
  mbox->mutex = sys_sem_new_(1);
  mbox->wait_send = 0;
  
#ifdef SYS_STATS
  lwip_stats.sys.mbox.used++;
  if(lwip_stats.sys.mbox.used > lwip_stats.sys.mbox.max) {
    lwip_stats.sys.mbox.max = lwip_stats.sys.mbox.used;
  }
#endif /* SYS_STATS */
  
  return mbox;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_free(struct sys_mbox *mbox)
{
  if(mbox != SYS_MBOX_NULL) {
#ifdef SYS_STATS
    lwip_stats.sys.mbox.used--;
#endif /* SYS_STATS */
    sys_sem_wait(mbox->mutex);
    
    sys_sem_free_(mbox->mail);
    sys_sem_free_(mbox->mutex);
    mbox->mail = mbox->mutex = NULL;
    /*  DEBUGF("sys_mbox_free: mbox 0x%lx\n", mbox); */
    free(mbox);
  }
}

/*-----------------------------------------------------------------------------------*/
void
sys_mbox_post(struct sys_mbox *mbox, void *msg)
{
  u8_t first;
  
  sys_sem_wait(mbox->mutex);
  
  DEBUGF(SYS_DEBUG, ("sys_mbox_post: mbox %p msg %p\n", mbox, msg));
  
  while((mbox->last + 1) >= (mbox->first + SYS_MBOX_SIZE)) {
    mbox->wait_send++;
    sys_sem_signal(mbox->mutex);
    sys_arch_sem_wait(mbox->mail, 0);
    sys_arch_sem_wait(mbox->mutex, 0);
    mbox->wait_send--;
  }
  
  mbox->msgs[mbox->last % SYS_MBOX_SIZE] = msg;
  
  if(mbox->last == mbox->first) {
    first = 1;
  } else {
    first = 0;
  }
  
  mbox->last++;
  
  if(first) {
    sys_sem_signal(mbox->mail);
  }

  sys_sem_signal(mbox->mutex);
}
/*-----------------------------------------------------------------------------------*/
u16_t
sys_arch_mbox_fetch(struct sys_mbox *mbox, void **msg, u16_t timeout)
{
  u16_t time = 1;
  
  /* The mutex lock is quick so we don't bother with the timeout
     stuff here. */
  sys_arch_sem_wait(mbox->mutex, 0);

  while(mbox->first == mbox->last) {
    sys_sem_signal(mbox->mutex);
    
    /* We block while waiting for a mail to arrive in the mailbox. We
       must be prepared to timeout. */
    if(timeout != 0) {
      time = sys_arch_sem_wait(mbox->mail, timeout);
      
      /* If time == 0, the sem_wait timed out, and we return 0. */
      if(time == 0) {
	return 0;
      }
    } else {
      sys_arch_sem_wait(mbox->mail, 0);
    }
    
    sys_arch_sem_wait(mbox->mutex, 0);
  }

  DEBUGF(SYS_DEBUG, ("sys_mbox_fetch: mbox %p msg %p\n", mbox, *msg));

  if(msg != NULL) {
    *msg = mbox->msgs[mbox->first % SYS_MBOX_SIZE];
  }

  mbox->first++;
  
  if(mbox->wait_send) {
    sys_sem_signal(mbox->mail);
  }

  sys_sem_signal(mbox->mutex);

  return time;
}
/*-----------------------------------------------------------------------------------*/
struct sys_sem *
sys_sem_new(u8_t count)
{
#ifdef SYS_STATS
  lwip_stats.sys.sem.used++;
  if(lwip_stats.sys.sem.used > lwip_stats.sys.sem.max) {
    lwip_stats.sys.sem.max = lwip_stats.sys.sem.used;
  }
#endif /* SYS_STATS */
  return sys_sem_new_(count);
}

/*-----------------------------------------------------------------------------------*/
static struct sys_sem *
sys_sem_new_(u8_t count)
{
  struct sys_sem *sem;
  
  sem = malloc(sizeof(struct sys_sem));
  sem->c = count;
  
  pthread_cond_init(&(sem->cond), NULL);
  pthread_mutex_init(&(sem->mutex), NULL);
  
  return sem;
}

/*-----------------------------------------------------------------------------------*/
static u16_t
cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex, u16_t timeout)
{
  int tdiff;
  unsigned long sec, usec;
  struct timeval rtime1, rtime2;
  struct timespec ts;
  struct timezone tz;
  int retval;
  
  if(timeout > 0) {
    /* Get a timestamp and add the timeout value. */
    gettimeofday(&rtime1, &tz);
    sec = rtime1.tv_sec;
    usec = rtime1.tv_usec;
    usec += timeout % 1000 * 1000;
    sec += (int)(timeout / 1000) + (int)(usec / 1000000);
    usec = usec % 1000000;
    ts.tv_nsec = usec * 1000;
    ts.tv_sec = sec;
    
    retval = pthread_cond_timedwait(cond, mutex, &ts);
    
    if(retval == ETIMEDOUT) {
      return 0;
    } else {
      /* Calculate for how long we waited for the cond. */
      gettimeofday(&rtime2, &tz);
      tdiff = (rtime2.tv_sec - rtime1.tv_sec) * 1000 +
	(rtime2.tv_usec - rtime1.tv_usec) / 1000;
      
      if(tdiff <= 0) {
	return 1;
      }
      
      return tdiff;
    }
  } else {
    pthread_cond_wait(cond, mutex);
    return 0;
  }
}
/*-----------------------------------------------------------------------------------*/
u16_t
sys_arch_sem_wait(struct sys_sem *sem, u16_t timeout)
{
  u16_t time = 1;
  
  pthread_mutex_lock(&(sem->mutex));
  while(sem->c <= 0) {
    if(timeout > 0) {
      time = cond_wait(&(sem->cond), &(sem->mutex), timeout);
      
      if(time == 0) {
	pthread_mutex_unlock(&(sem->mutex));
	return 0;
      }
      /*      pthread_mutex_unlock(&(sem->mutex));
	      return time; */
    } else {
      cond_wait(&(sem->cond), &(sem->mutex), 0);
    }
  }
  sem->c--;
  pthread_mutex_unlock(&(sem->mutex));
  return time;
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_signal(struct sys_sem *sem)
{
  pthread_mutex_lock(&(sem->mutex));
  sem->c++;

  if(sem->c > 1) {
    sem->c = 1;
  }

  pthread_cond_broadcast(&(sem->cond));
  pthread_mutex_unlock(&(sem->mutex));
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_free(struct sys_sem *sem)
{
  if(sem != SYS_SEM_NULL) {
#ifdef SYS_STATS
    lwip_stats.sys.sem.used--;
#endif /* SYS_STATS */
    sys_sem_free_(sem);
  }
}

/*-----------------------------------------------------------------------------------*/
static void
sys_sem_free_(struct sys_sem *sem)
{
  pthread_cond_destroy(&(sem->cond));
  pthread_mutex_destroy(&(sem->mutex));
  free(sem);
}
/*-----------------------------------------------------------------------------------*/
unsigned long
sys_unix_now()
{
  struct timeval tv;
  struct timezone tz;
  long sec, usec;
  unsigned long msec;
  gettimeofday(&tv, &tz);
  
  sec = tv.tv_sec - starttime.tv_sec;
  usec = tv.tv_usec - starttime.tv_usec;
  msec = sec * 1000 + usec / 1000;
    
  return msec;
}
/*-----------------------------------------------------------------------------------*/
void
sys_init()
{
  struct timezone tz;
  gettimeofday(&starttime, &tz);
}
/*-----------------------------------------------------------------------------------*/
struct sys_timeouts *
sys_arch_timeouts(void)
{
  struct sys_thread *thread;

  thread = current_thread();
  return &thread->timeouts;
}
/*-----------------------------------------------------------------------------------*/
