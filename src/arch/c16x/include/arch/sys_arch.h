#ifndef __SYS_ARCH_H__
#define __SYS_ARCH_H__

#define SEMA int
#define QUEUE int
#define TASK int

#define SYS_MBOX_NULL (QUEUE)0
#define SYS_SEM_NULL  (SEMA)0

typedef SEMA sys_sem_t;
typedef QUEUE sys_mbox_t;
typedef TASK sys_thread_t;

#endif /* __SYS_ARCH_H__ */
