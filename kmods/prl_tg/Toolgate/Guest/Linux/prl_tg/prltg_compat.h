/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#ifndef __PRL_TG_COMPAT_H__
#define __PRL_TG_COMPAT_H__

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#ifndef __user
#define __user
#endif

#ifndef IRQ_RETVAL
#define IRQ_RETVAL(x)
#define irqreturn_t void
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(x)
#endif

#undef dev_put
#define dev_put(x) __dev_put(x)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static inline struct proc_dir_entry *prl_PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *)inode->u.generic_ip;
}
#define PDE(x) prl_PDE(x)

#undef pci_register_driver
#define pci_register_driver pci_module_init

#undef container_of
#define container_of list_entry

static void prl_synchronize_irq(void)
{
	synchronize_irq();
}
#undef synchronize_irq
#define synchronize_irq(x) prl_synchronize_irq()

#endif /* old 2.4 kernels */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#define msleep(x) do {					\
	set_current_state(TASK_UNINTERRUPTIBLE);	\
	schedule_timeout((x * HZ)/1000 + 1);		\
} while (0)
#endif /* < 2.6.8 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define PDE_DATA(x) (PDE(x)->data)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#define pm_message_t u32
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#ifndef RHEL_RELEASE_CODE
#define IRQ_HANDLER_T 1
#elif (RHEL_RELEASE_CODE < 1024)
#define IRQ_HANDLER_T 1
#else
#define IRQ_HANDLER_T 0
#endif
#if IRQ_HANDLER_T
typedef irqreturn_t (*irq_handler_t)(int, void*, struct pt_regs *);
#endif
typedef irqreturn_t (*prl_irq_handler_t)(int, void*);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#define prl_irqreturn_t irqreturn_t
#else
#define prl_irqreturn_t int
#endif
static inline prl_irqreturn_t prl_request_irq(unsigned int irq,
						prl_irq_handler_t handler,
						unsigned long flags,
						const char *name, void *id)
{
	return request_irq(irq, (irq_handler_t)handler, flags, name, id);
}
#undef request_irq
#define request_irq(a, b, c, d, e) prl_request_irq((a),(b),(c),(d),(e))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#undef INIT_WORK
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#define INIT_WORK(a,b)				\
do {						\
	(a)->pending = 0;			\
	(a)->data = (a);			\
	(a)->func = (void (*)(void *))(b);	\
	INIT_LIST_HEAD(&(a)->entry);		\
	init_timer(&(a)->timer);		\
} while (0)
#else /* for 2.4 kernels */
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK(a,b) INIT_TQUEUE(a,(void (*)(void *))b,a)
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks
#endif /* for 2.4 kernels */
#endif /* for kernels before 2.6.20 */

#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) && \
	defined(CONFIG_X86_64) && defined(CONFIG_COMPAT)
#include <linux/compat.h>
#define	PRL_32BIT_COMPAT_TEST \
	((test_thread_flag(TIF_IA32)) && (nbytes == sizeof(compat_uptr_t)))
#else
#define PRL_32BIT_COMPAT_TEST	0
#endif

#if defined PRL_INTERRUPTIBLE_COMPLETION
int wait_for_completion_interruptible(struct completion *c)
{
	spin_lock_irq(&c->wait.lock);
	if (!c->done) {
		DECLARE_WAITQUEUE(w, current);
		w.flags |= WQ_FLAG_EXCLUSIVE;
		__add_wait_queue_tail(&c->wait, &w);
		while (!c->done) {
			if (signal_pending(current)) {
				__remove_wait_queue(&c->wait, &w);
				spin_unlock_irq(&c->wait.lock);
				return -ERESTARTSYS;
			}
			__set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(&c->wait.lock);
			schedule();
			spin_lock_irq(&c->wait.lock);
		}
		__remove_wait_queue(&c->wait, &w);
	}
	c->done--;
	spin_unlock_irq(&c->wait.lock);
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define PROC_OWNER(p, own)	p->owner = own
#else
#define PROC_OWNER(p, own)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define HAVE_OLD_IOCTL	1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include "prl_tg.ver"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define FILE_DENTRY(f) ((f)->f_path.dentry)
#else
#define FILE_DENTRY(f) ((f)->f_dentry)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define page_cache_get(x) get_page(x)
#define page_cache_release(x) put_page(x)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
		LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0) && \
		defined(FAULT_FLAG_REMOTE)
#define OPENSUSE_4_4_76
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0) || defined(OPENSUSE_4_4_76)
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(_1, _2, (_3) ? FOLL_WRITE : 0, _4, _5)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(_1, _2, _3, 0, _4, _5)
#else
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(current, current->mm, _1, _2, _3, 0, _4, _5)
#endif
