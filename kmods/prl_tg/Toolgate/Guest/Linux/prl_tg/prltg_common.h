/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#ifndef __PRL_TG_COMMON_H__
#define __PRL_TG_COMNON_H__
#include <linux/version.h>
#include <linux/pm.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <linux/libata-compat.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define PRLVTG_MMAP
#include <linux/mm.h>
#include <video/vga.h>
#endif

#include "../Interfaces/prltg.h"
#include "../../Interfaces/tgreq.h"
#include "../../../Interfaces/Tg.h"

/* define to 1 to enable copious debugging info */
#undef DRV_DEBUG

/* define to 1 to disable lightweight runtime debugging checks */
#undef DRV_NDEBUG

#ifdef DRV_DEBUG
/* note: prints function name for you */
#  define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#else
#  define DPRINTK(fmt, args...)
#endif

#ifdef DRV_NDEBUG
#  define assert(expr) do {} while (0)
#else
#  define assert(expr) \
        if(!(expr)) {					\
        printk( "Assertion failed! %s,%s,%s,line=%d\n",	\
        #expr,__FILE__,__FUNCTION__,__LINE__);		\
        }
#endif

#define DRV_LOAD_MSG	DRV_LONG_NAME " driver " DRV_VERSION " loaded"
#define PFX				DRV_SHORT_NAME ": "

#define INLINE_SIZE(a)	(((a)->InlineByteCount + sizeof(u64) - 1) & ~(sizeof(u64) - 1))

#define VTG_HASH_BITS	4
#define VTG_HASH_SIZE	(1UL << VTG_HASH_BITS)
#define VTG_HASH_MASK	(VTG_HASH_SIZE-1)

typedef enum {
	TOOLGATE = 0,
	VIDEO_TOOLGATE = 1,
	VIDEO_DRM_TOOLGATE = 2
} board_t;

#define TG_DEV_FLAG_MSI (1<<0)

struct tg_dev {
	board_t board;
	int drv_flags;
	unsigned int irq;
	unsigned long base_addr;
	spinlock_t queue_lock; /* protects queue of submitted requests */
	struct list_head pr_list; /* pending requests list */
	struct work_struct work;
	struct pci_dev *pci_dev;
	spinlock_t lock;	/* protects device's port IO operations */
	unsigned int flags;
#ifdef PRLVTG_MMAP
	resource_size_t mem_phys, mem_size;
#endif
};

struct TG_PENDING_REQUEST
{
	struct tg_dev *dev;
	TG_REQ_DESC *sdesc;
	TG_PAGED_REQUEST *dst;

	struct list_head pr_list;
	struct list_head up_list;

	struct completion waiting;
	int processed;				/* Protected by queue_lock */
	dma_addr_t phys;			/* Physical address of first page of request */
	struct page *pg;			/* First page of request descriptor */
};

/*
 * Build request pin vmalloced pages in memory to prevent swapping.
 * Also, pages got from userspace pinned too. Those pages must be
 * released at completion. As all request structures are shared between
 * lot of places - the list to store pages is good enough.
 */
struct up_list_entry {
	struct list_head up_list;
	int count;
	/* user pages must be marked dirty if device touched them */
	unsigned writable;
	struct page *p[0];
};

struct vtg_filp_private {
	struct list_head	filp_list;
	spinlock_t			filp_lock;
	struct file			*filp;
};

/* The rest of these values should never change. */

/* Symbolic offsets to registers. */
enum TgRegisters {
	TG_PORT_STATUS = 0,
	TG_PORT_MASK = 0,
	TG_PORT_SUBMIT = 0x8,
	TG_PORT_CANCEL = 0x10,
	TG_MAX_PORT = 0x18
};

/* Port IO primitives */
static __inline u32
tg_in32(struct tg_dev *dev, unsigned long port)
{
	u32 x;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	x = inl(dev->base_addr + port);
	spin_unlock_irqrestore(&dev->lock, flags);
	return (x);
}

static __inline unsigned long
tg_in(struct tg_dev *dev, unsigned long port)
{
	unsigned long val, flags;
	unsigned long len = (sizeof(unsigned long) >> 2);
	void *ptr = &val;
	port += dev->base_addr;

	spin_lock_irqsave(&dev->lock, flags);
#ifdef CONFIG_AMD_MEM_ENCRYPT
	asm volatile("rep; insl" : "+D"(ptr), "+c"(len) : "d"(port) : "memory");
#else
	insl(port, ptr, len);
#endif
	spin_unlock_irqrestore(&dev->lock, flags);
	return (val);
}

static __inline void
tg_out32(struct tg_dev *dev, unsigned long port, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	outl(val, dev->base_addr + port);
	spin_unlock_irqrestore(&dev->lock, flags);
}

static __inline void
tg_out(struct tg_dev *dev, unsigned long port, unsigned long long val)
{
	unsigned long flags;
	unsigned long len = (sizeof(unsigned long long) >> 2);
	void *ptr = &val;
	port += dev->base_addr;

	DPRINTK("send %llx\n", val);
	spin_lock_irqsave(&dev->lock, flags);
#ifdef CONFIG_AMD_MEM_ENCRYPT
	asm volatile("rep; outsl" : "+S"(ptr), "+c"(len) : "d"(port) : "memory");
#else
	outsl(port, ptr, len);
#endif
	spin_unlock_irqrestore(&dev->lock, flags);
}

// Exported functions
int prl_tg_probe_common(struct pci_dev *pdev, board_t board, struct file_operations *fops);
void prl_tg_remove_common(struct pci_dev *pdev);
#ifdef CONFIG_PM
int prl_tg_suspend_common(struct pci_dev *pdev, pm_message_t state);
int prl_tg_resume_common(struct pci_dev *pdev);
#endif

struct vtg_filp_private *prl_vtg_open_common(struct file *filp);
void prl_vtg_release_common(struct vtg_filp_private *fp);

int prl_vtg_create_drawable(struct vtg_filp_private *fp, unsigned int id);
int prl_vtg_destroy_drawable(struct vtg_filp_private *fp, unsigned int id);
int prl_vtg_clip_drawable(struct vtg_filp_private *fp, struct draw_bdesc *hdr);
int prl_tg_user_to_host_request(struct tg_dev *dev, void *ureq);
#endif

