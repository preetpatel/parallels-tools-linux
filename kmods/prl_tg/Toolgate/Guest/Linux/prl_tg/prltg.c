/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/hash.h>
#include <linux/delay.h>
#include "prltg_common.h"
#include "prltg_compat.h"
#include "../Interfaces/prltg_call.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	#include <linux/uaccess.h>
#else
	#include <asm/uaccess.h>
#endif

static char version[] = KERN_INFO DRV_LOAD_MSG "\n";
static int novtg = 0;

/* indexed by board_t, above */
static struct {
	const char *name;
	char *nick;
} board_info[] = {
	{ "Parallels ToolGate", TOOLGATE_NICK_NAME },
	{ "Parallels Video ToolGate", VIDEO_TOOLGATE_NICK_NAME },
	{ "Parallels Video DRM ToolGate", VIDEO_DRM_TOOLGATE_NICK_NAME }
};

static struct pci_device_id prl_tg_pci_tbl[] = {
	{0x1ab8, 0x4000, PCI_ANY_ID, PCI_ANY_ID, 0, 0, TOOLGATE },
	{0x1ab8, 0x4005, PCI_ANY_ID, PCI_ANY_ID, 0, 0, VIDEO_TOOLGATE },
	{0,}
};
MODULE_DEVICE_TABLE (pci, prl_tg_pci_tbl);

DEFINE_SPINLOCK(vtg_hash_lock);
static struct list_head vtg_hashtable[VTG_HASH_SIZE];

struct vtg_buffer {
	atomic_t		refcnt;
	struct draw_bdesc	bdesc;
};

struct vtg_hash_entry {
	unsigned int		id;
	unsigned int		used;
	struct list_head	filp_list;
	struct list_head	hash_list;
	struct file		*filp;
	struct vtg_buffer	*vtg_buffer;
};

/* Interrupt's bottom half */
static void tg_do_work(struct work_struct *work)
{
	struct list_head completed;
	struct list_head *tmp, *n;
	struct TG_PENDING_REQUEST *req;
	struct tg_dev *dev = container_of(work, struct tg_dev, work);
	unsigned long flags;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&completed);
	spin_lock_irqsave(&dev->queue_lock, flags);
	list_for_each_safe(tmp, n, &dev->pr_list) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		if (req->dst->Status == TG_STATUS_PENDING)
			continue;
		list_move(&req->pr_list, &completed);
		req->processed = 1;
	}
	spin_unlock_irqrestore(&dev->queue_lock, flags);

	/* enable Toolgate's interrupt */
	if (!(dev->flags & TG_DEV_FLAG_MSI))
		tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	list_for_each_safe(tmp, n, &completed) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		complete(&req->waiting);
	}

	DPRINTK("EXIT\n");
}

static void tg_req_cancel_all(struct tg_dev *dev)
{
	struct list_head cancelled;
	struct list_head *tmp, *n;
	struct TG_PENDING_REQUEST *req;
	unsigned long flags;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&cancelled);
	spin_lock_irqsave(&dev->queue_lock, flags);
	list_for_each_safe(tmp, n, &dev->pr_list) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		if (req->dst->Status == TG_STATUS_PENDING) {
			list_move(&req->pr_list, &cancelled);
			req->processed = 1;
		}
	}
	spin_unlock_irqrestore(&dev->queue_lock, flags);

	list_for_each(tmp, &cancelled) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		tg_out(dev, TG_PORT_CANCEL, req->phys);
	}
	/* waiting host's confirmation up to several seconds */
	list_for_each_safe(tmp, n, &cancelled) {
		int timeout = 1;

		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		while ((req->dst->Status == TG_STATUS_PENDING) &&
							(timeout < 4*HZ)) {
			msleep(timeout);
			timeout *= 2;
		}
		if (req->dst->Status == TG_STATUS_PENDING)
			/* Host don't cancel request. If we free it we can get
			 * the memory corruption if host will handle it later.
			 * If we don't free it, we'll leak the memory if host
			 * forget about this request. I think memory leak is
			 * better than memory corruption */
			 printk(KERN_ERR PFX "Host don't handle "
					"request's cancel %p\n", req);
		else
		complete(&req->waiting);
	}
	DPRINTK("EXIT\n");
}

static struct vtg_buffer * replace_buffer(TG_REQ_DESC *);

static inline void put_vtg_buffer(struct vtg_buffer *vb)
{
	if (vb && atomic_dec_and_test(&vb->refcnt)) {
		kfree(vb->bdesc.u.pbuf);
		kfree(vb);
	}
}

static int complete_userspace_request(char *u, TG_REQ_DESC *sdesc)
{
	int i, ret;
	TG_REQUEST *src;
	TG_BUFFER *sbuf;

	DPRINTK("ENTER\n");
	ret = 0;

	src = sdesc->src;
	/* copy request status back to userspace */
	if (copy_to_user(u, src, sizeof(TG_REQUEST)))
		ret = -EFAULT;

	u += sizeof(TG_REQUEST);
	/* copy inline data back to userspace */
	if ((src->InlineByteCount != 0) && (src->Status == TG_STATUS_SUCCESS) &&
	    (copy_to_user(u, sdesc->idata, src->InlineByteCount)))
		ret = -EFAULT;

	sbuf = sdesc->sbuf;
	u += INLINE_SIZE(src) + offsetof(TG_BUFFER, ByteCount);
	for (i = 0; i < src->BufferCount; i++) {
		/* copy buffer's ButeCounts back to userspace */
		if ((src->Status != TG_STATUS_CANCELLED) &&
		    copy_to_user(u, &sbuf->ByteCount, sizeof(sbuf->ByteCount)))
			ret = -EFAULT;
		sbuf++;
		u += sizeof(TG_BUFFER);
	}
	DPRINTK("EXIT, returning %d\n", ret);
	return ret;
}

static inline void get_vtg_buffer(struct vtg_buffer *vb)
{
	if (vb)
		atomic_inc(&vb->refcnt);
}

static struct vtg_buffer * replace_buffer(TG_REQ_DESC *sdesc)
{
	TG_REQUEST *src;
	TG_BUFFER *sbuf;
	struct vtg_buffer *vb = NULL;
	unsigned id;
	struct list_head *head, *tmp;
	struct vtg_hash_entry *p;

	src = sdesc->src;
	if (src->BufferCount != 4)
		goto out;

	if (src->InlineByteCount < sizeof(unsigned)*3)
		goto out;

	id = *((unsigned *)sdesc->idata + 2);

	head = &vtg_hashtable[hash_ptr((void *)(unsigned long)id, VTG_HASH_BITS)];
	spin_lock(&vtg_hash_lock);
	list_for_each(tmp, head) {
		p = list_entry(tmp, struct vtg_hash_entry, hash_list);
		if (p->id == id) {
			vb = p->vtg_buffer;
			get_vtg_buffer(vb);
			p->used++;
			break;
		}
	}
	spin_unlock(&vtg_hash_lock);

	if (!vb)
		goto out;

	sbuf = sdesc->sbuf;
	sbuf += 3;
	sbuf->u.Va = vb->bdesc.u.va;
	sbuf->ByteCount = vb->bdesc.bsize;
	sbuf->Writable = 0;
	prltg_buf_set_kernelspace(sdesc, 3);

out:
	return vb;
}

int prl_tg_user_to_host_request(struct tg_dev *dev, void *ureq)
{
	TG_REQ_DESC sdesc;
	TG_REQUEST hdr, *src;
	TG_BUFFER *sbuf = NULL;
	struct vtg_buffer *vb = NULL;
	void *u;
	int ret = -EFAULT;

	src = &hdr;
	/* read request header from userspace */
	if (copy_from_user(src, ureq, sizeof(TG_REQUEST)))
		goto err;

	/*
	 * requests up to TG_REQUEST_SECURED_MAX are for drivers only and are
	 * denied by guest driver if come from user space to maintain guest
	 * kernel integrity (prevent malicious code from sending FS requests)
	 * dynamically assigned requests start from TG_REQUEST_MIN_DYNAMIC
	 */
	if (src->Request <= TG_REQUEST_SECURED_MAX) {
		ret = -EINVAL;
		goto err;
	}

	memset(&sdesc, 0, sizeof(TG_REQ_DESC));
	sdesc.src = src;
	u = ureq + sizeof(TG_REQUEST);
	if (src->InlineByteCount) {
		sdesc.idata = vmalloc(src->InlineByteCount);
		if (sdesc.idata == NULL) {
			ret = -ENOMEM;
			goto err;
		}

		if (copy_from_user(sdesc.idata, u, src->InlineByteCount)) {
			ret = -EFAULT;
			goto err_vm;
		}
	}
	u += INLINE_SIZE(src);
	if (src->BufferCount) {
		/* allocate memory for request's buffers */
		int ssize = src->BufferCount * sizeof(TG_BUFFER);
		sbuf = vmalloc(ssize);
		if (!sbuf) {
			ret = -ENOMEM;
			goto err_vm;
		}
		/* copy buffer descriptors from userspace */
		if (copy_from_user(sbuf, u, ssize)) {
			ret = -EFAULT;
			goto err_vm;
		}
		sdesc.sbuf = sbuf;
		/* leaving sdesc.kernel_bufs set to 0 to indicate that all the buffers
		   are Userspace */

		if (src->Request == TG_REQUEST_GL_COMMAND)
			vb = replace_buffer(&sdesc);
	}

    ret = call_tg_sync(dev->pci_dev, &sdesc);
    if (ret)
        goto err_vtg;

    /* copy requiered data back to userspace */
    ret = complete_userspace_request(ureq, &sdesc);

err_vtg:
	put_vtg_buffer(vb);

err_vm:
	if (sdesc.sbuf)
		vfree(sdesc.sbuf);
	if (sdesc.idata)
		vfree(sdesc.idata);
err:
	return ret;
}
EXPORT_SYMBOL(prl_tg_user_to_host_request);

static ssize_t prl_tg_write(struct file *file, const char __user *buf,
	size_t nbytes, loff_t *ppos)
{
	const struct inode *ino = FILE_DENTRY(file)->d_inode;
	struct tg_dev *dev = PDE_DATA(ino);
	void *ureq = NULL;
	int ret = -EINVAL;

	DPRINTK("ENTER\n");
	if ((nbytes != sizeof(TG_REQUEST *)) && !PRL_32BIT_COMPAT_TEST)
		goto err;

	/* read userspace pointer */
	if (copy_from_user(&ureq, buf, nbytes)) {
		ret = -EFAULT;
		goto err;
	}

	ret = prl_tg_user_to_host_request(dev, ureq);

err:
	DPRINTK("EXIT, returning %d\n", ret);
	return ret;
}

struct vtg_filp_private *prl_vtg_open_common(struct file *filp)
{
	struct vtg_filp_private *fp;

	fp = kmalloc(sizeof(*fp), GFP_KERNEL);
	if (fp == NULL)
		return NULL;

	memset (fp, 0, sizeof(*fp));
	spin_lock_init(&fp->filp_lock);
	INIT_LIST_HEAD(&fp->filp_list);
	fp->filp = filp;
	return fp;
}
EXPORT_SYMBOL(prl_vtg_open_common);

static int prl_vtg_open(struct inode *inode, struct file *filp)
{
	struct vtg_filp_private *fp;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	fp = prl_vtg_open_common(filp);
	if (fp == NULL)
		return -ENOMEM;

	filp->private_data = fp;
#ifdef FMODE_ATOMIC_POS
	filp->f_mode &= ~FMODE_ATOMIC_POS;
#endif

	return 0;
}

static int prl_tg_open(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

#ifdef FMODE_ATOMIC_POS
	filp->f_mode &= ~FMODE_ATOMIC_POS;
#endif
	return 0;
}

void prl_vtg_release_common(struct vtg_filp_private *fp)
{
	while (!list_empty(&fp->filp_list)) {
		struct list_head *tmp;
		struct vtg_hash_entry *p;

		spin_lock(&fp->filp_lock);
		if (unlikely(list_empty(&fp->filp_list))) {
			spin_unlock(&fp->filp_lock);
			break;
		}
		tmp = fp->filp_list.next;
		list_del(tmp);
		p = list_entry(tmp, struct vtg_hash_entry, filp_list);
		spin_unlock(&fp->filp_lock);
		spin_lock(&vtg_hash_lock);
		list_del(&p->hash_list);
		spin_unlock(&vtg_hash_lock);
		put_vtg_buffer(p->vtg_buffer);
		kfree(p);
	}

	kfree(fp);
}
EXPORT_SYMBOL(prl_vtg_release_common);

static int prl_vtg_release(struct inode *inode, struct file *filp)
{
	prl_vtg_release_common(filp->private_data);
	module_put(THIS_MODULE);
	return 0;
}

static int prl_tg_release(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;
	module_put(THIS_MODULE);
	return 0;
}

int prl_vtg_create_drawable(struct vtg_filp_private *fp, unsigned int id)
{
	struct vtg_hash_entry *vhe, *p;
	struct list_head *head, *tmp;

	vhe = kmalloc(sizeof(*vhe), GFP_KERNEL);
	if (vhe == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&vhe->filp_list);
	INIT_LIST_HEAD(&vhe->hash_list);
	vhe->id = id;
	vhe->filp = fp->filp;
	vhe->vtg_buffer = NULL;
	vhe->used = 0;

	head = &vtg_hashtable[hash_ptr((void *)(unsigned long)vhe->id, VTG_HASH_BITS)];
	spin_lock(&vtg_hash_lock);
	list_for_each(tmp, head) {
		p = list_entry(tmp, struct vtg_hash_entry, hash_list);
		if (p->id == id) {
			spin_unlock(&vtg_hash_lock);
			kfree(vhe);
			return -EINVAL;
		}
	}
	list_add(&vhe->hash_list, head);
	spin_unlock(&vtg_hash_lock);
	spin_lock(&fp->filp_lock);
	list_add(&vhe->filp_list, &fp->filp_list);
	spin_unlock(&fp->filp_lock);
	return 0;
}
EXPORT_SYMBOL(prl_vtg_create_drawable);

int prl_vtg_destroy_drawable(struct vtg_filp_private *fp, unsigned int id)
{
	struct vtg_hash_entry *p = NULL;
	struct list_head *head, *tmp, *n;
	struct vtg_buffer *old_vb = NULL;
	int ret = -EINVAL;

	head = &vtg_hashtable[hash_ptr((void *)(unsigned long)id, VTG_HASH_BITS)];
	spin_lock(&vtg_hash_lock);
	list_for_each_safe(tmp, n, head) {
		p = list_entry(tmp, struct vtg_hash_entry, hash_list);
		if (p->id == id) {
			if (p->filp == fp->filp) {
				old_vb = p->vtg_buffer;
				p->vtg_buffer = NULL;
				list_del(&p->hash_list);
				ret = 0;
			}
			break;
		}
	}
	spin_unlock(&vtg_hash_lock);
	if (!ret) {
		spin_lock(&fp->filp_lock);
		list_del(&p->filp_list);
		spin_unlock(&fp->filp_lock);
		put_vtg_buffer(old_vb);
		kfree(p);
	}
	return ret;
}
EXPORT_SYMBOL(prl_vtg_destroy_drawable);

int prl_vtg_clip_drawable(struct vtg_filp_private *fp, struct draw_bdesc *hdr)
{
	struct vtg_hash_entry *p = NULL;
	struct list_head *head, *tmp;
	struct vtg_buffer *vb, *old_vb = NULL;
	int size = hdr->bsize;
	int ret = -ENOMEM;

	hdr->used = 0;
	vb = (struct vtg_buffer *)kmalloc(sizeof(*vb), GFP_KERNEL);
	if (!vb)
		return ret;
	memset(vb, 0, sizeof(*vb));

	vb->bdesc.u.pbuf = kmalloc(size, GFP_KERNEL);
	if (!vb->bdesc.u.pbuf)
		goto out_free;

	vb->bdesc.bsize = size;
	vb->bdesc.id = hdr->id;
	atomic_set(&vb->refcnt, 1);

	ret = -EFAULT;
	if (copy_from_user(vb->bdesc.u.pbuf,  (void __user *)hdr->u.pbuf, size))
		goto out_vfree;

	head = &vtg_hashtable[hash_ptr((void *)(unsigned long)hdr->id, VTG_HASH_BITS)];
	ret = -EINVAL;
	spin_lock(&vtg_hash_lock);
	list_for_each(tmp, head) {
		p = list_entry(tmp, struct vtg_hash_entry, hash_list);
		if (p->id == hdr->id) {
			if (p->filp == fp->filp) {
				old_vb = p->vtg_buffer;
				p->vtg_buffer = vb;
				hdr->used = p->used;
				p->used = 0;
				ret = 0;
			}
			break;
		}
	}
	spin_unlock(&vtg_hash_lock);
	if (!ret) {
		put_vtg_buffer(old_vb);
		return 0;
	}

out_vfree:
	kfree(vb->bdesc.u.pbuf);
out_free:
	kfree(vb);
	return ret;
}
EXPORT_SYMBOL(prl_vtg_clip_drawable);

static int prl_vtg_ioctl(struct inode *inode, struct file *filp,
	unsigned int cmd, unsigned long arg)
{
	struct vtg_filp_private *fp  = filp->private_data;
	struct draw_bdesc hdr;
	int ret = -ENOTTY;

	switch (cmd) {
	case VIDTG_CREATE_DRAWABLE:
		ret = prl_vtg_create_drawable(fp, (unsigned int)arg);
		break;

	case VIDTG_CLIP_DRAWABLE:
		if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr))) {
			ret = -EFAULT;
			break;
		}

		ret = prl_vtg_clip_drawable(fp, &hdr);
		if (ret)
			break;

		if (copy_to_user((void __user *)arg, &hdr, sizeof(hdr)))
			ret = -EFAULT;
		break;

	case VIDTG_DESTROY_DRAWABLE:
		ret = prl_vtg_destroy_drawable(fp, (unsigned int)arg);
		break;

#ifdef PRLVTG_MMAP
	case VIDTG_GET_MEMSIZE: {
		const struct inode *ino = FILE_DENTRY(filp)->d_inode;
		struct tg_dev *dev = PDE_DATA(ino);
		unsigned int memsize = dev->mem_size;
		ret = copy_to_user((void __user *)arg, &memsize, sizeof(memsize));
		break;
	}

	case VIDTG_ACTIVATE_SVGA:
		outb(0xae, VGA_SEQ_I);
		outb((arg == 0) ? 0 : 1, VGA_SEQ_D);
		ret = 0;
		break;
#endif
	}

	return ret;
}

#ifdef HAVE_UNLOCKED_IOCTL
static long prl_vtg_unlocked_ioctl(struct file *filp,
			unsigned int cmd, unsigned long arg)
{
	return prl_vtg_ioctl(NULL, filp, cmd, arg);
}
#endif

#ifdef PRLVTG_MMAP
static int prl_vtg_mmap(struct file *filp, struct vm_area_struct *vma)
{
	const struct inode *ino = FILE_DENTRY(filp)->d_inode;
	struct tg_dev *dev = PDE_DATA(ino);
	unsigned long len = vma->vm_end - vma->vm_start;

	if (len > dev->mem_size)
		return -EINVAL;
	return vm_iomap_memory(vma, (phys_addr_t)dev->mem_phys, len);
}
#endif

/* The interrupt handler */
static irqreturn_t prl_tg_interrupt(int irq, void *dev_instance)
{
	struct tg_dev *dev = (struct tg_dev *) dev_instance;
	int status = TG_MASK_COMPLETE;
	int ret = 0;

	if (!(dev->flags & TG_DEV_FLAG_MSI))
		status = tg_in32(dev, TG_PORT_STATUS);
	if (status) {
		/* if it is toolgate's interrupt schedule bottom half */
		ret = 1;
		schedule_work(&dev->work);
	}
	DPRINTK("prl_tg exiting interrupt, ret %d\n", ret);
	return IRQ_RETVAL(ret);
}

/* Initialize PCI device */
static int prl_tg_initialize(struct pci_dev *pdev, struct tg_dev *dev)
{
	int rc;

	DPRINTK ("ENTER\n");

	/* enable device (incl. PCI PM wakeup), and bus-mastering */
	rc = pci_enable_device(pdev);
	if (rc) {
		printk(KERN_ERR PFX "could not enable device\n");
		goto out;
	}

	rc = -ENODEV;

	/* make sure PCI base addr 0 is PIO */
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_IO)) {
		printk(KERN_ERR PFX "region #0 not a PIO resource\n");
		goto err_out;
	}

	/* check for weird/broken PCI region reporting */
	if (pci_resource_len(pdev, 0) < TG_MAX_PORT) {
		printk(KERN_ERR PFX "Invalid PCI region size(s)\n");
		goto err_out;
	}

#ifdef PRLVTG_MMAP
	if (dev->board != TOOLGATE) {
		const int memres = 1;
		if (!(pci_resource_flags(pdev, memres) & IORESOURCE_MEM)) {
			printk(KERN_ERR PFX "region #%d not a MEM resource\n", memres);
			goto err_out;
		}
		dev->mem_phys = pci_resource_start(pdev, memres);

		// read VESA regs for MEMSIZE
		outb(0xa0, VGA_SEQ_I);
		dev->mem_size = inl(VGA_SEQ_D);
		printk(KERN_INFO
			"%s: memory physaddr %llx, size %lldMb\n",
			board_info[dev->board].name,
			dev->mem_phys, dev->mem_size);
		dev->mem_size *= 1024 * 1024;
	}
#endif
	/* Set DMA ability. Only lower 4G is possible to address */
	rc = pci_set_dma_mask(pdev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		DMA_64BIT_MASK
#else
		DMA_BIT_MASK(64)
#endif
		);
	if (rc) {
		printk(KERN_ERR "no usable DMA configuration\n");
		goto err_out;
	}

	rc = pci_request_region(pdev, 0, board_info[dev->board].nick);
	if (rc) {
		printk(KERN_ERR PFX "could not reserve PCI I/O and memory resources\n");
		goto err_out;
	}

	dev->base_addr = pci_resource_start(pdev, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
	rc = pci_enable_msi(pdev);
	if (rc == 0)
		dev->flags |= TG_DEV_FLAG_MSI;
#endif
	dev->irq = pdev->irq;

	rc = request_irq(dev->irq, prl_tg_interrupt,
		(dev->flags & TG_DEV_FLAG_MSI) ? 0 : IRQF_SHARED, board_info[dev->board].nick, dev);
	if (rc) {
		pci_release_region(pdev, 0);
err_out:
		if (dev->board == TOOLGATE)
			pci_disable_device(pdev);
	}

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}

static struct proc_dir_entry *
prltg_proc_create_data(char *name, umode_t mode, struct proc_dir_entry *parent,
                       struct file_operations *fops, void *data)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct proc_dir_entry *p = create_proc_entry(name, mode, parent);
	if (p)
	{
		p->proc_fops = fops;
		p->data = data;
	}
	return p;
#else
	return proc_create_data(name, mode, parent, fops, data);
#endif
}

int prl_tg_probe_common(struct pci_dev *pdev, board_t board, struct file_operations *fops)
{
	struct tg_dev *dev;
	int rc = -ENOMEM;
	dev = kmalloc(sizeof(struct tg_dev), GFP_KERNEL);
	if (!dev)
		goto out;
	dev->flags = 0;
#ifdef PRLVTG_MMAP
	dev->mem_phys = 0, dev->mem_size = 0;
#endif
	spin_lock_init(&dev->lock);
	spin_lock_init(&dev->queue_lock);
	INIT_LIST_HEAD(&dev->pr_list);
	dev->pci_dev = pdev;
	dev->board = board;

	/* masks interrupts on the device probing */
	/* ayegorov@:
	 * Masking of interrupt at this step is illegal, i.e. first we have to
	 * initialize 'base_addr' variable in 'dev' data structure. Also I have
	 * commented this line, because we should know exactly should this function
	 * call be here or not!
	tg_out32(dev, TG_PORT_MASK, 0); */

	rc = prl_tg_initialize(pdev, dev);
	if (rc) {
		kfree(dev);
		goto out;
	}

	pci_set_drvdata(pdev, dev);

	INIT_WORK(&dev->work, tg_do_work);

	/* enable interrupt */
	tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	if (board != VIDEO_DRM_TOOLGATE) {
		struct proc_dir_entry *p;
		char proc_file[16];
		snprintf(proc_file, 16, "driver/%s", board_info[board].nick);

		p = prltg_proc_create_data(proc_file,
			S_IWUGO | ((dev->board == VIDEO_TOOLGATE) ? S_IRUGO : 0), NULL, fops, dev);
		if (p)
			PROC_OWNER(p, THIS_MODULE);
		else
			printk(KERN_WARNING "cannot create %s proc entry\n", proc_file);
	}

	printk(KERN_INFO "detected %s, base addr %08lx, IRQ %d\n",
		board_info[board].name, dev->base_addr, dev->irq);

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}
EXPORT_SYMBOL(prl_tg_probe_common);

/* Deinitialize PCI device */
static void prl_tg_deinitialize(struct pci_dev *pdev, struct tg_dev *dev)
{
	DPRINTK("ENTER\n");

	synchronize_irq(dev->irq);
	free_irq(dev->irq, dev);
	if (dev->flags & TG_DEV_FLAG_MSI) {
		dev->flags &= ~TG_DEV_FLAG_MSI;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
		pci_disable_msi(pdev);
#endif
	}
	flush_scheduled_work();

	pci_release_region(pdev, 0);
	if (dev->board == TOOLGATE)
		pci_disable_device(pdev);

	DPRINTK("EXIT\n");
}

void prl_tg_remove_common(struct pci_dev *pdev)
{
	struct tg_dev *dev = pci_get_drvdata(pdev);
	assert(dev != NULL);

	DPRINTK("ENTER\n");

	if (dev->board != VIDEO_DRM_TOOLGATE) {
		char proc_file[16];
		snprintf(proc_file, 15, "driver/%s", board_info[dev->board].nick);
		remove_proc_entry(proc_file, NULL);
	}

	tg_out32(dev, TG_PORT_MASK, 0);
	prl_tg_deinitialize(pdev, dev);
	pci_set_drvdata(pdev, NULL);
	kfree(dev);

	DPRINTK("EXIT\n");
}
EXPORT_SYMBOL(prl_tg_remove_common);

static struct file_operations prl_vtg_fops = {
	.write		= prl_tg_write,
#ifdef HAVE_OLD_IOCTL
	.ioctl		= prl_vtg_ioctl,
#endif
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl	= prl_vtg_unlocked_ioctl,
#endif
	.open		= prl_vtg_open,
	.release	= prl_vtg_release,
#ifdef PRLVTG_MMAP
	.mmap		= prl_vtg_mmap,
#endif
};

static struct file_operations prl_tg_fops = {
	.write		= prl_tg_write,
	.open		= prl_tg_open,
	.release	= prl_tg_release,
};

static int prl_tg_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int rc = -EINVAL;

/* when built into the kernel, we only print version if device is found */
#ifndef MODULE
	static int printed_version;
	if (!printed_version++)
		printk(version);
#endif

	DPRINTK ("ENTER\n");

	assert(pdev != NULL);
	assert(ent != NULL);

	if (ent->driver_data == VIDEO_TOOLGATE) {
		if (novtg) {
			printk("Parallels Video ToolGate disabled!\n");
			goto out;
		}
		rc = prl_tg_probe_common(pdev, VIDEO_TOOLGATE, &prl_vtg_fops);
	} else
		rc = prl_tg_probe_common(pdev, TOOLGATE, &prl_tg_fops);

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}

#ifdef CONFIG_PM
int prl_tg_suspend_common(struct pci_dev *pdev, pm_message_t state)
{
	struct tg_dev *dev = pci_get_drvdata(pdev);

	/* VvS: I don't found a way to detect hibernate on all linuxes,
	 * therore we'll cancel all request on each suspend */
	tg_req_cancel_all(dev);

	tg_out32(dev, TG_PORT_MASK, 0);
	prl_tg_deinitialize(pdev, dev);

	return 0;
}
EXPORT_SYMBOL(prl_tg_suspend_common);

int prl_tg_resume_common(struct pci_dev *pdev)
{
	struct tg_dev *dev = pci_get_drvdata(pdev);
	int rc;

	rc = prl_tg_initialize(pdev, dev);
	if (!rc)
		tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	return rc;
}
EXPORT_SYMBOL(prl_tg_resume_common);
#endif /* CONFIG_PM */

static struct pci_driver prl_tg_pci_driver = {
	.name		= DRV_SHORT_NAME,
	.id_table	= prl_tg_pci_tbl,
	.probe		= prl_tg_probe,
	.remove		= prl_tg_remove_common,
#ifdef CONFIG_PM
	.suspend	= prl_tg_suspend_common,
	.resume		= prl_tg_resume_common,
#endif /* CONFIG_PM */
};

module_param(novtg, int, 0);
MODULE_PARM_DESC(novtg, "Disable Parallels Video ToolGate");

static int __init prl_tg_init_module(void)
{
	int i;

/* when a module, this is printed whether or not devices are found in probe */
#ifdef MODULE
	printk(version);
#endif

	for (i = 0; i < VTG_HASH_SIZE; i++)
		INIT_LIST_HEAD(&vtg_hashtable[i]);

	/* we don't return error when devices probing fails,
	 * it's required for proper supporting hot-pluggable device */
	return pci_register_driver(&prl_tg_pci_driver);
}

static void __exit prl_tg_cleanup_module(void)
{
	pci_unregister_driver(&prl_tg_pci_driver);
}

MODULE_AUTHOR ("Parallels International GmbH");
MODULE_DESCRIPTION ("Parallels toolgate driver");
MODULE_LICENSE("Parallels");
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 0)
MODULE_INFO (supported, "external");
#endif

module_init(prl_tg_init_module);
module_exit(prl_tg_cleanup_module);
