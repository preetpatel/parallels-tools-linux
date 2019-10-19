/*
 * @file  compat.h
 * @author vgusev
 *
 * Copyright (C) 1999-2016 Parallels International GmbH.
 * All Rights Reserved.
 * http://www.parallels.com
 */

#ifndef __COMPAT_H__
#define __COMPAT_H__

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,40)) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
/* Fedora 15 uses 2.6.4x kernel version enumeration instead of 3.x */
#define MINOR_3X_LINUX_VERSION LINUX_VERSION_CODE - KERNEL_VERSION(2,6,40)
#define REAL_LINUX_VERSION_CODE	KERNEL_VERSION(3,MINOR_3X_LINUX_VERSION,0)
#else
#define REAL_LINUX_VERSION_CODE	LINUX_VERSION_CODE
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#define RHEL3_KERNEL					\
	(LINUX_VERSION_CODE == KERNEL_VERSION(2, 4, 21) && RED_HAT_LINUX_KERNEL)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define compat_irq_handler(__name, __irq, __dev)	\
	__name(__irq, __dev)
#else
#define compat_irq_handler(__name, __irq, __dev)	\
	__name(__irq, __dev, struct pt_regs * regs)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#endif	/* 2.6.4 */

#include <linux/netdevice.h>

/*
 * The HAVE_NET_DEVICE_OPS first appeared on 2.6.29
 * and was completely removed in 3.1.0. Define it themselves.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
#  if !defined(HAVE_NET_DEVICE_OPS)
#    define HAVE_NET_DEVICE_OPS
#  endif
#endif


/*
 * Linux 2.4.x compatibility
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)

#define MODULE_INFO(tag, info)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 27)
static inline void *netdev_priv(struct net_device *dev)
{
	return dev->priv;
}
#endif	/* 2.4.27 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 25)
#define SET_NETDEV_DEV(net, pdev) do { } while (0)
#endif	/* 2.4.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 23)

#if !RHEL3_KERNEL

static struct net_device *
alloc_netdev(int sizeof_priv, const char *mask,
	     void (*setup)(struct net_device *))
{
	struct net_device *dev;

	dev = alloc_etherdev(sizeof_priv);
	if (!dev)
		return NULL;

	setup(dev);
	return dev;
}

#define free_netdev(dev)   kfree(dev)

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}

#endif /* RHEL3 */

typedef void irqreturn_t;
#define IRQ_RETVAL(h)
#define IRQ_NONE
#define IRQ_HANDLED

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(dev, ops)
#endif
#endif	/* 2.4.23 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 22) && !RHEL3_KERNEL
static inline char *pci_name(struct pci_dev *pdev)
{
	return pdev->slot_name;
}
#endif	/* 2.4.22 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 10)
#define MODULE_LICENSE(x)
#endif	/* 2.4.10 */

/* synchronize_irq */
static void _compat_synchronize_irq(void) { synchronize_irq(); }
#undef synchronize_irq
#define synchronize_irq(irq)  _compat_synchronize_irq()

#define MODULE_INFO(version, _version)

#endif	/* end Linux 2.4.x */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 9)

/* pci_register_driver */
#include <linux/pci.h>
#undef pci_register_driver
#define pci_register_driver(drv) pci_module_init(drv)

#ifndef __iomem
#define __iomem
#endif

static inline void __iomem *
pci_iomap(struct pci_dev *dev, int bar, unsigned long maxlen)
{
	unsigned long start = pci_resource_start(dev, bar);
	unsigned long len = pci_resource_len(dev, bar);
	unsigned long flags = pci_resource_flags(dev, bar);

	if (!len || !start)
		return NULL;
	if (maxlen && len > maxlen)
		len = maxlen;
	if (flags & IORESOURCE_IO) {
		BUG();
	}
	if (flags & IORESOURCE_MEM) {
		if (flags & IORESOURCE_CACHEABLE)
			return ioremap(start, len);
		return ioremap_nocache(start, len);
	}
	return NULL;
}

static inline void pci_iounmap(struct pci_dev *pdev, void *mem)
{
	iounmap(mem);
}

#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN 2
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

#endif /* 2.6.9 */


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
#define SET_ETHTOOL_OPS(netdev, ops) ((netdev)->ethtool_ops = (ops))
#endif

#ifdef SET_ETHTOOL_OPS
#define HAVE_ETHTOOL_OPS   1
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)

#define compat_alloc_netdev(sizeof_priv, mask, net_device) \
	alloc_netdev((sizeof_priv), (mask), NET_NAME_ENUM, (net_device))

#else

#define compat_alloc_netdev(sizeof_priv, mask, net_device) \
	alloc_netdev((sizeof_priv), (mask), (net_device))

#endif /* 3.17 */

#endif	/* __COMPAT_H__ */
