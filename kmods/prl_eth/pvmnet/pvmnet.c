/*
 * @file  pvmnet.c
 *
 * A virtual network driver for Parallels
 *
 * Written by Vitaliy Gusev <vgusev@parallels.com> for Parallels
 *
 * Copyright (C) 1999-2016 Parallels International GmbH.
 * All Rights Reserved.
 * http://www.parallels.com
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#include <asm/system.h>
#endif
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>

#include "compat.h"
#include "pvmeth.h"		/* PRLETH_xxx */
#include "pvmnet_hw.h"		/* io_xxx functions */

#define NE_IO_EXTENT	0x20

#define DRV_NAME     "prl_eth"
#define DRV_VERSION  "1.1"

struct pvmnet_priv {
	struct net_device_stats stats;
	struct pci_dev *pci_dev;
	u8 __iomem *mmio;
};

static struct pci_device_id pvmnet_pci_tbl[] = {
	{ 0x10ec, 0x8029, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, pvmnet_pci_tbl);

static void pvmnet_setup(struct net_device *dev);

/*
 * System specific part
 */

static int pvmnet_pci_init(struct pci_dev *pdev,
				     const struct pci_device_id *ent)
{
	struct net_device *dev;
	struct pvmnet_priv *priv;
	unsigned long ioaddr;
	void __iomem *mmio;
	int i, err;
	int irq;

	i = pci_enable_device(pdev);
	if (i)
		return i;

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		printk (KERN_ERR "%s: I/O resources busy\n", DRV_NAME);
		goto err_req;
	}

	err = -EIO;
	mmio = pci_iomap(pdev, 1, pci_resource_len(pdev, 1));
	if (!mmio)
		goto err_iomap;

	err = -ENODEV;
	ioaddr = pci_resource_start(pdev, 0);
	irq = pdev->irq;
	if (io_enable_interface(ioaddr)) {
		printk("%s: Can't initialize virtual card!\n", DRV_NAME);
		goto err_interface;
	}

	err = -ENOMEM;
	dev = compat_alloc_netdev(sizeof(struct pvmnet_priv), "eth%d",
			pvmnet_setup);
	if (!dev) {
		goto err_free_res;
	}

	SET_NETDEV_DEV(dev, &pdev->dev);

	io_get_mac_address(ioaddr, dev->dev_addr, ETH_ALEN);

	dev->irq = irq;
	dev->base_addr = ioaddr;
	pci_set_drvdata(pdev, dev);

	priv = netdev_priv(dev);
	priv->pci_dev = pdev;
	priv->mmio = mmio;

	err = register_netdev(dev);
	if (err)
		goto err_free_netdev;

	printk("%s: found at %#lx, IRQ %d\n", dev->name, ioaddr, dev->irq);

	return 0;

err_free_netdev:
	free_netdev(dev);
err_free_res:
	io_disable_interface(ioaddr);
err_interface:
	pci_iounmap(pdev, mmio);
err_iomap:
	pci_release_regions(pdev);
err_req:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void pvmnet_pci_remove(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct pvmnet_priv *priv;

	if (!dev)
		BUG();

	unregister_netdev(dev);
 	io_disable_interface(dev->base_addr);

	priv = netdev_priv(dev);
	pci_iounmap(pdev, priv->mmio);
	free_netdev(dev);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver pvmnet_driver = {
	.name		= DRV_NAME,
	.probe		= pvmnet_pci_init,
	.remove		= pvmnet_pci_remove,
	.id_table	= pvmnet_pci_tbl,
};

/*
 * Network implementation
 */

#ifdef HAVE_ETHTOOL_OPS

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
static int pvmnet_get_link_ksettings(struct net_device *dev,
		struct ethtool_link_ksettings *ecmd)
{
	u32 supported = (SUPPORTED_1000baseT_Full |
			SUPPORTED_FIBRE);
	ethtool_convert_legacy_u32_to_link_mode(
			ecmd->link_modes.supported,
			supported);
	ecmd->base.port = PORT_TP;
	ecmd->base.transceiver = XCVR_EXTERNAL;
	ecmd->base.speed = SPEED_1000;
	ecmd->base.duplex = DUPLEX_FULL;
	ecmd->base.autoneg = AUTONEG_DISABLE;
	return 0;
}
#else
static int pvmnet_get_settings(struct net_device *dev,
		struct ethtool_cmd *ecmd)
{
	ecmd->supported   = (SUPPORTED_1000baseT_Full |
			     SUPPORTED_FIBRE);
	ecmd->port = PORT_TP;
	ecmd->transceiver = XCVR_EXTERNAL;
	ecmd->speed = SPEED_1000;
	ecmd->duplex = DUPLEX_FULL;
	ecmd->autoneg = AUTONEG_DISABLE;
	return 0;
}
#endif

static void pvmnet_get_drvinfo(struct net_device *dev,
				 struct ethtool_drvinfo *info)
{
	struct pvmnet_priv *priv = netdev_priv(dev);

	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->bus_info, pci_name(priv->pci_dev));
}

static struct ethtool_ops pvmnet_ethtool_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
	.get_link_ksettings = pvmnet_get_link_ksettings,
#else
	.get_settings = pvmnet_get_settings,
#endif
	.get_drvinfo            = pvmnet_get_drvinfo,
	.get_link               = ethtool_op_get_link,
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,39))
	.get_tx_csum            = ethtool_op_get_tx_csum,
	.get_sg                 = ethtool_op_get_sg,
#endif
};
#endif	/* HAVE_ETHTOOL_OPS */

static irqreturn_t
compat_irq_handler(pvmnet_interrupt, int irq, void *dev_id)
{
	struct net_device *dev = (struct net_device *)dev_id;
	unsigned int status;
	int irq_wanted = 1;

	status = io_get_status(dev->base_addr);
	if (!(status & (PRLETH_STATUS_RECVD |
			PRLETH_STATUS_SPACE |
			PRLETH_STATUS_CABLE)))
		return IRQ_NONE;     /* No interrupt: shared IRQs cause this */

	if (status & PRLETH_STATUS_CABLE) {
		if (status & PRLETH_STATUS_CONNECTED) {
			printk("%s: link is up\n", dev->name);
			netif_carrier_on(dev);
			netif_wake_queue(dev);
		} else {
			printk("%s: link is down\n", dev->name);
			netif_carrier_off(dev);
			netif_stop_queue(dev);
		}
	}

	if (status & PRLETH_STATUS_SPACE)
		netif_wake_queue(dev);

	if (status & PRLETH_STATUS_RECVD) {
		struct net_device_stats *stats;
		struct pvmnet_priv *priv = netdev_priv(dev);
		unsigned int offset;

		stats = &priv->stats;
		offset = io_get_rcv_offset(priv->mmio);

		for (;;) {
			struct sk_buff *skb;
			unsigned int size;

			size = io_get_packet_size(priv->mmio, offset);

			if (size == 0)
				break;

			if (size < ETH_HLEN || size > ETH_FRAME_LEN) {
				io_drop_packet(&offset, size);
				stats->rx_errors++;
				stats->rx_length_errors++;
				continue;
			}

			skb = dev_alloc_skb(size + NET_IP_ALIGN);
			if (!skb) {
				io_drop_packet(&offset, size);
				stats->rx_dropped++;
				continue;
			}

			skb_reserve(skb, NET_IP_ALIGN);
			skb->dev = dev;
			skb_put(skb, size);

			io_read_data(priv->mmio, &offset, skb->data, size);

			skb->protocol = eth_type_trans(skb, dev);
			netif_rx(skb);

			stats->rx_bytes += size;
			stats->rx_packets++;
		}

		/* It also enables interrupts */
		io_move_rcv_offset(dev->base_addr, offset);
		irq_wanted = 0;
	}

	if (irq_wanted)
		io_enable_interrupts(dev->base_addr);

	return IRQ_HANDLED;
}

static int pvmnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	unsigned int size;

	size = skb->len;

	if (size > 0 && size <= ETH_FRAME_LEN) {
		struct net_device_stats *stats;
		struct pvmnet_priv *priv = netdev_priv(dev);
		int err;

		err = io_write_data(dev->base_addr, priv->mmio, skb->data, size);
		if (err) {
			netif_stop_queue(dev);
			io_notify_sndbuf_full(dev->base_addr);
			return NETDEV_TX_BUSY;
		}

		stats = &priv->stats;
		stats->tx_bytes += size;
		stats->tx_packets++;
	}

	dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

static void pvmnet_set_multicast_list(struct net_device *dev)
{
	unsigned int cmd;

	cmd = dev->flags & IFF_PROMISC;
	io_promisc(dev->base_addr, cmd ? 1 : 0);

	cmd = dev->flags & IFF_ALLMULTI;
	io_multicast(dev->base_addr, cmd ? 1 : 0);
}

static struct net_device_stats *
pvmnet_get_stats(struct net_device *dev)
{
	struct pvmnet_priv *priv;

	priv = netdev_priv(dev);
	return &priv->stats;
}

static int pvmnet_open(struct net_device *dev)
{
	int status;
	int ret;

	/* Avoid race with interrupt handler */
	status = io_get_status(dev->base_addr);

	ret = request_irq(dev->irq, pvmnet_interrupt, IRQF_SHARED, dev->name,
			      dev);
	if (ret)
		return ret;

	io_enable_interrupts(dev->base_addr);

	netif_start_queue(dev);

	if (status & PRLETH_STATUS_CONNECTED)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);

	return 0;
}

static int pvmnet_close(struct net_device *dev)
{
	io_disable_interrupts(dev->base_addr);

	netif_stop_queue(dev);
	netif_carrier_off(dev);

	synchronize_irq(dev->irq);
	free_irq(dev->irq, dev);

	return 0;
}

static int pvmnet_init(struct net_device *dev)
{
	return 0;
}

static void pvmnet_free(struct net_device *dev)
{
}


#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops pvmnet_netdev_ops = {
   .ndo_start_xmit = pvmnet_xmit,
   .ndo_get_stats = pvmnet_get_stats,
   .ndo_open = pvmnet_open,
   .ndo_stop = pvmnet_close,
   .ndo_init = pvmnet_init,
   .ndo_uninit = pvmnet_free,
#if REAL_LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
   .ndo_set_multicast_list = pvmnet_set_multicast_list,
#else
   .ndo_set_rx_mode = pvmnet_set_multicast_list,
#endif

#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5)
	.extended.ndo_change_mtu = eth_change_mtu,
#else
	.ndo_change_mtu = eth_change_mtu,
#endif
#endif
};
#endif

static void pvmnet_setup(struct net_device *dev)
{
	ether_setup(dev);

#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops = &pvmnet_netdev_ops;
#else
	dev->hard_start_xmit = pvmnet_xmit;
	dev->get_stats = pvmnet_get_stats;
	dev->open = pvmnet_open;
	dev->stop = pvmnet_close;
	dev->init = pvmnet_init;
	dev->destructor = pvmnet_free;
	dev->set_multicast_list = pvmnet_set_multicast_list;
#endif

	SET_ETHTOOL_OPS(dev, &pvmnet_ethtool_ops);
}

/* Module initialization/cleanup */
static int pvmnet_module_init(void)
{
	int res;

	res = pci_register_driver(&pvmnet_driver);
	return res;
}

static void pvmnet_module_cleanup(void)
{
	pci_unregister_driver(&pvmnet_driver);
}

module_init(pvmnet_module_init);
module_exit(pvmnet_module_cleanup);

MODULE_AUTHOR("Parallels International GmbH");
MODULE_DESCRIPTION("Parallels virtual network driver");
MODULE_LICENSE("Parallels");
MODULE_VERSION(DRV_VERSION);
MODULE_INFO(supported, "external");
