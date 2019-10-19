/*
 * @file  pvmnet_hw.h
 * @author vgusev
 *
 * Copyright (C) 1999-2016 Parallels International GmbH.
 * All Rights Reserved.
 * http://www.parallels.com
 */

#ifndef __PVMNET_HW__
#define __PVMNET_HW__

#include <asm/io.h>
#include "pvmeth.h"

/*
 * Hardware specific part
 */

static inline int
io_enable_interface(unsigned long io_base)
{
	outl(PRLETH_COMMAND_PRLETH, io_base + PRLETH_PORT_COMMAND);
	outw(PRLETH_COMMAND_ENABLE, io_base + PRLETH_PORT_COMMAND);
	return 0;
}

static inline void
io_disable_interface(unsigned long io_base)
{
	outw(PRLETH_COMMAND_DISABLE, io_base + PRLETH_PORT_COMMAND);
	outl(PRLETH_COMMAND_RTL8029, io_base + PRLETH_PORT_COMMAND);
}

static inline void
io_get_mac_address(unsigned long io_base, unsigned char *mac,
		   unsigned int len)
{
	outw(PRLETH_COMMAND_GET_ADDRESS, io_base + PRLETH_PORT_COMMAND);
#ifdef CONFIG_AMD_MEM_ENCRYPT
	asm volatile("rep; insb" : "+D"(mac), "+c"(len) : "d"(io_base + PRLETH_PORT_DATA) : "memory");
#else
	insb(io_base + PRLETH_PORT_DATA, mac, len);
#endif
}

#define ASSIGN_NETBUF_32(ptr, member, value) ( \
		writel(value, ptr + offsetof(NET_BUFFER, member)))

#define READ_NETBUF_32(ptr, member) ( \
		readl(ptr + offsetof(NET_BUFFER, member)))

/*
 * @return zero if success
 */
static inline int
io_write_data(unsigned long io_base,
	      u8 __iomem *ioaddr,
	      void *data,
	      unsigned int size)
{
	unsigned int fullsize;
	unsigned int end, start;
	NET_PACKET *packet;

	start = readl(ioaddr + offsetof(NET_BUFFER, uSendTail));
	end = readl(ioaddr + offsetof(NET_BUFFER, uSendHead));

	fullsize = FULL_PACKET_SIZE(size);
	if (fullsize > (IO_NET_SIZE - (start - end))) {
		/* Buffer is full */
		return -1;
	}

	packet = NET_GET_SND_PACKET(ioaddr, start);
	writew(size, &packet->uLenAndFlags);
	memcpy_toio(packet->aDataBuf, data, size);

	ASSIGN_NETBUF_32(ioaddr, uSendTail, start + fullsize);

	if (0 == READ_NETBUF_32(ioaddr, bSendPacketPresent)) {
		ASSIGN_NETBUF_32(ioaddr, bSendPacketPresent, 1);
		/* kick send */
		outl(PRLETH_COMMAND_FLUSH, io_base + PRLETH_PORT_COMMAND);
	}

	return 0;
}

static inline void
io_notify_sndbuf_full(unsigned long io_base)
{
	outl(PRLETH_COMMAND_BUFOVERFLOW, io_base + PRLETH_PORT_COMMAND);
}

static inline void
io_interrupts(unsigned long io_base, int enable)
{
	unsigned int mask = enable ? PRLETH_MASK_ENABLE : 0;
	outw(mask, io_base + PRLETH_PORT_MASK);
}

#define io_enable_interrupts(base) io_interrupts(base, 1)
#define io_disable_interrupts(base) io_interrupts(base, 0)

static inline unsigned int
io_get_rcv_offset(u8 __iomem *ioaddr)
{
	return readl(ioaddr + offsetof(NET_BUFFER, uHead));
}

/* Move read pointer in receive buffer and
 * enable interrupt from card
 */
static inline void
io_move_rcv_offset(unsigned long io_base,
		   unsigned int offset)
{
	outl(offset, io_base + PRLETH_PORT_MOVE_RECV_HEAD);
}

static inline unsigned int
io_get_packet_size(u8 __iomem *ioaddr,
		   unsigned int offset)
{
	unsigned int end;
	NET_PACKET *packet;

	end = readl(ioaddr + offsetof(NET_BUFFER, uTail));

	if (offset == end)
		return 0;	/* No more messages */

	packet = NET_GET_RCV_PACKET(ioaddr, offset);
	return readw(&packet->uLenAndFlags) & NET_PACKET_LEN_MASK;
}

/*
 * Read data and move offset to the next position
 */
static inline void
io_read_data(u8 __iomem *ioaddr, unsigned int *offset,
	     void *ptr, unsigned int size)
{
	NET_PACKET *packet;

	packet = NET_GET_RCV_PACKET(ioaddr, *offset);

	memcpy_fromio(ptr, packet->aDataBuf, size);
	*offset += FULL_PACKET_SIZE(size);
}

/*
 * Drop packet and move offset to next position
 */
static inline void
io_drop_packet(unsigned int *offset, unsigned int size)
{
	*offset += FULL_PACKET_SIZE(size);
}

/*
 * Get status causes disabling interrupts from
 * card if status was changed
 */
static inline unsigned int
io_get_status(unsigned long io_base)
{
	return inw(io_base + PRLETH_PORT_STATUS);
}

static inline void
io_multicast(unsigned long io_base, int enable)
{
	unsigned int cmd;

	if (enable)
		cmd = PRLETH_COMMAND_PASS_MULTICAST;
	else
		cmd = PRLETH_COMMAND_FILTER_MULTICAST;

	outw(cmd, io_base + PRLETH_PORT_COMMAND);
}

static inline void
io_promisc(unsigned long io_base, int enable)
{
	unsigned int cmd;

	if (enable)
		cmd = PRLETH_COMMAND_SET_PROMISCUOUS;
	else
		cmd = PRLETH_COMMAND_CLR_PROMISCUOUS;

	outw(cmd, io_base + PRLETH_PORT_COMMAND);
}

#undef ASSIGN_NETBUF_32

#endif	/* __PVMNET_HW__ */
