//////////////////////////////////////////////////////////////////////////
///
/// @file ApiNet.h
///
/// @brief @brief Ring buffer description
///
/// @author ?
///
/// @brief Ring buffer description
///
/// Copyright (c) 1999-2016 Parallels International GmbH.
/// All Rights Reserved.
/// http://www.parallels.com
///
//////////////////////////////////////////////////////////////////////////

#ifndef API_NET_H
#define API_NET_H

// We need some standard types definitions here
#include "ParallelsTypes.h"

#include <Interfaces/packed.h>

// Ring buffer for packets maximum size
#define IO_NET_SIZE (256*1024)

#define PRL_ETH_HEADER_SIZE		14
#define PRL_ETH_VLAN_HEADER_SIZE 4
#define PRLETH_MAX_FRAME_SIZE	1534

#define NET_ENABLE_RX_PROMISC	(1ull << 0)
// First enable rx after reset of card
#define NET_ENABLE_RX_AFTER_RESET (1ull << 1)

/**
 * @brief
 *		Ring buffer for packet reception description
 *
 *		Struct of ring buffer:
 *		|<---------------------------------------- NET_BUFFER ------------------------------------------->|
 *		|                                                                                                 |
 *		|             |<--------------------------------- NET_BUFFER.aBuffer ---------------------------->|
 *		|             |                                                                                   |
 *		+-------------+--------------------------------+-----+--------------------------------+-----------+
 *		| Info about  |        Received packet         | ... |        Received packet         | Free      |
 *		| ring buffer.+---------------+----------------+ ... +---------------+----------------+           +
 *		| (aBuffer)   | PACKET_HEADER | Packet(data)   | ... | PACKET_HEADER | Packet(data)   |  area     |
 *		+-------------+---------------+----------------+-----+---------------+----------------+-----------+
 *		              ^
 *		              0
 */
typedef struct _NET_BUFFER
{
	// Packet(s) present into buffer
	UINT	bRecPacketPresent;
	// Packet(s) present in send buffer
	UINT	bSendPacketPresent;
	// Virtual cable is plugged
	UINT	bCableUnplugged;
	// Set to true when no space is available for sending packets
	UINT    bBufferFull;

	// Types of packets to accept
	// broad/multicasts always pass currently
	UINT	uRecFilter;
#define NET_FILTER_DIRECTED 1
#define NET_FILTER_BROADCAST 2
#define NET_FILTER_MULTICAST 4
#define NET_FILTER_PROMISCUOUS 8
#define NET_FILTER_ACCEPT_ALL (NET_FILTER_DIRECTED | NET_FILTER_BROADCAST | NET_FILTER_MULTICAST)
#define NET_FILTER_DISABLE_ADAPTER 0

#define NET_FILTER_IS_RX_ON(uRecFilter) ((uRecFilter) & NET_FILTER_ACCEPT_ALL)

	// Indirect rx mode:
	// Pvsnet receive packet, copy it to aBuffer and advance uTail
	// Monitor copy packet from aBuffer to guest memory and advance uHead
	// uHead <= uTail

	// Head of buffer (first allocated packet)
	UINT	uHead;
	// Tail of buffer
	UINT	uTail;
	// Head of buffer (first allocated packet)
	UINT	uSendHead;
	// Tail of buffer
	UINT	uSendTail;

	// if driver that uses this netbuf understands checksum
#define NET_BUFFER_FLAG_WANT_RX_UDP_CKSUM	(1 << 0)
#define NET_BUFFER_FLAG_WANT_RX_TCP_CKSUM	(1 << 1)
#define NET_BUFFER_FLAG_WANT_RX_CKSUM	(NET_BUFFER_FLAG_WANT_RX_TCP_CKSUM | NET_BUFFER_FLAG_WANT_RX_UDP_CKSUM)
	// true if guest driver understands extended flags on packet
#define NET_BUFFER_FLAG_EXT_NETBUF		(1 << 2)
	UINT	uFlags;

	// Flags for virtio network card
#define NET_VIRTIO_RX_DIRECT			(1 << 0)
	UINT	uVirtIoFlags;
	UINT	uVirtIoHostFeatures;
	UINT	uVirtIoAckedFeatures;

	// Must be >= the vcpu_count. Use in multiqueue-devices.
#define NETBUF_MAX_QUEUE_COUNT  64
	UINT16	uQueuedPktSize[NETBUF_MAX_QUEUE_COUNT];

	//
	// Statistics. Warning: don't change the order of these vars!
	// Add variables only to the end.
	//
	LONG64	bytes_in;  // bytes in
	LONG64  bytes_out; // bytes out
	LONG64 	pkts_in;   // packets in
	LONG64 	pkts_out;  // packets out
	LONG64	bcast_in;  // multicast packets in
	LONG64	mcast_in;  // multicast packets out
	LONG64	pkt_dropped_in; // number of in packet dropped due to buf overflow
	LONG64	pkt_err_in; // number of in packets dropped due to errors in packet
	LONG64	pkt_err_out; // number of out packets dropped due to errors in packet
	LONG64	send_buffer_notifications; // notifications to do immediate sends
	LONG64	pkt_err_security; // outgoing packets that didn't pass pktfilter
	LONG64	rx_buffer_notifications; // notifications from virtio about rx-buffers avail
	LONG64	generic_err; // generic errors. Incremented in various situations.
	LONG64	arps_blocked; // Blocked and dropped ARPs while bridge to WiFi.
	LONG64	tail_dropped_in;  // Rx dropped due to rate-limit constraints
	LONG64	tail_dropped_out; // Tx dropped due to rate-limit constraints
	LONG64	immitated_dropped_in;  // Immitated Rx drop
	LONG64	immitated_dropped_out; // Immitated Tx drop

	// align to 1Kb boundary here
	UCHAR	pad[1024 - 324];

	// data buffers allow 1.5Kb tailroom to ease wraparound
	// Note: aSendBuffer is not used in e1000-mode. It just extends the aBuffer
	// to allow 16384bytes-frames or more rx-descriptors in direct-rx mode
	UCHAR	aBuffer[IO_NET_SIZE + 1536];
	UCHAR	aSendBuffer[IO_NET_SIZE + 1536];
} NET_BUFFER;
typedef NET_BUFFER *PNET_BUFFER;


static __inline UINT prlnet_vio_get_feature(NET_BUFFER *nb, int feature_num)
{
	return (nb->uVirtIoAckedFeatures & (1 << feature_num));
}


static __inline void prlnet_vio_host_add_feature(NET_BUFFER *nb, UINT feature_num) {
	nb->uVirtIoHostFeatures |= (1 << feature_num);
}


static __inline void prlnet_vio_host_del_feature(NET_BUFFER *nb, UINT feature_num) {
	nb->uVirtIoHostFeatures &= ~(1 << feature_num);
}

// Network buffer size in pages (for packets)
#define NET_BUFF_PAGES	BYTES2PAGES(sizeof(NET_BUFFER))

BUILD_BUG_ON(IO_NET_SIZE & (IO_NET_SIZE-1));
BUILD_BUG_ON(sizeof(NET_BUFFER) != 4096 + IO_NET_SIZE * 2);
BUILD_BUG_ON(offsetof(NET_BUFFER, aBuffer) != 1024);

/**
 * Received Packet information (Indirect mode)
 *
 * eth header happens to be 14 bytes long
 * IP payload is aligned on 16 byte boundary
 */
typedef struct _NET_PACKET
{
	/* Flags of the packet. Note: if guest driver have not set
	   capabilities in flags, then all bits except MASK must be zero
	   to ensure compatibility with prev. version of this structure
	*/
	/* maximum packet size is 16k-1 */
	#define NET_PACKET_LEN_MASK 0x3fff
	#define NET_PACKET_MAX_SIZE 16383

	/* not zero if driver set NET_BUFFER_FLAG_WANT_RX_CKSUM capability
	   and csum of packet is valid */
	#define NET_PACKET_FLAG_RX_CSUM_VALID (1<<15)
	UINT16 uLenAndFlags; // len and flags of the packet

	// Packed data start
	UINT8	aDataBuf[1];
} NET_PACKET;

struct AssertIPHeaderAlignment {
	char assert[(sizeof(NET_PACKET) - 1 + 14) & 15 ? -1 : 1];
};

#define NET_PACKET_DATA_LEN(pkt) (((NET_PACKET *)(pkt))->uLenAndFlags & NET_PACKET_LEN_MASK)
#define NET_PACKET_SET_DATA_LEN(pkt, len)  ((NET_PACKET *)(pkt))->uLenAndFlags = (UINT16)(len)
#define NET_PACKET_FLAGS(pkt) (((NET_PACKET *)(pkt))->uLenAndFlags & ~NET_PACKET_LEN_MASK)

// Packets are aligned on 16 byte boundary
#define NET_PACKET_SIZE(pkt) \
	((sizeof(NET_PACKET) - 1 + NET_PACKET_DATA_LEN(pkt) + 15) & ~15)

// return size of NET_PACKET required to fit the size
#define FULL_PACKET_SIZE(size) \
	((sizeof(NET_PACKET) - 1 + (size) + 15) & ~15)

#define NET_GET_SND_PACKET(ptr, offset) ((NET_PACKET *) \
		(((NET_BUFFER *)ptr)->aSendBuffer + \
		(offset & (IO_NET_SIZE - 1))))

#define NET_GET_RCV_PACKET(ptr, offset) ((NET_PACKET *) \
		(((NET_BUFFER *)ptr)->aBuffer + \
		(offset & (IO_NET_SIZE - 1))))

#define NET_IS_SENDBUF_EMPTY(netbuf) \
	((netbuf)->uSendTail == (netbuf)->uSendHead)
#include <Interfaces/unpacked.h>

#endif // API_NET_H
