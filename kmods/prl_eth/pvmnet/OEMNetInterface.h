//////////////////////////////////////////////////////////////////////////
///
/// @file OEMNetInterface.h
///
/// @brief Interface to OEM card
///
/// @author ?
///
/// Copyright (c) 1999-2016 Parallels International GmbH.
/// All Rights Reserved.
/// http://www.parallels.com
///
//////////////////////////////////////////////////////////////////////////

#ifndef __OEM_NET_INTERFACE_H__
#define __OEM_NET_INTERFACE_H__

// for ISA card emulation
#define PRLETH_ISA_PORT 0x4a20


#define PRLETH_MCAST_LIST_SIZE 32

// total size of IOrange of ParallelsEthernet Device
#define PRLETH_PORT_NPORTS             32

//
// In Ports
//
#define PRLETH_PORT_STATUS             2

// Size of current packet. Does not modify state.
#define PRLETH_PORT_CURRPKT_SIZE       8

// Size of current packet. Does not modify state.
#define PRLETH_PORT_MEDIA_STATUS       12
//
// Out ports
//
#define PRLETH_PORT_MASK               2
// Port for writing full packet with one outsb
#define PRLETH_PORT_PKTDATA			   8
// Update send tail to specified value
#define PRLETH_PORT_MOVE_SEND_TAIL	   12
// Update read head to specified value and enable interrupts
#define PRLETH_PORT_MOVE_RECV_HEAD	   16

//
// In/Out ports
//
#define PRLETH_PORT_COMMAND 		   0
#define PRLETH_PORT_PKTSIZE             4
#define PRLETH_PORT_DATA                6
// Read statistics-info in the order described in NETBUF;
// Usage: write stat-index, read back two 32bit, which are UINT64 stat-value
#define PRLETH_PORT_STATISTICS          10


//
// Command register values
//
# define PRLETH_COMMAND_DISABLE 			0x00
# define PRLETH_COMMAND_ENABLE 				0x01
# define PRLETH_COMMAND_GET_ADDRESS 		0x100
# define PRLETH_COMMAND_SET_MCAST_LIST 		0x200
# define PRLETH_COMMAND_FILTER_MULTICAST 	0x210
# define PRLETH_COMMAND_PASS_MULTICAST 		0x211
# define PRLETH_COMMAND_CLR_PROMISCUOUS 	0x220
# define PRLETH_COMMAND_SET_PROMISCUOUS 	0x221
// tell to the card that driver will not send any packets until interrupt
// with notification about available buffer space is generated
# define PRLETH_COMMAND_BUFOVERFLOW 		0x222

//
// Additional status can be read from CMD-reg
//
#define PRLETH_COMMAND_BUFOVERFLOW_BIT		(1<<0)

// check whether flag force_kicksend is true
#define PRLETH_GET_NEED_KICKSEND		0x223

// switch card to ParallelsEthernet mode
# define PRLETH_COMMAND_PRLETH  			0x1AB8400E
// switch card to RTL8029 mode
# define PRLETH_COMMAND_RTL8029 			0x10EC8029
// Magic number written to adapter 0 port, Mean that card must immediately send packet
// without waiting for Mon/Host switching.
# define PRLETH_COMMAND_FLUSH 				0x31415927

//
// Status bits
//
# define PRLETH_STATUS_RECVD          	0x01         /* Packet received */
# define PRLETH_STATUS_SPACE          	0x02         /* Send space become available */
# define PRLETH_STATUS_CABLE          	0x04
# define PRLETH_STATUS_CONNECTED      	0x100

//
// Mask for all interrupts
//
#define PRLETH_MASK_ENABLE (PRLETH_STATUS_RECVD | PRLETH_STATUS_CABLE | PRLETH_STATUS_SPACE)

#endif // __OEM_NET_INTERFACE_H__
