#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script detect is DHCP enabled for SuSE like VMs.
#
# Arguments: <ADDR> <DEV> <PROTO>
#   ADDR       - hardware address of adapter
#   DEV        - name of device ( eth1 )
#   PROTO      - proto "4" or "6". If empty - 4.
#
# Return:
#   2 - can't detect or some error
#   0 - enabled
#   1 - disabled 
#

ADDR=$1
DEV=$2
PROTO=$3

configs="/etc/sysconfig/network/ifcfg-eth-id-${ADDR} /etc/sysconfig/network/ifcfg-${DEV}"
CONFIG=""

for conf in $configs ; do
	[ -f $conf ] && CONFIG=$conf
done

#config was not found
[ -z "${CONFIG}" ] && exit 2

if [ "x$PROTO" != "x6" ] ; then
	LANG=C egrep -iq "^[[:space:]]*BOOTPROTO=.*?dhcp6.*?" "${CONFIG}"
else
	LANG=C egrep -iq "^[[:space:]]*BOOTPROTO=.*?dhcp4.*?" "${CONFIG}"
fi

if [ $? -eq 0 ] ; then
	exit 0
else
	LANG=C egrep -iq "^[[:space:]]*BOOTPROTO=.*?dhcp.*?" "${CONFIG}"
fi

if [ $? -eq 0 ] ; then
    exit 0
fi

exit 1


