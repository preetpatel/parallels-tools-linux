#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script configure adapter to use DHCP inside Debian like VM.
#
# Parameters: <dev> <MAC_addr>
#   <dev>         - name of device. (example: eth2)
#   <MAC_addr>    - MAC address of device
#

prog="$0"
path="${prog%/*}"
funcs="$path/functions"

if [ -f "$funcs" ] ; then
	. $funcs
else
	echo "Program $0"
	echo "File $funcs not found"
	exit 1
fi

ETH_DEV=$1
ETH_MAC=$2
PROTO=$3
ETH_MAC_NW=`echo $ETH_MAC | sed "s,00,0,g"`

PROTO4="no"
PROTO6="no"

for proto in ${PROTO}; do
	if [ "x$proto" == "x4" ] ; then
		PROTO4="yes"
	elif [ "x$proto" == "x6" ] ; then
		PROTO6="yes"
	fi
done


if [ -f $NWSYSTEMCONF -o -f $NMCONFFILE ]; then
	ls $NWSYSTEMCONNECTIONS/* >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		for i in $NWSYSTEMCONNECTIONS/*; do
			cat "$i" | grep -E "$ETH_MAC|$ETH_MAC_NW" >/dev/null 2>&1
			[ $? -eq 0 ] && rm -f "$i"
		done
	fi

	if [ ! -f "${NWMANAGER}" ] ; then
		echo "Network manager ${NWMANAGER} not found"
		exit 3
	fi

	echo "[connection]
id=$ETH_DEV
uuid=`generate_uuid`
type=802-3-ethernet
autoconnect=true
timestamp=0
" > $NWSYSTEMCONNECTIONS/$ETH_DEV

	if [ "x$PROTO4" == "xyes" ] ; then
		echo "
[ipv4]
method=auto
ignore-auto-routes=false
ignore-auto-dns=false
never-default=false
" >> $NWSYSTEMCONNECTIONS/$ETH_DEV
	fi

	if [ "x$PROTO6" == "xyes" ] ; then
		echo "
[ipv6]
method=auto
ignore-auto-routes=false
ignore-auto-dns=false
never-default=false
" >> $NWSYSTEMCONNECTIONS/$ETH_DEV
	fi

	echo "
[802-3-ethernet]
speed=0
duplex=full
auto-negotiate=true
mac-address=$ETH_MAC_NW
mtu=0" >> $NWSYSTEMCONNECTIONS/$ETH_DEV

	chmod 0600 $NWSYSTEMCONNECTIONS/$ETH_DEV

	remove_debian_interface ${ETH_DEV} $CONFIGFILE
	remove_debian_interface "${ETH_DEV}:[0-9]+" $CONFIGFILE
else
	CONFIGFILE="/etc/network/interfaces"

	remove_debian_interface "${ETH_DEV}:[0-9]+" ${CONFIGFILE}
	remove_debian_interface ${ETH_DEV} ${CONFIGFILE}

	echo "auto ${ETH_DEV}" >> $CONFIGFILE

	if [ "x$PROTO4" == "xyes" ] ; then
		#clean old IPv4
		ip -4 addr flush dev ${ETH_DEV}
		echo >> $CONFIGFILE
		echo "iface ${ETH_DEV} inet dhcp" >> $CONFIGFILE
		# 2.6.35 kernel doesn't flush IPv6 addresses
		echo "	pre-down ip -6 addr flush dev ${ETH_DEV} scope global || :" >> $CONFIGFILE
		echo >> $CONFIGFILE
	fi

	if [ "x$PROTO6" == "xyes" ] ; then
		#don't support dhcpv6 by config
		set_wide_dhcpv6 ${ETH_DEV}
	fi

fi

$path/debian-restart.sh

exit 0
# end of script
