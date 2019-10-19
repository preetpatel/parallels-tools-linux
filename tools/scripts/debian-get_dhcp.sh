#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script detect is DHCP enabled for Debian like VMs.
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

ETH_MAC=$1
ETH_DEV=$2
PROTO=$3
ETH_MAC_NW=`echo $ETH_MAC | sed "s,00,0,g"`

prog="$0"
path="${prog%/*}"
funcs="$path/functions"

if [ -f "$funcs" ] ; then
	. $funcs
else
	echo "Program $0"
	echo "File $funcs not found"
	exit 2
fi

if [ -f $NWSYSTEMCONF -o -f $NMCONFFILE ]; then
	ls $NWSYSTEMCONNECTIONS/* >/dev/null 2>&1
	[ $? -eq 2 ] && exit 2
	for i in $NWSYSTEMCONNECTIONS/*; do
		cat "$i" | grep -E "$ETH_MAC|$ETH_MAC_NW" >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			if [ "x${PROTO}" != "x6" ] ; then
				cat "$i" | awk '
					/^\[ipv4\]/ { catchsection=1; next; }
					$1 ~ /^\[/ && catchsection { catchsection=0 }
					$1 ~ /^method=auto/ && catchsection { exit 1 }
					{ next } '
			else
				cat "$i" | awk '
					/^\[ipv6\]/ { catchsection=1; next; }
					$1 ~ /^\[/ && catchsection { catchsection=0 }
					$1 ~ /^method=auto/ && catchsection { exit 1 }
					{ next } '
			fi
			[ $? -eq 1 ] && exit 0 || exit 1
		fi
	done
	exit 2
else

	if [ "x${PROTO}" == "x6" ] ; then
		CONFIGFILE="/etc/default/wide-dhcpv6-client"

		# config was not found
		[ -f "${CONFIGFILE}" ] || exit 1

		cat $CONFIGFILE | grep "^[[:space:]]*INTERFACES.*$ETH_DEV" >/dev/null 2>&1
	else
		CONFIGFILE="/etc/network/interfaces"

		# config was not found
		[ -f "${CONFIGFILE}" ] || exit 2

		inet="inet"

		cat $CONFIGFILE | grep "^[[:space:]]*iface $ETH_DEV $inet" | grep dhcp >/dev/null 2>&1
	fi

	[ $? -eq 0 ] && exit 0 || exit 1
fi
