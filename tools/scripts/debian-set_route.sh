#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script configure gateway inside Debian like VM.
#
# Parameters: <dev> <IP> <MAC_addr>
#   <dev>         - name of device. (example: eth2)
#   <IP>          - IP address of gateway
#   <MAC_addr>    - MAC address of device
#

prog="$0"
path="${prog%/*}"
funcs="$path/functions"


if [ -f "$funcs" ]; then
	. $funcs
else
	echo "Program $0"
	echo "File $funcs not found"
	exit 1
fi

ETH_DEV=$1
ETH_GATEWAY=$2
ETH_MAC=$3
ETH_MAC_NW=`echo $ETH_MAC | sed "s,00,0,g"`

if [ ! -f $NWSYSTEMCONF -a ! -f $NMCONFFILE ]; then
	CONFIGFILE="/etc/network/interfaces"

	for gw in ${ETH_GATEWAY}; do
		inet="inet"

		if [ "${gw}" == "remove" -o "${gw}" == "removev6" ] ; then
			continue
		fi

		if is_ipv6 ${gw}; then
			inet="inet6"
			
			awk '
			/^\tup route -A '${inet}' add .* dev '${ETH_DEV}'/ { next; }
			/^\taddress/ { print; next; }
			/^\tnetmask/ { print; next; } 
			/^\tpre-down/ { print; next; } 
			/^\tup ip/ { print; next; } 
			/^\tbroadcast/ { print; next; }
			$1 == "iface" && $2 ~/'${ETH_DEV}'$/ && $3 == "'${inet}'" { addgw=1; print; next; }
			addgw {	print "\tup route -A '${inet}' add '${gw}' dev '${ETH_DEV}' ";  addgw=0 }
			{ print }
			' < ${CONFIGFILE} > ${CONFIGFILE}.$$ && mv -f ${CONFIGFILE}.$$ ${CONFIGFILE}
		else
			awk '
			/^\tup route -A '${inet}' add .* dev '${ETH_DEV}'/ { next; }
			/^\taddress/ { print; next; }
			/^\tnetmask/ { print; next; } 
			/^\tpre-up/ { print; next; } 
			/^\tbroadcast/ { print; next; }
			$1 == "iface" && $2 ~/'${ETH_DEV}'$/ && $3 == "'${inet}'" { addgw=1; print; next; }
			addgw {	
				print "\tup route -A '${inet}' add '${gw}' dev '${ETH_DEV}'";
				addgw=0
				}
			{ print }
			' < ${CONFIGFILE} > ${CONFIGFILE}.$$ && mv -f ${CONFIGFILE}.$$ ${CONFIGFILE}
		fi
	done

	$path/debian-restart.sh
fi
exit 0
# end of script
