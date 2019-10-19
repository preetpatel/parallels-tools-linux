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

if [ -f $NWSYSTEMCONF -o -f $NMCONFFILE ]; then
	ls $NWSYSTEMCONNECTIONS/* >/dev/null 2>&1
	[ $? -eq 2 ] && exit 1
	if [ ! -f "${NWMANAGER}" ] ; then
		echo "Network manager ${NWMANAGER} not found"
		exit 3
	fi

	for i in $NWSYSTEMCONNECTIONS/*; do
		for gw in ${ETH_GATEWAY}; do
			cat "$i" | grep -E "$ETH_MAC|$ETH_MAC_NW" >/dev/null 2>&1
			if [ $? -eq 0 ]; then
				if is_ipv6 ${gw}; then
					[ "x$gw" = "xremove" ] && gw="::"
					cat "$i" | awk -F ',' '
					$1 ~ /^addresses1/ && $1 ~ /:/  { FS=";"; print $1",""'${gw}'"; next }
					{ print }' > "$i.$$" && mv -f "$i.$$" "$i"; chmod 0600 "$i"

				else
					[ "x$gw" = "xremove" ] && gw="0.0.0.0"
					cat "$i" | awk -F ';' '
					$1 ~ /^addresses1/ && $1 ~ /\./ { FS=";"; print $1";"$2";'${gw}';"; next }
					{ print }' > "$i.$$" && mv -f "$i.$$" "$i"; chmod 0600 "$i"
				fi
			fi
		done
	done

	remove_debian_interface ${ETH_DEV} $CONFIGFILE
	remove_debian_interface "${ETH_DEV}:[0-9]+" $CONFIGFILE
else
	CONFIGFILE="/etc/network/interfaces"

	for gw in ${ETH_GATEWAY}; do
		inet="inet"

		if [ "${gw}" == "remove" -o "${gw}" == "removev6" ] ; then
			continue
		fi

		if is_ipv6 ${gw}; then
			inet="inet6"
		fi
		
		awk '
			/^\tup route -A '${inet}' add .* dev '${ETH_DEV}'/ { next; }
			/^\tup route -A '${inet}' add default/ { next; }
			/^\taddress/ { print; next; }
			/^\tnetmask/ { print; next; } 
			/^\tpre-down/ { print; next; } 
			/^\tup ip/ { print; next; } 
			/^\tbroadcast/ { print; next; }
			$1 == "iface" && $2 ~/'${ETH_DEV}'$/ && $3 == "'${inet}'" { addgw=1; print; next; }
			addgw { 
				print "\tup route -A '${inet}' add '${gw}' dev '${ETH_DEV}'";
				print "\tup route -A '${inet}' add default gw '${gw}' dev '${ETH_DEV}'";
				addgw=0
			}
			{ print }
		' < ${CONFIGFILE} > ${CONFIGFILE}.$$ && mv -f ${CONFIGFILE}.$$ ${CONFIGFILE}
	done

fi

$path/debian-restart.sh

exit 0
# end of script
