#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script configure gateway inside RedHat like VM.
#
# Parameters: <dev> <IP>
#   <dev>         - name of device. (example: eth2)
#   <IP>          - IP address of gateway
#  

prog="$0"
path="${prog%/*}"
funcs="$path/functions"

if [ -f "$funcs" ] ; then
	. $funcs
else
	echo "Program $0"
	echo "'$funcs' was not found"
	exit 1
fi


ETH_DEV=$1
ETH_GATEWAY=$2
ETH_DEV_CFG=ifcfg-$ETH_DEV

IFCFG_DIR=/etc/sysconfig/network-scripts
IFCFG=${IFCFG_DIR}/${ETH_DEV_CFG}

ETH_ROUTE_CFG=route-$ETH_DEV
ROUTE_CFG=${IFCFG_DIR}/${ETH_ROUTE_CFG}

function set_gateway()
{
	if [ -f ${IFCFG} ] ; then
		/bin/rm -f ${ROUTE_CFG}
	else
		error "Config file ${IFCFG} is not found"
	fi

	for gw in ${ETH_GATEWAY}; do
		if [ "${gw}" == "remove" ]; then
			del_param ${IFCFG} "GATEWAY"
		elif [ "${gw}" == "removev6" ]; then
			del_param ${IFCFG} "IPV6_DEFAULTGW"
			del_param "/etc/sysconfig/network" "IPV6_DEFAULTDEV"
		elif is_ipv6 ${gw}; then
			put_param ${IFCFG} "IPV6_DEFAULTGW" ${gw}
			put_param "/etc/sysconfig/network" "IPV6_DEFAULTDEV" ${ETH_DEV}
		else
			put_param ${IFCFG} "GATEWAY" ${gw}
			echo "${gw} dev ${ETH_DEV} scope link" >> $ROUTE_CFG
			echo "default via ${gw}" >> $ROUTE_CFG
		fi
	done
	
	is_device_up ${ETH_DEV} && /sbin/ifdown ${ETH_DEV}
	/sbin/ifup ${ETH_DEV}
}

set_gateway

exit 0
# end of script
