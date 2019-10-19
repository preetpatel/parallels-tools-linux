#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script configure IP alias(es) inside SuSE like VM.
#
# Parameters: <dev> <MAC_addr> <IPs>
#   <dev>         - name of device. (example: eth2)
#   <MAC_addr>    - MAC address of device
#   <IP/MASKs>    - IP address(es) with MASK 
#                   (example: 192.169.1.30/255.255.255.0)
#                   (several addresses should be divided by space)
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
ETH_MAC=$2
IP_MASKS=$3
OPTIONS=$4
ETH_DEV_CFG=ifcfg-$ETH_DEV
IFNUM=-1

IFCFG_DIR=/etc/sysconfig/network/
IFCFG=${IFCFG_DIR}/${ETH_DEV_CFG}

set_options "${OPTIONS}"

function get_config_name()
{ #problem: network configs on suse 10(,9) and suse 11 contains the same information,
  #but have different config names
  #examples:
  #suse 10: ifcfg-eth-id-00:0c:29:90:c3:91
  #suse 11: ifcfg-eth1

  ETH_DEV_CFG=ifcfg-eth-id-$ETH_MAC
  IFCFG=${IFCFG_DIR}/${ETH_DEV_CFG}
  [ -f $IFCFG ] && return 0
  
  ETH_DEV_CFG=ifcfg-$ETH_DEV
  IFCFG=${IFCFG_DIR}/${ETH_DEV_CFG}
  [ -f $IFCFG ] && return 0

  #if config not found - check suse-release
  grep -qi "^[[:space:]]*VERSION.*1[1-9]" /etc/SuSE-release
  [ $? -eq 0 ] && return 0

  ETH_DEV_CFG=ifcfg-eth-id-$ETH_MAC
  IFCFG=${IFCFG_DIR}/${ETH_DEV_CFG}
}

function create_config()
{
	local ip=$1
	local mask=$2
	local ifnum=$3
	local ifcfg=$4

	[ -z "${ip}" ] && \
		error "Empty value of IP"

	[ "${ip}" == "remove" ] && ip=""

	[ -z "${mask}" ] && \
		error "Empty value of MASK"

	local dhcp_type="static"
	if [ $USE_DHCPV4 -eq 1 -a $USE_DHCPV6 -eq 1 ]; then
		dhcp_type="dhcp"
	elif grep -qi "^[[:space:]]*VERSION.*1[1-9]" /etc/SuSE-release ; then
		# Only SUSE 11 and up supports explicit dhcp4 / dhcp6
		[ $USE_DHCPV4 -eq 1 ] && dhcp_type="dhcp4"
		[ $USE_DHCPV6 -eq 1 ] && dhcp_type="dhcp6"
	else
		[ $USE_DHCPV4 -eq 1 ] && dhcp_type="dhcp"
	fi

	echo "BOOTPROTO='${dhcp_type}'
STARTMODE='auto'
USERCONTROL='no'
IPADDR=${ip}" > ${ifcfg} || \
	error "Unable to create interface config file" ${VZ_FS_NO_DISK_SPACE}

	if ! is_ipv6 "${ip}" ; then
		echo "NETMASK=${mask}" >> ${ifcfg}
	else
		echo "PREFIXLEN=${mask}" >> ${ifcfg}
	fi

}

function add_alias()
{
	local ip=$1
	local mask=$2
	local ifnum=$3
	local ifcfg=$4
	local cfg

	if [ ! -f ${ifcfg} ]; then
		create_config "$ip" "$mask" "0" "$ifcfg"
		return
	fi
	cfg="IPADDR_${ifnum}=${ip}
LABEL_${ifnum}=${ifnum}"

	if ! is_ipv6 ${ip} ; then
		cfg="${cfg}
NETMASK_${ifnum}=${mask}"
	else
		cfg="${cfg}
PREFIXLEN_${ifnum}=${mask}"
	fi

	echo "${cfg}" >> ${ifcfg} || error "Unable to create interface config file ${ifcfg}" ${VZ_FS_NO_DISK_SPACE}
}

function move_configs()
{
	cd ${IFCFG_DIR} || return 1
	rm -rf ${ETH_DEV_CFG}*
	mv -f bak/* ${IFCFG_DIR}/ >/dev/null 2>&1 
	rm -rf ${IFCFG_DIR}/bak
}

function set_ip()
{
	local ip_mask ip mask
	local new_ips
	local ifcfg="${IFCFG_DIR}/bak/${ETH_DEV_CFG}"

	rm -rf ${IFCFG_DIR}/bak/ >/dev/null 2>&1
	mkdir -p ${IFCFG_DIR}/bak

	new_ips="${IP_MASKS}"
	for ip_mask in ${new_ips}; do
		let IFNUM=IFNUM+1
		if echo ${ip_mask} | grep -q '/' ; then
			mask=${ip_mask##*/}
		else
			if is_ipv6 ${ip_mask} ; then
				mask="64"
			else
				mask='255.255.255.255'
			fi
		fi
		ip=${ip_mask%%/*}
		if [ ${IFNUM} -eq 0 ] ; then
			create_config "${ip}" "${mask}" "${IFNUM}" "${ifcfg}"
		else
			add_alias "${ip}" "${mask}" "${IFNUM}" "${ifcfg}"
		fi
	done

	/sbin/ifdown ${ETH_DEV}

	move_configs

	/sbin/ifup ${ETH_DEV}
}

get_config_name
set_ip

exit 0
# end of script
