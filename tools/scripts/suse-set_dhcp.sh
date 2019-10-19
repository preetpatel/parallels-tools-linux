#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script configure adapter to use DHCP inside SuSE like VM.
#
# Parameters: <dev> <mac>
#   <dev>         - name of device. (example: eth2)
#   <mac>         - hardware address of device
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
PROTO=$3
IFCFG_DIR=/etc/sysconfig/network

PROTO4="no"
PROTO6="no"

for proto in ${PROTO}; do
	if [ "x$proto" == "x4" ] ; then
		PROTO4="yes"
	elif [ "x$proto" == "x6" ] ; then
		PROTO6="yes"
	fi
done


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
	local dhcp_type="dhcp"

	if [ "x$PROTO4" == "xyes" -a "x$PROTO6" != "xyes" ] ; then
		dhcp_type="dhcp4"
	elif [ "x$PROTO6" == "xyes" -a "x$PROTO4" != "xyes" ] ; then
		dhcp_type="dhcp6"
	fi

	echo "BOOTPROTO='${dhcp_type}'
BROADCAST=''
ETHTOOL_OPTIONS=''
MTU=''
NETWORK=''
USERCONTROL='no'
STARTMODE='auto'"  > ${IFCFG_DIR}/bak/${ETH_DEV_CFG} || \
	error "Unable to create interface config file" ${VZ_FS_NO_DISK_SPACE}
}


function backup_configs()
{
	local delall=$1

	rm -rf ${IFCFG_DIR}/bak/ >/dev/null 2>&1
	mkdir -p ${IFCFG_DIR}/bak
	[ -n "${delall}" ] && return 0

	cd ${IFCFG_DIR} || return 1
	${CP} ${ETH_DEV_CFG} ${IFCFG_DIR}/bak/
}

function move_configs()
{
	cd ${IFCFG_DIR} || return 1
	mv -f bak/* ${IFCFG_DIR}/ >/dev/null 2>&1 
	rm -rf ${IFCFG_DIR}/bak
}

function set_dhcp()
{
	backup_configs
	create_config
	move_configs

	is_device_up ${ETH_DEV} && /sbin/ifdown ${ETH_DEV}

	/sbin/ifup ${ETH_DEV}
}

get_config_name
set_dhcp

exit 0
# end of script
