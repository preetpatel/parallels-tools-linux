#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script sets up resolver inside VM
#
# arguments: <NAMESERVER> <SEARCHDOMAIN>
#   <SEARCHDOMAIN>
#       Sets search domain(s). Modifies /etc/resolv.conf
#   <NAMESERVER>
#       Sets name server(s). Modifies /etc/resolv.conf

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

NAMESERVER="$1"
SEARCHDOMAIN="$2"
HOSTNAME="$3"
DISTR="$4"

RESOLVDIR=/etc/resolvconf
RESOLVCONF_LNK="${RESOLVDIR}/run/resolv.conf"
RESOLVCONF="${RESOLVDIR}/resolv.conf.d/base"

function set_dns()
{
	local cfgfile="$1"
	local server="$2"
	local search="$3"
	local srv fname

	if [ -L ${cfgfile} ]; then
		# resolvconf configuration
		fname="$(readlink "${cfgfile}")"
		if [ "${fname}" = "${RESOLVCONF_LNK}" ]; then
			cfgfile=${RESOLVCONF}
		fi
	fi 
	if [ -n "${search}" ]; then
		if [ "${search}" = '#' ]; then
			sed -i "/search.*/d" ${cfgfile} || \
				error "Can't change file ${cfgfile}" ${VZ_FS_NO_DISK_SPACE} 
		else
			put_param2 "${cfgfile}" search "${search}"
		fi
	fi
	if [ -n "${server}" ]; then
		[ -f ${cfgfile} ] || touch ${cfgfile}
		sed -i "/nameserver.*/d" ${cfgfile} || \
			error "Can't change file ${cfgfile}" ${VZ_FS_NO_DISK_SPACE} 
		[ "${server}" = '#' ] && return
		for srv in ${server}; do
			echo "nameserver ${srv}" >> ${cfgfile} || \
				error "Can't change file ${cfgfile}" ${VZ_FS_NO_DISK_SPACE} 
		done
	fi
	chmod 644 ${cfgfile}
}

function set_hostname()
{
	local hostname="$1"
	local distr="$2"

	# nothing to do
	if [ -z "${hostname}" ]; then
		exit 0
	fi

	hostname "${hostname}";

	if [ "${distr}" = "redhat" ]; then
		put_param "/etc/sysconfig/network" "HOSTNAME" "${hostname}"	
	elif [ "${distr}" = "suse" ]; then
		echo "${hostname}" > /etc/HOSTNAME
	elif [ "${distr}" = "debian" ]; then
		echo "${hostname}" > /etc/hostname
	fi
}

set_dns /etc/resolv.conf "${NAMESERVER}" "${SEARCHDOMAIN}"
set_hostname "${HOSTNAME}" "${DISTR}"

exit 0
