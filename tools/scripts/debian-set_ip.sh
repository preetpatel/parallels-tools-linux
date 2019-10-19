#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script configure IP alias(es) inside Debian like VM.
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
CONFIGFILE="/etc/network/interfaces"

if [ -f "$funcs" ] ; then
	. $funcs
else
	echo "Program $0"
	echo "File ${func} not found"
	exit 1
fi

ETH_DEV=$1
ETH_MAC=$2
IP_MASKS=$3
OPTIONS=$4
ETH_MAC_NW=`echo $ETH_MAC | sed "s,00,0,g"`
IFNUM=-1
IFNUM6=-1
IP4_MASKS=
IP6_MASK=
SET_AUTO[0]="no"

set_options "${OPTIONS}"

for ip_mask in ${IP_MASKS}; do
	if [ "${ip_mask}" == "remove" ] ; then
		continue
	elif is_ipv6 ${ip_mask}; then
		IP6_MASKS="${IP6_MASKS} ${ip_mask}"
	else
		IP4_MASKS="${IP4_MASKS} ${ip_mask}"
	fi
done


function print_ipv6_header()
{
	local device=$1
	local method=$2
	if [ "${SET_AUTO[0]}" != "yes" ] ; then
		SET_AUTO[0]="yes"
		echo "auto ${device}" >> $CONFIGFILE
	fi

	echo "iface ${device} inet6 ${method}" >> $CONFIGFILE

	# 2.6.35 kernel doesn't flush IPv6 addresses
	echo "	pre-down ip -6 addr flush dev ${device} scope global || :" >> $CONFIGFILE
}

function add_ip6()
{
	local ip=$1
	local mask=$2
	local device=$3
	local ifnum=${IFNUM6}
	local ifnum_postfix=":${IFNUM6}"
	local inet="inet6"

	[ -z "${ip}" ] && \
		error "Empty value of IP"

	[ -z "${mask}" ] && \
		error "Empty value of MASK"


	if [ "x${IFNUM6}" == "x0" ] ; then
		print_ipv6_header ${device} static

		echo "	address ${ip}" >> $CONFIGFILE
		echo "	netmask ${mask}" >> $CONFIGFILE
	else
		awk 'BEGIN {found = 0}
		NF == 0 {next}
		!found && $1 == "iface" && $2 ~/'${device}'$/ && $3 == "inet6" {
			found = 1;
			print;
			next;
		}
		found == 1 && !/^\t/{
			print "\tup ip addr add '${ip}'/'${mask}' dev '${device}'";
			found++;
		}
		{print}
		END {
			if (found == 1) {
				print "\tup ip addr add '${ip}'/'${mask}' dev '${device}'";
			}
		}
		' < ${CONFIGFILE} > ${CONFIGFILE}.$$ && mv -f ${CONFIGFILE}.$$ ${CONFIGFILE}
	fi

	echo >> $CONFIGFILE
	echo >> $CONFIGFILE
}

function create_config()
{
	local ip=$1
	local mask=$2
	local device=$3
	local ifnum=${IFNUM}
	local ifnum_postfix=":${IFNUM}"
	local inet="inet"

	[ -z "${ip}" ] && \
		error "Empty value of IP"

	[ -z "${mask}" ] && \
		error "Empty value of MASK"

	[ "x${IFNUM}" == "x0" ] && ifnum_postfix=""

	if [ "${SET_AUTO[${ifnum}]}" != "yes" ] ; then
		SET_AUTO[${ifnum}]="yes"
		echo "auto ${device}${ifnum_postfix}" >> $CONFIGFILE
	fi

	echo "iface ${device}${ifnum_postfix} ${inet} static" >> $CONFIGFILE

	if [ "${ip}" == "remove" ] ; then
		echo "" >> $CONFIGFILE
		return
	fi

	echo "	address ${ip}
	netmask ${mask}" >> $CONFIGFILE
	echo "	broadcast +
" >> $CONFIGFILE
}

function set_ip()
{
	local ip_mask ip mask
	local new_ips

	remove_debian_interface ${ETH_DEV} $CONFIGFILE
	remove_debian_interface "${ETH_DEV}:[0-9]+" $CONFIGFILE

	new_ips="${IP_MASKS}"
	for ip_mask in ${new_ips}; do
		if is_ipv6 ${ip_mask} ; then
			let IFNUM6=IFNUM6+1
			if echo ${ip_mask} | grep -q '/' ; then
				mask=${ip_mask##*/}
			else
				mask='64'
			fi
			ip=${ip_mask%%/*}
			add_ip6 "${ip}" "${mask}" ${ETH_DEV}
		else
			let IFNUM=IFNUM+1
			if echo ${ip_mask} | grep -q '/' ; then
				mask=${ip_mask##*/}
			else
				mask='255.255.255.255'
			fi
			ip=${ip_mask%%/*}
			create_config "${ip}" "${mask}" ${ETH_DEV}
		fi
	done

	#clean IPv4
	ip -4 addr flush dev ${ETH_DEV}
	if [ "x$IP4_MASKS" == "x" ] ; then
		if [ $USE_DHCPV4 -eq 1 ] ; then
			echo "
iface ${ETH_DEV} inet dhcp
" >> $CONFIGFILE
		fi
	fi

	# unset IPv6 addresses on interface down
	[ "x$IP6_MASKS" == "x" ] && print_ipv6_header ${ETH_DEV} manual

	if [ "x$IP6_MASKS" == "x" -a $USE_DHCPV6 -eq 1 ] ; then
		#don't support dhcpv6 by config
		set_wide_dhcpv6 ${ETH_DEV}
	else
		unset_wide_dhcpv6 ${ETH_DEV}
	fi
}

function add_ips_nm()
{
	local ip_mask ip mask
	local new_ips=$1

	IFNUM=0
	for ip_mask in ${new_ips}; do
		let IFNUM=IFNUM+1
		if ! is_ipv6 ${ip_mask} ; then
			if echo ${ip_mask} | grep -q '/' ; then
				mask=` echo ${ip_mask##*/} | \
				awk -F '.' 'function calc_digit (n)
				{
					if (n ~ 255) return 8
					if (n ~ 254) return 7
					if (n ~ 252) return 6
					if (n ~ 248) return 5
					if (n ~ 240) return 4
					if (n ~ 224) return 3
					if (n ~ 192) return 2
					if (n ~ 128) return 1
					if (n ~ 0) return 0
					return 127
				}
				function calc_mask (a, b, c, d,  e, mymask)
				{
					e = calc_digit(a)
					if (e !~ 127) mymask += e; else return 1
					e = calc_digit(b)
					if (e !~ 127) mymask += e; else return 1
					e = calc_digit(c)
					if (e !~ 127) mymask += e; else return 1
					e = calc_digit(d)
					if (e !~ 127) mymask += e; else return 1
					print mymask
				}
				{ exit calc_mask($1, $2, $3, $4) }'`
				[ "x$mask" = "x" ] && exit 1
			else
				mask='32'
			fi
			ip=${ip_mask%%/*}
			echo "addresses${IFNUM}=${ip};${mask};0.0.0.0;" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}
		else
			echo "addresses${IFNUM}=${ip_mask},::" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}
		fi

	done

}


function set_ip_nm() {
	local ip_mask ip mask
	local new_ips

	ls $NWSYSTEMCONNECTIONS/* >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		for i in $NWSYSTEMCONNECTIONS/*; do
			cat "$i" | grep -E "$ETH_MAC|$ETH_MAC_NW" >/dev/null 2>&1
			[ $? -eq 0 ] && rm -f "$i"
		done
	fi

	type NetworkManager &>/dev/null
	if [ $? -ne 0 ] ; then
		echo "Network manager ${NWMANAGER} not found"
		exit 3
	fi

	echo "[connection]
id=${ETH_DEV}
uuid=`generate_uuid`
type=802-3-ethernet
autoconnect=true
timestamp=0" > $NWSYSTEMCONNECTIONS/${ETH_DEV}


	if [ "x${IP4_MASKS}" != "x" ] ; then
		echo "
[ipv4]
method=manual" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}

		ip -4 addr flush dev ${ETH_DEV}
		add_ips_nm "${IP4_MASKS}"

		echo "ignore-auto-routes=false
ignore-auto-dns=false
never-default=false
" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}
	else
		echo "
[ipv4]
method=auto
ignore-auto-dns=false
never-default=false
" >> $NWSYSTEMCONNECTIONS/$ETH_DEV
	fi


	if [ "x${IP6_MASKS}" != "x" ] ; then
		echo "
[ipv6]
method=manual" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}

		add_ips_nm "${IP6_MASKS}"

		echo "ignore-auto-routes=false
ignore-auto-dns=false
never-default=false
" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}
	elif [ $USE_DHCPV6 -eq 1 ] ; then
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
mtu=0" >> $NWSYSTEMCONNECTIONS/${ETH_DEV}

	chmod 0600 $NWSYSTEMCONNECTIONS/${ETH_DEV}

	remove_debian_interface ${ETH_DEV} $CONFIGFILE
	remove_debian_interface "${ETH_DEV}:[0-9]+" $CONFIGFILE
}

if [ -f $NWSYSTEMCONF -o -f $NMCONFFILE ]; then
	set_ip_nm
else
	set_ip
fi

$path/debian-restart.sh

exit 0
# end of script
