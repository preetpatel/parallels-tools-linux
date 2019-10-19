#!/bin/bash
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
#
# Script prints to stdout list of registered in Linux system services in format:
# service_name (running|stopped)
# where 'running' means service is enabled for default runlevel while
# 'stopped' - disabled.
#

SERVICE="/usr/bin/service"

function list_services_chkconfig
{
	xinetd_enabled=0
	runlevel=`/sbin/runlevel | awk '{print $2}'`

	if [ -z "$runlevel" ]; then
		# we failed to determine current runlevel
		return;
	fi

	/sbin/chkconfig --list | \
		sed -n "s/^\(\w\+\)\s\+.*$runlevel:\(\w\+\).*$/\1 \2/p;
			/^\s\+\w\+/p" | \
	while read service state; do
		if `echo $service | grep -q ":$"`; then
			# xinetd based service
			if [ $xinetd_enabled -ne 1 ]; then
				continue
			fi
			echo -n "${service%:}"
		else
			echo -n "$service"
		fi

		if [ $state == "on" ]; then
			echo " running"
		else
			echo " stopped"
		fi

		if [ "$service" == "xinetd" -a "$state" == "on" ]; then
			xinetd_enabled=1
		fi
	done
}

function list_services_service
{
	$SERVICE --status-all 2>&1 | \
		sed -n "s/^ \[ \(.\) \]\s\+\(.*\)$/\2 \1/p" | \
	while read service state; do
		echo -n "$service"
		if [ $state == "+" ]; then
			echo " running"
		elif [ $state == "-" ]; then
			echo " stopped"
		else
			echo " unknown"
		fi
	done
}

if [ -x /sbin/chkconfig ]; then
	list_services_chkconfig
elif [ -x $SERVICE ]; then
	list_services_service
elif [ -x /usr/sbin/service ]; then
	SERVICE="/usr/sbin/service"
	list_services_service
fi
