#!/bin/sh
###########################################################################
# Autostart script for guest tools' service.
#
# Copyright (c) 2005-2015 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
###########################################################################


###
# chkconfig: 2345 10 20
# description: Autostart script for guest tools' service.
###

### BEGIN INIT INFO
# Provides: prltoolsd
# required-start:
# required-stop:
# Default-Start: 2 3 4 5
# Default-Stop:  0 1 6
# Description:   Autostart script for guest tools' service.
### END INIT INFO

. "/usr/lib/parallels-tools/installer/prl-functions.sh"

PATH=${PATH:+$PATH:}/sbin:/bin:/usr/sbin:/usr/bin

###########################################################################
# Set configuration data
###########################################################################

prlfile="prltoolsd"
exefile="/usr/bin/${prlfile}"
pidfile="/var/run/${prlfile}.pid"

lockdir=/var/lock/subsys
lockfile=$lockdir/prltoolsd

log="/var/log/parallels.log"

touch $log
chmod go+rw $log

# Set custom options if they are required
PRLTOOLSD_OPTIONS="-p $pidfile"

# Don't load prl_freeze on system with 2.4 kernel and older.
# And check if avaiable on the current system.
if ! uname -r | grep -q '^[0-2]\.[0-4]'; then
	modpath=$(modprobe -l prl_fs_freeze 2>/dev/null)
	if modprobe -n prl_fs_freeze 2>/dev/null ||
		[ -n "$modpath" ]; then
		LOAD_PRL_FREEZE="yes"
	fi
fi

prl_begin_msg() {
	echo -n "$*" | tee -a "$log"
}

prl_end_msg() {
	echo "$*" | tee -a "$log"
}

prl_log_msg() {
	echo "$*" | tee -a "$log"
}

###########################################################################
# Install client ID for wireless bridged networking
###########################################################################

# Install record for client ID sending for each networking card
# in the system in the dhclient.conf (dhclient is installed)
dhclient_install() {
	# Locate dhclient.conf using strings. The directory can be
	# different on different distributions
	CONF=`strings /sbin/dhclient | grep etc | grep dhclient.conf`
	IFACES=$*

	# and can even not exists...
	mkdir -p `dirname $CONF`
	touch $CONF

	for IFACE in $IFACES; do
		HWADDR=`ifconfig -a | grep ^$IFACE | awk '{ print $5 }'`
		export IFACE HWADDR

		# Install section like
		# interface "eth0" {
		#	send dhcp-client-identifier 1:<real_mac>;
		# }
		# or leave it untouched if present
		awk '
			BEGIN {
				inside_iface = 0
				iface_found = 0
			}
			END {
				iface = ENVIRON["IFACE"]
				addr = ENVIRON["HWADDR"]
				if (!iface_found) {
					print "interface \""iface"\" {"
					print "	send dhcp-client-identifier 1:"addr"; # Remove this comment on manual client-id modification"
					print "}"
				}
			}

			/^ *interface/ {
				iface = ENVIRON["IFACE"]
				test_if = $2
				gsub(/\"/, "", test_if)
				gsub(/ /, "", test_if)
				if (test_if == iface)
					iface_found = inside_iface = 1
			}

			/dhcp-client-identifier/ {
				str = $0
				if (inside_iface &&
					match(str, /Remove this/))
					next
				else
					inside_iface = 0
			}

			/\}/ {
				addr = ENVIRON["HWADDR"]

				if (inside_iface)
					print "	send dhcp-client-identifier 1:"addr"; # Remove this comment on manual client-id modification"
				inside_iface = 0
			}

			{
				print $0
			}
		' $CONF >$CONF.tmp1 || exit 0
		mv $CONF.tmp1 $CONF
	done
}

# Install key to send client ID (dhcpcd is installed)
# Kludge to do this on the per/interface basis is not found
dhcpc_install() {
	CONF="/etc/sysconfig/network/dhcp"
	HWADDR=`/sbin/ifconfig -a | awk '/HWaddr/ { print $5 ; exit }'`
	export HWADDR
	awk '/DHCLIENT_CLIENT_ID=/{
		str = str1 = $0
		sub(/\".*\"/, "", str1)
		if (length(str1) + 2 >= length(str) || match($str, /Remove this/))
			print "DHCLIENT_CLIENT_ID=\"1:"ENVIRON["HWADDR"]"\" # Remove this comment on manual client-id modification"
		else
			print $0
		next
	}
	{
		print $0
	}
	' $CONF >$CONF.tmp1 || exit 0
	mv $CONF.tmp1 $CONF
}

clientid_install() {
	IFACES=`ifconfig -a | awk '/HWaddr/{ print $1 }' | xargs`
	if [ -n "$IFACES" ]; then
		[ -f /sbin/dhclient ] && dhclient_install $IFACES
		[ -f /etc/sysconfig/network/dhcp ] && dhcpc_install $IFACES
	fi
}


###########################################################################
# Start and Stop operations for tools' daemon
###########################################################################

start() {
	local vmcheck='/usr/bin/prlvmcheck'
	if [ -x "$vmcheck" ]; then
		"$vmcheck" || return
	fi

	prl_begin_msg "Loading Parallels ToolsGate driver: "
	if modprobe prl_tg; then
		prl_end_msg "done"
	else
		prl_end_msg "failed"
	fi

	prl_begin_msg "Loading Parallels Network driver: "

	# Installing client-id to the DHCP client configuration
	# is temporary disabled.

	#clientid_install

	if modprobe prl_eth; then
		prl_end_msg "done"
	else
		prl_end_msg "failed"
	fi

	prl_begin_msg "Loading Parallels Shared Folders driver: "
	if modprobe prl_fs; then
		prl_end_msg "done"
		prl_begin_msg "Mounting Parallels Shared Folders: "
		if mount -a -t prl_fs; then
		prl_end_msg "done"
		else
			prl_end_msg "failed"
		fi
	else
		prl_end_msg "failed"
	fi

	if [ -n "$LOAD_PRL_FREEZE" ]; then
		prl_begin_msg "Loading Parallels Filesystem Freeze driver: "
		if modprobe prl_fs_freeze; then
		prl_end_msg "done"
		else
			prl_end_msg "failed"
		fi
	fi

	if fgrep -qs CONFIG_ACPI_HOTPLUG_MEMORY=m /boot/config-$(uname -r); then
		prl_begin_msg "Loading ACPI memory hotplug module: "
		if modprobe acpi_memhotplug; then
		prl_end_msg "done"
		else
			prl_end_msg "failed"
		fi
	fi

	[ -d "$lockdir" ] && touch "$lockfile"

	if [ -f "$pidfile" ]; then
		prlpid=`cat "$pidfile"`

		kill -0 "$prlpid"
		if [ $? -eq 0 ]; then
		prl_log_msg "Daemon alive with pid $prlpid"
		return 0
		else
			rm -f "$pidfile";
		fi
	fi

	prl_begin_msg "Starting Parallels tools daemon: "

	LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/usr/lib/parallels-tools/lib"
	export LD_LIBRARY_PATH

	if [ "$1" = "dry" ]; then
		return 0
	fi
	daemon_output=`$exefile ${PRLTOOLSD_OPTIONS} 2>&1`
	RETVAL=$?
	if [ $RETVAL -eq 0 ]; then
		prl_end_msg "done"
	else
		prl_end_msg "failed"
		echo "$daemon_output" >>"$log"
	fi

	return $RETVAL
}

stop() {
	RETVAL=0

	prlfsmountd='/usr/bin/prlfsmountd'
	if [ -x "$prlfsmountd" ]; then
		prl_begin_msg "Umounting Shared Folders: "
		"$prlfsmountd" -u && prl_end_msg "done" || prl_end_msg "failed"
	fi

	prl_begin_msg "Shutting down Parallels tools daemon: "

	if [ -f "$pidfile" ]; then
		prlpid=`cat "$pidfile"`
		kill "$prlpid" >/dev/null 2>&1
		RETVAL=$?
	fi

	if [ $RETVAL -eq 0 ]; then
		prl_end_msg "done"
	else
		prl_end_msg "failed"
	fi

	rm -f "$lockfile"
	return $RETVAL
}


###########################################################################
# Start/stop guest tools' service
###########################################################################

case "$1" in
	start)
		start
	;;
	stop)
		stop
	;;
	restart)
		stop
		start
	;;
	prestart)
		start dry
	;;
	status)
		status "prltoolsd" "$pidfile"
	;;
	*)
		echo "=> This script starts/stops Parallels guest tools' service"
		echo "Usage: $0 <start | stop | restart | status>"
		exit 1
	;;
esac

exit $?
