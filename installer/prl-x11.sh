#!/bin/bash

### BEGIN INIT INFO
# Provides: prl-x11
# Required-Start:
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Autostart script for Parallels service
# Description: Autostart script for Parallels service that configure X server in guest.
### END INIT INFO

###########################################################################
# Autostart script for Parallels service that configure X server in guest.
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
###########################################################################


###
# chkconfig: 345 06 20
# description: Autostart script for Parallels service that configure X server in guest.
###

. "/usr/lib/parallels-tools/installer/prl-functions.sh"

PATH=${PATH:+$PATH:}/sbin:/bin:/usr/sbin:/usr/bin
pidfile="/var/run/prl-x11.pid"

###########################################################################
# Set configuration data
###########################################################################
xorgconffixer="/usr/sbin/prl-xorgconf-fixer"
xorgconf=`readlink -f "/etc/X11/xorg.conf"`

show_vm_cfg="/usr/bin/prl_showvmcfg"
opengl_switcher="/usr/sbin/prl-opengl-switcher.sh"

log="/var/log/parallels.log"

[ ! -f $log ] && touch $log && chmod go+rw $log

###########################################################################
# Helpers functions
###########################################################################
process_opengl() {
	# Show in log Xorg process to detect is X server already running
	echo "Xorg processes:" >> "$log"
	ps -eo comm,args | grep Xorg | grep -v grep >> "$log"
	echo "End of Xorg processes" >> "$log"

	if [ ! -x "$opengl_switcher" ]; then
		echo "Can not find executable OpenGL switching tool by path $opengl_switcher" >> "$log"
		return 1
	fi

	if [ ! -x "$show_vm_cfg" ]; then
		echo "Can not find executable Show Vm config binary by path $show_vm_cfg" >> "$log"
		return 1
	fi

	vm_cfg=$("$show_vm_cfg")
	echo "Output of show_vm_cfg utility: $vm_cfg" >> "$log"
	opengl_support=$(echo "$vm_cfg" | grep 'opengl-support:' | awk '{print $2}')
	if [ "x$opengl_support" == "x1" ]; then
		echo "Found OpenGL support in host; set up OpenGL libs in guest" >> "$log"
		"$opengl_switcher" --on >> "$log" 2>&1
	else
		echo "No OpenGL support in host; skip set up OpenGL libs in guest" >> "$log"
		"$opengl_switcher" --off >> "$log" 2>&1
	fi
	return 0
}

###########################################################################
# Start operation for tools' daemon
###########################################################################
start() {
	# Check xorg.conf
	if [ -r "$xorgconf" -a -w "$xorgconf" ]; then
		if ! "$xorgconffixer" check "$xorgconf"; then
			echo $"Xorg config file is broken. Fixing..." >> "$log"

			# Backup xorg.conf
			xorgconf_backup="$xorgconf.$(date +'%Y-%m-%d_%H-%M-%S')"
			cp "$xorgconf" "$xorgconf_backup"
			echo $"Xorg config file back up $xorgconf_backup" >> "$log"

			# Run fixer
			if ! "$xorgconffixer" fix "$xorgconf"; then
				echo $"   Unable to fix Xorg config file. Please contact support for help"
				echo $"Unable to fix Xorg config file" >> "$log"
				mv "$xorgconf_backup" "$xorgconf"
			fi
		fi
	fi

	process_opengl || echo "Error during set up  OpenGL libraries" >> "$log"
}

# See how we were called.
case "$1" in
  start)
	echo "$$" > "$pidfile"
	start
	rm "$pidfile"
		;;
  stop)
	# Do nothing
		;;
  status)
	status "prl-x11" "$pidfile"
		;;
  *)
		echo $"Usage: $0 {start|status|stop}"
		exit 1
esac

exit 0
