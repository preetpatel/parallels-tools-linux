#!/bin/sh
### BEGIN INIT INFO
# Provides:			 prltools updater
# Required-Start:	 $network $local_fs
# Required-Stop:
# Default-Start:	 2 3 4 5
# Default-Stop:		 0 1 6
# Short-Description: Parallels tools autoupdater service for sysV
# Description:		 Copyright (c) 2004-2014 Parallels International GmbH.
#### END INIT INFO
###
# chkconfig: 345 06 20
# description: Autostart script for Parallels service that autoupdate tools in guest.
###

. "/usr/lib/parallels-tools/installer/prl-functions.sh"

PATH=${PATH:+$PATH:}/sbin:/bin:/usr/sbin:/usr/bin

log="/var/log/parallels.log"
touch $log && chmod go+rw $log

pidfile="/var/run/prltools_updater.pid"

start()
{
	prltools_updater.sh -i
}

case "$1" in
  start)
	echo "$$" > "$pidfile"
	start
	rm "$pidfile"
		;;
  status)
	status "prltools_updater" "$pidfile"
		;;
  stop)
		;;
  *)
		echo "Usage: $0 {start|status}"
		exit 1
esac

exit 0
