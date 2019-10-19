###############################################################################
# Common functions for Parallels init scripts
#
# Copyright (c) 2005-2016 Parallels International GmbH
# All rights reserved.
# http://www.parallels.com
###############################################################################

status() {
	local prefix="$1" # name of service we're checking
	local pidfile="$2"
	echo -n "$prefix "
	if [ -r "$pidfile" ]; then
		local prlpid=$(cat "$pidfile")
		kill -0 $prlpid 2>/dev/null
		if [ $? -eq 0 ]; then
			echo "(pid $prlpid) is running..."
			exit 0
		fi
		# script crashed somehow, only .pid file left
		echo "has crashed!"
		exit 1
	else
		echo "is stopped"
		exit 3
	fi
}
