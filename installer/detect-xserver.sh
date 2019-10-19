#!/bin/bash
####################################################################################################
# @file detect-xserver.sh
#
# Detect Xorg version and modules directory
#
# @author ksenks@
# @author owner is anatolykh@
#
# Copyright (c) 2005-2016 Parallels International GmbH
# All rights reserved.
# http://www.parallels.com
####################################################################################################

PATH=${PATH:+$PATH:}/sbin:/bin:/usr/sbin:/usr/bin:/usr/X11R6/bin

ARCH=$(uname -m)

E_NOERR=0
E_NOPARAM=150
E_NOXSERV=163
E_NOXMODIR=164

####################################################################################################
# Definition of X.Org server configuration directories
####################################################################################################

# Note that this variable is used for 64-bit Debian-based systems as well.
XORG_MODULES_DIRS32="/usr/lib/xorg/modules      \
                     /usr/lib/X11/modules       \
                     /usr/X11R6/lib/modules"

XORG_MODULES_DIRS64="/usr/lib64/xorg/modules    \
                     /usr/lib64/X11/modules     \
                     /usr/X11R6/lib64/modules"


####################################################################################################
# Show error
####################################################################################################

perror() {
	echo $1 1>&2
}

####################################################################################################
# Detection of Xorg version in format - major.minor
####################################################################################################
get_x_server_version() {
	xver=`get_x_server_version_full`
	ret=$? 
	if [ $ret -ne $E_NOERR ]; then
		exit $ret
	fi
	xver="$(echo $xver | awk -F . '{ printf "%s.%s", $1, $2 }')"
	echo "$xver"
	exit $E_NOERR
}

####################################################################################################
# Detection of Xorg version in full format - major.minor.patch
####################################################################################################
get_x_server_version_full() {
	xver=
	if type Xorg > /dev/null 2>&1; then
		# Get version of X.Org server
		xver=$(Xorg -version 2>&1 | grep -i "x.org x server" | awk '{ print $4 }' | awk -F . '{ printf "%s.%s.%s", $1, $2, $3 }')
		if [ -z "$xver" ]; then
			xver=$(Xorg -version 2>&1 | grep -i "x window system version" | awk '{ print $5 }' | awk -F . '{ printf "%s.%s.%s", $1, $2, $3 }')
			if [ -z "$xver" ]; then
				xver=$(Xorg -version 2>&1 | grep -i "x protocol version" | awk '{ print $8 }' | awk -F . '{ printf "%s.%s", $1, $2 }')
			fi
		fi
	else
		perror "Error: XFree86 server is not supported now"
	fi
	if [ -z "$xver" ]; then
		perror "Error: could not determine X server version"
		exit $E_NOXSERV
	fi
	echo "$xver"
	exit $E_NOERR
}

####################################################################################################
# Detection of Xorg modules source installation directoy, according to the current Xorg version
#     param $1 - base directory to search installation x modules from
####################################################################################################
get_xmodules_source_dir() {
	xbasedir=$1
	if [ ! -d $xdirbase ]; then
		exit $E_NOXMODIR
	fi
	xver=`get_x_server_version_full`
	ret=$? 
	if [ $ret -ne $E_NOERR ]; then
		exit $ret
	fi

	# Find source directory with required modules
	xmods=""
	found=0
	vmajor=$(echo $xver | awk -F . '{ printf "%d", $1 }')
	vminor=$(echo $xver | awk -F . '{ printf "%d", $2 }')
	vpatch=$(echo $xver | awk -F . '{ printf "%d", $3 }')
	if (( $vpatch >= 0 )) && (( $vpatch < 100 )); then
		for (( v=$vpatch; v>=0; v-- )); do
		        xmods="$xbasedir/xorg.$vmajor.$vminor.$v"
		        if [ -d "$xmods" ]; then
		                found=1
		                break
		        fi
		done
	fi
	if (( found != 1 )); then
		xmods="$xbasedir/xorg.$vmajor.$vminor"
		if [ ! -d "$xmods" ]; then
			perror "Error: no prebuilt modules for X server ($xver)"
			exit $E_NOXMODIR
		fi
	fi

	echo "$xmods"
	exit $E_NOERR
}

####################################################################################################
# Detection of Xorg modules directories
####################################################################################################
get_xmodules_dir() {
	xdirs=
	if [ "$ARCH" = "x86_64" ]; then
		# For 64-bit Debian-based systems 64-bit stuff is placed in /lib and
		# /usr/lib. So need to go through _DIRS32 as well.
		# It should be noted that if the system was updated from 32-bit one
		# this code may not work correctly. But it's not clear how it should
		# work in this case.
		xdirs="$XORG_MODULES_DIRS64 $XORG_MODULES_DIRS32"
	else
		xdirs="$XORG_MODULES_DIRS32"
	fi
	for xdir in $xdirs; do
		if [ -d "$xdir" ]; then
			echo "$xdir"
			exit $E_NOERR
		fi
	done

	perror "Error: could not find system directory with X modules"
	exit $E_NOXMODIR
}

case "$1" in
	-v | --xver)
		get_x_server_version
		;;
	-vf | --xverfull)
		get_x_server_version_full
		;;
	-dsrc | --xsrcdir)
		get_xmodules_source_dir $2
		;;
	-d | --xdir)
		get_xmodules_dir
		;;
	*)
		perror "Error: not enough parameteres"
		exit $E_NOPARAM
esac

