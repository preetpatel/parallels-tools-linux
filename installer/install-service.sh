#!/bin/sh
####################################################################################################
# @file install-service.sh
#
# Perform installation or removal of service.
#
# @author ayegorov@
# @author owner is alexg@
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
####################################################################################################

LEVEL="$3"
SERVICE="$2"
DEFAULT="$def_sysconfdir/rc.local"

####################################################################################################
# Definition of error codes
####################################################################################################

E_NOERROR=0
E_NOACT=121
E_NOSRV=122
E_FAIL=123

####################################################################################################
# Show error
####################################################################################################

perror() {
	echo $1 1>&2
}

####################################################################################################
# Remove registered service
####################################################################################################

remove_service() {
	if type chkconfig > /dev/null 2>&1; then
		# RedHat, SuSe
		chkconfig --del "$SERVICE"
	elif type update-rc.d > /dev/null 2>&1; then
		# Debian
		update-rc.d -f "$SERVICE" remove
	elif type rc-update > /dev/null 2>&1; then
		# Gentoo
		rc-update del "$SERVICE" default
	elif [ -n "$def_sysconfdir" ]; then
		# Generic
		sed -i -e '/^[[:space:]]*\/etc\/init.d\/$SERVICE/d' "$DEFAULT"
	else
		perror "Error: there is no option to remove $SERVICE service"
		return $E_FAIL
	fi
}

####################################################################################################
# Install service
####################################################################################################

install_service() {
	if type chkconfig > /dev/null 2>&1; then
		# RedHat, SuSe
		chkconfig --add "$SERVICE"
		chkconfig --level 2345 "$SERVICE" on
	elif type update-rc.d > /dev/null 2>&1; then
		# Debian
		update-rc.d "$SERVICE" start "$LEVEL" 2 3 4 5 . stop 0 0 1 6 .
	elif type rc-update > /dev/null 2>&1; then
		# Gentoo
		rc-update add "$SERVICE" default
	elif [ -n "$def_sysconfdir" ]; then
		# Generic
		echo "" >> "$DEFAULT"
		echo "Run Parallels $SERVICE service" >> "$DEFAULT"
		echo "/etc/init.d/$SERVICE start" >> "$DEFAULT"
	else
		perror "Error: there is no option to install $SERVICE service"
		return $E_FAIL
	fi
}

####################################################################################################
# Start installation or removal of service
####################################################################################################

if [ -z "$SERVICE" ]; then
	perror "Error: service to be installed or removed was not specified"
	exit $E_NOSRV
fi

[ -z "$LEVEL" ] && LEVEL=99

case "$1" in
	-i | --install)
		install_service
		result=$?
		if [ $result -ne $E_NOERROR ]; then
			perror "Error: failed to install $SERVICE service"
		else
			echo "Installation of $SERVICE service was finished successfully"
		fi
		exit $result
		;;
	-r | --remove)
		remove_service
		result=$?
		if [ $result -ne $E_NOERROR ]; then
			perror "Error: failed to remove $SERVICE service"
		else
			echo "Removal of $SERVICE service was finished successfully"
		fi
		exit $result
		;;
esac

exit $E_NOACT
