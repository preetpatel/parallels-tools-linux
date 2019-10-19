#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script restart network inside Debian like VM.
#

prog="$0"
path="${prog%/*}"
funcs="$path/functions"
NMCONFIGFILE="/etc/NetworkManager/NetworkManager.conf"

tag="prl_nettool:"$(basename "$prog")

log_warn() {
	_log "Warning" "$1"
}


log_err() {
	_log "Error" "$1"
}


log_fatal() {
	_log "Fatal error" "$1"
}


log() {
	_log "" "$1"
}


_log() {
	[[ $1 ]] && local level=$1": "
	local message=$2
	logger -t "$tag" "${level}${message}"
}


ctl_nm() {
	if ! type NetworkManager > /dev/null 2>&1; then
		log_warn "NetworkManager not found, skipping action $1"
		# Don't need this function anymore, if NetworkManager is missing
		ctl_nm() {
			return
		}
		return
	fi
	# In ubuntu 14.04 Desktop or based distros like Linux Mint
	# network-manager is restarted and watched by initctl
	if type initctl > /dev/null 2>&1; then
		initctl $1 network-manager
		local code=$?
		if [[ $code -ne 0 ]]; then
			log_warn "initctl $1 network-manager failed with code $code"
			log_warn "falling back to systemctl and initscript"
		else
			return 0
		fi
	fi

	# In newer Ubuntu and Debian systemctl is a main system control tool
	if type systemctl > /dev/null 2>&1; then
		systemctl $1 network-manager
		local code=$?
		if [[ $code -ne 0 ]]; then
			log_warn "systemctl $1 network-manager failed with code $code"
			log_warn "falling back to initscript"
		else
			return 0
		fi
	fi

	# fall back to SysV init scripts
	local nw_script="/etc/init.d/network-manager"
	if [[ -x "$nw_script" ]]; then
		"$nw_script" $1
		local code=$?
		if [[ $code -ne 0 ]]; then
			log_err "$nw_script $1 failed with code $code"
			# initscript is a last resort. if it failed, then
			# other methods are failed us too
			exit $code
		else
			return 0
		fi
	fi

	log_err "can't find a way to $1 NetworkManager!"
	log_err "neither of initctl, systemctl or $nw_script found in system!"
	exit 1
}

# ip wrapper with error checking
ctl_ip() {
	ip "$@"
	code=$?
	if [[ $code -ne 0 ]]; then
	    log_err "ip $@ failed with code $code"
	    exit $code
	fi
}

if [[ -f "$funcs" ]] ; then
	. $funcs
else
	log_fatal "file ${func} not found. Exiting"
	exit 1
fi

ctl_nm stop

interfaces=$(ctl_ip addr show | grep "^.*: .*,\?UP" | cut -d: -f2)
for i in $interfaces; do
	ctl_ip link set $i down
	ctl_ip addr flush $i
	ctl_ip link set $i up
done

ifdown -a
ifup -a

ctl_nm start

log "Network restarted"

exit 0
