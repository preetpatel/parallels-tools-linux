#!/bin/bash
#
# Parallels Tools for Linux. Shared Folders automounting tool.
#
# Copyright (c) 1999-2015 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com

MOUNTS=/etc/mtab
SF_LIST=/proc/fs/prl_fs/sf_list
POLL_TIME=5
MNT_OPS=sync,nosuid,nodev,noatime,share
PRL_LOG=/var/log/parallels.log

if [ "$1" = "-f" ]; then
	# Foreground mode: just run remounting once.
	RUN_MODE=f
elif [ "$1" = "-u" ]; then
	# Umount mode: umount everything and exit.
	RUN_MODE=u
else
	# Background mode: do remounting infinitely with POLL_TIME sleep.
	RUN_MODE=b
	PID_FILE=$1
	if test -z "$PID_FILE"; then
		echo "Pid-file must be given as an argument." >&2
		exit 2
	fi

	if ! echo $$ >"$PID_FILE"; then
		echo "Failed to write into pid-file '$PID_FILE'." >&2
		exit 1
	fi
fi

[ -d "/media" ] && MNT_PT=/media/psf || MNT_PT=/mnt/psf

# remove all obsolete mount points in MNT_PT dir
rmdir "$MNT_PT"/* 2>/dev/null

type semodule >/dev/null 2>&1 &&
	MNT_OPS=$MNT_OPS',context=system_u:object_r:removable_t:s0'

prl_log() {
	level=$1
	shift
	msg=$*
	timestamp=`date '+%m-%d %H:%M:%S    '`
	echo "$timestamp $level SHAREDFOLDERS: $msg" >>"$PRL_LOG"
}

# $1 -- SF name
# $2 -- mount point
do_mount() {
	if uname -r | grep -q '^[0-2].[0-4]'; then
		mount -t prl_fs -o $MNT_OPS,sf="$1" none "$2"
	else
		mount -t prl_fs -o $MNT_OPS "$1" "$2"
	fi
	return $?
}

IFS=$'\n'
while true; do
	# Get list of SFs which are already mounted
	curr_mounts=$(cat "$MOUNTS" | awk '{
		if ($3 == "prl_fs") {
			if ($1 == "none") {
				split($4, ops, ",")
				for (i in ops) {
					if (ops[i] ~ /^sf=/) {
						split(ops[i], sf_op, "=")
						print sf_op[2]
						break
					}
				}
			} else {
				n = split($1, dir, "/")
				print dir[n]
			}
		}}')
	# and list of their mount points.
	curr_mnt_pts=$(cat "$MOUNTS" | awk '{if ($3 == "prl_fs") print $2}' | \
		while read -r f; do printf "${f/\%/\%\%}\n"; done)
	if [ -r "$SF_LIST" -a $RUN_MODE != 'u' ]; then
		sf_list=$(cat "$SF_LIST" | sed '
			1d
			s/^[[:xdigit:]]\+: \(.*\) r[ow]$/\1/')
		# Go through all enabled SFs
		for sf in $sf_list; do
			mnt_pt="$MNT_PT/$sf"
			curr_mnt_pts=`echo "$curr_mnt_pts" | sed "/^${mnt_pt//\//\\\/}$/d"`
			# Check if shared folder ($sf) is not mounted already
			printf "${curr_mounts/\%/\%\%}" | grep -q "^$sf$" && continue
			if [ ! -d "$MNT_PT" ]; then
				mkdir "$MNT_PT"
				chmod 755 "$MNT_PT"
			fi
			mkdir "$mnt_pt"
			mount_out=`do_mount "$sf" "$mnt_pt" 2>&1`
			rc=$?
			if [ $rc -eq 0 ]; then
				prl_log I "Mounted shared folder '$sf'"
			else
				prl_log E "Failed to mount shared folder '$sf'. " \
					"Retcode=$rc Output: $mount_out"
			fi
		done
	fi
	# Here in $curr_mnt_pts is the list of SFs which are disabled
	# but still mounted -- umount all them.
	for mnt_pt in $curr_mnt_pts; do
		# Skip all those mounts outside of our automount directory.
		# Seems user has mounted them manually.
		if ! echo "$mnt_pt" | grep -q "^${MNT_PT}"; then
			prl_log I "Skipping shared folder '${mnt_pt}'"
			continue
		fi
		umount_out=`umount "$mnt_pt" 2>&1`
		rc=$?
		if [ $rc -eq 0 ]; then
			prl_log I "Umounted shared folder '$mnt_pt'"
			rmdir "$mnt_pt"
		else
			prl_log E "Failed to umount shared folder '$mnt_pt'. " \
				"Retcode=$rc Output: $umount_out"
		fi
	done
	[ $RUN_MODE != 'b' ] && exit $rc
	sleep $POLL_TIME
done
