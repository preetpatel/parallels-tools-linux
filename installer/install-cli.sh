#!/bin/bash
#
# Installation, deinstallation or upgrade of Parallels Guest Tools for Linux.
# Copyright (c) 1999-2017 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com

PATH=/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}
export LANG=C

TOOLS_NAME='Parallels Guest Tools'
BASE_DIR=$(readlink -f "$(dirname "$(readlink -f "$0")")/..")

# Installation package files
INSTALLER_DIR="$BASE_DIR/installer"
KMODS_DIR="$BASE_DIR/kmods"
TOOLS_DIR="$BASE_DIR/tools"
INSTALL="$BASE_DIR/install"
INSTALL_GUI="$BASE_DIR/install-gui"

PMANAGER="$INSTALLER_DIR/pm.sh"

# Dracut kmods blacklist file
DRACUT_CONF_DIR="/etc/dracut.conf.d"
DRACUT_KMODS_FILE="/etc/dracut.conf.d/parallels-tools.conf"

# Target installation files
# The IBACKUP folder is the backupfolder in /var/lib
# the BACKUP folder is the old one in /usr/lib we save it
# in order not to broke the upgrade procedure of the old
# version of parallels-tools

IBACKUP_DIR="/var/lib/parallels-tools"
INSTALL_DIR="/usr/lib/parallels-tools"
INSTALL_DIRS="$INSTALL_DIR \
		/usr/lib/parallels-server-tools \
		/usr/lib/parallels"
MODPROBED_DIR="/etc/modprobe.d"
MODPROBE_CONF="/etc/modprobe.conf"
ALIAS_NE2K_OFF="install ne2k-pci /bin/true # replaced by prl_eth"
ALIAS_NE2K_OVERRIDE="install ne2k-pci modprobe -q prl_eth || modprobe -i ne2k-pci"
MODPROBE_PRL_ETH_CONF="$MODPROBED_DIR/prl_eth.conf"

INSTALL_DIR_KMODS="$INSTALL_DIR/kmods"
INSTALL_DIR_TOOLS="$INSTALL_DIR/tools"

if [ -z "$FLAG_CHECK_GUI" ]; then
	FLAG_CHECK_GUI=""
fi

# Kernel modules installation/removal
KVER=$(uname -r)
KDIR="/lib/modules/$KVER/extra"

if [ -r "$INSTALL_DIR/version" ]; then
	FULL_PRODUCT_VERSION=$(cat "$INSTALL_DIR/version")
fi
INSTALL_FULL_PRODUCT_VERSION=$(cat "$BASE_DIR/version")

# Kernel modules to be installed
KMODS_PATHS="prl_eth/pvmnet \
	prl_tg/Toolgate/Guest/Linux/prl_tg \
	prl_fs/SharedFolders/Guest/Linux/prl_fs"

# Extentions of kernel modules depend on version
if [ "$KVER" = "$(echo -e "$KVER"'\n2.5' | sort -t'.' -g | tail -n 1)" ]; then
	KEXT=ko
	KMODS_PATHS="$KMODS_PATHS prl_fs_freeze/Snapshot/Guest/Linux/prl_freeze"
else
	KEXT=o
fi

UPDATE_MODE=0
RESTORE_ON_FAIL=0
REBOOT_REQUIRED=0

# Tools locations and helper scripts and files
DETECT_X_SERVER="$INSTALLER_DIR/detect-xserver.sh"
REGISTER_SERVICE="$INSTALLER_DIR/install-service.sh"

XCONF_BACKUP="$IBACKUP_DIR/.xconf.info"
TOOLS_BACKUP="$IBACKUP_DIR/.tools.list"
PSF_BACKUP="$IBACKUP_DIR/.psf"
SLP_BACKUP="$IBACKUP_DIR/.${SLP_NAME}.selinux"

ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
	TOOLS_BIN_DIR="$INSTALL_DIR_TOOLS/prltools.x64"
else
	TOOLS_BIN_DIR="$INSTALL_DIR_TOOLS/prltools"
fi
COMMON_TOOLS_BIN_DIR="$TOOLS_BIN_DIR/xorg.7.1"

# System directories
BIN_DIR="/usr/bin"
SBIN_DIR="/usr/sbin"
INITD_DIR="/etc/init.d"
INIT_DIR="/etc/init"
ICONS_DIR="/usr/share/icons/hicolor"
KERNEL_CONFIG="/boot/config-$KVER"

# X server configuration variables
XVERSION=""
XMODULES_SRC_DIR=""
XMODULES_DIR=""

# User space modules
TOOLSD="prltoolsd"
TOOLSD_SERVICE="$INSTALLER_DIR/$TOOLSD.sh"
TOOLSD_ISERVICE="$INITD_DIR/$TOOLSD"
TOOLSD_SD_SERVICE="$TOOLSD.service"        # systemd service file
TOOLSD_JOB="$INSTALLER_DIR/$TOOLSD.conf"        # upstart job config
TOOLSD_INSTALL_JOB="$INIT_DIR/$TOOLSD.conf"

XTOOLS="prl-x11"
XTOOLS_SERVICE="$INSTALLER_DIR/$XTOOLS.sh"
XTOOLS_ISERVICE="$INITD_DIR/$XTOOLS"
XTOOLS_JOB="$INSTALLER_DIR/$XTOOLS.conf"
XTOOLS_INSTALL_JOB="$INIT_DIR/$XTOOLS.conf"
XTOOLS_SD_SERVICE="$XTOOLS.service"

UTOOLS="prltools_updater"
UTOOLS_SERVICE_INIT="$INSTALLER_DIR/${UTOOLS}_sysv.sh"
UTOOLS_ISERVICE="$INITD_DIR/$UTOOLS"
UTOOLS_JOB="$INSTALLER_DIR/$UTOOLS.conf"
UTOOLS_INSTALL_JOB="$INIT_DIR/$UTOOLS.conf"
UTOOLS_SD_SERVICE="$UTOOLS.service"

OPENGL_SWITCHER="prl-opengl-switcher.sh"

# Error codes
E_NOERROR=0
E_NOLINUX=101
E_NOPERM=102
E_NOARGS=103
E_WARG=104
E_NOTOOLS=106
E_PMLOCKED=123 # defined in pm.sh
E_NOPM=124   # defined in pm.sh
E_BFAIL=143
E_NOPKG=149
E_CHKFAIL=150
E_NOXSERV=163
E_NOXMODIR=164
E_BFAIL=167
E_IFAIL=168

# Logging routines
LOG="/var/log/parallels-tools-install.log"
VERBOSE=0

start_logging() {
	if [[ $VERBOSE -eq 1 ]]; then
		# Both errors and other output goes to both terminal and log file
		exec &> >(tee -a "$LOG")
	else
		# Only errors are reported to the user, other output goes to the log
		# We still need to tell user some things sometimes,
		# so save original stdout
		exec 3>&1
		exec 2> >(tee -a "$LOG") >> "$LOG"
	fi
}

# Uncondional console output, regardless of VERBOSE state
# For example, we want to tell user to reboot the VM after
# tools installation, even if it was installed in silent mode
tell_user() {
	echo $@
	if [[ $VERBOSE -eq 0 ]]; then
		# original stdout is in 4th descriptor so
		# we ensure that user recieved our message
		echo $@ >&3
	fi
}

# Show error
# Error message should always go to the log and to console
perror() {
	echo "$1" >&2
}

# Report installation progress for ptiagent-gui
PROGR_TOTAL=10
PROGR_CURR=0
SHOW_PROGRESS=0
echo_progress() {
	[ $SHOW_PROGRESS -eq 0 ] && return
	p=$(awk -v a=$PROGR_TOTAL -v b=$PROGR_CURR  \
		'BEGIN {printf("%f", (100 / a * b))}')
	tell_user "installer:%$p"
	let PROGR_CURR+=1
}

# Help message
usage() {
	cat << EOF
Perform installation, deinstallation or upgrade of Parallels Guest Tools for Linux
Usage: $0 [option] [--skip-rclocal-restore] [--progress] [--restore-on-fail]
         -i, --install                    install or upgrade Parallels tools in Guest OS
         --install-unattended             perform unattended installation or upgrade of Parallels tools
         --install-unattended-with-deps   perform unattended installation or upgrade of Parallels tools
                                          with downloading required packages
         --install-ptiagent               install Parallels Tools Installation Agent only
         -r, --remove                     remove Parallels tools from Guest OS
         -v, --version                    output version information
         -h, --help                       display this help message
         --skip-rclocal-restore           flag to disable restoring /etc/rc.local broken by unsuccessful
                                          express installation (for Ubuntu systems)
         --progress                       show installation progress in terminal
         --verbose                        report installation process also to stdout
         --restore-on-fail                try to restore previous Parallels Guest Tools installation
                                          (if it exists) in case of this one is failed
EOF
}

# Check requirements to run this script
check_requirements() {
	if [ "x$(uname -s)" != "xLinux" ]; then
		perror "Error: these $TOOLS_NAME can be installed on Linux guest OS only."
		exit $E_NOLINUX
	fi

	if [ "x$(id -u)" != "x0" ]; then
		perror "Error: you do not have permissions to run this script."
		exit $E_NOPERM
	fi
}

check_required_packages() {
	# Check... are there required package manager and packages?
	local packages retcode
	packages=$("$PMANAGER" --check gtools)
	retcode=$?
	packages=$(echo "$packages" | grep '^[mo] ')
	[[ -z "$packages" && $retcode -eq 0 ]] && return $E_NOERROR

	for i in {1..10}; do
		"$PMANAGER" --install gtools
		local result_pm=$?
		# pm.sh retcode E_PMLOCKED (123) means package manager is locked at the
		# moment. It is highly probale if PTfL are updated after VM resume. So
		# let's retry installation attempt after 10 seconds pause.
		[ $result_pm -ne $E_PMLOCKED ] && break
		[ $i -ne 10 ] &&
			echo 'Package manager is locked. Trying once again.' && sleep 10
	done

	[ $result_pm -eq 0 ] && return $E_NOERROR
	[ $result_pm -eq $E_NOPM ] &&
		perror "Error: none of supported package managers found in system." ||
		perror "Error: failed to install mandatory packages."
	return $E_CHKFAIL
}

check_restrictions() {
	# Do not check restrictions if and only if
	# we are installing tools from GUI application
	if [ -z "$FLAG_CHECK_GUI" ]; then
		# Perform basic checks
		check_requirements
		check_required_packages
		result=$?
		[ $result -ne $E_NOERROR ] && return $result
	fi

	return $E_NOERROR
}

# Remove kernel modules

remove_weak_updates() {
	# On CentOS and RHEL there's mechanism called weak-updates,
	# which creates symlinks for all modules in
	# /lib/modules/$(uname -r)/weak-updates/ directory
	# It's nice to clean that symlinks from that dir also.
	local mod="${1##*/}"
	for kver in /lib/modules/*; do
		rm -f "${kver}/weak-updates/${mod}"
	done
}

remove_kernel_modules() {
	# Removing dkms modules. Should be done first cause dkms is too smart: it
	# may restore removed modules by original path.
	if type dkms > /dev/null 2>&1; then
		# Previously we registered our kmods under different name.
		# So need to support removing them as well.
		for mod_name in parallels-tools-kernel-modules parallels-tools; do
			# Unfortunately we cannot relay on dkms status retcode. So need to
			# grep it's output. If there's nothing - there was no such modules
			# registered.
			dkms status -m $mod_name -v "$FULL_PRODUCT_VERSION" |
				grep -q $mod_name || continue
			dkms remove -m $mod_name -v "$FULL_PRODUCT_VERSION" --all &&
				tell_user "DKMS modules were removed successfully"
		done
	fi

	for kmod_path in $KMODS_PATHS; do
		local kmod="${kmod_path%%/*}"
		local kmod_dir="$INSTALL_DIR_KMODS/$kmod"
		local fmod="$KDIR/$kmod.$KEXT"

		tell_user "Start removal of $kmod kernel module"

		# Unload kernel module
		if rmmod "$kmod" > /dev/null 2>&1; then
			tell_user "Kernel module $kmod was unloaded"
		else
			perror "Error: could not unload $kmod kernel module"
		fi

		# Remove kernel module from directory
		rm -f "$fmod"

		# Remove directory if it exists
		[ -d "$kmod_dir" ] && rm -rf "$kmod_dir"
	done
}

remove_kernel_modules_backup() {
	local backup="$BACKUP_DIR/.kmods.list"
	tell_user "Remove kernel modules according to $backup file"
	while read -r line; do
		rm -f "$line"
		remove_weak_updates "$line"
	done < "$backup"
	rm -f "$backup"
}

# Install kernel modules

install_kmods_src() {
	local backup="$BACKUP_DIR/.kmods.list"

	cp -Rf "$KMODS_DIR" "$INSTALL_DIR"
	tar -xzf "$INSTALL_DIR_KMODS/prl_mod.tar.gz" -C "$INSTALL_DIR_KMODS"

	make -C "$INSTALL_DIR_KMODS" -f Makefile.kmods
	local result=$?
	if [ $result -ne 0 ]; then
		perror "Error: could not build kernel modules"
		return $E_BFAIL
	fi

	mkdir -p "$KDIR"
	for kmod_path in $KMODS_PATHS; do
		local kernel_module_name="${kmod_path%%/*}"
		local kernel_dir="$INSTALL_DIR_KMODS/$kmod_path"
		tell_user "Start installation of $kernel_module_name kernel module"
		local found_module="$kernel_dir/$kernel_module_name.$KEXT"
		if [ ! -e "$found_module" ]; then
			perror "Error: could not find $kernel_module_name kernel module"
			return $E_BFAIL
		fi
		cp -f "$found_module" "$KDIR"
		echo "$KDIR/$kernel_module_name.$KEXT" >> "$backup"
	done

	depmod -a
}

install_kmods_dkms() {
	if type dkms > /dev/null 2>&1; then
		# Starting from version 2.2 dkms broke options compatibility:
		# option "ldtarball" will refuse to get our kmods archive. But at the
		# same time "add" option will eat our kmods sources.
		if dkms --version | sed 's/dkms: \([0-9]\+\.[0-9]\+\)\..*/\1/' |
			awk '{if ($1 < 2.2) exit 1}'
		then
			dkms add "$INSTALL_DIR_KMODS"
		else
			dkms ldtarball --archive="$INSTALL_DIR_KMODS/prl_mod.tar.gz"
		fi
		if [ $? -eq 0 ]; then
			tell_user "DKMS modules were added successfully"
		else
			tell_user "DKMS modules were not added"
		fi
		for mod_path in /lib/modules/*; do
			local _kver=${mod_path##*/}
			local tools_modules_name=parallels-tools
			if dkms build -m $tools_modules_name \
					-v "$INSTALL_FULL_PRODUCT_VERSION" \
					-k "$_kver" > /dev/null 2>&1; then
				tell_user "DKMS modules for kernel $_kver were built successfully"
			else
				perror "DKMS modules for kernel $_kver building failed"
			fi
			if dkms install -m $tools_modules_name \
					-v "$INSTALL_FULL_PRODUCT_VERSION" \
					-k "$_kver" --force > /dev/null 2>&1; then
				tell_user "DKMS modules for kernel $_kver were installed successfully"
			else
				perror "DKMS modules for kernel $_kver installation failed"
			fi
		done
	fi
}

install_kernel_modules() {
	install_kmods_src || return $?
	install_kmods_dkms

	modprobe prl_tg
}

# Tools modules installation

update_icon_cache()
{
	# mech is taken from host Linux installers
	if type gtk-update-icon-cache > /dev/null 2>&1; then
		local ignore_th_index=
		[ -f "$ICONS_DIR/index.theme" ] || ignore_th_index=--ignore-theme-index
		gtk-update-icon-cache $ignore_th_index -fq "$ICONS_DIR" > /dev/null 2>&1
	fi
}

# Init system related helper functions

# Check for systemd being main init system.
# Official systemd man suggests this as a reliable check.
# See `sd_booted` documentation on freedesktop.org.
systemd_enabled() {
	[ -d "/run/systemd/system" ]
}

# Check underlying operaion system.for being RHEL/Centos 6.x.
# 6.x have old upstart as init manager, and actually this
# function is an indirect check for this case.
not_rhel6() {
	local major=$(rev /etc/redhat-release | cut -d" " -f2 | cut -d. -f2)
	[ "$major" != "6" ]
}

# Check if system has upstart of correct version and all
# necessary directories to install our job files into.
# Old versions and certain OSes are known to have issues,
# and it's safer to fallback on sysv init scripts on such
# systems.
upstart_enabled() {
	/sbin/init --version 2>/dev/null | grep -q upstart &&
		not_rhel6 &&
		[ -d "/etc/init/" ]
}

# Remove user space tools' modules

remove_orphaned_files() {
	# In previous versions these files may not be put into TOOLS_BACK
	# log-file correctly. So need to remove them explicitely.
	if [ -e "$UTOOLS_INSTALL_JOB" ] || [ -e "$XTOOLS_INSTALL_JOB" ]; then
		rm -f "$UTOOLS_INSTALL_JOB"
		rm -f "$XTOOLS_INSTALL_JOB"
		type initctl >/dev/null 2>&1 && initctl reload-configuration
	fi

	rm -f "$BIN_DIR/prlfsmountd"

	# Some systemd units also might have missed the TOOLS_BACK file,
	# so we need to check for them too.
	rm -f "/usr/lib/systemd/user/${UTOOLS_SD_SERVICE}"

	# On PDFM 11 K20prltoolsd remained in
	# /etc/rc.d/* dirs on systems with systemd,
	# since prtloosd used init compatibility mode,
	# and used to be started by corresponding service
	for rc_level in /etc/rc.d/*; do
		rm -f "${rc_level}/K20prltoolsd"
	done
}

remove_tools_modules() {
	local skip_xconf_removal=0
	if [ "$1" = "--skip-xconf" ]; then
		skip_xconf_removal=1
	fi

	if [ -e "$TOOLSD_ISERVICE" ]; then
		"$TOOLSD_ISERVICE" stop
		local pidfile="/var/run/$TOOLSD.pid"
		if [ -r "$pidfile" ]; then
			# in some versions of tools service there was bug
			# which preveted correct stopping
			# so here is kludge for this situation
			local svc_pid=$(< "$pidfile")
			kill "$svc_pid"
		fi
		if systemd_enabled; then
			systemctl stop "$TOOLSD_SD_SERVICE"
			systemctl disable "$TOOLSD_SD_SERVICE" 2>&1
		else
			"$REGISTER_SERVICE" --remove "$TOOLSD"
		fi
		rm -f "$TOOLSD_ISERVICE"
	fi

	if systemd_enabled; then
		systemctl stop "$UTOOLS_SD_SERVICE"
		systemctl stop "$XTOOLS_SD_SERVICE"
		systemctl disable "$UTOOLS_SD_SERVICE" 2>&1
		systemctl disable "$XTOOLS_SD_SERVICE" 2>&1
	elif upstart_enabled; then
		# nothing to do, jobs are installed via install_file
		# function and will be removed automatically
		:
	else
		if [[ -e "$XTOOLS_ISERVICE" ]]; then
			"$REGISTER_SERVICE" --remove "$XTOOLS"
			rm -f "$XTOOLS_ISERVICE"
		fi

		if [[ -e "$UTOOLS_ISERVICE" ]]; then
			"$REGISTER_SERVICE" --remove "$UTOOLS"
			rm -f "$UTOOLS_ISERVICE"
		fi
	fi

	# kill control all center processes
	for prlcc_pid in $(ps -A -opid,command | grep -v grep | grep "prlcc\>" | awk '{print $1}'); do
		kill "$prlcc_pid"
	done

	# unload selinux policy
	if [ -e "$SLP_BACKUP" ]; then
		IFS=$'\n'
		while read mod; do semodule -r "$mod"; done < "$SLP_BACKUP"
		unset IFS
	fi

	#remove shared folder
	local mpoint=$(head -n1 $PSF_BACKUP)
	IFS=$'\n'
	awk '{if ($3 == "prl_fs") print $2}' /proc/mounts |
		while read -r f; do
			local mnt_pt=$(printf "%s\n" "$f")
			umount "$mnt_pt"
			rmdir "$mnt_pt"
		done
	unset IFS
	umount -at prl_fs
	rmdir "$mpoint"
	# remove fstab entries after tools of version < 9
	sed -i -e 'N;/\n#Parallels.*/d;P;D;' /etc/fstab
	sed -i -e '/prl_fs/d' /etc/fstab

	# delete created links on psf on users desktop
	grep 'Desktop' $PSF_BACKUP | sed 's/\ /\\\ /g' | xargs rm -f

	# Unset parallels OpenGL libraries
	if [ -x "$SBIN_DIR/$OPENGL_SWITCHER" ]; then
		"$SBIN_DIR/$OPENGL_SWITCHER" --off
	else
		perror "Can not find executable OpenGL switching tool by path $OPENGL_SWITCHER"
	fi

	if [ -e "$TOOLS_BACKUP" ]; then
		tell_user "Remove tools according to $TOOLS_BACKUP file"
		while read line; do
			# Kludge to fix previous buggy backup files on Fedora 19.
			[ -f "$line" ] || line=$(echo $line | sed 's/^‘\(.*\)’$/\1/')
			# Kludge to support case when 64-bit Ubuntu 11.04
			# was updated to 11.10: symlink /usr/lib64 was removed.
			[ -f "$line" ] || line=${line/usr\/lib64/usr\/lib}
			echo " rm $line"
			rm -f "$line"
		done < "$TOOLS_BACKUP"
		rm -f "$TOOLS_BACKUP"
	fi

	# Files from previous versions, which have been forgotten
	# to be added to backup files, and thus remained after
	# tools removal. They are all special cases, and are
	# needed to be removed
	remove_orphaned_files

	# Parallels Tools icon was removed
	# So need to update icon cache
	update_icon_cache

	# Remove directory with extracted prltools.$arch.tar.gz
	# with old modules built for all version of Xorg
	rm -rf "$TOOLS_BIN_DIR"

	rmdir '/etc/prltools'

	if [ $skip_xconf_removal -eq 1 ]; then
		tell_user "Removing of X server configuration is skipped."
		# we also should not delete directory with tools case backups are stored there
		return 0
	fi

	if [ -e "$XCONF_BACKUP" ]; then
		tell_user "Restore X server configuration file according to $XCONF_BACKUP"
		. "$XCONF_BACKUP"
		if [ -z "$BACKUP_XBCONF" ]; then
			rm -f "$BACKUP_XCONF"
		else
			[ -e "$BACKUP_XBCONF" ] && mv -f "$BACKUP_XBCONF" "$BACKUP_XCONF"
		fi
		# Now we do not remove "evdev_drv.so" driver, but previously we could do this.
		# Thus, leave this string for compatibility with previous versions of Guest Tools.
		[ -e "$BACKUP_XBEVDEV" ] && mv -f "$BACKUP_XBEVDEV" "$BACKUP_XEVDEV"
		rm -f "$XCONF_BACKUP"
	fi

	# Attempt to remove INITD_DIR, as it may have been
	# created by our installer (in case of Arch/Manjaro)
	rmdir "$INITD_DIR" --ignore-fail-on-non-empty

	# Per-user cleanup actions:
	for d in $(awk -F: '{print $6}' /etc/passwd); do
		# Restore configuration of users directories after
		# Shared Profile changes.
		for f in user-dirs.dirs gtk-bookmarks; do
			local cfg=${d}/.parallels/${f}
			local bkp=${cfg}.orig
			if [ -r "$bkp" ] && [ -L "$cfg" ]; then
				cp -f "$bkp" "$cfg"
				rm -f "$cfg" "$bkp"
			fi
		done

		# Cleanup custom monitors configs of dynamic resolution tool.
		rm -f "${d}/.config/monitors.xml"
	done
}


# Install user space tools' modules

check_x_server_version() {
	XVERSION=$("$DETECT_X_SERVER" -v)
	if [ $? -ne $E_NOERROR ]; then
		XVERSION="6.7"
		return $E_NOXSERV
	fi
	echo $XVERSION
	return $E_NOERROR
}

get_x_server_version() {
	XVERSION=$(check_x_server_version)
	[ $? -ne $E_NOERROR ] && return $E_NOXSERV
	echo "X server version: $XVERSION"
	XMODULES_SRC_DIR=$("$DETECT_X_SERVER" -dsrc "$TOOLS_BIN_DIR")
	if [ $? -eq $E_NOERROR ]; then
		echo "System X modules are installing from $XMODULES_SRC_DIR"
	else
		return $E_NOXMODIR
	fi

	XMODULES_DIR=$("$DETECT_X_SERVER" -d)
	if [ $? -eq $E_NOERROR ]; then
		echo "System X modules are placed in $XMODULES_DIR"
	else
		return $E_NOXMODIR
	fi
	return $E_NOERROR
}

get_x_server_version_num() {
	local vmajor=$(echo "$XVERSION" | awk -F . '{ printf "%s", $1 }')
	local vminor=$(echo "$XVERSION" | awk -F . '{ printf "%s", $2 }')
	local vpatch=$(echo "$XVERSION" | awk -F . '{ printf "%s", $3 }')

	if [ $vmajor -ge 6 ]; then
	# Must discount major version,
	# because XOrg changes versioning logic since 7.3 (7.3 -> 1.3)
		vmajor=$((vmajor - 6))
	fi

	local v=$((vmajor*1000000 + vminor*1000))
	if [ -n "$vpatch" ]; then
		v=$((v + vpatch))
	fi
	echo $v
}

# Prints path to X11 configuration file
find_xorgconf() {
	# Starting from Xorg 1.15 all config files should be stored
	# in another place:
	local v=$(get_x_server_version_num)
	if [ $v -ge 1005000 ]; then
		local d='/usr/share/X11/xorg.conf.d'
		if [ -d "$d" ]; then
			echo "$d/40-prltools.conf"
			return
		fi
	fi

	local xdir=""
	local xcfg=""

	# Search through all possible directories and X server configuration file
	local xorg_conf_dirs="/etc \
		/etc/X11 \
		/usr/etc \
		/usr/etc/X11 \
		/usr/lib/X11 \
		/usr/X11R6/etc \
		/usr/X11R6/etc/X11 \
		/usr/X11R6/lib/X11"

	local xorg_conf_files="xorg.conf xorg.conf-4"
	local xorg_conf_default="/etc/x11/xorg.conf"

	for d in $xorg_conf_dirs; do
		for f in $xorg_conf_files; do
			if [ -e "$d/$f" ]; then
				xdir="$d"
				xcfg="$f"
				break 2
			fi
		done
	done

	if ([ -n "$xdir" ] && [ -n "$xcfg" ]); then
		echo "$xdir/$xcfg"
	else
		echo "$xorg_conf_default"
	fi
}

configure_x_server() {
	local xconf=$(find_xorgconf)
	local xbconf=''
	if [ -f "$xconf" ]; then
		xbconf="$BACKUP_DIR/.${xconf##*/}"
		cp -f "$xconf" "$xbconf"

		echo "X server config: $xconf"
	else
		# X server config doesn't exist
		# So value of xbconf will be empty
		echo "X server config: $xconf (doesn't exist)"
	fi

	# ... and save information about X server configuration files
	echo "BACKUP_XCONF=$xconf"	>>	"$XCONF_BACKUP"
	echo "BACKUP_XBCONF=$xbconf"	>>	"$XCONF_BACKUP"

	# Fedora since 25 doesn't ship python2 at all
	# python command is also absent, python3 is the only option
	local configure_x_server="$INSTALLER_DIR/xserver-config.py"
	if type python3 2>/dev/null; then
		python3 "$configure_x_server" "xorg" "$XVERSION" "$xbconf" "$xconf"
	else
		python "$configure_x_server" "xorg" "$XVERSION" "$xbconf" "$xconf"
	fi
	if [ "x$?" != "x0" ]; then
		cp -f "$xbconf" "$xconf"
		return 1
	fi
}

install_file() {
	local src=$1
	local dst=$2
	[ -d "$dst" ] && dst="${dst}/${src##*/}"
	cp -vf "$src" "$dst" && echo "$dst" >>"$TOOLS_BACKUP"
}

install_symlink() {
	local src=$1
	local lnk=$2
	[ -d "$lnk" ] && lnk="${lnk}/${src##*/}"
	ln -svf "$src" "$lnk" && echo "$lnk" >>"$TOOLS_BACKUP"
}

install_x_modules() {
	local xmod="$1/x-server/modules"

	# Link X modules for 6.7 and 6.8 versions of X.Org server
	if ([ "x$XVERSION" = "x6.7" ] || [ "x$XVERSION" = "x6.8" ]); then
		if [ "$ARCH" != "x86_64" ]; then
			local xlib="$TOOLS_BIN_DIR/lib"
			local vdrv="prlvideo_drv"
			local xvideo="$xmod/drivers/$vdrv"
			local mdrv="prlmouse_drv"
			local xmouse="$xmod/input/$mdrv"

			gcc -shared "$xvideo.o" "$xlib/libTISGuest.a" "$xlib/libOTGGuest.a" "$xlib/libBitbox.a" \
				-L"$XMODULES_DIR" -lvbe -lddc -lint10 -lramdac -lfb \
				-Wl,-z -Wl,now -Wl,-soname -Wl,"$vdrv.so" -o "$xvideo.so"

			local result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xvideo.so" "$XMODULES_DIR/drivers" && rm -f "$xvideo.so"

			gcc -shared "$xmouse.o" "$xlib/libTISGuest.a" "$xlib/libOTGGuest.a" "$xlib/libBitbox.a" \
				-Wl,-z -Wl,now -Wl,-soname -Wl,"$mdrv.so" -o "$xmouse.so"

			result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xmouse.so" "$XMODULES_DIR/input" && rm -f "$xmouse.so"
		else
			local xlib="$TOOLS_BIN_DIR/lib"
			local vdrv="prlvideo_drv"
			local xvideo="$xmod/drivers/$vdrv"
			local mdrv="prlmouse_drv"
			local xmouse="$xmod/input/$mdrv"

			gcc -r "$xvideo.o" -nostdlib -o "$xvideo-out.o"

			local result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xvideo-out.o" "$XMODULES_DIR/drivers/$vdrv.o" &&
				rm -f "$xvideo-out.o"

			gcc -r "$xmouse.o" "$xlib/libTISGuest_nopic.a" "$xlib/libOTGGuest_nopic.a" "$xlib/libBitbox_nopic.a" \
				-nostdlib -o "$xmouse-out.o"

			result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xmouse-out.o" "$XMODULES_DIR/input/$mdrv.o" &&
				rm -f "$xmouse-out.o"
		fi
	else
		for f in 'input/prlmouse_drv.so' 'drivers/prlvideo_drv.so'; do
			install_file "${xmod}/${f}" "${XMODULES_DIR}/${f}"
		done
	fi
}

apply_x_modules_fixes() {
	local v=$(get_x_server_version_num)
	# Starting from XServer 1.4 we are must configure udev,
	# in this purposes we will setup hall/udev rules

	if [ "$v" -ge "1004000" ]; then
	# Configuring udev via hal scripts
		local hal_policy="/usr/share/hal/fdi/policy"
		if [[ -d "$hal_policy" ]]; then
			local hal_other="${hal_policy}/20thirdparty"
			mkdir -p "$hal_other"
			local x11prl="x11-parallels.fdi"

			# Let's set this level, why not!
			local level=20
			install_file "$INSTALL_DIR_TOOLS/$x11prl" "$hal_other/$level-$x11prl"
		else
			echo "Directory '${hal_policy}' doesn't exist," \
				"skip x11-parallels.fdi installation"
		fi
	fi

	if [ "$v" -ge "1007000" ]; then
	# Configuring udev via rules

		local udev_dir="/lib/udev/rules.d"
		local xorgprlmouse="xorg-prlmouse.rules"
		local level=69
		install_file "$INSTALL_DIR_TOOLS/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"

		xorgprlmouse="prlmouse.conf"
		level=90
		udev_dir="/usr/lib/X11/xorg.conf.d"
		if [ -d "$udev_dir" ]; then
			install_file "$INSTALL_DIR_TOOLS/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
		udev_dir="/usr/lib64/X11/xorg.conf.d"
		if [ -d "$udev_dir" ]; then
			install_file "$INSTALL_DIR_TOOLS/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
		udev_dir="/usr/share/X11/xorg.conf.d"
		if [ -d "$udev_dir" ]; then
			install_file "$INSTALL_DIR_TOOLS/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
		udev_dir="/etc/X11/xorg.conf.d"
		if [ -d "$udev_dir" ]; then
			install_file "$INSTALL_DIR_TOOLS/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
	fi
}

# Set driver for our device 1ab8:4005 to "prl_tg" if it is "unknown"
# This is to make kudzu happy and not repatch xorg.conf
fix_hwconf() {

	local hwconf_file='/etc/sysconfig/hwconf'

	[ -r "$hwconf_file" ] || return

	local hwconf_file_content=$(< "$hwconf_file")
	[ -z "$hwconf_file_content" ] && return

	echo "$hwconf_file_content" | awk '
	{
		if ($0 == "-")
		{
			if (NR > 1)
			{
				# One section is already read. Dump it.
				for (i = 0;  i < idx; ++i)
					print items[i]
			}

			# Start reading section
			idx = 0
			class = ""
			device_id = ""
			vendor_id = ""
			driver = ""
			driver_idx = 0
		}
		else
		if ($1 == "class:")
			class = $2
		else
		if ($1 == "vendorId:")
			vendor_id = $2
		else
		if ($1 == "deviceId:")
			device_id = $2
		else
		if ($1 == "driver:")
		{
			driver = $2
			driver_idx = idx
		}

		if (class == "VIDEO" && vendor_id == "1ab8" && device_id == "4005" && driver == "unknown")
		{
			# Section for our video device! Replace driver to prl_tg
			items[driver_idx] = "driver: prl_tg"
			class = ""
		}

		# Appeding item to currect section
		items[idx] = $0
		++idx
	}

	END {

		# Dumping the very last section
		for (i = 0;  i < idx; ++i)
			print items[i]

	}' > "$hwconf_file"
}

# Setup launcher into users's session in all available DEs
# $1 - path to launcher .desktop-file
setup_session_launcher() {

	local autostart_paths="/etc/xdg/autostart
/usr/share/autostart
/usr/share/gnome/autostart
/usr/local/share/autostart
/usr/local/share/gnome/autostart
/opt/gnome/share/autostart
/opt/kde/share/autostart
/opt/kde3/share/autostart
/opt/kde4/share/autostart"

	# Try to use kde-config for KDE if available
	if type kde-config >/dev/null 2>&1; then
		local kde_autostart_paths="$(kde-config --prefix)/share/autostart"
		if ! echo "$autostart_paths" | grep -q "\<$kde_autostart_paths\>"; then
			autostart_paths="$autostart_paths
$kde_autostart_paths"
		fi
	fi

	local symlink_name="${1##*/}"
	for autostart_path in $autostart_paths; do
		if [ -d "$autostart_path" ]; then
			install_symlink "$1" "${autostart_path}/${symlink_name}"
		fi
	done
}

install_cpuhotplug_rules()
{
	. "$INSTALLER_DIR/pm.sh" >/dev/null 2>&1
	local os_name=$(detect_os_name)
	local os_version=$(detect_os_version "$os_name")
	local dst_cpuhotplug_rules="/etc/udev/rules.d/99-parallels-cpu-hotplug.rules"
	local os_version=$(echo $os_version | sed 's+.*\.++g')
	if [ "$os_name" = "redhat" ] &&
			[ "$os_version" -le "5" ] &&
			[ -r "$KERNEL_CONFIG" ] &&
			grep -q "^CONFIG_HOTPLUG_CPU=y" "$KERNEL_CONFIG"; then
		cp -vf "$INSTALL_DIR_TOOLS/parallels-cpu-hotplug.rules" "$dst_cpuhotplug_rules"
	fi
}

install_memory_hotplug_rules()
{
	local mem_rule="parallels-memory-hotplug.rules"
	local dst_mem_rule="/etc/udev/rules.d/99-$mem_rule"
	grep -qs '^CONFIG_MEMORY_HOTPLUG=y' "$KERNEL_CONFIG" &&
		install_file "$INSTALL_DIR_TOOLS/$mem_rule" "$dst_mem_rule"
}

# Updates boot loader configuration
# Current implementation provides only one simple thing:
#  it finds all kernels that don't have 'divider' option
#  and adds 'divider=10' to them.
# Implementation is targeted only for RHEL/CentOS 5.x family.
update_grubconf()
{
	echo "Going to update boot loader cofiguration..."
	local grubby_util=/sbin/grubby
	if [ ! -x "$grubby_util" ]; then
		perror "grubby not found"
		return 1
	fi

	local grub_conf=/boot/grub/grub.conf
	if [ ! -r "$grub_conf" ]; then
		perror "Cannot find loader conf at path '$grub_conf'"
		return 1
	fi

	grep '^\s*kernel' "$grub_conf" | grep -v divider= |
		awk '{print $2}' |
		while read kern; do
			local kern="/boot${kern##/boot}"
			[ -f "$kern" ] || continue
			echo " * $kern"
			"$grubby_util" --update-kernel="$kern" --args=divider=10
		done
}

install_selinux_module_make() {
	local makefile="/usr/share/selinux/devel/Makefile"
	local policy=$1
	local bin_path="$2"
	local mod_name=${policy##*/}; mod_name=${mod_name%.*}

	[ ! -f $makefile ] && return 1

	local tempdir=$(mktemp -d /tmp/XXXXXX-parallels-tools-selinux)
	[ -z "$tempdir" ] || [ ! -d "$tempdir" ] && return 1

	cp "$policy" "$tempdir"
	cp "${policy%.*}.fc" "$tempdir"
	pushd "$tempdir"
	make -f "$makefile" "${mod_name}.pp"
	popd
	local mod_pkg="$tempdir/${mod_name}.pp"
	[ -e "$mod_pkg" ] &&
		semodule -i "$mod_pkg" &&
		restorecon "$bin_path" &&
		echo "$mod_name" >>"$SLP_BACKUP"
	local ret_code=$?
	rm -rf "$tempdir"
	return $ret_code
}

install_selinux_module() {
	local policy=$1
	local mod_name=${policy##*/}; mod_name=${mod_name%.*}
	local bin_policy="$TOOLS_BIN_DIR/${mod_name}.mod"
	local mod_pkg="$TOOLS_BIN_DIR/${mod_name}.pp"

	# Check if SELinux stuff is available
	type checkmodule >/dev/null 2>&1 || return 1

	# Build and install module package
	checkmodule -m -M "$policy" -o "$bin_policy"
	[ -e "$bin_policy" ] && semodule_package -m "$bin_policy" -o "$mod_pkg"
	[ -e "$mod_pkg" ] && semodule -i "$mod_pkg" &&
		echo "$mod_name" >>"$SLP_BACKUP" && return 0
	return 1
}

install_compiz_plugin() {
	if [ "$ARCH" = "x86_64" ] && [ -d "/usr/lib64" ]; then
		local compizdir_target="/usr/lib64/compiz"
	else
		local compizdir_target="/usr/lib/compiz"
	fi
	if ! [ -d "$compizdir_target" ]; then
		tell_user "Can't find compiz lib dir, skipping compiz pluing install"
		return
	fi
	# Copy from main directory
	local compizdir="$TOOLS_BIN_DIR/lib/compiz"
	for lib in "$compizdir"/* ; do
		[ -d "$lib" ] && continue # it's a dir, not a file
		local libname=${lib##*/}
		install_file "$lib" "$compizdir_target/$libname"
	done

	if ! [ -e /etc/os-release ]; then
		# this is not Ubuntu 15.10, 16.04 or 16.10,
		# thus we skip this step, since we have
		# special plugin versions only for them
		return
	fi
	local release=$(awk -F= '/PRETTY_NAME/ { print $2 }' \
			/etc/os-release | tr -d '"')
	# Copy from tagged sub directories
	for dir in "$compizdir/"*; do
		[ -d "$dir" ] || continue
		# check if dir name is prefix of release, e.g.
		# "Ubuntu 16.04" is prefix of "Ubuntu 16.04.1 LTS",
		# with the latter being PRETTY_NAME of the release
		# and the former our directory with needed compiz
		# plugin libraries
		[[ "$release" = "${dir##*/}"* ]] || continue
		for lib in "$dir"/* ; do
			install_file "$lib" "$compizdir_target/${lib##*/}"
		done
		break
	done
}

install_gnome_coherence_extension() {
	local ext_dir="/usr/share/gnome-shell/extensions"
	if ! [[ -d "$ext_dir" ]]; then
		tell_user "Cant't find Gnome Shell extensions dir, skipping plugin install"
		return $E_NOERROR
	fi

	local ext_name="coherence-gnome-shell@parallels.com"
	local dest_path="$ext_dir/$ext_name"
	mkdir -p "$dest_path"

	local src_path="$INSTALL_DIR_TOOLS/gnome-coherence"
	local src_files="extension.js metadata.json stylesheet.css"
	for f in $src_files; do
		if ! install_file "$src_path"/"$f" "$dest_path"; then
			perror "Failed to install file $src_path/$f"
			return $E_IFAIL
		fi
	done
}

install_and_configure_x() {
	local skip_xconf=0
	[ -n "$1" ] && skip_xconf=$1

	get_x_server_version
	local result=$?
	if [ $result -ne $E_NOERROR ]; then
		perror "Failed to detect X server version"
		return $result
	fi

	if [ $skip_xconf -eq 1 ]; then
		tell_user "X server configuration was skipped"
	else
		configure_x_server
		local result=$?
		if [ $result -ne $E_NOERROR ]; then
			perror "Error: could not configure X server"
			return $result
		fi
	fi

	install_x_modules "$XMODULES_SRC_DIR"
	local result=$?
	if [ $result -ne $E_NOERROR ]; then
		perror "Error: could not install X modules"
		return $result
	fi

	apply_x_modules_fixes
	fix_hwconf

	install_compiz_plugin

	# Here we install and enable gnome coherence
	# extension. We enable it system-wide, for every
	# user who launches gnome shell session.
	install_gnome_coherence_extension
	local result=$?
	if [ $result -ne $E_NOERROR ]; then
		perror "Fatal error during Gnome Coherence extension installation"
		return $result
	fi

	setup_session_launcher "${INSTALL_DIR_TOOLS}/prlcc.desktop"

	# we need to force reloading of the udev rules and
	# reinitialization of devices in order to make X server
	# able to use correct driver for our mouse
	if type udevadm >/dev/null 2>&1; then
		udevadm control --reload-rules && udevadm trigger
		echo "udevadm exited with status $?"
	fi

	if [ -d "$ICONS_DIR" ]; then
		local tools_icon="parallels-tools.png"
		local icon="$INSTALL_DIR_TOOLS/$tools_icon"
		local icon_target="$ICONS_DIR/48x48/apps/$tools_icon"
		if [ -e "$icon" ]; then
			install_file "$icon" "$icon_target"
		fi
		update_icon_cache
	fi

	return 0
}

install_tools_modules() {
	local skip_xconf=0
	if [ "$1" = "--skip-xconf" ]; then
		skip_xconf=1
	fi

	mkdir -p "$TOOLS_BIN_DIR"

	# Unpack user space modules
	tar -xzf "$TOOLS_BIN_DIR.tar.gz" -C "$TOOLS_BIN_DIR"


	# Check XServer version, and is there requires version of X modules?
	get_x_server_version
	local result=$?

	if [ $result -eq $E_NOERROR ]; then
		install_and_configure_x $skip_xconf
		result=$?
		if [ $result -ne $E_NOERROR ]; then
			return $result
		fi
	else
		tell_user "Skip X server configuration and installation of X modules"
	fi

	#prepare for shared folders features using
	if [ -d /media ]; then
		local mpoint="/media/psf"
	else
		local mpoint="/mnt/psf"
	fi

	echo "$mpoint" > "$PSF_BACKUP"

	mkdir -p "$mpoint"
	if [ -d "$mpoint" ]; then
		chmod 0555 "$mpoint"
		install_selinux_module "$INSTALLER_DIR/prlfs.te"

		# add shared mount point to fstab
		for i in $(awk -F: '{print $6}' /etc/passwd); do
			if [ -d "$i"/Desktop ]; then
				local link_name="$i/Desktop/Parallels Shared Folders"
				install_symlink "$mpoint" "$link_name"
			fi
		done
	fi

	install_selinux_module "$INSTALLER_DIR/prlvtg.te"

	# Install time sync tool
	local timesync="$COMMON_TOOLS_BIN_DIR/usr/bin/prltimesync"
	install_file "$timesync" "$BIN_DIR/prltimesync"
	# prltoolsd's SELinux module will need types defined for prltimesync, so
	# we must install timesync SELinux module before prltoolsd's one
	install_selinux_module_make "$INSTALLER_DIR/prltimesync.te" "$BIN_DIR/prltimesync"

	# Install tools' service
	mkdir -p "$INITD_DIR"
	install_file "$TOOLS_BIN_DIR/bin/$TOOLSD" "$BIN_DIR/$TOOLSD"
	cp -f "$TOOLSD_SERVICE" "$TOOLSD_ISERVICE"

	if systemd_enabled; then
		install_file "$INSTALLER_DIR/$TOOLSD_SD_SERVICE" '/etc/systemd/system/' &&
			systemctl enable "$TOOLSD_SD_SERVICE" 2>&1
	elif upstart_enabled; then
		install_file "$TOOLSD_JOB" "$TOOLSD_INSTALL_JOB"
		initctl reload-configuration
	else
		"$REGISTER_SERVICE" --install "$TOOLSD"
	fi

	result=$?
	[ $result -ne $E_NOERROR ] && return $result

	# Exclude ne2k-pci module from initramfs image on Debian-based systems
	if type update-initramfs > /dev/null 2>&1; then
		local initramfs_hooks_dir=/usr/share/initramfs-tools/hooks
		local prl_tools_initramfs_hook_target="$initramfs_hooks_dir/parallels_tools"
		[ -d "$initramfs_hooks_dir" ] &&
			install_file "$INSTALLER_DIR/parallels_tools.initramfs-hook" \
					"$prl_tools_initramfs_hook_target"
		update-initramfs -u
	fi

	# Install Parallels Shared Folders automount daemon
	local fsmountd_src="$INSTALL_DIR_TOOLS/prlfsmountd.sh"
	local fsmountd_dst="$BIN_DIR/prlfsmountd"
	install_file "$fsmountd_src" "$fsmountd_dst"

	install_selinux_module_make "$INSTALLER_DIR/prltoolsd.te" "$BIN_DIR/$TOOLSD"
	# prltoolsd accesses this directory during startup
	# and this should be permitted by SELinux
	local installer_dir="${INSTALL_DIR_TOOLS}/../installer"
	if type semanage > /dev/null 2>&1; then
		semanage fcontext -a -t lib_t "${installer_dir}(/.*)?"
		restorecon -RFv "$installer_dir"
	else
		echo "Warning: no semanage found in system"
		echo "Not changing type for ${installer_dir}."
	fi

	# Install prl-x11 service
	cp -f "$XTOOLS_SERVICE" "$XTOOLS_ISERVICE"
	# Install prl_updater service for sysV or systemd or upstart
	if systemd_enabled; then
		install_file "$INSTALLER_DIR/$UTOOLS_SD_SERVICE" '/etc/systemd/system/' &&
			systemctl enable "$UTOOLS_SD_SERVICE" 2>&1
		install_file "$INSTALLER_DIR/$XTOOLS_SD_SERVICE" '/etc/systemd/system/' &&
			systemctl enable "$XTOOLS_SD_SERVICE" 2>&1
	elif upstart_enabled; then
		install_file "$UTOOLS_JOB" "$UTOOLS_INSTALL_JOB" &&
			initctl reload-configuration
	else
		cp -f "$UTOOLS_SERVICE_INIT" "$UTOOLS_ISERVICE" &&
			"$REGISTER_SERVICE" --install "$UTOOLS"
	fi
	# Check if any upstart services emits 'starting-dm' event
	# and use parallels upstart service to start prl-x11 before X service
	# In other cases use chkconfig service that starts in the beginning
	# of startup. Upstart service was implemented only for Ubuntu yet
	[ -d "$INIT_DIR" ] && grep -q -r "filesystem" "$INIT_DIR" &&
		install_file "$XTOOLS_JOB" "$XTOOLS_INSTALL_JOB" ||
				"$REGISTER_SERVICE" --install "$XTOOLS"

	# Install Parallels Control Center
	# It is built with xorg-7.1 only
	local ctlcenter="$COMMON_TOOLS_BIN_DIR/usr/bin/prlcc"
	install_file "$ctlcenter" "$BIN_DIR/prlcc"

	# and just the same for DnD tool
	local dndtool="$COMMON_TOOLS_BIN_DIR/usr/bin/prldnd"
	install_file "$dndtool" "$BIN_DIR/prldnd"

	# and CP tool as well
	local cptool="$COMMON_TOOLS_BIN_DIR/usr/bin/prlcp"
	install_file "$cptool" "$BIN_DIR/prlcp"

	# and don't forget brand new SGA
	local sgatool="$COMMON_TOOLS_BIN_DIR/usr/bin/prlsga"
	install_file "$sgatool" "$BIN_DIR/prlsga"

	# Install host time utility
	local hostime="$TOOLS_BIN_DIR/bin/prlhosttime"
	install_file "$hostime" "$BIN_DIR/prlhosttime"

	# Install istatus utility
	local show_vm_cfg="$TOOLS_BIN_DIR/bin/prl_showvmcfg"
	install_file "$show_vm_cfg" "$BIN_DIR/prl_showvmcfg"

	# Install network tool utility
	local nettool="$TOOLS_BIN_DIR/sbin/prl_nettool"
	install_file "$nettool" "$SBIN_DIR/prl_nettool"

	# Install utility for smoof filesystems backup
	local snap_tool="$TOOLS_BIN_DIR/sbin/prl_snapshot"
	install_file "$snap_tool" "$SBIN_DIR/prl_snapshot"

	# Install shared profile tool
	local shprof="$TOOLS_BIN_DIR/bin/prlshprof"
	install_file "$shprof" "$BIN_DIR/prlshprof"

	# Install shared printers tool
	local shprint="$TOOLS_BIN_DIR/bin/prlshprint"
	install_file "$shprint" "$BIN_DIR/prlshprint"

	# Install xorg.conf fixer
	local xorgfix="$TOOLS_BIN_DIR/sbin/prl-xorgconf-fixer"
	install_file "$xorgfix" "$SBIN_DIR/prl-xorgconf-fixer"

	# Install OpenGL switcher
	local openglsw="$TOOLS_BIN_DIR/sbin/$OPENGL_SWITCHER"
	install_file "$openglsw" "$SBIN_DIR/$OPENGL_SWITCHER"

	# Install Parallels Tools updater
	local prltoolsup="$TOOLS_BIN_DIR/sbin/prltools_updater.sh"
	install_file "$prltoolsup" "$SBIN_DIR/prltools_updater.sh"

	# Man-page for prl_fs
	local manpage_name='mount.prl_fs.8'
	local manpage="$INSTALL_DIR_TOOLS/$manpage_name"
	local man_dir='/usr/share/man/man8'
	if [ -d "$man_dir" ]; then
		install_file "$manpage" "$man_dir/$manpage_name"
	fi

	# For RHEL/CentOS 5.x we need to add special kernel option
	local release_file=/etc/redhat-release
	if [ -r "$release_file" ] &&
			[ "$(rpm -qf "$release_file" | sed -e "s/.*release-\([0-9]*\).*/\1/g")" -eq 5 ]
	then
		update_grubconf || perror "Error: failed to update grub.conf"
	fi

	if [[ -d /etc/pm/sleep.d/ ]]; then
		local toolsd_hibernate="$INSTALL_DIR_TOOLS/99prltoolsd-hibernate"
		install_file "$toolsd_hibernate" "/etc/pm/sleep.d/99prltoolsd-hibernate"
	fi

	install_cpuhotplug_rules
	install_memory_hotplug_rules

	[ "$ARCH" = 'x86_64' ] && arch_suffix=64 || arch_suffix=32
	local ptiagent_cmd_symlink="$BIN_DIR/ptiagent-cmd"
	install_symlink \
			"$INSTALL_DIR_TOOLS/../installer/iagent$arch_suffix/parallels-wrapper" \
			"$ptiagent_cmd_symlink"
	install_ptiagent_starters

	return $E_NOERROR
}

check_xconf_patched() {
	# Check whether xorg.conf is already patched by PT installer or not yet
	check_x_server_version >/dev/null
	local rc=$?
	if [ $rc -ne $E_NOERROR ]; then
		echo "Xorg was not found"
		return $rc
	fi
	local xconf=$(find_xorgconf)

	# Will return false if there's no info about xorg.conf backup _and_ there's no prlmouse entry
	[ -f "$XCONF_BACKUP" ] || grep -qs '^\W*Driver\W+"prlmouse"' "$xconf" || return $E_BFAIL

	# Bug in case of presense of smth metioned above - consider xorg.conf is patched
	return $E_NOERROR
}

# Remove Guest Tools

remove_gt3() {
	daemon=""
	sremove=""

	if [ "$1" = "/usr/lib/parallels" ]; then
		tell_user "Remove Guest Tools 3.x version"
		daemon="prluserd"
		sremove="remove"
	elif [ "$1" = "/usr/lib/parallels-server-tools" ]; then
		tell_user "Remove Guest Tools 4.0 RC"
		daemon="prltoolsd"
		sremove="unregister"
	else
		perror "Error: invalid installation directory: $1"
		return $E_NOTOOLS
	fi

	uninstall="$1/uninstall.sh"
	if [ -x "$uninstall" ]; then
		"$uninstall"
	else
		fdaemon="$1/$daemon"
		if [ -x "$fdaemon" ]; then
			echo "Stop Guest Tools service"
			"$fdaemon" stop
		fi

		service="$1/iscripts"
		if [ -x "$service" ]; then
			echo "Unregister Guest Tools service"
			iservice="/etc/init.d/$daemon"
			"$service" $sremove
			rm -f "$iservice"
		fi

		xconf="$1/.xcfg.info"
		if [ -f "$xconf" ]; then
			echo "Restore X server configuration"
			. "$xconf"

			xfile=""
			if [ -f "$CFGDIR/$LASTCFG" ]; then
				xfile="$CFGDIR/$CURRCFG"
				mv "$CFGDIR/$LASTCFG" "$xfile"
			elif [ -f "$BKPCFG" ]; then
				xfile="$CURCFG"
				mv "$BKPCFG" "$xfile"
			fi

			# Remove X server "fail safe" files
			rm -f "$xfile."*
		fi

		evdev="$1/.evdev.info"
		if [ -f "$evdev" ]; then
			echo "Restore evdev driver"
			. "$evdev"
			fevdev="$1/$EVDEV"
			[ -f "$fevdev" ] && mv "$fevdev" "$XIDIR/$EVDEV"
		fi

		itab="$1/.inittab.fc6"
		if [ -f "$itab" ]; then
			echo "Restore inittab file"
			mv -f "$itab" "/etc/inittab"
		fi

		ilist="$1/.install.lst"
		if [ -f "$ilist" ]; then
			echo "Remove Guest Tools modules"
			while read line; do
				echo "$line" | tr -d \' | xargs rm -f
			done < "$ilist"
		fi
	fi

	echo "Remove $1 directory"
	rm -rf "$1"
}

remove_gt4() {

	# Remove user space modules
	local remove_mode
	[ $UPDATE_MODE -eq 1 ] && [ "x$1" != "x-f" ] && remove_mode='--skip-xconf'

	remove_tools_modules "$remove_mode"

	# Check... should we completely remove Guest Tools?
	if ([ "$1" = "-f" ] || [ "$BASE_DIR" != "$INSTALL_DIR" ]); then
		# Remove kernel modules
		remove_kernel_modules
		remove_kernel_modules_backup

		# Backups will be removed only if we are in non-update or force-remove mode
		if [ "$1" = "-f" ] || [ $UPDATE_MODE -ne 1 ]; then
			# Remove backup directory
			rm -rf "$BACKUP_DIR"
		fi
		# Finally remove installation directory
		echo "Remove $INSTALL_DIR directory"
		rm -rf "$INSTALL_DIR"
	else
		# Remove kernel modules
		remove_kernel_modules

		echo "Skip removal of $INSTALL_DIR directory"
	fi
}

remove_gt() {
	result=$E_NOTOOLS
	n=0
	if [ -d "$INSTALL_DIR/.backup" ]; then
		echo "old version of parallels tools"
		BACKUP_DIR="$INSTALL_DIR/.backup"
	else
		echo "new version of parallels tools"
		BACKUP_DIR="$IBACKUP_DIR/.backup"
	fi
	XCONF_BACKUP="$BACKUP_DIR/.xconf.info"
	TOOLS_BACKUP="$BACKUP_DIR/.tools.list"
	PSF_BACKUP="$BACKUP_DIR/.psf"
	SLP_BACKUP="$BACKUP_DIR/.${SLP_NAME}.selinux"

	rm -f "$MODPROBED_DIR/blacklist-parallels.conf"
	rm -f "$MODPROBED_DIR/blacklist-parallels"
	rm -f "$MODPROBE_PRL_ETH_CONF"
	rm -f "$DRACUT_KMODS_FILE"
	if [ -f "$MODPROBE_CONF" ]; then
		cmds="$ALIAS_NE2K_OFF:$ALIAS_NE2K_OVERRIDE"
		IFS=':'
		for cmd in $cmds; do
			esc_cmd=$(echo "$cmd" | sed 's/\//\\\//g')
			grep -q "^\W*$cmd" "$MODPROBE_CONF" && sed -i "/^\W*$esc_cmd/d" "$MODPROBE_CONF"
		done
		unset IFS
	fi

	# Find directory with installed Guest Tools
	for idir in $INSTALL_DIRS; do
		if [ -d "$idir" ]; then
			echo "Found Guest Tools directory: $idir"
			case "$n" in
				0) remove_gt4 "$1" ;;
				# Remove old versions of Guest Tools
				1 | 2) remove_gt3 "$idir" ;;
			esac
			result=$E_NOERROR
		fi
		n=$((n + 1))
	done

	if [ $result -ne $E_NOERROR ]; then
		echo "Installed Guest Tools were not found"
		UPDATE_MODE=0
	fi

	return $result
}

istatus() {
	local argument=$1
	local version=$2
	local error_msg=$3

	local istatus_dir=$INSTALLER_DIR
	[ -n "$ISTATUS_DIR" ] && istatus_dir=$ISTATUS_DIR
	local arch_suffix=32
	[ "$ARCH" = 'x86_64' ] && arch_suffix=64
	local istatus_cmd=$istatus_dir/prl_istatus$arch_suffix

	"$istatus_cmd" "$argument" "$version" ||
		perror "Error during report about ${error_msg}."
}

remove_guest_tools() {
	tell_user
	tell_user $(date)
	tell_user "Start removal of Guest Tools"

	# Special kludge to store prl_istatus binary temporarily if we are calling
	# uninstaller "in place".
	local tmp_istatus=$(mktemp -d -t prlistatus-XXXXXX)
	cp "$INSTALLER_DIR"/prl_istatus{32,64} "$tmp_istatus"

	remove_gt -f
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		rm -rf "$tmp_istatus"
		return $result
	fi

	ISTATUS_DIR=$tmp_istatus istatus uninstalled "$FULL_PRODUCT_VERSION" \
		"uninstalled tools version"
	rm -rf "$tmp_istatus"
	return $E_NOERROR
}

restore_rclocal() {
	rclocal=/etc/rc.local
	rclocal_backup=/etc/rc.local.backup

	[[ -f "$rclocal" ]] || [[ -f "$rclocal_backup" ]] || return

	# Try criterias of damaged express installation
	grep -q 'HOME_DIR' "$rclocal" || return
	grep -q '^mv /etc/rc.local.backup /etc/rc.local$' "$rclocal" || return
	grep -q '^reboot$' "$rclocal" || return

	tell_user "Failed express installation is detected!"
	tell_user "Trying to restore /etc/rc.local and other stuff"

	# Here are the commands which were not executed during the end
	# of express installation. See Ubuntu's part of UnattendedCd lib.
	mv -f "$rclocal_backup" "$rclocal"
	mv -f /opt/prl-tools-installer/S*gdm /etc/rc2.d/
	mv -f /opt/prl-tools-installer/S*kdm /etc/rc2.d/
	rm -rf /opt/prl-tools-installer
	mv -f /etc/issue.backup /etc/issue
}

# Install Guest Tools

install_guest_tools() {

	echo_progress
	istatus install_started "$INSTALL_FULL_PRODUCT_VERSION" \
		"start installation of parallels tools"

	tell_user
	tell_user $(date)
	tell_user "Start installation or upgrade of Guest Tools"

	echo_progress
	if [ -z "$SKIP_RCLOCAL_RESTORE" ]; then
		restore_rclocal
	else
		echo "Restoring rc.local is skipped"
	fi

	# Switching to update mode
	# If guest tools are not installed really remove_gt() will set UPDATE_MODE=0
	echo_progress
	UPDATE_MODE=1
	remove_gt

	result=$?
	if [ $result -eq $E_NOERROR ]; then
		echo "Register service to install new Guest Tools"
		# TODO register service
	fi

	echo_progress
	echo "Perform installation into the $INSTALL_DIR directory"
	# Create installation directory and copy files
	mkdir -p "$INSTALL_DIR"
	# Set up new style backup_dir
	BACKUP_DIR="$IBACKUP_DIR/.backup"
	# Create directory for backup files
	mkdir -p "$BACKUP_DIR"

	echo_progress
	install_kernel_modules
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		# Compilation of kernel modules is failed so do clean up
		rm -rf "$INSTALL_DIR"
		istatus install_failed "$INSTALL_FULL_PRODUCT_VERSION" \
			"failed installation of parallels tools"
		return $result
	fi

	# Ensure that after kernel update on CentOS
	# or RHEL our drivers won't end up in freshly
	# generated initramfs
	if [ -d "$DRACUT_CONF_DIR" ]; then
		echo 'omit_drivers+="prl_.*"' > "$DRACUT_KMODS_FILE"
	fi

	echo_progress
	# Special procedure to update installer stuff
	# because PTIAgent may be running there.
	local TMP_INSTALLER_DIR="$(mktemp -d -t prlinstallerXXXXXX)"
	cp -Rf "$INSTALLER_DIR" "$TMP_INSTALLER_DIR"
	mv -f "$TMP_INSTALLER_DIR/installer" "$INSTALL_DIR"
	chmod 755 "$INSTALL_DIR/installer"
	rm -rf "$TMP_INSTALLER_DIR"

	echo_progress
	cp -Rf "$TOOLS_DIR" "$INSTALL_DIR"
	cp -Rf "$INSTALL" "$INSTALL_DIR"
	cp -Rf "$INSTALL_GUI" "$INSTALL_DIR"
	cp -Rf "$BASE_DIR/version" "$INSTALL_DIR"
	[[ $UPDATE_MODE -eq 1 ]] &&
		if [ -d "$INSTALL_DIR/.backup" ]; then
			cp -Rf "$INSTALL_DIR/.backup" "$IBACKUP_DIR" &&
				rm -rf "$INSTALL_DIR/.backup"
		fi

	# Install blacklist and override ne2k-pci by our prl_eth
	if [ -d "$MODPROBED_DIR" ]; then
		cp -f "$INSTALLER_DIR/blacklist-parallels.conf" "$MODPROBED_DIR"
		echo "$ALIAS_NE2K_OVERRIDE" > "$MODPROBE_PRL_ETH_CONF"
	elif [ -f "$MODPROBE_CONF" ]; then
		echo "$ALIAS_NE2K_OVERRIDE" >> "$MODPROBE_CONF"
	else
		echo "$MODPROBE_CONF is missing"
	fi

	echo_progress
	# Install user space applications and drivers
	install_mode='--install'
	[[ $UPDATE_MODE -eq 1 ]] &&
		check_xconf_patched &&
			install_mode='--skip-xconf'
	install_tools_modules "$install_mode"
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		istatus install_failed "$INSTALL_FULL_PRODUCT_VERSION" \
			"failed installation of parallels tools"
		return $result
	fi

	echo_progress
	echo "Send installed Parallels Tools version to dispatcher."
	istatus installed "$INSTALL_FULL_PRODUCT_VERSION" "installed tools version"
	echo_progress
	return $E_NOERROR
}

install_ptiagent_starters() {
	local ptiagent_starter="${INSTALL_DIR_TOOLS}/../install-gui"
	local ptiagent_symlink="${BIN_DIR}/ptiagent"
	install_symlink "$ptiagent_starter" "$ptiagent_symlink"

	setup_session_launcher "${INSTALL_DIR_TOOLS}/ptiagent.desktop"
}

install_ptiagent() {
	TOOLS_BACKUP="$IBACKUP_DIR/.backup/.tools.list"
	mkdir -p "${TOOLS_BACKUP%/*}"

	local tgt_installer_dir="${INSTALL_DIR}/installer"
	mkdir -p "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/ptiagent32" "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/ptiagent64" "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/iagent32" "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/iagent64" "$tgt_installer_dir"

	mkdir -p "$INSTALL_DIR_TOOLS"
	cp -f "${TOOLS_DIR}/ptiagent.desktop" "$INSTALL_DIR_TOOLS"

	cp -f "$INSTALL_GUI" "$INSTALL_DIR"
	cp -f "${BASE_DIR}/version" "$INSTALL_DIR"

	install_ptiagent_starters
	install_kmods_src
}

is_reboot_required() {
	"$INSTALLER_DIR/detect-xserver.sh" -v >/dev/null 2>&1
	[ $? -eq $E_NOERROR ]
}

post_install() {
	echo ">>> Postinstall"
	echo "Enabling PRL_GL"
	/etc/init.d/prl-x11 start
	echo "Writing OS version and Xorg version"
	"$PMANAGER" --os-ver > "$IBACKUP_DIR/os.version"
	"$INSTALLER_DIR/detect-xserver.sh" --xver > "$IBACKUP_DIR/xorg.version"
	echo "Starting prltoolsd service:"
	PRL_SKIP_PTIAGENT_START=1 /etc/init.d/prltoolsd start
	echo_progress
}

RESTORE_BACKUP=
backup_old_version() {
	if [ ! -d "$INSTALL_DIR" ]; then
		echo "Previous version was not found. Nothing to backup."
		return 1
	fi

	echo "Installation of $TOOLS_NAME version '$FULL_PRODUCT_VERSION' was found."

	RESTORE_BACKUP=$(mktemp -t prltools-backup-XXXXXX.tar.gz)
	tar cz -C "$INSTALL_DIR" . >"$RESTORE_BACKUP" &&
		echo "Created previous version backup in '$RESTORE_BACKUP'" ||
		echo "Failed to create backup of previous version."
}

restore_old_version() {
	[ -r "$RESTORE_BACKUP" ] || return 1
	echo
	echo "Reinstalling previous version '$FULL_PRODUCT_VERSION'" \
		"from backup '$RESTORE_BACKUP'"
	echo '--------------------------------------------------------'
	tmp_installer=$(mktemp -d -t prl-tools-lin-XXXXXX)
	tar xzf "$RESTORE_BACKUP" -C "$tmp_installer" || return 1
	rm -f "$RESTORE_BACKUP"
	"$tmp_installer/install" --install-unattended-with-deps
	rc=$?
	echo '--------------------------------------------------------'
	[ $rc -eq 0 ] &&
		tell_user "Previous version '$FULL_PRODUCT_VERSION' was" \
			"reinstalled successfully" ||
		perror "Failed to restore previous version '$FULL_PRODUCT_VERSION'" \
			"(retcode $rc)"
	rm -rf "$tmp_installer"
	return $rc
}

show_installer_error() {
	if [ $result -ne $E_NOPKG -a -z "$FLAG_CHECK_GUI" ]; then
		# Log is not created if installer failed with error $E_NOPKG
		perror "Error: failed to $2 $TOOLS_NAME!"
		[ -f "$LOG" ] && [ -z $VERBOSE ] &&
			perror "Please, look at $LOG file for more information."
	fi
}

show_installer_ok() {
	if [ "$1" = 'install' ]; then
		msg0='installed'
		msg1='installation'
	elif [ "$1" = 'upgrade' ]; then
		msg0='upgraded'
		msg1='upgrade'
	elif [ "$1" = 'remove' ]; then
		msg0='removed'
		msg1='removal'
	elif [ "$1" = 'restore' ]; then
		msg0='restored'
		msg1='recovery'
	fi

	tell_user "$TOOLS_NAME were $msg0 successfully!"
	[ $REBOOT_REQUIRED -eq 1 ] &&
		tell_user "Please, reboot your OS to finish $msg1 of $TOOLS_NAME."
}

install_proc() {
	tell_user "Started installation of $TOOLS_NAME version '$INSTALL_FULL_PRODUCT_VERSION'"
	check_restrictions
	result=$?
	[ $result -ne $E_NOERROR ] &&
		{ show_installer_error $result "install or upgrade"; return $result; }

	[ $RESTORE_ON_FAIL -eq 1 ] && backup_old_version
	install_guest_tools
	result=$?
	# UPDATE_MODE is set only in install_guest_tools
	[ $UPDATE_MODE -eq 1 ] && type_msg='upgrade' || type_msg='install'
	if [ $result -ne $E_NOERROR ]; then
		show_installer_error $result "$type_msg"
		if [ $RESTORE_ON_FAIL -eq 1 ]; then
			tell_user "Trying to restore previous $TOOLS_NAME installation..."
			type_msg='restore'
			restore_old_version || return $?
		else
			return $result
		fi
	fi
	post_install
	result=$?
	show_installer_ok "$type_msg"
	return $result
}

remove_proc() {
	check_requirements
	remove_guest_tools
	result=$?
	msg='remove'
	if [ $result -eq $E_NOERROR ]; then
		show_installer_ok "$msg"
	else
		show_installer_error $result "$msg"
	fi
	if ( type lsb_release && type dpkg-reconfigure ) > /dev/null 2>&1; then
		distro=$(lsb_release -i | awk -F " " '{print $3}')
		if [ "$distro" = "Ubuntu" ]; then
			dpkg-reconfigure xserver-xorg
		fi
	fi
	return $result
}

install_x_tools_modules() {
	tell_user $(date)
	tell_user "Starting installation of Parallels Tools for Linux X modules"
	install_and_configure_x
	local result=$?
	if [ $result -eq 0 ]; then
		tell_user "PTfL X modules installation finished successfully"
	else
		tell_user "PTfL X modules installation failed"
	fi
	return $result
}

# Install, upgrade or remove Guest Tools

is_reboot_required && REBOOT_REQUIRED=1

if [ $# -eq 0 ]; then
	perror "Error: wrong number of input parameters [$#]"
	perror
	usage
	exit $E_NOARGS
fi

while [[ $# -gt 0 ]]; do
	case "$1" in
		--install-x-modules)
			action="install_x_tools_modules"
			;;

		--install-ptiagent)
			action="install_ptiagent"
			;;

		-i | --install | --install-unattended \
				| --force-install | --install-unattended-with-deps)
			action="install_proc"
			;;

		-r | --remove)
			action="remove_proc"
			;;

		-v | --version)
			echo "$INSTALL_FULL_PRODUCT_VERSION"
			exit $E_NOERROR
			;;

		-h | --help)
			usage
			exit $E_NOERROR
			;;

		--verbose)
			VERBOSE=1
			;;

		--progress)
			SHOW_PROGRESS=1
			;;

		--restore-on-fail)
			RESTORE_ON_FAIL=1
			;;

		--skip-rclocal-restore)
			SKIP_RCLOCAL_RESTORE=1
			;;

		*)
			perror "Error: wrong input parameter [$1]"
			perror
			usage
			exit $E_WARG
			;;
	esac
	shift
done

start_logging
$action
exit $?
