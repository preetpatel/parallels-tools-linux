#!/bin/bash
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
#
# Script to make everybody happy

# Supported distributions:
#	- debian (ubuntu)
#	- redhat
#	- fedora
#	- mandrake
#	- suse

# Supported products:
#	- sdk
#	- gtools

# Supported generic package names
#	- gcc
#	- make
#	- kheaders
#	- libc32
#	- alsa32
#	- alsa64
#	- nbd
#	- dkms
#	- pam32
#	- perl
#	- checkpolicy
#	- hp_ppd
#	- kpartx
#	- dmsetup
#	- libelf-devel

PATH=${PATH:+$PATH:}/sbin:/bin:/usr/sbin:/usr/bin

# Script return codes
PM_OK=0
PM_NOT_FOUND=124
PM_LOCKED=123
PM_FAILED=3

# Globals
target_product=''
logfile=''
lib_deps_file=''
karch=$(uname -m)

# Some variables for check_precomp_kmods
BASE_DIR="$(dirname "$0")"
KMOD_DIR="$BASE_DIR/../kmods"

KMODS_PATHS="	prl_eth/pvmnet	\
		prl_tg/Toolgate/Guest/Linux/prl_tg	\
		prl_fs/SharedFolders/Guest/Linux/prl_fs"

package_manager()
{
	type dnf >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		echo "dnf"
		return 0
	fi

	type yum >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		echo "yum"
		return 0
	fi

	# TODO up2date for redhat enterprise <= 4

	# yast is unsupported

	# zypper for suse > 10.1
	# zypper precedes apt-get because apt-get is also present and
	# may be used on Suse, but zypper takes priority, being native
	# package manager, with all consequences regarding, for example,
	# deprecation of apt-get in Suse 42.1
	type zypper >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		echo "zypper"
		return 0
	fi

	# TODO rug in sles/sled, suse <= 10.1

	type apt-get >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		#don't use old apt-get
		ver=$(apt-get -v | grep -m 1 apt)
		ver=${ver#* }
		#compare with 0.6.
		echo $ver | grep -q "^0\.[0-5]\."
		rc1=$?
		if [ $rc1 -ne 0 ] ; then
			echo "apt-get"
			return 0
		fi
	fi

	type urpmi >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		echo "urpmi"
		return 0
	fi

	type pacman >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		echo "pacman"
		return 0
	fi

	return 1
}


# Returns packages suffix for ia32 architecture for
# RedaHat-based distros
# Arguments
#  $1 - os name
#  $2 - os version
rh_arch()
{
	if [ "x$1" = "xfedora" -a $2 -ge 11 -o \
		 "x$1" = "xredhat" -a $2 -ge 6 ]; then
		echo "i686"
	else
		echo "i386"
	fi
}


# Prints package name $1 specific to distro $2 of version $3
# Returns:
# 0 - package name mapping was found successfully
# 1 - mapping was not found
# 2 - some other error
map_package_name()
{
	local package_name=$1
	local os_name=$2
	local os_version=$3

	case "$package_name" in
		gcc)
			echo "gcc"
		;;

		make)
			echo "make"
		;;

		kheaders)
			local kver=$(uname -r)
			case "$os_name" in
				debian)
					echo "linux-headers-${kver}"
				;;
				redhat|fedora)
					if [ -d /lib/modules/$kver ]; then
						kernel_package=$(rpm -qf /lib/modules/$kver)
						devel_package=$(echo $kernel_package | \
							sed "s/kernel\(-[a-zA-Z\-]*\)/kernel\1devel-/")
						if [ "$os_name" = 'fedora' -a $os_version -ge 21 ]; then
							devel_package=$(echo $devel_package | sed "s/-core-/-/")
						fi
						echo $devel_package
					else
						return 1
					fi
				;;
				suse)
					# sample: uname -r = 2.6.25.9-0.2-default
					# but package version is 2.6.25.9-0.2
					kver_base=$(echo $kver | sed -e "s/\(.*\)-[a-z]*/\1/g")
					# kernel-*-devel was introduced in SLES/SLED 11.1 and
					# in OpenSUSE 11.2
					test -f /etc/SuSE-release &&
						grep -qi openSUSE /etc/SuSE-release &&
						kdev_ver=11.2 || \
						kdev_ver=11.1
					if awk "BEGIN {exit !($os_version >= $kdev_ver)}"; then
						echo "kernel-${kver##*-}-devel=${kver_base}"
					else
						echo "kernel-source=${kver_base}"
					fi
				;;
				mageia)
					echo "kernel-$(echo $kver | cut -d- -f2)-devel"
				;;
				mandrake)
					# for 2008.0 & 2008.1 - kernel-devel
					# for older and newer - need to investigate
					echo "kernel-devel"
				;;
				archlin)
					# E.g., for kernel 4.10 Arch has
					# package named linux410-headers
					local kver_maj_min=$(echo $kver | awk -F. '{ print $1$2 }')
					echo "linux${kver_maj_min}-headers"
				;;
				*)
					echo "kernel headers"
					return 1
				;;
			esac
		;;

		libc32)
			case "$os_name" in
				debian)
					echo "libc6-i386"
				;;
				redhat|fedora)
					echo "glibc.$(rh_arch $os_name $os_version)"
				;;
				suse)
					echo "glibc-32bit"
				;;
				mandrake|mageia)
					echo "glibc6"
				;;
				*)
					echo "32-bit glibc"
					return 1
				;;
			esac
		;;

		alsa32)
			# alsa32 can be requested both for 32- and 64-bit systems.
			# If on 64-bit system alsa is already installed need to try
			# to install 32-bit of exactly the same version.
			# If on 64-bit system there's no alsa of any bitness let's
			# install package without specifying version because recent one
			# should be used by package management system.
			case "$os_name" in
				debian)
					# 32-bit version has strict dependency on 64-bit
					test "_$karch" = "_x86_64" &&
						echo "lib32asound2" ||
						echo "libasound2"
				;;
				redhat|fedora)
					# check if 64-bit version is installed
					alsalib=$(rpm -q alsa-lib.x86_64 2>/dev/null)
					# strip out x86_64 suffix
					test $? -eq 0 -a -n "$alsalib" &&
						alsalib="${alsalib%.x86_64}" ||
						alsalib=alsa-lib
					echo "${alsalib}.$(rh_arch $os_name $os_version)"
				;;
				suse)
					if [ "_$karch" = "_x86_64" ]; then
						alsalib=$(rpm -q libasound2 2>/dev/null)
						test $? -eq 0 -a -n "$alsalib" &&
							ver="=$(echo "$alsalib" | sed 's/^libasound2-//')" ||
							ver=
						echo "libasound2-32bit$ver"
					else
						echo "libasound2"
					fi
				;;
				mandrake|mageia)
					# TODO Strict version install is not implemented
					echo "libalsa2"
				;;
				*)
					echo "32-bit libasound"
					return 1
				;;
			esac
		;;

		alsa64)
			# Is expected to be requested only on 64-bit systems. The same thing with version
			# as for alsa32.
			case "$os_name" in
				debian)
					echo "libasound2"
				;;
				redhat|fedora)
					# check if 32-bit version is installed
					alsalib=$(rpm -q alsa-lib 2>/dev/null)
					# strip out suffix
					test $? -eq 0 -a -n "$alsalib" &&
						alsalib="${alsalib%.i?86}" ||
						alsalib=alsa-lib
					echo "${alsalib}.x86_64"
				;;
				suse)
					alsalib=$(rpm -q libasound2-32bit 2>/dev/null)
					test $? -eq 0 -a -n "$alsalib" &&
						ver="=$(echo "$alsalib" | sed 's/^libasound2-32bit-//')" ||
						ver=
					echo "libasound2$ver"
				;;
				mandrake|mageia)
					echo "libalsa2"
				;;
				*)
					echo "64-bit libasound"
					return 1
				;;
			esac
		;;

		nbd)
			if [ "$os_name" = "debian" ]; then
				echo "nbd-client"
			else
				echo "nbd"
			fi
		;;

		dkms)
			echo "dkms"
		;;

		pam32)
			case "$os_name" in
				debian)
					echo "lib32pam-modules"
				;;
				redhat|fedora)
					echo "pam.$(rh_arch $os_name $os_version)"
				;;
				suse)
					echo "pam-32bit"
				;;
				mandrake|mageia)
					echo "pam"
				;;
				*)
					echo "32-bit pam modules"
					return 1
				;;
			esac
		;;

		perl)
			case "$os_name" in
				debian)
					echo "perl-base"
				;;
				redhat|fedora)
					echo "perl"
				;;
				suse)
					[ $os_version -ge 11 ] && echo "perl-base" || echo "perl"
				;;
				mandrake|mageia)
					echo "perl-base"
				;;
				archlin)
					echo "perl"
				;;
				*)
					echo "perl"
					return 1
				;;
			esac
		;;

		checkpolicy)
			echo "checkpolicy"
		;;

		selinux-policy-devel)
			# This package only is needed in Fedora 20 and above
			echo "selinux-policy-devel"
		;;

		dmsetup)
			case "$os_name" in
				debian)
					echo "dmsetup"
				;;
				redhat|fedora)
					echo "device-mapper"
				;;
				suse)
					echo "device-mapper"
				;;
				mandrake|mageia)
					echo "dmsetup"
				;;
				*)
					echo "dmsetup"
					return 1
				;;
			esac
		;;

		hp_ppd)
			case "$os_name" in
				debian)
					echo "printer-driver-postscript-hp"
				;;
				redhat)
					[ $os_version -ge 6 ] && echo "hpijs" || echo "foomatic"
				;;
				fedora)
					echo "hpijs"
				;;
				suse)
					echo "manufacturer-PPDs"
				;;
				mandrake|mageia)
					echo "hplip-hpijs-ppds"
				;;
				archlin)
					echo "hplip"
				;;
				*)
					echo "hpijs"
					return 1
				;;
			esac
		;;

		kpartx)
			echo "kpartx"
		;;

		libelf-devel)
			case "$os_name" in
				debian)
					echo "libelf-dev"
				;;
				redhat|fedora)
					echo "elfutils-libelf-devel"
				;;
				suse)
					echo "libelf-devel"
				;;
				mandrake|mageia)
					echo "libelfutils-devel"
				;;
				archlin)
					echo "libelf"
				;;
				*)
					echo "libelf-devel"
					return 1
				;;
			esac
		;;

		*)
			# unknown/unsupported package
			return 1
		;;
	esac

	return 0
}

map_libpackage_name_dnf_yum()
{
	local yum="$1"
	local libname="$2"
	local postfix=""
	local arch=$(uname -m)
	[ "$arch" == "x86_64" ] && postfix="()(64bit)"

	# the library architecture should specified be for dnf/yum
	local output=$(LANG=C $yum provides -q "${libname}${postfix}" 2>/dev/null)
	local rc=$?
	test $rc -eq 0 || return $PM_FAILED

	# no matching was found
	test -z "$output" && return $PM_FAILED

	# trying to pick out package name from dnf/yum's mass of output
	local packages_list=$(echo "$output" | grep ':' |
		egrep -v '^(Other|Matched from)' |
		grep -v '^[[:space:]]*:' |
		grep -v '^Repo' |
		sed 's/^\(.*\) :.*/\1/' |
		sed 's,^[0-9]*:,,g')
	local result_package=$(echo "$packages_list" | head -n 1)
	# trying to find newest package in the repository
	IFS=$'\n'
	for package in $packages_list; do
		[ "$package" \> "$result_package" ] && result_package=$package
	done
	unset IFS
	echo $result_package
	return $PM_OK
}

# Tries to map library name into package name relying on package manager
map_libpackage_name()
{
	pm=`package_manager`
	libname=$1

	case "$pm" in
		dnf)
			map_libpackage_name_dnf_yum "dnf" "$libname"
			return $?
		;;

		yum)
			map_libpackage_name_dnf_yum "yum" "$libname"
			return $?
		;;

		apt-get)
			# hueristics (or may be policy?) for debian-based distros:
			#  libName.so.N -> libnameN
			lib_name=`echo "$libname" | cut -d. -f1 | LANG=C tr '[[:upper:]]' '[[:lower:]]'`
			lib_ver=`echo "$libname" | cut -d. -f3`
			# if library name ends with number - add dash to separate it from lib version
			echo "${lib_name:${#lib_name}-1}" | grep -q '[0-9]' && \
				lib_name="${lib_name}-"
			echo "${lib_name}${lib_ver}"
			return $PM_OK
		;;

		zypper)
			# if zypper has capability option - use it, otherwise don't know how to map
			zypper_output=`zypper wp "${libname}" 2>/dev/null`
			rc=$?
			test $rc -eq 0 || return $PM_FAILED
			echo "$zypper_output" | tail -n1 | awk '{print $3}'
			return $PM_OK
		;;

		urpmi)
			# just asking urmpq to find rpm name
			urpmq -p "$libname" 2>/dev/null
			test $? -eq 0 && return $PM_OK
			return $PM_FAILED
		;;

		*)
			perror "Unknown utility for automatical download packages"
			# we must use return instead of abort to allow
			# showing of uninstalled packages instead of just strange error
			# (e.g. packages func will be called next)
			return 1
		;;
	esac
}


# Check if all packages listed in $1 installed on system where rpm presented.
# Using for fixing problems appeared when yum or zypper return success return
# code when repository is not avalable or requires package is absent in repo.
rpm_check_installed()
{
	for package in $1; do
		# In case of suse we may append exact version with '=':
		#	"pkg_name=pkg_version"
		# With such form of name we are not able to query it by rpm
		# and need to replace it with "pkg_name-pkg_verson*" which works.
		echo "$package" | grep -q '=' && package="${package/=/-}*"
		rpm -q "$package" >/dev/null 2>&1 || return 1
	done
}

# Install packages listed in $2 using package manager $1.
# All output is appended to file $3 (if not null).
# Returns:
# {yes, this script returns something TODO}
pm_install()
{
	local pm=$1
	local list="$2"
	local output="$3"

	exec 3>&-
	if [ -z "$output" ]; then
		exec 3>&1
	else
		exec 3>"$output"
	fi
	case "$pm" in
		dnf)
			local dnf_cahe="/var/cache/dnf"
			local dnf_persist="/var/lib/dnf"
			local rpmdb_lock_file="${dnf_persist}/rpmdb_lock.pid"
			local metadata_lock_file="$(find "$dnf_cahe" -name metadata_lock.pid -print -quit)"
			local download_lock_file="$(find "$dnf_cahe" -name download_lock.pid -print -quit)"
			if [ -r "$rpmdb_lock_file" ]; then
				local dnf_pid=$(cat "$rpmdb_lock_file")
			elif [ -r "$metadata_lock_file" ]; then
				local dnf_pid=$(cat "$metadata_lock_file")
			elif [ -r "$download_lock_file" ]; then
				local dnf_pid=$(cat "$download_lock_file")
			else
				local dnf_pid=''
			fi
			kill -0 "$dnf_pid" > /dev/null 2>&1
			if [ $? -ne 0 ];
			then
				dnf -y install $list >&3 2>&1
				rpm_check_installed "$list" || return $PM_FAILED
				return $PM_OK
			fi
			return $PM_LOCKED
		;;

		yum)
			kill -0 $(cat '/var/run/yum.pid' 2> /dev/null) > /dev/null 2>&1
			if [ $? -ne 0 ];
			then
				yum -y install $list >&3 2>&1
				rpm_check_installed "$list" || return $PM_FAILED
				return $PM_OK
			fi
			return $PM_LOCKED
		;;

		apt-get)
			local dpkg_lockfile='/var/lib/dpkg/lock'
			test -f "$dpkg_lockfile" && \
				grep -q $(stat -c %i "$dpkg_lockfile") /proc/locks && \
				exit $PM_LOCKED

			local src_list='/etc/apt/sources.list'
			local need_check_src=0
			if grep -qs '^[[:space:]]*deb[[:space:]]\+cdrom:' "$src_list"; then
				# cdroms is in sources configuration
				# need to check if it is mounted before apt-get call
				# otherwise it will stall promting to insert disk
				need_check_src=1

				# so let's gather disk lables of all mounted cdroms
				local disk_labels=
				IFS=$'\n'
				for mnt_pt in $(df -P -t iso9660 2> /dev/null | sed '1d' | awk '{print $6}'); do
					disk_info="$mnt_pt"/.disk/info
					test -r "$disk_info" || continue
					# double quotes should be replaced by underscores
					# as it is done in output of apt-get
					disk_labels="$disk_labels$(cat "$disk_info" | tr '"' '_')"$'\n'
				done
				unset IFS
			fi

			# Don't fail if 'apt-get update' return not succeed code
			# because the main task is to install packages and
			# 'apt-get install' can work even if update failed
			apt-get -q update >&3 2>&1
			echo "Return code from apt-get update is $?" >&3 2>&1

			retcode=0
			for pkg in $list;
			do
				local rc=0
				if [ $need_check_src -eq 1 ]; then
					msg=$(
						apt-get install -y -q --print-uris $pkg | grep "^'cdrom:\[" | \
						sed "s/^'cdrom:\[\(.*\)\].*/\1/" | \
						while read label; do
							# check each required label
							if ! echo "$disk_labels" | grep -q "$label"; then
								echo "Disk with label \"$label\" is not mounted"
								echo " - skipping package $pkg"
								break
							fi
						done
					)
					if [ -n "$msg" ]; then
						echo "$msg" >&3
						rc=1
					fi
				fi

				test $rc -eq 0 && apt-get -q -qq --allow-unauthenticated install "$pkg" \
					>&3 2>&1
				rc=$?
				# will just save the first error retcode
				test $retcode -eq 0 && retcode=$rc
			done
			test $retcode -eq 0 && return $PM_OK
			return $PM_FAILED
		;;

		zypper)
			kill -0 $(cat '/var/run/zypp.pid' 2> /dev/null) > /dev/null 2>&1
			if [ $? -ne 0 ];
			then
				zypper_opt="install -y"
				# Detect that options 'non-inveractive' and 'no-gpg-checks'
				# are supported by current version of zypper.
				for mode in 'non-interactive' 'no-gpg-checks';
				do
					LANG=C zypper --$mode 2>/dev/null |
						grep -q "Entering '\?$mode'\? mode" &&
							zypper_opt="--$mode $zypper_opt"
				done
				# Use 'capability' option starting for zypper 0.8
				zypper_ver=($(zypper --version 2>&1 | sed 's/^zypper \([0-9]*\)\.\([0-9]*\)\..*$/\1 \2/'))
				if [ ${zypper_ver[0]} -eq 0 -a ${zypper_ver[1]} -lt 8 ]; then
					list="$(echo $list | sed -e 's/kernel-source[^\ ]*/kernel-source/')"
				else
					zypper_opt="$zypper_opt --capability"
				fi
				for pkg in $list; do
					zypper $zypper_opt $pkg >&3 2>&1
				done
				rpm_check_installed "$list" || return $PM_FAILED
				return $PM_OK
			fi
			exit $PM_LOCKED
		;;
		urpmi)
			local urpmi_lockfile='/var/lib/urpmi/.LOCK'
			if [ ! -f "$urpmi_lockfile"  ] ||
				! grep -q $(stat -c %i "$urpmi_lockfile") /proc/locks;
			then
				urpmi --auto $list >&3 2>&1

				#if [ "$IS_KHEAD" != "0" ]
				#then
				#	# Just a small help for poor user
				#	# to avoid awful Mandriva's problem
				#	KSCR_0="/lib/modules/$(uname -r)/build"
				#	KSCR_1='/usr/src/linux'
				#	LINUX_FILE='include/linux/version.h'
				#	test ! -f "$KSRC_0/$LINUX_FILE" &&
				#		test -f "$KSRC_1/$LINUX_FILE" &&
				#			ln -s $KSRC_1 $KSRC_0
				#fi

				test $? -eq 0 && return $PM_OK
				return $PM_FAILED
			fi
			exit $PM_LOCKED
		;;

		pacman)
			if [ -f /var/lib/pacman/db.lck ]; then
				return $PM_LOCKED
			fi
			pacman --noconfirm -Sq $list >&3 2>&1
			pacman -Q $list >&3 2>&1
			[ $? -eq 0 ] && return $PM_OK
			return $PM_FAILED
		;;

		*)
			error "Unknown utility for automatical download packages"
			# we must use return instead of abort to allow
			# showing of uninstalled packages instead of just strange error
			# (e.g. packages func will be called next)
			return 1
		;;
	esac
}


perror () {
	echo "${@}" 1>&2
}


pm_help ()
{
help_text=`cat <<EOF
Usage: pm.sh [OPTIONS]

This utility is capable for managing packages Parallels products for Linux are depends on.
Main actions are checking for packages in system and installing them automatically.

Options:
    -c, --check PRODUCT       Prints list of packages needed to install for PRODUCT
    -i, --install PRODUCT     Installs packages needed for PRODUCT
    -l, --logfile FILENAME    Print all output from package manager into FILENAME instead of stdout
    --lib-deps FILENAME       File with libraries which dependences should be resolved
    --os-ver                  Prints OS version, according to lsb release
    -h, --help                Print this help

Supported products:
    sdk          (Parallels Virtualization SDK)
    gtools       (Parallels Guest Tools for Linux)
EOF`
	echo "$help_text" 1>&2
}


pm_parse_cmdline()
{
	while true; do
		case "${1}" in
			--check | -c)
				if [ "x${2}" = "x" ]; then
					perror "Missing argument to option: '${1}'"
					perror

					pm_help
					exit 1
				fi

				action='check'
				target_product="${2}"
				shift 2
				;;
			--install | -i)
				if [ "x${2}" = "x" ]; then
					perror "Missing argument to option: '${1}'"
					perror

					pm_help
					exit 1
				fi

				action='install'
				target_product="${2}"
				shift 2
				;;
			--logfile | -l)
				if [ "x${2}" = "x" ]; then
					perror "Missing argument to option: '${1}'"
					perror

					pm_help
					exit 1
				fi

				logfile="${2}"
				shift 2
				;;
			--lib-deps)
				if [ "x${2}" == "x" ]; then
					perror "Missing argument to option: '${1}'"
					perror

					pm_help
					exit 1
				fi

				lib_deps_file="${2}"
				shift 2
				;;
			--help | -h)
				pm_help
				exit 0
				;;
			--os-ver)
				action='--os-ver'
				target_product='gtools'
				shift 1
				;;
			*)
				if [ "x${1}" != "x" ]; then
					perror "Unknown option: '${1}'"
					perror

					pm_help
				else
					break
				fi
				exit 1
				;;
		esac
	done
}


detect_os_name()
{
	if [ -f "/etc/lsb-release" ] ; then
		egrep -q -i "debian|ubuntu" /etc/lsb-release
		if [ $? -eq 0 ] ; then
			echo "debian" #and ubuntu
			return 0
		fi
	fi

	if [ -f "/etc/debian_version" -a ! -f "/etc/xandros-desktop-version" ] ; then
		echo "debian"
		return 0
	fi


	if [ -f "/etc/fedora-release" ] ; then
		echo "fedora"
		return 0
	fi

	if [ -f "/etc/mageia-release" ] ; then
		echo "mageia"
		return 0
	fi

	if [ -f "/etc/mandrake-release" -o -L "/etc/mandriva-release" ] ; then
		echo "mandrake"
		return 0
	fi

	if [ -f "/etc/redhat-release" ] ; then
		echo "redhat" #and centos
		return 0
	fi

	if [ -f "/etc/SuSE-release" ] ; then
		echo "suse"
		return 0
	fi

	if grep -Eq 'NAME.*SUSE (Leap|Tumbleweed)' /etc/os-release 2>/dev/null; then
		echo "suse"
		return 0
	fi

	if [ -f "/etc/manjaro-release" ] ||
		[ -f "/etc/arch-release" ] ; then
		echo "archlin"
		return 0
	fi

	echo "unknown"
	return 1
}


# Prints
detect_os_version()
{
	local osname=$1 ver=""

	case "$osname" in
		debian)
			if type lsb_release >/dev/null 2>&1; then
				ver=$(lsb_release -r | \
					awk '{
						if (match($2, "[0-9]"))
							print $2
					}')
			else
				ver=$(cat /etc/issue | sed "s/[^0-9.]//g")
			fi
			echo $ver
		;;
		redhat|fedora)
			ver=`rpm -qf /etc/redhat-release | sed -e "s/[-a-zA-Z]*-\([0-9]\+\).*/\1/g"`
			echo $ver
		;;
		mageia)
			ver=$(cut -d' ' -f3 /etc/mageia-release)
			echo $ver
		;;
		mandrake)
			ver=`cat /etc/mandrake-release | cut -d' ' -f4`
			echo $ver
		;;
		suse)
			if [ -f '/etc/SuSE-release' ]; then
				release=`sed -n 's/VERSION[[:space:]]*=[[:space:]]*\([[:digit:]]\+\)/\1/p' /etc/SuSE-release`
				patchlevel=`sed -n 's/PATCHLEVEL[[:space:]]*=[[:space:]]*\([[:digit:]]\+\)/\1/p' /etc/SuSE-release`
				[ -n "$patchlevel" ] &&
					echo "$release.$patchlevel" ||
					echo "$release"
			else
				echo $(source /etc/os-release; echo $VERSION)
			fi
		;;
		unknown|*)
			echo ""
		;;
	esac

	return 0
}


# Returns:
# 0 - precompiled kernel modules are available for kernel version $1 on arch $2
# 1 - otherwise
check_precomp_kmods()
{
	if [ $(echo $1 | cut -d'.' -f2) -eq 4 ]; then
		# 2.4.x
		kext=o
	else
		# 2.6.x
		kext=ko
	fi

	# TODO
	# Rework this stupid code.

	[ -d "$KMOD_DIR" ] || return 1
	kdir=$(ls "$KMOD_DIR" 2>/dev/null | grep "${1}-${2}")
	[ -n "$kdir" ] || return 1
	for kmod_path in $KMODS_PATHS; do
		kmod=$(echo "$kmod_path" | sed -e "s#/.*##")
		fmod="${KMOD_DIR}/${kdir}/${kmod}.${kext}"
		[ -e "$fmod" ] || return 1
	done

	return 0
}


# Checks if libasound.so.2 is installed in system
# Argument:
#  32 or 64 - requested bitness of libasound
# Returns:
# 0 - libasound.so.2 is installed
# 1 - otherwise
check_alsa()
{
	LANG=C file -L `ldconfig -p |
		grep '/libasound\.so\.2' |
		sed -e 's/^.* => //'` 2>/dev/null |
		grep -q "ELF ${1}-bit" && return 0

	return 1
}


# Checks if 32-bit PAM modules are available in system
# Returns:
# 0 - 32-bit PAM is available
# 1 - otherwise
check_pam32()
{
	for d in /lib/security /lib32/security
	do
		mod="$d/pam_unix.so"
		test -f "$mod" && LANG=C file -L "$mod" |
			grep -q 'ELF 32-bit' && return 0
	done
	return 1
}


# Checks if libelf-dev is available in system.
# The best check is to try to link simple program with '-lelf' but
# at the moment compiler may not be available.
check_libelf()
{
	LANG=C ldconfig -p | grep -q '^[[:space:]]*libelf.so (' && return 0
	local lib_list
	if [ "$karch" = 'x86_64' ]; then
		lib_list='lib lib64 lib/x86_64-linux-gnu'
	else
		lib_list='lib lib/i386-linux-gnu lib/i686-linux-gnu'
	fi
	for d in $lib_list; do
		[ -r "/usr/${d}/libelf.so" ] && return 0
	done
	return 1
}

# Returns 0 if current kernel version is equal or greater then $1.$2.
# Only major and minor numbers are taken, patch version is not considered.
kver_ge()
{
	local maj=$1
	local min=$2
	local kver_items
	(IFS=. kver_items=($kver)
	[ ${kver_items[0]} -gt $maj ] && return 0
	[ ${kver_items[0]} -eq $maj -a ${kver_items[1]} -ge $min ])
}


# Prints out list of packages needed to install to resolve dependences
# of libraries listed in $lib_deps_file.
# All packages are marked as mandatory.
process_lib_deps_file()
{
	test  -r "$lib_deps_file" || \
		(perror "Cannot read lib deps file '${lib_deps_file}'"; exit 1)

	local dep_libs_list=''
	IFS=$'\n'
	for elf_file in `cat "$lib_deps_file"`
	do
		if ! ldd "$elf_file" >/dev/null 2>&1; then
			# file is not an valid executalbe for this system, just skip it
			continue
		fi
		deps=`LANG=C ldd "$elf_file" | grep 'not found' | awk '{print $1}'`
		dep_libs_list="${dep_libs_list:+${dep_libs_list}${IFS}}${deps}"
	done
	unset IFS
	dep_libs_list=`echo "$dep_libs_list" | sort -u`

	# all dependencies are met
	test -z "$dep_libs_list" && return

	# need to get list of packages to resolve all that deps
	mapped_dep_libs_list=`echo "$dep_libs_list" |
		while read libname; do
			mapped_libname=$(map_libpackage_name ${libname})
			test $? -eq 0 && echo "m ${mapped_libname}" || echo "m ${libname}"
		done`
	echo "$mapped_dep_libs_list" | sort -u
}


# Returns list of packages needed for product $1 on distro $2 of version $3
check_deps()
{
	local deps_list=''

	if [ "$1" = 'gtools' ]; then
		# product uses kernel modules

		local kver=$(uname -r)

		install_need='m'
		if check_precomp_kmods $kver $karch; then
			# Install packages optionally
			install_need='o'
		fi

		type gcc > /dev/null 2>&1 ||
			deps_list="${deps_list:+${deps_list}\n}$install_need gcc"

		type make > /dev/null 2>&1 ||
			deps_list="${deps_list:+${deps_list}\n}$install_need make"

		if [ ! -f "/lib/modules/${kver}/build/include/linux/version.h" -a \
			 ! -f "/lib/modules/${kver}/build/include/generated/uapi/linux/version.h" ]
		then
			deps_list="${deps_list:+${deps_list}\n}$install_need kheaders"
		fi

		type perl > /dev/null 2>&1 ||
			deps_list="${deps_list:+${deps_list}\n}$install_need perl"

		type dkms > /dev/null 2>&1 ||
			deps_list="${deps_list:+${deps_list}\n}o dkms"

		# We require libelf-devel starting from kernel 4.15
		if kver_ge 4 15; then
			check_libelf ||
				deps_list="${deps_list:+${deps_list}\n}m libelf-devel"
		fi

		local selinux_policy_file="/usr/share/selinux/devel/Makefile"
		if [ ! -f $selinux_policy_file ]; then
			local selinux_needed=0
			case "$os_name" in
				fedora)
					[ $os_version -ge 20 ] && selinux_needed=1
				;;
				redhat)
					[ $os_version -ge 7 ] && selinux_needed=1
				;;
			esac
			[ $selinux_needed -eq 1 ] && \
				deps_list="${deps_list:+${deps_list}\n}m selinux-policy-devel"
		fi

	fi

	if [ "x$1" = "xgtools" ]; then
		if type sestatus >/dev/null 2>&1; then
			type checkmodule >/dev/null 2>&1 ||
				deps_list="${deps_list:+${deps_list}\n}m checkpolicy"
		fi

		if type lpinfo >/dev/null 2>&1; then
			lpinfo -m 2>/dev/null | fgrep -q 'HP Color LaserJet 8500 Postscript' ||
				deps_list="${deps_list:+${deps_list}\n}o hp_ppd"
		fi
	fi

	echo -e "$deps_list"
	return 0
}


# Prints list of packages needed for installation
# in such form:
# >m package_name0
# >m package_name2
# >...
# >o package_nameX
# >o package_nameX+1
#
# Here the first letter is 'status' of the package:
# m - mandatory
# o - optional
# - they are processed differently
check_packages()
{
	local os_name=`detect_os_name`
	local os_version=`detect_os_version $os_name`
	local deps_list=`check_deps $target_product $os_name $os_version`

	# if lib-deps option was specified - process deps from appropriate file
	test -n "$lib_deps_file" && \
		process_lib_deps_file

	# If list is empty - dont print anything to keep output clear
	test -z "$deps_list" && return

	local deps_list_mapped=`echo "$deps_list" |
	while read package_state package_name; do
		echo "${package_state} $(map_package_name \
			${package_name} ${os_name} ${os_version})"
	done`
	echo "$deps_list_mapped" | sort
}


# Returns list of packages (generic names) required by guest tools
get_gtools_deps()
{
	local os_name=`detect_os_name`
	local os_version=`detect_os_version $os_name`
	check_deps gtools $os_name $os_version
}


pm_parse_cmdline $@


case $action in
	check)
		deps_list=`check_packages`

		test -z "$deps_list" && exit $PM_OK

		# There are some packages to install
		pm=`package_manager`
		# Show them, and place mandatory packages first
		echo "$deps_list"
		test -z $pm && exit $PM_NOT_FOUND
		exit $PM_OK
	;;

	install)
		pm=`package_manager`
		test -z $pm && exit $PM_NOT_FOUND

		deps_list=`check_packages`
		# Suppose here that package names dont have spaces in their names
		mnd_deps_list=`echo "$deps_list" | grep '^m' | cut -d' ' -f2`
		opt_deps_list=`echo "$deps_list" | grep '^o' | cut -d' ' -f2`

		# Processing mandatory packages
		# Inability to install some of them is fatal for the installation process
		if [ -n "$mnd_deps_list" ]; then
			# There are some mandatory packages to install
			mnd_deps_list=`echo "$mnd_deps_list" | tr '\n' ' '`
			pm_install $pm "$mnd_deps_list" "$logfile"
			rc=$?

			test $rc -eq $PM_LOCKED && exit $PM_LOCKED
			if [ $rc -ne $PM_OK ]; then
				check_packages
				exit $PM_FAILED
			fi
		fi

		# Processing optional packages
		# If we are failed to install some of them - not fatal
		if [ -n "$opt_deps_list" ]; then
			# There are some optional packets to install
			opt_deps_list=`echo "$opt_deps_list" | tr '\n' ' '`
			pm_install $pm "$opt_deps_list" "$logfile"
			rc=$?

			test $rc -eq $PM_LOCKED && exit $PM_LOCKED
			if [ $rc -ne $PM_OK ]; then
				# Error in optional packets installation is not fatal
				check_packages
				exit $PM_OK
			fi
		fi

		exit $PM_OK
	;;

	--os-ver)
		detect_os_version $(detect_os_name)
		exit 0
	;;

	*)
		perror "Unknown action"
	;;
esac
