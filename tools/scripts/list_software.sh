#!/bin/bash
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
#
# Script prints to stdout list of installed in Linux system packages in format:
# <package_name> <version> <vendor>
#

PATH="/bin:/sbin:/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/bin:/usr/local/sbin:$PATH"

which rpm > /dev/null 2>&1 && \
	rpm -qa --qf "%{name} %{version}-%{release} %{vendor}\n"
which dpkg-query > /dev/null 2>&1 && \
	dpkg-query -W -f='${Package} ${Version} ${Maintainer}\n'
