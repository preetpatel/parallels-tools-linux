#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script restart network inside RedHat like VM.
#

nmcli_reset
/etc/init.d/network restart

exit 0
# end of script
