#!/bin/bash
# Copyright (C) 1999-2016 Parallels International GmbH. All rights reserved.
#
# This script restart network inside SuSE like VM.
#

SPATH="/etc/init.d"
SERVICE="network"

if [ ! -f $SPATH/$SERVICE ]; then
	service $SERVICE restart
else
	$SPATH/$SERVICE restart
fi
  
exit 0
# end of script
