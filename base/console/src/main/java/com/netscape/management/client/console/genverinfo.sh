#!/bin/sh
# BEGIN COPYRIGHT BLOCK
# Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
# Copyright (C) 2005 Red Hat, Inc.
# All rights reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation version
# 2.1 of the License.
#                                                                                 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#                                                                                 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# END COPYRIGHT BLOCK

#
# Shell script to create versioninfo.properties file
# Input parameters are:
#                 outputFile       (e.g. versioninfo.properties)
#                 versionNumber    (e.g. 4.1)
#                 buildNUmberFile  (e.g. /ns/netsite/WINNT/buildnum.dat)
#
#

if [ $# -ne 4 ]; then 
	echo Usage: $0 outputFile versionNumber majorVersionNumber buildNumberFile
	exit  1
fi

echo console-versionNumber=$2 > $1
echo console-majorVersionNumber=$3 >> $1
bld=`cat $4`
echo console-buildNumber=`eval eval echo $bld` >> $1
