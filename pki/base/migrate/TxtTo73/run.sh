#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

#####################################################################
###                                                               ###
###  This script converts a normalized <Source CS Version> ldif   ###
###  text file (e. g. - created via a <Source CS Version>ToTxt    ###
###  script) into a CS 7.3 ldif data file.                        ###
###                                                               ###
###  This CS 7.3 ldif data file can then be imported into         ###
###  the internal database of the desired CS 7.3 server           ###
###  using a utility such as ldif2db.                             ###
###                                                               ###
#####################################################################

###
###  Java Runtime Environment
###
JRE_ROOT=/usr/lib/jvm/jre-1.5.0
export JRE_ROOT

############################################################################
###                                                                      ###
###             *** DON'T CHANGE ANYTHING BELOW THIS LINE ***            ###
###                                                                      ###
############################################################################


###
###  Script-defined constants
###

CS="CS 7.3"
export CS

OS_NAME=`uname`
export OS_NAME

ARCH=`uname -i`
export ARCH


##
##  Perform a usage check for the appropriate number of arguments:
##

if [ $# -lt 1 -o $# -gt 2 ] ; then
	echo
	echo "Usage:  $0 input [errors] > output"
	echo
	echo "        where:  input  - the specified ${CS} ldif data file,"
	echo "                errors - an optional errors file containing"
	echo "                         skipped attributes, and"
	echo "                output - the normalized ${CS} ldif text file."
	echo
	echo "                NOTE:  If no redirection is provided to"
	echo "                       'output', then the normalized"
	echo "                       ${CS} ldif text will merely"
	echo "                       be echoed to stdout."
	echo
	exit 1
fi


###
###  Check that the specified "input" file exists and is a regular file.
###

if [ ! -f $1 ] ; then
	echo "ERROR:  Either the specified 'input' file, '$1', does not exist, "
	echo "        or it is not a regular file!"
	echo
	exit 2
fi


###
###  Check that the specified "input" file exists and is not empty.
###

if [ ! -s $1 ] ; then
	echo "ERROR:  The specified 'input' file, '$1', is empty!"
	echo
	exit 3
fi


###
###  If an "errors" file is specified, then check that it does not already
###  exist.
###

if [ $# -eq 2 ] ; then
	if [ -f $2 ] ; then
		echo "ERROR:  The specified 'errors' file, '$2', already exists!"
		echo "        Please specify a different file!"
		echo
		exit 4
	fi
fi

###
###  Setup the appropriate library path environment variable
###  based upon the platform
###
###  NOTE:  As of SunOS JDK 1.4.0, the required "Unicode" classes
###         have been moved from "i18n.jar" to "rt.jar".
###

CLASSPATH=/usr/share/rhpki/migrate/TxtTo73/classes:/usr/share/java/rhpki/certsrv.jar:/usr/share/java/rhpki/cmscore.jar:/usr/share/java/rhpki/nsutil.jar:/usr/lib/java/dirsec/jss4.jar:${JRE_ROOT}/lib/rt.jar
export CLASSPATH

if [ ${OS_NAME} = "Linux" ] ; then
    if [ ${ARCH} = "i386" ] ; then
	  LD_LIBRARY_PATH=/usr/lib/dirsec:/usr/lib:${JRE_ROOT}/lib:${JRE_ROOT}/lib/i386/native_threads
	  export LD_LIBRARY_PATH
    else # x86_64
	  LD_LIBRARY_PATH=/usr/lib64/dirsec:/usr/lib64:${JRE_ROOT}/lib:${JRE_ROOT}/lib/i386/native_threads
	  export LD_LIBRARY_PATH
      CLASSPATH=/usr/share/rhpki/migrate/TxtTo73/classes:/usr/share/java/rhpki/certsrv.jar:/usr/share/java/rhpki/cmscore.jar:/usr/share/java/rhpki/nsutil.jar:/usr/lib64/java/dirsec/jss4.jar:${JRE_ROOT}/lib/rt.jar
      export CLASSPATH
    fi
else # SunOS 64-bits
	LD_LIBRARY_PATH=/usr/lib/sparcv9/dirsec:/usr/lib/sparcv9:${JRE_ROOT}/lib:${JRE_ROOT}/lib/sparc/native_threads
	export LD_LIBRARY_PATH
    CLASSPATH=/usr/share/rhpki/migrate/TxtTo73/classes:/usr/share/java/rhpki/certsrv.jar:/usr/share/java/rhpki/cmscore.jar:/usr/share/java/rhpki/nsutil.jar:/usr/lib/sparcv9/java/dirsec/jss4.jar:${JRE_ROOT}/lib/rt.jar
     export CLASSPATH
fi


###
###  Convert the specified ${CS} ldif data file
###  into a normalized ${CS} ldif text file.
###

${JRE_ROOT}/bin/java -classpath ${CLASSPATH} Main $1 $2
