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
###  This script converts a normalized <Source CMS Version> ldif  ###
###  text file (e. g. - created via a <Source CMS Version>ToTxt   ###
###  script) into a CMS 6.1 ldif data file.                       ###
###                                                               ###
###  This CMS 6.1 ldif data file can then be imported into the    ###
###  internal database of the desired CMS 6.1 server using a      ###
###  utility such as ldif2db.                                     ###
###                                                               ###
#####################################################################


###
###  SERVER_ROOT - fully qualified path of the location of the server
###

#SERVER_ROOT=/export/home/migrate/cms61
#export SERVER_ROOT


###
###  INSTANCE  - if the CMS instance directory is called 'cert-ca',
###              set the CMS instance to 'ca'
###
###              NOTE:  When a single SERVER_ROOT contains more than
###                     one CMS instance, this script must be run multiple
###                     times.  To do this, there is only a need to change
###                     the INSTANCE parameter.
###

#INSTANCE=ca
#export INSTANCE


############################################################################
###                                                                      ###
###             *** DON'T CHANGE ANYTHING BELOW THIS LINE ***            ###
###                                                                      ###
############################################################################


###
###  Script-defined constants
###

CMS="CMS 6.1"
export CMS


OS_NAME=`uname`
export OS_NAME


##
##  Perform a usage check for the appropriate number of arguments:
##

if [ $# -lt 1 -o $# -gt 2 ] ; then
	echo
	echo "Usage:  $0 input [errors] > output"
	echo
	echo "        where:  input  - the specified ${CMS} ldif data file,"
	echo "                errors - an optional errors file containing"
	echo "                         skipped attributes, and"
	echo "                output - the normalized ${CMS} ldif text file."
	echo
	echo "                NOTE:  If no redirection is provided to"
	echo "                       'output', then the normalized"
	echo "                       ${CMS} ldif text will merely"
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
###  Check presence of user-defined variables
###

if [ -z "${SERVER_ROOT}" -o -z "${INSTANCE}" ] ; then
	echo "ERROR:  Please specify the SERVER_ROOT and INSTANCE "
	echo "        environment variables for this script!"
	echo
	exit 5
fi


###
###  Check that the specified SERVER_ROOT exists and is a directory
###

if [ ! -d "${SERVER_ROOT}" ] ; then
	echo "ERROR:  Either the specified SERVER_ROOT does not exist, "
	echo "        or it is not a directory!"
	echo
	exit 6
fi


###
###  Check that the specified INSTANCE exists and is a directory
###

if [ ! -d "${SERVER_ROOT}/cert-${INSTANCE}" ] ; then
	echo "ERROR:  Either the specified INSTANCE does not exist, "
	echo "        or it is not a directory!"
	echo
	exit 7
fi


###
###  Setup the appropriate library path environment variable
###  based upon the platform
###

if [ ${OS_NAME} = "HP-UX" ] ; then
	SHLIB_PATH=${SERVER_ROOT}/bin/cert/lib:${SERVER_ROOT}/bin/cert/jre/lib:${SERVER_ROOT}/bin/cert/jre/lib/PA_RISC/native_threads
	export SHLIB_PATH
elif [ ${OS_NAME} = "Linux" ] ; then
	LD_LIBRARY_PATH=${SERVER_ROOT}/bin/cert/lib:${SERVER_ROOT}/bin/cert/jre/lib:${SERVER_ROOT}/bin/cert/jre/lib/i386/native_threads
	export LD_LIBRARY_PATH
else # SunOS
	LD_LIBRARY_PATH=${SERVER_ROOT}/bin/cert/lib:${SERVER_ROOT}/bin/cert/jre/lib:${SERVER_ROOT}/bin/cert/jre/lib/sparc/native_threads
	export LD_LIBRARY_PATH
fi


###
###  Convert the specified ${CMS} ldif data file
###  into a normalized ${CMS} ldif text file.
###

${SERVER_ROOT}/bin/cert/jre/bin/java -classpath ./classes:${SERVER_ROOT}/cert-${INSTANCE}/classes:${SERVER_ROOT}/bin/cert/classes:${SERVER_ROOT}/bin/cert/jars/certsrv.jar:${SERVER_ROOT}/bin/cert/jars/cmscore.jar:${SERVER_ROOT}/bin/cert/jars/nsutil.jar:${SERVER_ROOT}/bin/cert/jars/jss3.jar:${SERVER_ROOT}/bin/cert/jre/lib/rt.jar Main $1 $2

