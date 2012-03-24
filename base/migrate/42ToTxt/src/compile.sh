#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#####################################################################
###                                                               ###
###  This script creates the "42ToTxt/classes/Main.class" and     ###
###  "42ToTxt/classes/CMS42LdifParser.class" which are            ###
###  used to create a normalized CMS 4.2 ldif text file.          ###
###                                                               ###
#####################################################################


###
###  Set SERVER_ROOT - identify the CMS <server_root> used to compile 42ToTxt
###

#SERVER_ROOT=/export/home/migrate/cms42
#export SERVER_ROOT


###
###  Set JDK_PLATFORM - must be "AIX", "HP-UX", "Linux", "OSF1", or "SunOS"
###

#JDK_PLATFORM=SunOS
#export JDK_PLATFORM


###
###  Set JDK_VERSION - specify the JDK version used by this version of CMS
###
###                    CMS 4.2 NOTE:  "AIX"   - 1.1.6_10
###                                   "HP-UX" - 1.1.6
###                                   "Linux" - 1.1.7
###                                   "OSF1"  - 1.1.6
###                                   "SunOS" - 1.1.6
###

#JDK_VERSION=CMS_4.2
#export JDK_VERSION


###
###  Set JAVA_HOME - specify the complete path to the JDK
###

#JAVA_HOME=/share/builds/components/cms_jdk/${JDK_PLATFORM}/${JDK_VERSION}
#export JAVA_HOME


############################################################################
###                                                                      ###
###             *** DON'T CHANGE ANYTHING BELOW THIS LINE ***            ###
###                                                                      ###
############################################################################


###
###  Script-defined constants
###

CMS="CMS 4.2"
export CMS


OS_NAME=`uname`
export OS_NAME


###
###  Perform a usage check for the appropriate number of arguments:
###

if [ $# -gt 0 ] ; then
	echo
	echo "Usage:  $0"
	echo
	echo "        NOTE:  No arguments are required to build the"
	echo "               normalized ${CMS} ldif text classes."
	echo
	exit 1
fi


###
###  Check presence of user-defined variables
###

if [ -z "${SERVER_ROOT}" -o -z "${JAVA_HOME}" ] ; then
	echo "ERROR:  Please specify the SERVER_ROOT and JAVA_HOME "
	echo "        environment variables for this script!"
	echo
	exit 2
fi


###
###  Check that the specified SERVER_ROOT exists and is a directory
###

if [ ! -d "${SERVER_ROOT}" ] ; then
	echo "ERROR:  Either the specified SERVER_ROOT does not exist, "
	echo "        or it is not a directory!"
	echo
	exit 3
fi


###
###  Check that the specified JAVA_HOME exists and is a directory
###

if [ ! -d "${JAVA_HOME}" ] ; then
	echo "ERROR:  Either the specified JAVA_HOME does not exist, "
	echo "        or it is not a directory!"
	echo
	exit 4
fi


###
###  Setup the appropriate library path environment variable
###  based upon the platform
###

if [ ${OS_NAME} = "AIX" ] ; then
	LIBPATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/aix/native_threads
	export LIBPATH
elif [ ${OS_NAME} = "HP-UX" ] ; then
	SHLIB_PATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/PA_RISC/native_threads
	export SHLIB_PATH
elif [ ${OS_NAME} = "Linux" ] ; then
	LD_LIBRARY_PATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/i386/native_threads
	export LD_LIBRARY_PATH
elif [ ${OS_NAME} = "OSF1" ] ; then
	LD_LIBRARY_PATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/alpha/native_threads
	export LD_LIBRARY_PATH
else # SunOS
	LD_LIBRARY_PATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/sparc/native_threads
	export LD_LIBRARY_PATH
fi


###
###  Set TARGET - identify the complete path to the new classes target directory
###

TARGET=../classes
export TARGET


###
###  Create the new classes target directory (if it does not already exist)
###

if [ ! -d ${TARGET} ]; then
	mkdir -p ${TARGET}
fi


###
###  Compile 42ToTxt - create "CMS42LdifParser.class" and "Main.class"
###

${JAVA_HOME}/bin/javac -d ${TARGET} -classpath ${JAVA_HOME}/lib/classes.zip:${SERVER_ROOT}/bin/cert/jars/certsrv.jar:${SERVER_ROOT}/bin/cert/jars/jss.jar:${SERVER_ROOT}/bin/cert/jars/jssjdk12.jar Main.java

