#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#####################################################################
###                                                               ###
###  This script creates the "45ToTxt/classes/Main.class" and     ###
###  "41ToTxt/classes/CMS45LdifParser.class" which are            ###
###  used to create a normalized CMS 4.5 ldif text file.          ###
###                                                               ###
#####################################################################


###
###  Set SERVER_ROOT - identify the CMS <server_root> used to compile 45ToTxt
###

#SERVER_ROOT=/export/home/migrate/cms45
#export SERVER_ROOT


###
###  Set JDK_PLATFORM - must be "Linux" or "SunOS"
###

#JDK_PLATFORM=SunOS
#export JDK_PLATFORM


###
###  Set JDK_VERSION - specify the JDK version used by this version of CMS
###
###                    CMS 4.5 NOTE:          "Linux" - 1.3.0
###                                           "SunOS" - 1.3.0
###
###                    CMS 4.5 CONSOLE NOTE:  "Linux" - 1.1.7
###                                           "SunOS" - 1.1.6
###

#JDK_VERSION=CMS_4.5
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

CMS="CMS 4.5"
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

if [ ${OS_NAME} = "Linux" ] ; then
	LD_LIBRARY_PATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/i386/native_threads
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
###  Compile 45ToTxt - create "CMS45LdifParser.class" and "Main.class"
###

${JAVA_HOME}/bin/javac -d ${TARGET} -classpath ${JAVA_HOME}/jre/lib/rt.jar:${SERVER_ROOT}/bin/cert/jars/certsrv.jar:${SERVER_ROOT}/bin/cert/jars/jss3.jar Main.java

