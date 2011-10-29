#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#####################################################################
###                                                               ###
###  This script creates the "TxtTo71/classes/Main.class",        ###
###  "TxtTo71/classes/CMS71LdifParser.class", and                 ###
###  "TxtTo71/classes/DummyAuthManager.class" which are           ###
###  used to create a CS 7.1 ldif data file.                      ###
###                                                               ###
#####################################################################


###
###  Set SERVER_ROOT - identify the CS <server_root> used to compile TxtTo71
###

#SERVER_ROOT=/export/home/migrate/cs71
#export SERVER_ROOT


###
###  Set JDK_PLATFORM - must be "HP-UX", "Linux", or "SunOS"
###

#JDK_PLATFORM=SunOS
#export JDK_PLATFORM


###
###  Set JDK_VERSION - specify the JDK version used by this version of CS
###
###                    CS 7.1 NOTE:   "HP-UX" - 1.4.0.00
###                                   "Linux" - 1.4.2
###                                   "SunOS" - 1.4.2
###

#JDK_VERSION=CS_7.1
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

CS="CS 7.1"
export CS


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
	echo "               ${CS} ldif data classes."
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

if [ ${OS_NAME} = "HP-UX" ] ; then
	SHLIB_PATH=${SERVER_ROOT}/bin/cert/lib:${JAVA_HOME}/lib:${JAVA_HOME}/lib/PA_RISC/native_threads
	export SHLIB_PATH
elif [ ${OS_NAME} = "Linux" ] ; then
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
###  Compile TxtTo71 - create "CMS71LdifParser.class", "DummyAuthManager.class",
###                    and "Main.class"
###

${JAVA_HOME}/bin/javac -d ${TARGET} -classpath ${JAVA_HOME}/jre/lib/rt.jar:${SERVER_ROOT}/bin/cert/jars/nsutil.jar:${SERVER_ROOT}/bin/cert/jars/certsrv.jar:${SERVER_ROOT}/bin/cert/jars/cmscore.jar:${SERVER_ROOT}/bin/cert/jars/jss3.jar Main.java

