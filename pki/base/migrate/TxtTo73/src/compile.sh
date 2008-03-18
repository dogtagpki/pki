#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#####################################################################
###                                                               ###
###  This script creates the "TxtTo73/classes/Main.class",        ###
###  "TxtTo73/classes/CMS73LdifParser.class", and                 ###
###  "TxtTo73/classes/DummyAuthManager.class" which are           ###
###  used to create a CS 7.3 ldif data file.                      ###
###                                                               ###
#####################################################################


###
###  Set JDK_PLATFORM - must be "HP-UX", "Linux", or "SunOS"
###

JDK_PLATFORM=Linux
export JDK_PLATFORM


###
###  Set JDK_VERSION - specify the JDK version used by this version of CS
###
###                    CS 7.3 NOTE:   "Linux" - 1.5.0 (IBM)
###                                   "SunOS" - 1.5.0
###

JDK_VERSION=PKI_7.3.0
export JDK_VERSION


###
###  Set JAVA_HOME - specify the complete path to the JDK
###

JAVA_HOME=/share/builds/components/cms_jdk/${JDK_PLATFORM}/${JDK_VERSION}
export JAVA_HOME


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

if [ -z "${JAVA_HOME}" ] ; then
	echo "ERROR:  Please specify the SERVER_ROOT and JAVA_HOME "
	echo "        environment variables for this script!"
	echo
	exit 2
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
	SHLIB_PATH=/usr/lib:/usr/lib/dirsec:${JAVA_HOME}/lib:${JAVA_HOME}/lib/PA_RISC/native_threads
	export SHLIB_PATH
elif [ ${OS_NAME} = "Linux" ] ; then
	LD_LIBRARY_PATH=/usr/lib:/usr/lib/dirsec:${JAVA_HOME}/lib:${JAVA_HOME}/lib/i386/native_threads
	export LD_LIBRARY_PATH
else # SunOS
	LD_LIBRARY_PATH=/usr/lib:/usr/lib/dirsec:${JAVA_HOME}/lib:${JAVA_HOME}/lib/sparc/native_threads
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
###  Compile TxtTo70 - create "CMS73LdifParser.class", "DummyAuthManager.class",
###                    and "Main.class"
###

${JAVA_HOME}/bin/javac -d ${TARGET} -classpath ${JAVA_HOME}/jre/lib/rt.jar:/usr/share/java/rhpki/nsutil.jar:/usr/share/java/rhpki/certsrv.jar:/usr/share/java/rhpki/cmscore.jar:/usr/lib/java/dirsec/jss4.jar Main.java

