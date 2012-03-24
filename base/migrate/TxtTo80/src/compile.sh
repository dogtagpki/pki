#!/bin/bash

# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2009 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

#####################################################################
###                                                               ###
###  This script creates:                                         ###
###                                                               ###
###      "TxtTo80/classes/CS80LdifParser.class",                  ###
###      "TxtTo80/classes/DummyAuthManager.class", and            ###
###      "TxtTo80/classes/Main.class",                            ###
###                                                               ###
###  which may be used to convert a "normalized" ldif data file   ###
###  exported from a version of CS prior to 8.0 into a CS 8.0     ###
###  ldif data file suitable for import into a CS 8.0 LDAP DB.    ###
###                                                               ###
#####################################################################

###
###  Provide a usage function
###

usage() {
	echo
	echo "Usage:  $0"
	echo
	echo "        NOTE:  No arguments are required to build the"
	echo "               CS 8.0 ldif data classes."
	echo
	exit 255
}

###
###  Perform a usage check for the appropriate number of arguments:
###

if [ $# -gt 0 ] ; then
	usage
fi


###
###  Set PKI_OS
###
###      CS 8.0 NOTE:  "Linux"
###                    "SunOS"
###

PKI_OS=`uname`
export PKI_OS

if	[ "${PKI_OS}" != "Linux" ] &&
	[ "${PKI_OS}" != "SunOS" ]; then
	printf "This '$0' script is ONLY executable\n"
	printf "on either a 'Linux' or 'Solaris' machine!\n"
	exit 255
fi


###
###  Set PKI_ARCHITECTURE
###
###      CS 8.0 NOTE:  "Linux i386"   - 32-bit ("i386")
###                    "Linux x86_64" - 64-bit ("x86_64")
###                    "SunOS sparc"  - 64-bit ("sparcv9")
###

if [ "${PKI_OS}" == "Linux" ]; then
	PKI_PLATFORM=`uname -i`
	export PKI_PLATFORM
	if	[ "${PKI_PLATFORM}" == "i386" ] ||
		[ "${PKI_PLATFORM}" == "x86_64" ]; then
		PKI_ARCHITECTURE="${PKI_PLATFORM}"
		export PKI_ARCHITECTURE
	else
		printf "On 'Linux', this '$0' script is ONLY executable\n"
		printf "on either an 'i386' or 'x86_64' architecture!\n"
		exit 255
	fi
elif [ "${PKI_OS}" == "SunOS" ]; then
	PKI_PLATFORM=`uname -p`
	export PKI_PLATFORM
	if [ "${PKI_PLATFORM}" == "sparc" ]; then
		PKI_ARCHITECTURE="sparcv9"
		export PKI_ARCHITECTURE
	else
		printf "On 'Solaris', this '$0' script is ONLY executable\n"
		printf "on a 'sparcv9' architecture!\n"
		exit 255
	fi
fi


###
###  Set PKI_OS_DISTRIBUTION
###
###      CS 8.0 NOTE:  "Linux Fedora 8"  - "Fedora"
###                    "Linux Fedora 9"  - "Fedora"
###                    "Linux Fedora 10" - "Fedora"
###                    "Linux RHEL 5"    - "Red Hat"
###                    "SunOS 5.9"       - "Solaris"
###

if [ "${PKI_OS}" == "Linux" ]; then
	IS_FEDORA=`test -e /etc/fedora-release && echo 1 || echo 0`
	if [ "${IS_FEDORA}" -eq 1 ]; then
		PKI_DISTRIBUTION="Fedora"
		export PKI_DISTRIBUTION
		PKI_OS_RPM_VERSION=`rpm -qf --qf='%{VERSION}' /etc/fedora-release`
		export PKI_OS_RPM_VERSION
		PKI_OS_VERSION=`echo "${PKI_OS_RPM_VERSION}" | tr -d [A-Za-z]`
		export PKI_OS_VERSION
	else
		IS_REDHAT=`test -e /etc/redhat-release && echo 1 || echo 0`
		if [ "${IS_REDHAT}" -eq 1 ]; then
			PKI_DISTRIBUTION="Red Hat"
			export PKI_DISTRIBUTION
			PKI_OS_RPM_VERSION=`rpm -qf --qf='%{VERSION}' /etc/redhat-release`
			export PKI_OS_RPM_VERSION
			PKI_OS_VERSION=`echo "${PKI_OS_RPM_VERSION}" | tr -d [A-Za-z]`
			export PKI_OS_VERSION
		else
			printf "On 'Linux',this '$0' script is ONLY executable\n"
			printf "on either a 'Fedora' or 'Red Hat' machine!\n"
			exit 255
		fi
	fi
elif [ "${PKI_OS}" == "SunOS" ]; then
	PKI_DISTRIBUTION="Solaris"
	export PKI_DISTRIBUTION
	PKI_OS_VERSION=`uname -r | awk -F. '{print $2}'`
	export PKI_OS_VERSION
fi


###
###  Set JAVA_HOME
###
###      CS 8.0 NOTE:  "Linux Fedora 8"  - JDK 1.7.0 (IcedTea)
###                    "Linux Fedora 9"  - JDK 1.6.0 (OpenJDK)
###                    "Linux Fedora 10" - JDK 1.6.0 (OpenJDK)
###                    "Linux RHEL 5"    - JDK 1.6.0 (OpenJDK)
###                    "SunOS 5.9"       - JDK 1.6.0 (Sun JDK)
###
###                    "Linux" - ALWAYS set specific JAVA_HOME 
###                    "SunOS" - ALLOW JAVA_HOME to be pre-defined
###

if [ "${PKI_OS}" == "Linux" ]; then
	if [ "${PKI_DISTRIBUTION}" == "Fedora" ]; then
		if [ ${PKI_OS_VERSION} -eq 8 ]; then
			if [ "${PKI_ARCHITECTURE}" == "i386" ]; then
				JAVA_HOME="/usr/lib/jvm/java-1.7.0-icedtea"
				JAVA_ARCHITECTURE="i386"
			else # "x86_64"
				JAVA_HOME="/usr/lib/jvm/java-1.7.0-icedtea.${PKI_ARCHITECTURE}"
				JAVA_ARCHITECTURE="amd64"
			fi
			if	[ ! -x "${JAVA_HOME}/bin/javac" ]                      &&
				[ ! -f "${JAVA_HOME}/jre/lib/rt.jar" ]                 &&
				[ ! -d "${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}" ]   &&
				[ ! -d "${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}/native_threads" ]; then
				printf "On 'Fedora 8', this '$0' script is ONLY executable\n"
				printf "by 'JDK 1.7.0 (IcedTea)'!\n"
				exit 255
			fi
		elif [ ${PKI_OS_VERSION} -gt 8 ]; then
			if [ "${PKI_ARCHITECTURE}" == "i386" ]; then
				JAVA_HOME="/usr/lib/jvm/java-1.6.0-openjdk"
				JAVA_ARCHITECTURE="i386"
			else # "x86_64"
				JAVA_HOME="/usr/lib/jvm/java-1.6.0-openjdk.${PKI_ARCHITECTURE}"
				JAVA_ARCHITECTURE="amd64"
			fi
			if	[ ! -x "${JAVA_HOME}/bin/javac" ]                      &&
				[ ! -f "${JAVA_HOME}/jre/lib/rt.jar" ]                 &&
				[ ! -d "${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}" ]   &&
				[ ! -d "${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}/native_threads" ]; then
				printf "On 'Fedora ${PKI_OS_VERSION}', "
				printf "this '$0' script is ONLY executable\n"
				printf "by 'JDK 1.6.0 (OpenJDK)'!\n"
				exit 255
			fi
		else
			printf "On 'Fedora', this '$0' script is ONLY executable\n"
			printf "on 'Fedora 8' or later!\n"
			exit 255
		fi
	elif [ "${PKI_DISTRIBUTION}" == "Red Hat" ]; then
		if [ ${PKI_OS_VERSION} -ge 5 ]; then
			if [ "${PKI_ARCHITECTURE}" == "i386" ]; then
				JAVA_HOME="/usr/lib/jvm/java-1.6.0-openjdk"
				JAVA_ARCHITECTURE="i386"
			else # "x86_64"
				JAVA_HOME="/usr/lib/jvm/java-1.6.0-openjdk.${PKI_ARCHITECTURE}"
				JAVA_ARCHITECTURE="amd64"
			fi
			if	[ ! -x "${JAVA_HOME}/bin/javac" ]                      &&
				[ ! -f "${JAVA_HOME}/jre/lib/rt.jar" ]                 &&
				[ ! -d "${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}" ]   &&
				[ ! -d "${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}/native_threads" ]; then
				printf "On 'RHEL ${PKI_OS_VERSION}', "
				printf "this '$0' script is ONLY executable\n"
				printf "by 'JDK 1.6.0 (OpenJDK)'!\n"
				exit 255
			fi
		else
			printf "On 'Red Hat', this '$0' script is ONLY executable\n"
			printf "on 'RHEL 5' or later!\n"
			exit 255
		fi
	fi
	JDK_EXE="${JAVA_HOME}/bin/javac"
	export JDK_EXE
	JDK_VERSION=`${JAVA_HOME}/bin/javac -version 2>&1 | cut -b7-11`
	export JDK_VERSION
elif [ "${PKI_OS}" == "SunOS" ]; then
	if [ "${JAVA_HOME}" ==  "" ]; then
		JAVA_HOME="/usr/java"
	fi
	JDK_EXE="${JAVA_HOME}/bin/${PKI_ARCHITECTURE}/javac"
	export JDK_EXE
	JDK_VERSION=`${JAVA_HOME}/bin/${PKI_ARCHITECTURE}/javac -version 2>&1 | cut -b7-11`
	export JDK_VERSION
	if [ ${PKI_OS_VERSION} -eq 9 ]; then
		if [ "${JDK_VERSION}" != "1.6.0" ]; then
			printf "On 'Solaris ${PKI_OS_VERSION}', "
			printf "this '$0' script is ONLY executable\n"
			printf "by 'JDK 1.6.0'!\n"
			exit 255
		fi
		if	[ ! -x "${JAVA_HOME}/bin/${PKI_ARCHITECTURE}/javac" ]  &&
			[ ! -f "${JAVA_HOME}/jre/lib/rt.jar" ]                 &&
			[ ! -d "${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}" ]    &&
			[ ! -d "${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}/native_threads" ]; then
			printf "On 'Solaris ${PKI_OS_VERSION}', "
			printf "this '$0' script is ONLY executable\n"
			printf "by 'JDK 1.6.0 (Sun JDK)'!\n"
			exit 255
		fi
	else
		printf "On 'Solaris', this '$0' script is ONLY executable\n"
		printf "on 'Solaris 9'!\n"
		exit 255
	fi
fi


###
###  Setup the appropriate CLASSPATH and LD_LIBRARY_PATH
###  environment variables based upon the platform
###

if	[ ! -f "/usr/share/java/pki/cmscore.jar" ] &&
	[ ! -f "/usr/share/java/pki/certsrv.jar" ]; then
	printf "This '$0' script must be COMPILED against\n"
	printf "the 'pki-common' package!\n"
	exit 255
fi
if [ ! -f "/usr/share/java/pki/nsutil.jar" ]; then
	printf "This '$0' script must be COMPILED against\n"
	printf "the 'pki-util' package!\n"
	exit 255
fi

if [ ${PKI_OS} = "Linux" ] ; then
	if [ ! -f "/usr/lib/java/jss4.jar" ]; then
		printf "This '$0' script must be COMPILED against\n"
		printf "the 'jss' package!\n"
		exit 255
	fi
	CLASSPATH=${JAVA_HOME}/jre/lib/rt.jar
	CLASSPATH=/usr/lib/java/jss4.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/nsutil.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/cmscore.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/certsrv.jar:${CLASSPATH}
	export CLASSPATH
	if [ ${PKI_ARCHITECTURE} = "i386" ] ; then
		LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}/native_threads
	    LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}:${LD_LIBRARY_PATH}
		LD_LIBRARY_PATH=/usr/lib:${LD_LIBRARY_PATH}
		export LD_LIBRARY_PATH
	else # "x86_64"
		LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}/native_threads
	    LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${JAVA_ARCHITECTURE}:${LD_LIBRARY_PATH}
		LD_LIBRARY_PATH=/usr/lib64:${LD_LIBRARY_PATH}
		export LD_LIBRARY_PATH
	fi
else # "SunOS"
	if [ ! -f "/usr/lib/java/dirsec/jss4.jar" ]; then
		printf "This '$0' script must be COMPILED against\n"
		printf "the 'dirsec-jss' package!\n"
		exit 255
	fi
	CLASSPATH=${JAVA_HOME}/jre/lib/rt.jar
	CLASSPATH=/usr/lib/java/dirsec/jss4.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/nsutil.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/cmscore.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/certsrv.jar:${CLASSPATH}
	export CLASSPATH
	LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}/native_threads
	LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}:${LD_LIBRARY_PATH}
	LD_LIBRARY_PATH=/usr/lib/${PKI_ARCHITECTURE}:${LD_LIBRARY_PATH}
	LD_LIBRARY_PATH=/usr/lib/${PKI_ARCHITECTURE}/dirsec:${LD_LIBRARY_PATH}
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
###  Compile TxtTo80 - create "CS80LdifParser.class", "DummyAuthManager.class",
###                    and "Main.class"
###

printf "================================================================\n"
printf "PKI_OS='${PKI_OS}'\n"
printf "PKI_DISTRIBUTION='${PKI_DISTRIBUTION}'\n"
printf "PKI_OS_VERSION='${PKI_OS_VERSION}'\n"
printf "PKI_ARCHITECTURE='${PKI_ARCHITECTURE}'\n"
printf "JAVA_HOME='${JAVA_HOME}'\n"
printf "JDK_EXE='${JDK_EXE}'\n"
printf "JDK_VERSION='${JDK_VERSION}'\n"
printf "================================================================\n\n"

${JDK_EXE} -d ${TARGET} -classpath ${CLASSPATH} Main.java

