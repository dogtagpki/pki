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
# Copyright (C) 2009 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

#####################################################################
###                                                               ###
###  This script converts a normalized <Source CS Version> ldif   ###
###  text file (e. g. - created via a <Source CS Version>ToTxt    ###
###  script) into a CS 8.0 ldif data file.                        ###
###                                                               ###
###  This CS 8.0 ldif data file can then be imported into         ###
###  the internal database of the desired CS 8.0 server           ###
###  using a utility such as ldif2db.                             ###
###                                                               ###
#####################################################################

###
###  Provide a usage function
###

usage() {
	echo
	echo "Usage:  $0 input [errors] > output"
	echo
	echo "        where:  input  - a "normalized" CS ldif data file,"
	echo "                errors - an optional errors file containing"
	echo "                         skipped attributes, and"
	echo "                output - the CS 8.0 ldif text file."
	echo
	echo "                NOTE:  If no redirection is provided to"
	echo "                       'output', then the CS 8.0 ldif text"
	echo "                       file will merely be echoed to stdout."
	echo
	exit 255
}


##
##  Perform a usage check for the appropriate number of arguments:
##

if [ $# -lt 1 -o $# -gt 2 ] ; then
	usage
fi


###
###  Check that the specified "input" file exists and is a regular file.
###

if [ ! -f $1 ] ; then
	echo "ERROR:  Either the specified 'input' file, '$1', does not exist, "
	echo "        or it is not a regular file!"
	echo
	usage
fi


###
###  Check that the specified "input" file exists and is not empty.
###

if [ ! -s $1 ] ; then
	echo "ERROR:  The specified 'input' file, '$1', is empty!"
	echo
	usage
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
		usage
	fi
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
###      CS 8.0 NOTE:  "Linux Fedora 8"  - JRE 1.7.0 (IcedTea)
###                    "Linux Fedora 9"  - JRE 1.6.0 (OpenJDK)
###                    "Linux Fedora 10" - JRE 1.6.0 (OpenJDK)
###                    "Linux RHEL 5"    - JRE 1.6.0 (OpenJDK)
###                    "SunOS 5.9"       - JRE 1.6.0 (Sun JDK)
###
###                    "Linux" - ALWAYS set specific JAVA_HOME 
###                    "SunOS" - ALLOW JAVA_HOME to be pre-defined
###

if [ "${PKI_OS}" == "Linux" ]; then
	if [ "${PKI_DISTRIBUTION}" == "Fedora" ]; then
		if [ ${PKI_OS_VERSION} -eq 8 ]; then
			if [ "${PKI_ARCHITECTURE}" == "i386" ]; then
				JAVA_HOME="/usr/lib/jvm/jre-1.7.0-icedtea"
				JAVA_ARCHITECTURE="i386"
			else # "x86_64"
				JAVA_HOME="/usr/lib/jvm/jre-1.7.0-icedtea.${PKI_ARCHITECTURE}"
				JAVA_ARCHITECTURE="amd64"
			fi
			if	[ ! -x "${JAVA_HOME}/bin/java" ]                   &&
				[ ! -f "${JAVA_HOME}/lib/rt.jar" ]                 &&
				[ ! -d "${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}" ]   &&
				[ ! -d "${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}/native_threads" ]; then
				printf "On 'Fedora 8', this '$0' script is ONLY executable\n"
				printf "by 'JRE 1.7.0 (IcedTea)'!\n"
				exit 255
			fi
		elif [ ${PKI_OS_VERSION} -gt 8 ]; then
			if [ "${PKI_ARCHITECTURE}" == "i386" ]; then
				JAVA_HOME="/usr/lib/jvm/jre-1.6.0-openjdk"
				JAVA_ARCHITECTURE="i386"
			else # "x86_64"
				JAVA_HOME="/usr/lib/jvm/jre-1.6.0-openjdk.${PKI_ARCHITECTURE}"
				JAVA_ARCHITECTURE="amd64"
			fi
			if	[ ! -x "${JAVA_HOME}/bin/java" ]                   &&
				[ ! -f "${JAVA_HOME}/lib/rt.jar" ]                 &&
				[ ! -d "${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}" ]   &&
				[ ! -d "${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}/native_threads" ]; then
				printf "On 'Fedora ${PKI_OS_VERSION}', "
				printf "this '$0' script is ONLY executable\n"
				printf "by 'JRE 1.6.0 (OpenJDK)'!\n"
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
				JAVA_HOME="/usr/lib/jvm/jre-1.6.0-openjdk"
				JAVA_ARCHITECTURE="i386"
			else # "x86_64"
				JAVA_HOME="/usr/lib/jvm/jre-1.6.0-openjdk.${PKI_ARCHITECTURE}"
				JAVA_ARCHITECTURE="amd64"
			fi
			if	[ ! -x "${JAVA_HOME}/bin/java" ]                   &&
				[ ! -f "${JAVA_HOME}/lib/rt.jar" ]                 &&
				[ ! -d "${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}" ]   &&
				[ ! -d "${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}/native_threads" ]; then
				printf "On 'RHEL ${PKI_OS_VERSION}', "
				printf "this '$0' script is ONLY executable\n"
				printf "by 'JRE 1.6.0 (OpenJDK)'!\n"
				exit 255
			fi
		else
			printf "On 'Red Hat', this '$0' script is ONLY executable\n"
			printf "on 'RHEL 5' or later!\n"
			exit 255
		fi
	fi
	JRE_EXE="${JAVA_HOME}/bin/java"
	export JRE_EXE
	JRE_VERSION=`${JAVA_HOME}/bin/java -version 2>&1 | cut -b15-19 | sed -n '/[0-9]\.[0-9]\.[0-9]/p'`
	export JRE_VERSION
elif [ "${PKI_OS}" == "SunOS" ]; then
	if [ "${JAVA_HOME}" ==  "" ]; then
		JAVA_HOME="/usr/java"
	fi
	JRE_EXE="${JAVA_HOME}/bin/${PKI_ARCHITECTURE}/java"
	export JRE_EXE
	JRE_VERSION=`${JAVA_HOME}/bin/${PKI_ARCHITECTURE}/java -version 2>&1 | cut -b15-19 | sed -n '/[0-9]\.[0-9]\.[0-9]/p'`
	export JRE_VERSION
	if [ ${PKI_OS_VERSION} -eq 9 ]; then
		if [ "${JRE_VERSION}" != "1.6.0" ]; then
			printf "On 'Solaris ${PKI_OS_VERSION}', "
			printf "this '$0' script is ONLY executable\n"
			printf "by 'JRE 1.6.0'!\n"
			exit 255
		fi
		if	[ ! -x "${JAVA_HOME}/bin/${PKI_ARCHITECTURE}/java" ]   &&
			[ ! -f "${JAVA_HOME}/jre/lib/rt.jar" ]                 &&
			[ ! -d "${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}" ]    &&
			[ ! -d "${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}/native_threads" ]; then
			printf "On 'Solaris ${PKI_OS_VERSION}', "
			printf "this '$0' script is ONLY executable\n"
			printf "by 'JRE 1.6.0 (Sun JDK)'!\n"
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
	printf "This '$0' script must be EXECUTED against\n"
	printf "the 'pki-common' package!\n"
	exit 255
fi
if [ ! -f "/usr/share/java/pki/nsutil.jar" ]; then
	printf "This '$0' script must be EXECUTED against\n"
	printf "the 'pki-util' package!\n"
	exit 255
fi
if [ ! -d "/usr/share/pki/migrate/TxtTo80/classes" ]; then
	printf "This '$0' script must be EXECUTED against\n"
	printf "the 'pki-migrate' package!\n"
	exit 255
fi

if [ ${PKI_OS} = "Linux" ] ; then
	if [ ! -f "/usr/lib/java/jss4.jar" ]; then
		printf "This '$0' script must be EXECUTED against\n"
		printf "the 'jss' package!\n"
		exit 255
	fi
	CLASSPATH=${JAVA_HOME}/lib/rt.jar
	CLASSPATH=/usr/lib/java/jss4.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/nsutil.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/cmscore.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/certsrv.jar:${CLASSPATH}
	CLASSPATH=/usr/share/pki/migrate/TxtTo80/classes:${CLASSPATH}
	export CLASSPATH
	if [ ${PKI_ARCHITECTURE} = "i386" ] ; then
		LD_LIBRARY_PATH=${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}/native_threads
	    LD_LIBRARY_PATH=${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}:${LD_LIBRARY_PATH}
		LD_LIBRARY_PATH=/usr/lib:${LD_LIBRARY_PATH}
		export LD_LIBRARY_PATH
	else # "x86_64"
		LD_LIBRARY_PATH=${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}/native_threads
	    LD_LIBRARY_PATH=${JAVA_HOME}/lib/${JAVA_ARCHITECTURE}:${LD_LIBRARY_PATH}
		LD_LIBRARY_PATH=/usr/lib64:${LD_LIBRARY_PATH}
		export LD_LIBRARY_PATH
	fi
else # "SunOS"
	if [ ! -f "/usr/lib/java/dirsec/jss4.jar" ]; then
		printf "This '$0' script must be EXECUTED against\n"
		printf "the 'dirsec-jss' package!\n"
		exit 255
	fi
	CLASSPATH=${JAVA_HOME}/jre/lib/rt.jar
	CLASSPATH=/usr/lib/java/dirsec/jss4.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/nsutil.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/cmscore.jar:${CLASSPATH}
	CLASSPATH=/usr/share/java/pki/certsrv.jar:${CLASSPATH}
	CLASSPATH=/usr/share/pki/migrate/TxtTo80/classes:${CLASSPATH}
	export CLASSPATH
	LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}/native_threads
	LD_LIBRARY_PATH=${JAVA_HOME}/jre/lib/${PKI_ARCHITECTURE}:${LD_LIBRARY_PATH}
	LD_LIBRARY_PATH=/usr/lib/${PKI_ARCHITECTURE}:${LD_LIBRARY_PATH}
	LD_LIBRARY_PATH=/usr/lib/${PKI_ARCHITECTURE}/dirsec:${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH
fi


###
###  Execute TxtTo80 to convert the "normalized" CS ldif data file in to
###  a CS 8.0 ldif text file suitable for import in to a CS 8.0 LDAP DB.
###

# printf "================================================================\n"
# printf "PKI_OS='${PKI_OS}'\n"
# printf "PKI_DISTRIBUTION='${PKI_DISTRIBUTION}'\n"
# printf "PKI_OS_VERSION='${PKI_OS_VERSION}'\n"
# printf "PKI_ARCHITECTURE='${PKI_ARCHITECTURE}'\n"
# printf "JAVA_HOME='${JAVA_HOME}'\n"
# printf "JRE_EXE='${JRE_EXE}'\n"
# printf "JRE_VERSION='${JRE_VERSION}'\n"
# printf "================================================================\n\n"

${JRE_EXE} -classpath ${CLASSPATH} Main $1 $2

