#!/bin/sh

########################################################################
#  RHCS INSTALL  SHARED LIBRARY
#######################################################################
# Includes:
#
#       verifyInstallAttribute
#
######################################################################
#######################################################################

#########################################################################
# verifyInstallAttribute Usage:
#       verifyInstallAttribute <command> <expected_msg>
#######################################################################

verifyInstallAttribute()
{
	install_output_file=$1
	attribute=$2
	value=$3
	rc=0
	rlLog "$FUNCNAME"
	attribute="$attribute:"
	myval=`cat $install_output_file | grep -i "$attribute $value" | xargs echo`
	cat $install_output_file | grep -i "$attribute $value"
	if [ $? -ne 0 ] ; then
		rlLog "ERROR: subsystem installation verification failed: Value of $attribute - GOT: $myval EXPECTED: $value"
		rc=1
	else
		rlLog "Value of $attribute for subsystem install is as expected - $myval"
	fi
	return $rc
}
