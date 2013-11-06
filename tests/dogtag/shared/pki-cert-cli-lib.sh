#!/bin/sh

########################################################################
#  PKI CERT SHARED LIBRARY
#######################################################################
# Includes:
#
#	generate_PKCS10
######################################################################
#######################################################################

#########################################################################
# create_certdb  Usage:
#       create_certdb <location of certdb> <certdb_password>
#######################################################################

create_certdb()
{
	local certdb_loc=$1
        local certdb_pwd=$2
        rlLog "certdb_loc = $certdb_loc"
        rlRun "mkdir $certdb_loc"
        rlRun "echo \"$certdb_pwd\" > $certdb_loc/passwd_certdb"
        rlRun "certutil -d $certdb_loc -N -f $certdb_loc/passwd_certdb"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

#########################################################################
# generate_PKCS10 Usage:
#	generate_PKCS10 <location of certdb> <certdb_password> <algorithm> <rsa key length> <output file> <subjectDN>
#######################################################################

generate_PKCS10()
{
	local certdb_loc=$1
	local certdb_pwd=$2
	local algorithm=$3
	local rsa_key_length=$4
	local output_file=$5
	local subjectDN=$6
	local rc=0
	exp=$certdb_loc/../expfile.out
	tmpout=$certdb_loc/../tmpout.out

	local cmd="PKCS10Client -p $certdb_pwd -d $certdb_loc -a $algorithm -l $rsa_key_length -o $output_file -n $subjectDN"
	rlLog "Executing: $cmd"
        rlRun "$cmd" 0 "Creating PKCS10 request"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
