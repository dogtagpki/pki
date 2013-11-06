#!/bin/sh

########################################################################
#  PKI USER SHARED LIBRARY
#######################################################################
# Includes:
#
#	importAdminCert
######################################################################
#######################################################################

#########################################################################
# importAdminCert Usage:
#	importAdminCert <AdminCertLocation> <Directory>
#######################################################################

importAdminCert()
{
	local admincert_p12file=$1
	local temp_dir=$2
	local nss_db_password=$3
	local admin_cert_nickname=$4
	local rc=0
	exp=$temp_dir/expfile.out
	tmpout=$temp_dir/tmpout.out

	rlLog "admincert_p12file = $admincert_p12file"
	rlLog "temp_dir = $temp_dir"
	rlRun "echo \"$nss_db_password\" > $temp_dir/passwd_certdb"
        rlRun "certutil -d $temp_dir -N -f $temp_dir/passwd_certdb"
	rlRun "echo \"$CA_CLIENT_PKCS12_PASSWORD\" > $temp_dir/admin_p12_password"
	local cmd="pk12util -i $admincert_p12file -d $temp_dir -w $temp_dir/admin_p12_password"
	echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn $cmd" >> $exp
        echo 'expect "*Password*: "' >> $exp
        echo "send -s -- \"$nss_db_password\r\"" >> $exp
        echo 'expect eof ' >> $exp
	rlLog "cat $exp"
        /usr/bin/expect $exp > $tmpout 2>&1
	if [ $? = 0 ]; then
                cat $tmpout | grep "pk12util: PKCS12 IMPORT SUCCESSFUL"
		if [ $? = 0 ]; then
			rlPass "pk12util command executed successfully"
			rlRun "certutil -L -d $temp_dir | grep $admin_cert_nickname" 0 "Verify Admin certificate is installed"
		else
			rlFail "ERROR: Admin certificate is not installed in $temp_dir"
			rc=1
		fi

        else
                rlFail "ERROR: pk12util execution failed."
        fi
	return $rc
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
