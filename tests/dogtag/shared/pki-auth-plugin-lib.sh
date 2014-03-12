#!/bin/bash
#Include below files
. /opt/rhqa_pki/env.sh
########################################################################
# AUTHENTICATION PLUGIN  SHARED LIBRARY
#######################################################################
# Includes:
#
#       UidPwdDirAuth
######################################################################
#######################################################################

#########################################################################
# UidPwdDirAuth  Usage:
#       create_certdb add/delete <hostname> <basedn> <port> <true/false> \
#	<attrName> <maxconns> <minconns>
# Example: UidPwdDirAuth add host1.example.org \
# "ou=People,dc=example,dc=org" 389
##############################################################
UidPwdDirAuth()
{
admin_user=$1
admin_pass=$2
action=$3
scope="instance"	
rs_id="UserDirEnrollment" 
implname="UidPwdDirAuth"
rulename="UserDirEnrollment"
ldap_host="$4"
ldap_basedn="$5"
ldap_port="$6"
ldap_secure="$7"
ldap_attrName="$8"
ldap_maxconns="$9"
ldap_minconns="${10}"
if [ "$action" == "add" ]; then
	action=OP_ADD
fi
if [ "$action" == "del" ]; then
	action=OP_DELETE
fi
rlRun "curl --capath "$CERTS_DB" --basic --user "$admin_user:$admin_pass" \
	-d "OP_TYPE=$action" \
	-d "OP_SCOPE=$scope" \
	-d "RS_ID=$rs_id" \
	-d "implName=$implname" \
	-d "RULENAME=$rulename" \
	-d "ldap.ldapconn.host=$ldap_host" \
	-d "ldap.ldapconn.port=$ldap_port" \
	-d "ldap.basedn=$ldap_basedn" \
	-d "ldap.ldapconn.SecureConn=$ldap_secure" \
	-d "ldap.attrName=$ldap_attrName" \
	-d "ldap.maxcons=$ldap_maxconns" \
	-d "ldap.mincons=$ldap_mincons" \
	https://$(hostname):$CA_SECURE_PORT/ca/auths" 0 
wait $!
RETVAL=$?
if [ $RETVAL != 0 ]; then
	echo -e "Adding UidPwdDirAuth Plugin Failed"
	return 1
else
	return 0
fi
}
