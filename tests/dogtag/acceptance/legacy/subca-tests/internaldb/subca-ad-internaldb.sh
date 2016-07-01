#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/subca_tests/internaldb/subca-ad-internaldb.sh
#   Description: SUBCA Admin Internal DB tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

run_admin-subca-intdb_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for ca-admin-internaldb tests
        rlPhaseStartSetup "pki_console_internaldb Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
	if [ $cs_Role="MASTER" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
        local target_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local tmp_ca_admin=$SUBCA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_admin_cert=$SUBCA_INST\_adminV
	local admin_out="$TmpDir/admin_out"
	local ldap_host=`hostname`
	local ldap_port=$(eval echo \$${SUBCA_INST}_LDAP_PORT)
	local ldap_bind=$(eval echo \$${SUBCA_INST}_LDAP_ROOTDN)
	local valid_admin_user=$SUBCA_INST\_adminV
        local valid_admin_user_password=$SUBCA_INST\_adminV_password

	rlPhaseStartTest "pki_console_list_intdb_subca-001:SUBCA - Admin Interface - list internaldb"
	header_001="$TmpDir/subca_intdb_001.txt"
	rlLog "List internal db"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_001 \
		--user "$valid_admin_user:$valid_admin_user_password" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&ldapconn.host=&ldapconn.port=&ldapconn.bindDN=&ldapconn.version=&\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/server >> $admin_out" 0 "List internal DB"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_001"
	rlAssertGrep "ldapconn.host=localhost" "$admin_out"
	rlAssertGrep "ldapconn.port=$(eval echo \$${SUBCA_INST}_LDAP_PORT)" "$admin_out"
	rlAssertGrep "ldapconn.bindDN=" "$admin_out"
	rlAssertGrep "ldapconn.version=" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_intdb_subca-002:SUBCA - Admin Interface - edit internaldb"
        rlLog "Edit internal db"
	header_002="$TmpDir/subca_intdb_002.txt"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_002 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&ldapconn.host=$ldap_host&ldapconn.port=$ldap_port&ldapconn.bindDN=$ldap_bind&ldapconn.version=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/server" 0 "Edit internal DB"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&ldapconn.host=&ldapconn.port=&ldapconn.bindDN=&ldapconn.version=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/server >> $admin_out" 0 "List internal DB"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_002"
        rlAssertGrep "ldapconn.host=$ldap_host" "$admin_out"
        rlAssertGrep "ldapconn.port=$ldap_port" "$admin_out"
        rlAssertGrep "ldapconn.bindDN=cn\%3DDSManager" "$admin_out"
        rlAssertGrep "ldapconn.version=" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&ldapconn.host=localhost&ldapconn.port=$ldap_port&ldapconn.bindDN=&ldapconn.version=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/server" 0 "Edit internal DB"
        rlPhaseEnd

	rlPhaseStartSetup "pki_console_internaldb-cleanup"
	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}

process_curl_output()
{
	output_file=$1
	sed -i "s/\&/\n&/g" $output_file
        sed -i "s/+//g"  $output_file
        sed -i "s/^&//g" $output_file
        sed -i "s/%3A/":"/g" $output_file
        sed -i "s/%3B/":"/g" $output_file
}
