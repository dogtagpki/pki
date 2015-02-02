#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/subca-tests/acls/subca-ad-acls.sh
#   Description: SUBCA ACL tests
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

run_admin-subca-acl_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for ca-admin-acl tests
        rlPhaseStartSetup "pki_console_acl Temporary Directory"
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
	local admin_out="$TmpDir/admin_out_acls"
	local valid_admin_user=$SUBCA_INST\_adminV
        local valid_admin_user_password=$SUBCA_INST\_adminV_password


	rlPhaseStartTest "pki_console_acl_subca-001:SUBCA - Admin Interface - list all ACLs"
	header_001="$TmpDir/subca_acl_001.txt"
	rlLog "List all ACLs"
	local acls=(certServer.ca certServer.securitydomain certServer.log certServer.acl certServer.general certServer.ee certServer.ra certServer.admin certServer.ocsp certServer.auth certServer.clone certServer.policy certServer.publisher certServer.registry certServer.profile)
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header $header_001 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=acls&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/acl >> $admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header $header_001 \
		--user "$valid_admin_user:$valid_admin_user_password" \
		-d \"OP_TYPE=OP_SEARCH&OP_SCOPE=acls&\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/acl >> $admin_out" 0 "List all ACLs"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_001"
	for i in ${acls[@]}; do
		rlAssertGrep "$i" "$admin_out"	
	done
	rlPhaseEnd

	rlPhaseStartSetup "pki_console_acl-cleanup"
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
