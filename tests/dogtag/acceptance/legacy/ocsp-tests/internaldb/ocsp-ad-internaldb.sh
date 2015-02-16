#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ocsp-tests/ocsp-ad-internaldb.sh
#   Description: OCSP Admin internaldb tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following legacy test is being tested:
#   OCSP Admin Internaldb tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mniranja@redhat.com>
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
. /opt/rhqa_pki/pki-auth-plugin-lib.sh
. /opt/rhqa_pki/env.sh

run_admin-ocsp-internaldb_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
        # Creating Temporary Directory for legacy test
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
	get_topo_stack $cs_Role $TmpDir/topo_file
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local OCSP_INST=$(cat $TmpDir/topo_file | grep MY_OCSP | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ocsp_host=$(eval echo \$${cs_Role})
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_ca_agent_cert=$CA_INST\_agentV
        local valid_agent=$OCSP_INST\_agentV
        local valid_agent_pwd=$OCSP_INST\_agentV_password
        local valid_audit=$OCSP_INST\_auditV
        local valid_audit_pwd=$OCSP_INST\_auditV_password
        local valid_operator=$OCSP_INST\_operatorV
        local valid_operator_pwd=$OCSP_INST\_operatorV_password
        local valid_admin=$OCSP_INST\_adminV
        local valid_admin_pwd=$OCSP_INST\_adminV_password
        local revoked_agent=$OCSP_INST\_agentR
        local revoked_admin=$OCSP_INST\_adminR
        local expired_admin=$OCSP_INST\_adminE
        local expired_agent=$OCSP_INST\_agentE
        local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"

	rlPhaseStartTest "pki_ocsp_ad-internaldb-001: OCSP Console: List Internaldb"
	local OP_TYPE='OP_READ'
	local OP_SCOPE='ldap'
	local RS_ID='RS_ID_CONFIG'
	local test_out=internaldb.out
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&ldapconn.host=&ldapconn.port=&ldapauth.bindDN=&ldapconn.version=&\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/server\" > $TmpDir/$test_out" 
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&ldapconn.host=&ldapconn.port=&ldapauth.bindDN=&ldapconn.version=&\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/server\" > $TmpDir/$test_out" 
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	rlAssertGrep "ldapconn.host=localhost" "$TmpDir/$test_out"
	rlAssertGrep "ldapconn.port=$(eval echo \$${OCSP_INST}_LDAP_PORT)" "$TmpDir/$test_out"
	rlAssertGrep "ldapauth.bindDN=cn=DirectoryManager" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_ad-internaldb-002: OCSP Console: Edit Internaldb"
	rlLog "Edit Internal DB"
        local OP_TYPE='OP_MODIFY'
        local OP_SCOPE='ldap'
        local RS_ID='RS_ID_CONFIG'
        local ldaphost="$(hostname)"
        local ldapport=$(eval echo \$${OCSP_INST}_LDAP_PORT)
        local ldapbindDN='cn=Directory Manager'
        local ldapversion='3'
        local maxConns='15'
        local minConns='3'
        local test_out=internaldb.out
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&ldapconn.host=$ldaphost&ldapconn.port=$ldapport&ldapauth.bindDN=$ldapbindDN&ldapconn.version=$ldapversion&maxConns=$maxConns&minConns=$minConns\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/server\" > $TmpDir/$test_out"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&ldapconn.host=$ldaphost&ldapconn.port=$ldapport&ldapauth.bindDN=$ldapbindDN&ldapconn.version=$ldapversion&maxConns=$maxConns&minConns=$minConns\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/server\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&ldapconn.host=&ldapconn.port=&ldapauth.bindDN=&ldapconn.version=&\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/server\" > $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertGrep "ldapconn.host=$ldaphost" "$TmpDir/$test_out"
        rlAssertGrep "ldapconn.port=$ldapport" "$TmpDir/$test_out"
        rlAssertGrep "ldapauth.bindDN=cn=DirectoryManager" "$TmpDir/$test_out"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&ldapconn.host=localhost&ldapconn.port=$ldapport&ldapauth.bindDN=$ldapbindDN&ldapconn.version=$ldapversion&maxConns=$maxConns&minConns=$minConns\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/server\" > $TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartCleanup "Delete temporary dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
