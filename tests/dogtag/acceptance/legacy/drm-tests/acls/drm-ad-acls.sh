#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/drm-tests/drm-ad-acls.sh
#   Description: DRM Admin ACL tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following legacy test is being tested:
#  DRM Admin ACL tests
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

run_admin-kra-acl_tests()
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
	local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_kra_host=$(eval echo \$${cs_Role})
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_ca_agent_cert=$CA_INST\_agentV
        local valid_agent=$KRA_INST\_agentV
        local valid_agent_pwd=$KRA_INST\_agentV_password
        local valid_audit=$KRA_INST\_auditV
        local valid_audit_pwd=$KRA_INST\_auditV_password
        local valid_operator=$KRA_INST\_operatorV
        local valid_operator_pwd=$KRA_INST\_operatorV_password
        local valid_admin=$KRA_INST\_adminV
        local valid_admin_pwd=$KRA_INST\_adminV_password
        local revoked_agent=$KRA_INST\_agentR
        local revoked_admin=$KRA_INST\_adminR
        local expired_admin=$KRA_INST\_adminE
        local expired_agent=$KRA_INST\_agentE
        local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"

	rlPhaseStartTest "pki_kra_ad-acl-001: DRM Console: List Acls"
	local acls=("certServer.log.content.system" "certServer.kra.request.status" "certServer.acl.configuration" "certServer.log.content.transactions" "certServer.kra.connector" "certServer.registry.configuration" "certServer.kra.selftests" "certServer.kra.keys" "certServer.general.configuration" "certServer.kra.keyrequests" "certServer.kra.getTransportCert" "certServer.kra.configuration" "certServer.kra.key" "certServer.kra.GenerateKeyPair" "certServer.clone.configuration" "certServer.kra.requests" "certServer.log.content.signedAudit" "certServer.auth.configuration" "certServer.kra.group" "certServer.kra.account" "certServer.kra.request" "certServer.kra.registerUser" "certServer.kra.groups" "certServer.kra.TokenKeyRecovery" "certServer.admin.certificate" "certServer.kra.users" "certServer.admin.request.enrollment" "certServer.securitydomain.domainxml" "certServer.kra.certificate.transport" "certServer.job.configuration" "certServer.kra.systemstatus" "certServer.log.configuration" "certServer.log.configuration.fileName")
	local OP_TYPE='OP_SEARCH'
	local OP_SCOPE='acls'
	local test_out=acls.out
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/acl\" > $TmpDir/$test_out" 
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/acl\" > $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	for i in "${acls[@]}"; do
	rlAssertGrep "$i" "$TmpDir/$test_out"
	done
	rlPhaseEnd

	rlPhaseStartCleanup "Delete temporary dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
