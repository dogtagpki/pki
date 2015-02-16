#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ocsp-tests/ocsp-ad-acls.sh
#   Description: OCSP Admin ACL tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following legacy test is being tested:
#   OCSP Admin ACL tests
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

run_admin-ocsp-acl_tests()
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
        local valid_admin=$OCSP_INST\_adminV
        local valid_admin_pwd=$OCSP_INST\_adminV_password
        local admin_out="$TmpDir/admin_out"

	rlPhaseStartTest "pki_ocsp_ad-acl-001: DRM Console: List Acls"
	local acls=("actions" "certServer.acl.configuration" "certServer.auth.configuration" "certServer.clone.configuration" "certServer.ee.crl" "certServer.ee.request.ocsp" "certServer.general.configuration" "certServer.log.configuration" "certServer.log.configuration.fileName" "certServer.log.content.signedAudit" "certServer.log.content.system" "certServer.log.content.system" "certServer.log.content.transactions" "certServer.ocsp.account" "certServer.ocsp.ca" "certServer.ocsp.cas" "certServer.ocsp.certificate" "certServer.ocsp.certificate" "certServer.ocsp.configuration" "certServer.ocsp.crl" "certServer.ocsp.group" "certServer.ocsp.groups" "certServer.ocsp.info" "certServer.ocsp.users" "certServer.registry.configuration" "certServer.securitydomain.domainxml")
	local OP_TYPE='OP_SEARCH'
	local OP_SCOPE='acls'
	local test_out=acls.out
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/acl\" > $TmpDir/$test_out" 
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/acl\" > $TmpDir/$test_out"
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
