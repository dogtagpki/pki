#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-profile-cli
#   Description: PKI CA PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki ca-profile-add
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
. /opt/rhqa_pki/env.sh

run_admin-ca-profile_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for pki ca-profile-add
        rlPhaseStartSetup "pki key-show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$CA_INST\_agentV
        local valid_audit_cert=$CA_INST\_auditV
        local valid_operator_cert=$CA_INST\_operatorV
        local valid_admin_cert=$CA_INST\_adminV
	local cert_find_info="$TmpDir/cert_find_info"
        local revoked_agent_cert=$CA_INST\_agentR
        local revoked_admin_cert=$CA_INST\_adminR
        local expired_admin_cert=$CA_INST\_adminE
        local expired_agent_cert=$CA_INST\_agentE
	local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')        
	local SSL_DIR=$CERTDB_DIR
	###SubCA
        local sub_ca_ldap_port=1800
        local sub_ca_http_port=14080
        local sub_ca_https_port=14443
        local sub_ca_ajp_port=14009
        local sub_ca_tomcat_port=14005
        local subca_instance_name=pki-example-$rand
        local SUBCA_SERVER_ROOT=/var/lib/pki/$subca_instance_name/ca

        rlPhaseStartSetup "Create user with only Admin privileges"
        local test_admin_user="idm_admin_user$RANDOM"
        local admin_user_fullName="idm Admin User"
        local test_admin_pwd="Secret123"
        rlLog "Create user with Admin Privileges only"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert  \
                user-add $test_admin_user  \
                --fullName \"$admin_user_fullName\" \
                --password $test_admin_pwd" 0 "Create $admin_user_fullName user"
        rlLog "Add user to Administrators Group"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert \
                group-member-add Administrators $test_admin_user" 0 "Add $admin_user_fullName to Administrators Group"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-001:CA - Admin Interface - list all profiles"
	rlLog "List all Profiles"
	local default_profiles=(caUserCert caECUserCert caUserSMIMEcapCert caDualCert caECDualCert AdminCert caSignedLogCert caTPSCert caRARouterCert caRouterCert caServerCert caSubsystemCert caStorageCert)
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_SEARCH&OP_SCOPE=rules&\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile >> $admin_out" 0 "List all defaul Profiles"
	for i in ${default_profiles[@]}; do
		rlAssertGrep "$i" "$admin_out"	
	done
	rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-002:CA - Admin Interface - View Profile Details"
	local profile="caUserSMIMEcapCert"
	rlLog "View Profile Details $profile"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=policies&RS_ID=$profile\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "View details of Profile $profile"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlLog "Verify Policy & Constraints"
	rlAssertGrep "SubjectNameDefault:SubjectNameConstraint" "$admin_out"
	rlAssertGrep "NoDefault:RenewalGracePeriodConstraint" "$admin_out"
	rlAssertGrep "ValidityDefault:ValidityConstraint" "$admin_out"
	rlAssertGrep "KeyDefault:KeyConstraint" "$admin_out"
	rlAssertGrep "AuthorityKeyIdentifierDefault:NoConstraint" "$admin_out"
	rlAssertGrep "AIAExtensionDefault:NoConstraint" "$admin_out"
	rlAssertGrep "KeyUsageDefault:KeyUsageExtensionConstraint" "$admin_out"
	rlAssertGrep "ExtendedKeyUsageExtensionDefault:NoConstraint" "$admin_out"
	rlAssertGrep "SubjectAltNameConstraint:NoConstraint" "$admin_out"
	rlAssertGrep "SigningAlg:NoConstraint" "$admin_out"
	local scope=profileInput
	rlLog "Verify $scope"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=profileInput&RS_ID=$profile\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "View details of Profile $profile"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "KeyGeneration" "$admin_out"
	rlAssertGrep "SubjectName" "$admin_out"
	rlAssertGrep "RequestorInformation" "$admin_out"
	local scope=profileOutput
	rlLog "Verify $scope"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=$scope&RS_ID=$profile\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "View details of Profile $profile"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "CertificateOutput" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-003:CA - Admin Interface - Verify Deleting enabled profile fails"
	local profile="caUserSMIMEcapCert"
	local op_scope=rules
	local op_type='OP_DELETE'
	rlLog "View Profile Details $profile"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=$op_type&OP_SCOPE=$op_scope&RS_ID=$profile\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "View details of Profile $profile"
	rlAssertGrep "Cannot delete enabled profile: $profile" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-004:CA - Admin Interface - Create a new user Profile using caUserCertEnrollImpl with Profile Authencation set to AgentCertAuth"
        local profile="caUserCert$RANDOM"
        local op_scope=rules
	local class=caUserCertEnrollImpl
	rlLog "Create new profile $profile"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=rules&RS_ID=$profile&impl=$class&name=$profile&visible=true&auth=AgentCertAuth&desc=$profile\" \
		-k  https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Create a new profile for user cert enrollment"
	rlLog "List all default Profiles"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=rules&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile >> $admin_out" 0 "List all default Profiles"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"	
	rlAssertGrep "$profile=$profile:visible:disabled" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-005:CA - Admin Interface - Add Authority Info Access Extension Default Policy"
	local op_scope=policies
	local policy=authInfoAccessExtDefaultImpl
	local policyname=AuthorityInfoAccessExtensionDefault
	local constraintname=NoConstraint
	local constraint=noConstraintImpl
	rlLog "Add Policy" 
	rlRun "curl --capath "$CERTDB_DIR" \
		--basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p6;$policy;$constraint\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Authority Info Access Extension Default Policy to $profile" 0 "Add Authority Info Access Extension Policy"
	local op_scope=defaultPolicy
	rlLog "Add $policy Details"
	rlRun "curl --capath "$CERTDB_DIR" \
		--basic --user "$test_admin_user:$test_admin_pwd" -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint&authInfoAccessCritical=false&authInfoAccessNumADs=1&authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1&authInfoAccessADLocationType_0=URIName&authInfoAccessADLocation_0=&authInfoAccessADEnable_0=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
	rlLog "Add Policy Constraint"
	local op_scope=constraintPolicy
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile"
	rlLog "Read all policies of $profile"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=policies&RS_ID=$profile\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "$policyname:$constraintname" "$admin_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-006:CA - Admin Interface - Add Authority key Identifier Extension Default Policy"
        local op_scope=policies
        local policy=authorityKeyIdentifierExtDefaultImpl
        local policyname=AuthorityKeyIdentifierExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p7;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Authority Key Identifier Extension Default Policy to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p7;$policy;$constraint\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p7;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile"
        rlLog "Get all policies of $profile"
	local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_profile-007:CA - Admin Interface - Add Auto request Assignment Default"
        local op_scope=policies
        local policy=autoAssignDefaultImpl
        local policyname=AutoRequestAssignmentDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p8;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Authority Info Access Extension Default Policy to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p8;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details" 0 
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p8;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
	rlPhaseEnd


        rlPhaseStartTest "pki_console_profile-008:CA - Admin Interface - Add Basic Constraints Extension Default"
        local op_scope=policies
        local policy=basicConstraintsExtDefaultImpl
        local policyname=BasicConstraintsExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p9;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Basic Constraints Extension to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint&basicConstraintsCritical=false&basicConstraintsIsCA=false&basicConstraintsPathLen=-1\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-009:CA - Admin Interface - Add Certificate Version Default Policy"
        local policy=certificateVersionDefaultImpl
        local policyname=CertificateVersionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
	local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Certificate Version Default Policy to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint&basicConstraintsCritical=false&basicConstraintsIsCA=false&basicConstraintsPathLen=-1\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd
		
	rlPhaseStartTest "pki_console_profile-0010:CA - Admin Interface - Add CRL Distribution Points Extension Default Policy & add custom CRL Url"
        local policy=crlDistributionPointsExtDefaultImpl
        local policyname=CRLDistributionPointsExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
	local crlurl='https://pki2.example.org:30042/crl/Mastercrl.bin'
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p11;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy CRL Distribution Points Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p11;$policy;$constraint&crlDistPointsCritical=false&crlDistPointsNum=1&crlDistPointsPointType_0=URIName&crlDistPointsPointName_0=$crlurl&crlDistPointsReasons_0=&crlDistPointsIssuerType_0=&crlDistPointsIssuerName_0=&crlDistPointsEnable_0=true\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p11;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0011:CA - Admin Interface - Add Extended Key Usage Extension Default Policy"
        local policy=extendedKeyUsageExtDefaultImpl
        local policyname=ExtendedKeyUsageExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        local crlurl='https://pki2.example.org:30042/crl/Mastercrl.bin'
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p12;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Extended Key Usage Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p12;$policy;$constraint&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details" 0 
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p12;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0012:CA - Admin Interface - Add Freshest CRL Extension Default"
        local policy=freshestCRLExtDefaultImpl
        local policyname=FreshestCRLExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        local crlurl="https://$tmp_ca_host:$target_secure_port/crl/Mastercrl.bin"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p13;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Freshest CRL Extension to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p13;$policy;$constraint&freshestCRLCritical=false&freshestCRLPointNum=1&freshestCRLPointType_0=URIName&freshestCRLPointName_0=$crlurl&freshestCRLPointIssuerType_0=&freshestCRLPointIssuerName_0=&freshestCRLPointEnable_0='true'\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p13;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_console_profile-0013:CA - Admin Interface - Add Key Usage Extension Default"
        local policy=keyUsageExtDefaultImpl
        local policyname=KeyUsageExtensionDefault
        local constraintname=KeyUsageExtensionConstraint
        local constraint=keyUsageExtConstraintImpl
	rlLog "Delete Existing Key Usage Policy"
	rlRun "curl --capath "$CERTDB_DIR" \
		--basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_DELETE&OP_SCOPE=policies&RS_ID=$profile&POLICYID=set1:p5\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Key Usage Policy"
	rlLog "Add Key Usage Policy"
        local op_scope=policies
        local crlurl="https://$tmp_ca_host:$target_secure_port/crl/Mastercrl.bin"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p14;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Key Usage Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p14;$policy;$constraint&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p14;$policy;$constraint&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0014:CA - Admin Interface - Add Issuer Alternative Name Extension Default"
        local policy=issuerAltNameExtDefaultImpl
        local policyname=IssuerAlternativeNameExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p15;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Issuer Alternative Name Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p15;$policy;$constraint&issuerAltNameExtCritical=false&issuerAltExtType=RFC822Name&issuerAltExtPattern=$request.requestor_email\$\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p15;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_profile-0014:CA - Admin Interface - Add Name Constraints Extension Default"
        local policy=nameConstraintsExtDefaultImpl
        local policyname=IssuerAlternativeNameExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        local crlurl="https://$tmp_ca_host:$target_secure_port/crl/Mastercrl.bin"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p15;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Name Constraints Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p15;$policy;$constraint&nameConstraintsCritical=false&nameConstraintsNumPermittedSubtrees=1&nameConstraintsPermittedSubtreeMinValue_0=1&nameConstraintsPermittedSubtreeNameChoice_0=URIName&nameConstraintsPermittedSubtreeNameValue_0=https://$tmp_ca_host:80&nameConstraintsPermittedSubtreeEnable_0=false&nameConstraintsNumExcludedSubtrees=1&nameConstraintsExcludedSubtreeMinValue_0=&nameConstraintsExcludedSubtreeMaxValue_0=&nameConstraintsExcludedSubtreeNameChoice_0=&nameConstraintsExcludedSubtreeNameValue_0=&nameConstraintsExcludedSubtreeEnable_0=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p15;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0015:CA - Admin Interface - Add Netscape Certificate Type Extension Default Policy"
        local policy=nsCertTypeExtDefaultImpl
        local policyname=NetscapeCertificateTypeExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p16;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Netscape Certificate Type Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p16;$policy;$constraint&nsCertCritical=true&nsCertSSLClient=true&nsCertSSLServer=true&nsCertEmail=true&nsCertObjectSigning=false&nsCertSSLCA=false&nsCertEmailCA=false&nsCertObjectSigningCA=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p16;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd
	

        rlPhaseStartTest "pki_console_profile-0016:CA - Admin Interface - Add OCSP No check Extension Default Policy"
        local policy=ocspNoCheckExtDefaultImpl
        local policyname=OCSPNoCheckExtensionDefault
        local constraintname=ExtensionConstraint
        local constraint=extensionConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p17;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy OCSP No check Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p17;$policy;$constraint&ocspNoCheckCritical=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p17;$policy;$constraint&extCritical=false&extOID=1.1.1.1.1\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0017:CA - Admin Interface - Add Signing Algorithm Default Policy"
        local policy=signingAlgDefaultImpl
        local policyname=SigningAlgorithmDefault
        local constraintname=SigningAlgorithmConstraint
        local constraint=signingAlgConstraintImpl
        rlLog "Delete Existing Key Usage Policy"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=policies&RS_ID=$profile&POLICYID=set1:p4\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Signing Algorithm Usage Policy"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p18;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Signing Algorithm Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p18;$policy;$constraint&signingAlg=SHA256withRSA\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p18;$policy;$constraint&signingAlgsAllowed=SHA1withRSA,MD5withRSA,MD2withRSA,SHA1withDSA,SHA256withRSA,SHA512withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0018:CA - Admin Interface - Add OCSP No check Extension Default Policy"
        local policy=ocspNoCheckExtDefaultImpl
        local policyname=OCSPNoCheckExtensionDefault
        local constraintname=ExtensionConstraint
        local constraint=extensionConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p17;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy OCSP No check Extension Default to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p17;$policy;$constraint&ocspNoCheckCritical=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p17;$policy;$constraint&extCritical=false&extOID=1.1.1.1.1\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                	--user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0019:CA - Admin Interface - Add signing Algorithm"
        local policy=signingAlgDefaultImpl	
        local policyname=SigningAlgorithmDefault
        local constraintname=SigningAlgorithmConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p18;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Signing Algorithm to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p18;$policy;$constraint&signingAlg=SHA256withRSA\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p18;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0020:CA - Admin Interface - Add Subject Alternative Name Extension Policy"
        local policy=subjectAltNameExtDefaultImpl
        local policyname=SubjectAlternativeNameExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p19;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Alternative Name Extension to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p19;$policy;$constraint&subjAltNameExtCritical=false&subjAltNameNumGNs=1&subjAltExtType_0=RFC822Name&subjAltExtPattern_0=\$request.requestor_email\$&subjAltExtGNEnable_0=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p19;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0021:CA - Admin Interface - Add Subject Directory Attributes Extension Policy"
        local policy=subjectDirAttributesExtDefaultImpl
        local policyname=SubjectDirectoryAttributesExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p20;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Directory Attributes Extension to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p20;$policy;$constraint&subjDirAttrsCritical=false&subjDirAttrsNum=1&subjDirAttrName_0=email&subjDirAttrPattern_0=\$request.requestor_email\$&subjDirAttrEnable=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p20;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0022:CA - Admin Interface - Add Subject Info Access Extension Policy"
        local policy=subjectInfoAccessExtDefaultImpl
        local policyname=SubjectInfoAccessExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p21;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Info access extension default a1to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p21;$policy;$constraint&subjInfoAccessCritical=false&subjInfoAccessNumADs=1&subjInfoAccessADMethod_0=1.2.3.4.5.6&subjInfoAccessADLocationType_0=URINAME&subjInfoAccessADLocation_0=&subjInfoAccessADEnable_0=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p21;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0023:CA - Admin Interface - Add Subject key Identifier Policy"
        local policy=subjectKeyIdentifierExtDefaultImpl
        local policyname=SubjectKeyIdentifierDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p22;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject key Identifier to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p22;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p22;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd	

        rlPhaseStartTest "pki_console_profile-0024:CA - Admin Interface - Add Subject Name Default Policy"
        local policy=subjectNameDefaultImpl
        local policyname=SubjectNameDefault
        local constraintname=SubjectNameConstraint
        local constraint=subjectNameConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p23;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Info access extension default a1to $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p23;$policy;$constraint&CN=TEST\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p23;$policy;$constraint&pattern=cn=\*\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0025:CA - Admin Interface - Add Validity Default Policy"
        local policy=validityDefaultImpl
        local policyname=ValidityDefault
        local constraintname=ValidityConstraint
        local constraint=validityConstraintImpl
        local op_scope=policies
        rlLog "Delete Existing Key Usage Policy"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=policies&RS_ID=$profile&POLICYID=set1:p2\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Validity Default usage Policy"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p24;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Validity Default policy $profile"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p24;$policy;$constraint&range=180&startTime=60\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p24;$policy;$constraint&range=365&notBeforeGracePeriod=0&notBeforeCheck=false&notAfterCheck=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0026:CA - Admin Interface - Add Certificate Request Input"
        local Input=certReqInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i4;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Certificate Request Input $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i4=CertificateRequestInput" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0027:CA - Admin Interface - Add CMC Request Input"
        local Input=cmcCertReqInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i5;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add CMC Request Input $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i5=CertificateRequestInput" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0028:CA - Admin Interface - Add Dual Key Generation Input"
        local Input=dualKeyGenInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i6;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Dual Key Generation Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i6=DualKeyGeneration" "$admin_out"
        rlPhaseEnd#

        rlPhaseStartTest "pki_console_profile-0029:CA - Admin Interface - Add File Signing  Input"
        local Input=fileSigningInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i7;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add File Signing Input $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "i7=FileSigningInput" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0030:CA - Admin Interface - Add Key Generation Input"
        local Input=keyGenInputImpl
        local op_scope=profileInput
        rlLog "Delete Existing Key Generation Input"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=profileInput&RS_ID=$profile&INPUTID=i1\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Validity Default usage Policy"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Key Generation Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i1=KeyGeneration" "$admin_out"
        rlPhaseEnd	

        rlPhaseStartTest "pki_console_profile-0031:CA - Admin Interface - Add Subject DN  Input"
        local Input=subjectDNInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i8;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Subject DN Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i8=SubjectName" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0032:CA - Admin Interface - Add Subject Name Input"
        local Input=subjectNameInputImpl
        local op_scope=profileInput
        rlLog "Delete Existing Subject Name Input"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=profileInput&RS_ID=$profile&INPUTID=i2\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Subject Name Input"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i2;$Input&sn_uid=true&sn_e=true&sn_cn=true&sn_ou3=true&sn_ou2=true&sn_ou1=true&sn_ou=true&sn_o=true&sn_c=true\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Subject Name Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i2=SubjectName" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0033:CA - Admin Interface - Add Certificate Output"
        local Input=certOutputImpl
        local op_scope=profileOutput
        rlLog "Delete Existing Certificate Output"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=profileOutput&RS_ID=$profile&OUTPUTID=o1\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Certificate Output"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;o1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Certificate Output to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "o1=CertificateOutput" "$admin_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_console_profile-0034:CA - Admin Interface - Add CMMF Output"
        local Input=cmmfOutputImpl
        local op_scope=profileOutput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;o1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Certificate Output to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "o1=CertificateOutput" "$admin_out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_profile-0035:CA - Admin Interface - Delete an existing Policy from Profile"
        local op_scope=policies
	rlLog "Read all the existing Policies"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlLog "Delete signing Algorithm Policy from the profile"
	local policyId=$(cat -v $admin_out | grep SigningAlgorithmDefault | awk -F ":" '{print $2}' | awk -F "=" '{print $1}')
	rlLog "policyId=$policyId"
        rlLog "Delete Existing Key Usage Policy"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=policies&RS_ID=$profile&POLICYID=set1:$policyId\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Validity Default usage Policy"
        rlLog "Read all the existing Policies"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"	
	rlAssertNotGrep "SigningAlgorithmDefault:SigningAlgorithmConstraint" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-0036:CA - Admin Interface - Delete Dual Key Generation Input from Profile"
        local op_scope=profileInput
	rlLog "Read Existing Certificate Input"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	local inputId=$(cat -v $admin_out | grep DualKeyGeneration | awk -F "=" '{print $1}')	
	rlLog "Delete Dual Key Generation Input"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=profileInput&RS_ID=$profile&INPUTID=$inputId\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Dual Key Generation Input"
        rlLog "Read Existing Certificate Input to verify Dual Key Generation Input is deleted"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"	
        rlAssertNotGrep "DualKeyGeneration" "$admin_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0037:CA - Admin Interface - Delete Certificate request output from Existing Profile"
        local Input=certOutputImpl
        local op_scope=profileOutput
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "o1=CertificateOutput" "$admin_out"
        rlLog "Delete Existing Certificate Output"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=profileOutput&RS_ID=$profile&OUTPUTID=o1\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Delete Existing Certificate Output"
	rlLog "Read Existing Outputs to verify Certificate Output is not present"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertNotGrep "o1=CertificateOutput" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-0038:CA - Admin Interface - Enable Existing Profile"
	rlLog "Enable a Disabled profile"
	local action=Approve
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" -d \"profileId=$profile&Approve=$action\"  https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove > $admin_out"
        rlLog "Verify if $profile is enabled by enabling using pki command"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD  -n $valid_agent_cert ca-profile-enable $profile > $ca_profile_out 2>&1" 255,1 "Execute pki ca-profile-enable $profile"
        rlAssertGrep "BadRequestException: Profile already enabled" "$ca_profile_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0039:CA - Admin Interface - Disable Existing Profile"
        rlLog "Disable a Enabled profile"
        local action=Disable
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$tmp_ca_agent:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&Disable=$action\"  https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove"
        rlLog "Disable profile $profile and verify profile is already disabled"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port  \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-disable $profile > $ca_profile_out 2>&1" \
                255,1 "Disable already disabled profile $profile"
        rlAssertGrep "BadRequestException: Profile already disabled" "$ca_profile_out"	
        rlPhaseEnd

	rlPhaseStartTest "pki_console_profile-0040: CA Admin Interface - Create a new profile as Admin Only user with caEnrollImpl with No Profile Authentication"
        local profile="caUserCert$RANDOM"
        local op_scope=rules
        local op_type='OP_DELETE'
        local class=caEnrollImpl
        rlLog "Create new profile $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=rules&RS_ID=$profile&impl=$class&name=$profile&visible=true&auth=&desc=$profile\" \
                -k  https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Create a new profile for user cert enrollment"
        rlLog "List all default Profiles"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=rules&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile >> $admin_out" 0 "List all default Profiles"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$profile=$profile:visible:disabled" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0041:CA - Admin Interface - Add Key Generation Input "
        rlLog "Add Key Generation Input"
        local Input=keyGenInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Key Generation Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i1=KeyGeneration" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0042:CA - Admin Interface - Add subject Name Input "
        rlLog "Add Subject Name Input"
        local Input=subjectNameInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i2;$Input&sn_uid=true&sn_e=true&sn_cn=true&sn_ou3=true&sn_ou2=true&sn_ou1=true&sn_ou=true&sn_o=true&sn_c=true\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Subject Name Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i2=SubjectName" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0043:CA - Admin Interface - Add Requestor Information Input "
        rlLog "Add Requestor Information"
        local Input=submitterInfoInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i3;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Subject Name Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i3=RequestorInformation" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0044:CA - Admin Interface - Add Certificate Output "
        local Input=certOutputImpl
        local op_scope=profileOutput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;o1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Certificate Output to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "o1=CertificateOutput" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0045:CA - Admin Interface - Add User Supplied Subject Name Input Default Policy"
        local policy=userSubjectNameDefaultImpl
        local policyname=UserSuppliedSubjectNameDefault
        local constraintname=SubjectNameConstraint
        local constraint=subjectNameConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p1;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Info access extension default a1to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p1;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p1;$policy;$constraint&pattern=UID=.*\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0046:CA - Admin Interface - Add NoDefault Policy"
        local policy=noDefaultImpl
        local policyname=NoDefault
        local constraintname=RenewalGracePeriodConstraint
        local constraint=renewGracePeriodConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p2;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy NoDefault to $profile"
        rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p2;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p2;$policy;$constraint&renewal.graceBefore=30&renewal.graceAfter=30\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
        rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        #rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0047:CA - Admin Interface - Add Validity Default Policy"
        local policy=validityDefaultImpl
        local policyname=ValidityDefault
        local constraintname=ValidityConstraint
        local constraint=validityConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p3;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Validity Default policy $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p3;$policy;$constraint&range=180&startTime=0\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p3;$policy;$constraint&range=365&notBeforeGracePeriod=0&notBeforeCheck=false&notAfterCheck=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0048:CA - Admin Interface - Add Extended Key Usage Extension Default Policy"
        local policy=extendedKeyUsageExtDefaultImpl
        local policyname=ExtendedKeyUsageExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p4;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Extended Key Usage Extension Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p4;$policy;$constraint&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details" 0 
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p4;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0049:CA - Admin Interface - Add Subject Alternative Name Extension Policy"
        local policy=subjectAltNameExtDefaultImpl
        local policyname=SubjectAlternativeNameExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p5;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Alternative Name Extension to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p5;$policy;$constraint&subjAltNameExtCritical=false&subjAltNameNumGNs=1&subjAltExtType_0=RFC822Name&subjAltExtPattern_0='$request.requestor_email$'&subjAltExtGNEnable_0=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p5;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd	

        rlPhaseStartTest "pki_console_profile-0049:CA - Admin Interface - Add User Key Default Policy(Admin Only)"
        local policy=userKeyDefaultImpl
        local policyname=UserSuppliedKeyDefault
        local constraintname=KeyConstraint
        local constraint=keyConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Userkey Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint&keyType=-&keyParameters=1024,2048,3072,4096,nistp256,nistp384,nistp521\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0050:CA - Admin Interface - Add Authority key Identifier Extension Default Policy"
        local op_scope=policies
        local policy=authorityKeyIdentifierExtDefaultImpl
        local policyname=AuthorityKeyIdentifierExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p7;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Authority Key Identifier Extension Default Policy to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p7;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p7;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0051:CA - Admin Interface - Add Authority Info Access Extension Default Policy"
        local op_scope=policies
        local policy=authInfoAccessExtDefaultImpl
        local policyname=AuthorityInfoAccessExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlLog "Add Policy" 
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p8;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Authority Info Access Extension Default Policy to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p8;$policy;$constraint&authInfoAccessCritical=false&authInfoAccessNumADs=1&authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1&authInfoAccessADLocationType_0=URIName&authInfoAccessADLocation_0=&authInfoAccessADEnable_0=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p8;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Read all policies of $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=policies&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0052:CA - Admin Interface - Add Key Usage Extension Default"
        local policy=keyUsageExtDefaultImpl
        local policyname=KeyUsageExtensionDefault
        local constraintname=KeyUsageExtensionConstraint
        local constraint=keyUsageExtConstraintImpl
        rlLog "Add Key Usage Policy"
        local op_scope=policies
        local crlurl="https://$tmp_ca_host:$target_secure_port/crl/Mastercrl.bin"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Key Usage Extension Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0053:CA - Admin Interface - Add Signing Algorithm Default Policy"
        local policy=signingAlgDefaultImpl
        local policyname=SigningAlgorithmDefault
        local constraintname=SigningAlgorithmConstraint
        local constraint=signingAlgConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Signing Algorithm Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint&signingAlg=SHA256withRSA\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint&signingAlgsAllowed=SHA1withRSA,MD5withRSA,MD2withRSA,SHA1withDSA,SHA256withRSA,SHA512withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0054:CA - Enroll a user certificate with newly created profile"
        rlLog "Enable a Disabled profile"
        local action=Approve
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&Approve=$action\"  https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove > $admin_out 2>&1"
        rlLog "Verify $profile is by disabling the profile using pki cli"
        rlLog "Verify if $profile is enabled by enabling using pki command"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port  \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1" 255,1 "Execute pki ca-profile-enable $profile"
        rlAssertGrep "BadRequestException: Profile already enabled" "$ca_profile_out"
	local temp_user=foo_User_$RANDOM	
        rlLog "Generate a cert with subject name CN=Foo User_1,UID=$Temp_user,E=$temp_user@example.org,OU=FOO,O=Example.org,C=US"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:1024 \
                subject_cn:\"Foo User_1\" \
                subject_uid:FooUser_1 \
                subject_email:FooUser_1@example.org \
                subject_ou:FOO \
		subject_o:Example.org \
                subject_c:US \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$valid_agent_cert\" \
                cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber > $cert_out" 0 "Executing pki cert-show $cert_serialNumber"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $pkcs10_requestdn" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlPhaseEnd

        rlPhaseStartSetup "Create user with only Agent privileges"
        local test_user="idm_agent_user$RANDOM"
        local test_user_fullName="idm Agent User"
        local test_user_pwd="Secret123"
	local target_group="Certificate Manager Agents"
        rlLog "Create user with Agent Privileges only"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert  \
                user-add $test_user  \
                --fullName \"$test_user_fullName\" \
                --password $test_user_pwd" 0 "Create $test_user_fullName user"
        rlLog "Add user to Administrators Group"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert \
                group-member-add \"$target_group\" $test_user > $TmpDir/group.out" 0 "Add $test_user_fullName to Certificate Agents Group"
	rlAssertGrep "Added group member \"$test_user\"" "$TmpDir/group.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0055: CA Admin Interface - Creating a new profile by user member of Certificate Agents should fail"
        local profile="caUserCert$RANDOM"
        local op_scope=rules
        local class=caEnrollImpl
        rlLog "Create new profile $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_user:$test_user_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=rules&RS_ID=$profile&impl=$class&name=$profile&visible=true&auth=&desc=$profile\" \
                -k  https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Create a new profile as $test_user_fullname"
	rlAssertGrep "You are not authorized to perform this operation" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Create user with only Audit privileges"
        local test_user="idm_agent_user$RANDOM"
        local test_user_fullName="idm Agent User"
        local test_user_pwd="Secret123"
        local target_group="Auditors"
        rlLog "Create user with Agent Privileges only"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert  \
                user-add $test_user  \
                --fullName \"$test_user_fullName\" \
                --password $test_user_pwd" 0 "Create $test_user_fullName user"
        rlLog "Add user to Administrators Group"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert \
                group-member-add \"$target_group\" $test_user > $TmpDir/group.out" 0 "Add $test_user_fullName to Certificate Agents Group"
        rlAssertGrep "Added group member \"$test_user\"" "$TmpDir/group.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_profile-0056: CA Admin Interface - Creating a new profile by user member of Auditors group should fail"
        local profile="caUserCert$RANDOM"
        local op_scope=rules
        local class=caEnrollImpl
        rlLog "Create new profile $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_user:$test_user_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=rules&RS_ID=$profile&impl=$class&name=$profile&visible=true&auth=&desc=$profile\" \
                -k  https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Create a new profile as $test_user_fullname"
        rlAssertGrep "You are not authorized to perform this operation" "$admin_out"
        rlPhaseEnd

}
