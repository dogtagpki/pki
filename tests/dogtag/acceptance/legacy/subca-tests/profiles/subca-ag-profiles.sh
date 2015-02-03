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

run_agent-subca-profile_tests()
{

	 # Creating Temporary Directory
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "export PYTHONPATH=$PYTHONPATH:/opt/rhqa_pki/"
        rlPhaseEnd

        # Local Variables
        local cs_Type=$1
        local cs_Role=$2
        get_topo_stack $cs_Role $TmpDir/topo_file
        if [ $cs_Role="MASTER" ]; then
                 SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
        local tomcat_name=$(eval echo \$${SUBCA_INST}_TOMCAT_INSTANCE_NAME)
        local target_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local tmp_ca_agent=$SUBCA_INST\_agentV
        local tmp_ca_admin=$SUBCA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$SUBCA_INST\_agentV
        local valid_audit_cert=$SUBCA_INST\_auditV
        local valid_operator_cert=$SUBCA_INST\_operatorV
        local valid_admin_cert=$SUBCA_INST\_adminV
	local cert_find_info="$TmpDir/cert_find_info"
        local revoked_agent_cert=$SUBCA_INST\_agentR
        local revoked_admin_cert=$SUBCA_INST\_adminR
        local expired_admin_cert=$SUBCA_INST\_adminE
        local expired_agent_cert=$SUBCA_INST\_agentE
	#users
	local valid_agent_user=$SUBCA_INST\_agentV
	local valid_audit_user=$SUBCA_INST\_auditV
	local valid_operator_user=$SUBCA_INST\_operatorV
	local valid_admin_user=$SUBCA_INST\_adminV
	local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')        
	local SSL_DIR=$CERTDB_DIR

	rlPhaseStartSetup "CA Admin Interface - Create a new profile as Admin Only user with caEnrollImpl with No Profile Authentication"
        local profile="caUserCert$RANDOM"
        local op_scope=rules
        local class=caEnrollImpl
        rlLog "Create new profile $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=rules&RS_ID=$profile&impl=$class&name=$profile&visible=true&auth=&desc=$profile\" \
                -k  https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Create a new profile for user cert enrollment"
        rlLog "List all default Profiles"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=rules&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile >> $admin_out" 0 "List all default Profiles"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$profile=$profile:visible:disabled" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Key Generation Input "
        rlLog "Add Key Generation Input"
        local Input=keyGenInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Key Generation Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i1=KeyGeneration" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add subject Name Input "
        rlLog "Add Subject Name Input"
        local Input=subjectNameInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i2;$Input&sn_uid=true&sn_e=true&sn_cn=true&sn_ou3=true&sn_ou2=true&sn_ou1=true&sn_ou=true&sn_o=true&sn_c=true\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Subject Name Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i2=SubjectName" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Requestor Information Input "
        rlLog "Add Requestor Information"
        local Input=submitterInfoInputImpl
        local op_scope=profileInput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;i3;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Subject Name Input to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "i3=RequestorInformation" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Certificate Output "
        local Input=certOutputImpl
        local op_scope=profileOutput
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;o1;$Input\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Certificate Output to $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "o1=CertificateOutput" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add User Supplied Subject Name Input Default Policy"
        local policy=userSubjectNameDefaultImpl
        local policyname=UserSuppliedSubjectNameDefault
        local constraintname=SubjectNameConstraint
        local constraint=subjectNameConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p1;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Info access extension default a1to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p1;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p1;$policy;$constraint&pattern=UID=.*\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add NoDefault Policy"
        local policy=noDefaultImpl
        local policyname=NoDefault
        local constraintname=RenewalGracePeriodConstraint
        local constraint=renewGracePeriodConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p2;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy NoDefault to $profile"
        rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p2;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
        rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p2;$policy;$constraint&renewal.graceBefore=30&renewal.graceAfter=30\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
        rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        #rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Validity Default Policy"
        local policy=validityDefaultImpl
        local policyname=ValidityDefault
        local constraintname=ValidityConstraint
        local constraint=validityConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p3;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Validity Default policy $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p3;$policy;$constraint&range=180&startTime=0\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p3;$policy;$constraint&range=365&notBeforeGracePeriod=0&notBeforeCheck=false&notAfterCheck=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Extended Key Usage Extension Default Policy"
        local policy=extendedKeyUsageExtDefaultImpl
        local policyname=ExtendedKeyUsageExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p4;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Extended Key Usage Extension Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p4;$policy;$constraint&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details" 0 
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p4;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Subject Alternative Name Extension Policy"
        local policy=subjectAltNameExtDefaultImpl
        local policyname=SubjectAlternativeNameExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p5;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile" 0 "Add Policy Subject Alternative Name Extension to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p5;$policy;$constraint&subjAltNameExtCritical=false&subjAltNameNumGNs=1&subjAltExtType_0=RFC822Name&subjAltExtPattern_0='$request.requestor_email$'&subjAltExtGNEnable_0=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p5;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd	

        rlPhaseStartSetup "Admin Interface - Add User Key Default Policy(Admin Only)"
        local policy=userKeyDefaultImpl
        local policyname=UserSuppliedKeyDefault
        local constraintname=KeyConstraint
        local constraint=keyConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Userkey Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p6;$policy;$constraint&keyType=-&keyParameters=1024,2048,3072,4096,nistp256,nistp384,nistp521\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Authority key Identifier Extension Default Policy"
        local op_scope=policies
        local policy=authorityKeyIdentifierExtDefaultImpl
        local policyname=AuthorityKeyIdentifierExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p7;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Authority Key Identifier Extension Default Policy to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p7;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p7;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Authority Info Access Extension Default Policy"
        local op_scope=policies
        local policy=authInfoAccessExtDefaultImpl
        local policyname=AuthorityInfoAccessExtensionDefault
        local constraintname=NoConstraint
        local constraint=noConstraintImpl
        rlLog "Add Policy" 
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=policies&RS_ID=$profile;set1:p8;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Authority Info Access Extension Default Policy to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p8;$policy;$constraint&authInfoAccessCritical=false&authInfoAccessNumADs=1&authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1&authInfoAccessADLocationType_0=URIName&authInfoAccessADLocation_0=&authInfoAccessADEnable_0=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p8;$policy;$constraint\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Read all policies of $profile"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=policies&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Key Usage Extension Default"
        local policy=keyUsageExtDefaultImpl
        local policyname=KeyUsageExtensionDefault
        local constraintname=KeyUsageExtensionConstraint
        local constraint=keyUsageExtConstraintImpl
        rlLog "Add Key Usage Policy"
        local op_scope=policies
        local crlurl="https://$tmp_ca_host:$target_secure_port/crl/Mastercrl.bin"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Key Usage Extension Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p9;$policy;$constraint&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Admin Interface - Add Signing Algorithm Default Policy"
        local policy=signingAlgDefaultImpl
        local policyname=SigningAlgorithmDefault
        local constraintname=SigningAlgorithmConstraint
        local constraint=signingAlgConstraintImpl
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Signing Algorithm Default to $profile"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        local op_scope=defaultPolicy
        rlLog "Add $policy Details"
        rlRun "curl --capath "$CERTDB_DIR" \
                --basic --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint&signingAlg=SHA256withRSA\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Add Policy Details"
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Add Policy Constraint"
        local op_scope=constraintPolicy
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=$op_scope&RS_ID=$profile;set1:p10;$policy;$constraint&signingAlgsAllowed=SHA1withRSA,MD5withRSA,MD2withRSA,SHA1withDSA,SHA256withRSA,SHA512withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC\" -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0
	rlAssertNotGrep "The server encountered an internal error" "$admin_out"
        rlLog "Get all policies of $profile"
        local op_scope=policies
        rlRun "curl --capath "$CERTDB_DIR" --basic \
                --user "$valid_admin_user:$valid_admin_user\_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=$op_scope&RS_ID=$profile\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caprofile > $admin_out" 0 "Read all existing policies of $profile"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "$policyname:$constraintname" "$admin_out"
        rlPhaseEnd

        rlPhaseStartSetup "Enroll a user certificate with newly created profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port  \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1" 0  "Execute pki ca-profile-enable $profile"
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
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Certificate,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $pkcs10_requestdn" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_agent_profile-001: SUBCA - Verify Disabling the profile with Admin only cert fails"
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Disable a Enabled profile"
        local action=Disable
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&Disable=$action\"  https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove"
        rlLog "Disable profile $profile and verify profile is already disabled"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port  \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1" \
                255,1 "Enable already Enabled profile $profile"
        rlAssertGrep "BadRequestException: Profile already enabled" "$ca_profile_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_agent_profile-002: SUBCA - Verify Enabling the profile with Admin cert fails"
	rlLog "Disable profile using Agent Cert"
	local action="Disable"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&$action=$action\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove > $admin_out"
        rlLog "Enable a Disabled profile"
        local action=Approve
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		-E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
		-d \"profileId=$profile&$action=$action\"  \
		https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove > $admin_out"
        rlLog "Verify if $profile is enabled by enabling using pki command"
        rlRun "pki -h $tmp_ca_host \
		-p $tmp_ca_port \
		-d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD  \
		-n $valid_agent_cert ca-profile-disable $profile > $ca_profile_out 2>&1" 255,1 "Execute pki ca-profile-enable $profile"
        rlAssertGrep "BadRequestException: Profile already disabled" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_agent_profile-003: SUBCA - Verify Disabling the profile with Audit cert fails"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Disable a Enabled profile"
        local action=Disable
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_audit_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&$action=$action\"  https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove"
        rlLog "Disable profile $profile and verify profile is already disabled"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port  \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1" \
                255,1 "Enable already Enabled profile $profile"
        rlAssertGrep "BadRequestException: Profile already enabled" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_agent_profile-004: SUBCA - Verify Enabling a disabled profile with Audit cert fails"
        rlLog "Disable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-disable $profile > $ca_profile_out"
        rlAssertGrep "Disabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Enable a Disabled profile"
        local action=Approve
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_audit_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&Approve=$action\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove > $admin_out"
        rlLog "Verify if $profile is disabled by disabling using pki command"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD  \
                -n $valid_agent_cert ca-profile-disable $profile > $ca_profile_out 2>&1" 255,1 "Execute pki ca-profile-disable $profile"
        rlAssertGrep "BadRequestException: Profile already disabled" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_agent_profile-005: SUBCA - Verify Disabling the enabled profile with Operator cert fails"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Disable a Enabled profile"
        local action=Disable
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_operator_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&Disable=$action\"  https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove"
        rlLog "verify profile is in enabled state by enabling it again using pki ca-profile-enable"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port  \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1" \
                255,1 "Enable already Enabled profile $profile"
        rlAssertGrep "BadRequestException: Profile already enabled" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_agent_profile-006: SUBCA - Verify Enabling a disabled profile with Operator cert fails"
        rlLog "Disable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-disable $profile > $ca_profile_out"
        rlLog "Enable a Disabled profile"
        local action=Approve
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                -E \"$valid_operator_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"profileId=$profile&Approve=$action\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileApprove > $admin_out"
        rlLog "Verify if $profile is disabled by disabling using pki command which should fail"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD  \
                -n $valid_agent_cert ca-profile-disable $profile > $ca_profile_out 2>&1" 255,1 "Execute pki ca-profile-enable $profile"
        rlAssertGrep "BadRequestException: Profile already disabled" "$ca_profile_out"
        rlPhaseEnd
	
	rlPhaseStartCleanup "Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd	

}
