#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/drm-tests/drm-ad-usergroups
#   Description: DRM Admin Console User groups tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following legacy test is being tested:
#  DRM Admin Console Usergroups tests
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

run_kra-ad_usergroups()
{
	local cs_Type=$1
        local cs_Role=$2
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)

        # Creating Temporary Directory for legacy test
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        disable_ca_nonce $tomcat_name
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
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
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local cert_show_out="$TmpDir/cert_show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')

	rlPhaseStartTest "pki_kra_ad_usergroups-001: DRM Console: List Users"
	local OP_TYPE='OP_SEARCH'
	local OP_SCOPE='users'
	local test_out=$OP_TYPE\.out
	rlLog "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
		-k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" >> $TmpDir/$test_out"
	rlRun "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
		-k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" >> $TmpDir/$test_out" 0 "List Users"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	rlAssertGrep "$valid_admin" "$TmpDir/$test_out"
	rlAssertGrep "$valid_agent" "$TmpDir/$test_out"
	rlAssertGrep "$valid_audit" "$TmpDir/$test_out"
	rlAssertGrep "$valid_operator" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-002: DRM Console: Add Users"
	local user1=$KRA_INST-$RANDOM
	local OP_TYPE='OP_ADD'
	local OP_SCOPE='users'
	local RS_ID=$user1
	local fullname=$user1
	local password=$user1
	local email=$user1@example.org
	local phone=''
	local state=''
	local groups='Data Recovery Manager Agents'
	local userType=''
	local test_out=add.out
	rlLog "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
		-k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlLog "List users"
	local OP_TYPE='OP_SEARCH'
	local OP_SCOPE='users'
	local test_out=$OP_TYPE\.out
	rlRun "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
		-k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "List Users"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	rlAssertGrep "$user1" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-003: DRM Console: Edit Users"
        local OP_TYPE='OP_MODIFY'
        local OP_SCOPE='users'
        local RS_ID=$user1
        local fullname=$user1-01
        local password=$user1
        local email=$user1@example.org
        local phone=''
        local state=''
        local userType=''
        local test_out=modify.out
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlLog "List users"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='users'
        local test_out=$OP_TYPE\.out
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "List Users"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	rlAssertGrep "$user1:$fullname" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartSetup "Generate certificate"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="$user1"
        local usercn="$fullname"
        local phone="1234-$RANDOM"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$usercn\" \
                subject_uid:$userid \
                subject_email:$usermail \
                subject_ou:IDM \
                subject_organization:RedHat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
        rlLog "Approve $request_id using $valid_agent_cert"
        local Second=`date +'%S' -d now`
        local Minute=`date +'%M' -d now`
        local Hour=`date +'%H' -d now`
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local Year=`date +'%Y' -d now`
        local start_year=$Year
        let end_year=$Year+1
        local end_day="1"
        local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
        local notAfter="$end_year-$Month-$end_day $Hour:$Minute:$Second"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit certificate request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	local certificate_in_base64=$(cat -v $TmpDir/$test_out | grep 'outputList.outputVal' | awk -F 'outputList.outputVal=\"' '{print $2}'  | awk -F '-----BEGIN CERTIFICATE-----' '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/-----END CERTIFICATE-----\\n\";/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-004: DRM Console: Import Cert to the user"
	local OP_TYPE='OP_ADD'
	local OP_SCOPE='certs'
	local RS_ID="$user1"
	local cert=$certificate_in_base64
	local test_out=addcert.out
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" --data-urlencode \"cert=$certificate_in_base64\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Import cert to $user1"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" --data-urlencode \"cert=$certificate_in_base64\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Import cert to $user1"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlLog "Verify if cert is added"
	local OP_TYPE='OP_READ'
	local OP_SCOPE='certs'
	local RS_ID="$userid"
	local test_out=search.out
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search certificate"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "-----BEGIN+CERTIFICATE-----" "$TmpDir/$test_out"
	rlAssertGrep "-----END+CERTIFICATE-----" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-005: DRM Console: Add Group"
	local group1=$KRA_INST-group-$RANDOM
	local OP_TYPE='OP_ADD'
	local OP_SCOPE='groups'
	local RS_ID=$group1
	local desc=$group1
	local user=$user1
	rlLog "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlLog "Verify group is added"
	local OP_TYPE='OP_SEARCH'
	local OP_SCOPE='groups'
	rlLog "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	rlAssertGrep "$group1" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-006: DRM Console: Edit Group"
	local OP_TYPE='OP_MODIFY'
	local OP_SCOPE='groups'
	local RS_ID=$group1
	local desc=$group1
	local user=$valid_admin,$valid_agent,$valid_audit
	local test_out=edit.out
	rlLog "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&desc=$desc&user=$user\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Edit $group1"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&desc=$desc&user=$user\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Edit $group1"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-007: DRM Console: Delete Group"
        local OP_TYPE='OP_DELETE'
        local OP_SCOPE='groups'
        local RS_ID=$group1
	local test_out=groupdelete.out
	rlLog "curl --capath $CERTDB_DIR \
		--dump-header $admin_out \
		--basic --user "$valid_admin:$valid_admin_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
	rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlLog "Verify group is deleted"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
	rlAssertNotGrep "$group1" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-008: DRM Console: Delete User"
        local OP_TYPE='OP_DELETE'
        local OP_SCOPE='users'
        local RS_ID="$user1:true"
	rlLog "Delete $user1"
	rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $user1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $user1"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlLog "List users"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='users'
        local test_out=$OP_TYPE\.out
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "List Users"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$user1" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-009: DRM Console: Verify Agent user cannot add new user"
        local user2=$KRA_INST-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='users'
        local RS_ID=$user2
        local fullname=$user2
        local password=$user2
        local email=$user2@example.org
        local phone=''
        local state=''
        local groups='Data Recovery Manager Agents'
        local userType=''
        local test_out=add.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "List users"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='users'
        local test_out=$OP_TYPE\.out
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "List Users"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$user2" "$TmpDir/$test_out"
	rlPhaseEnd


        rlPhaseStartTest "pki_kra_ad_usergroups-0010: DRM Console: Verify Audit user cannot add new user"
        local user2=$KRA_INST-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='users'
        local RS_ID=$user2
        local fullname=$user2
        local password=$user2
        local email=$user2@example.org
        local phone=''
        local state=''
        local groups='Data Recovery Manager Agents'
        local userType=''
        local test_out=add.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_audit:$valid_audit_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_audit:$valid_audit_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "List users"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='users'
        local test_out=$OP_TYPE\.out
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "List Users"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$user2" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0011: DRM Console: Verify Operator user cannot add new user"
	local user2=$KRA_INST-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='users'
        local RS_ID=$user2
        local fullname=$user2
        local password=$user2
        local email=$user2@example.org
        local phone=''
        local state=''
        local groups='Data Recovery Manager Agents'
        local userType=''
        local test_out=add.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_operator:$valid_operator_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_operator:$valid_operator_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=$groups&userType=$userType\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "List users"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='users'
        local test_out=$OP_TYPE\.out
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" \
                -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "List Users"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$user2" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0012: DRM Console: Verify Agent user cannot add new group"
        local group2=$KRA_INST-group-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='groups'
        local RS_ID=$group2
        local desc=$group2
        local user=$user2
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "Verify group is added"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$group2" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0013: DRM Console: Verify Audit user cannot add new group"
        local group2=$KRA_INST-group-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='groups'
        local RS_ID=$group2
        local desc=$group2
        local user=$user2
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_audit:$valid_audit_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_audit:$valid_audit_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "Verify group is added"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$group2" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0014: DRM Console: Verify Operator user cannot add new group"
        local group2=$KRA_INST-group-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='groups'
        local RS_ID=$group2
        local desc=$group2
        local user=$user2
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_operator:$valid_operator_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_operator:$valid_operator_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "Verify group is added"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$group2" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0015: DRM Console: Verify Agent User cannot delete existing group"
        local OP_TYPE='OP_DELETE'
        local OP_SCOPE='groups'
        local RS_ID=$group1
        local test_out=groupdelete.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlLog "Verify group is deleted"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertNotGrep "$group1" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartSetup "DRM Console: Add Group"
        local group1=$KRA_INST-group-$RANDOM
        local OP_TYPE='OP_ADD'
        local OP_SCOPE='groups'
        local RS_ID=$group1
        local desc=$group1
        local user=$user1
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Add Group $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlLog "Verify group is added"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertGrep "$group1" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0016: DRM Console: Verify Agent User cannot delete existing group"
        local OP_TYPE='OP_DELETE'
        local OP_SCOPE='groups'
        local RS_ID=$group1
        local test_out=groupdelete.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_agent:$valid_agent_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "Verify group is not deleted"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertGrep "$group1" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0017: DRM Console: Verify Audit User cannot delete existing group"
        local OP_TYPE='OP_DELETE'
        local OP_SCOPE='groups'
        local RS_ID=$group1
        local test_out=groupdelete.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_audit:$valid_audit_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_audit:$valid_audit_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "Verify group is not deleted"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertGrep "$group1" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ad_usergroups-0018: DRM Console: Verify Operator User cannot delete existing group"
        local OP_TYPE='OP_DELETE'
        local OP_SCOPE='groups'
        local RS_ID=$group1
        local test_out=groupdelete.out
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_operator:$valid_operator_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_operator:$valid_operator_pwd" -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE&RS_ID=$RS_ID\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Delete $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/$test_out"
        rlLog "Verify group is not deleted"
        local OP_TYPE='OP_SEARCH'
        local OP_SCOPE='groups'
        rlLog "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlRun "curl --capath $CERTDB_DIR \
                --dump-header $admin_out \
                --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=$OP_SCOPE\" -k \"https://$tmp_kra_host:$target_secure_port/kra/ug\" > $TmpDir/$test_out" 0 "Search for $group1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "process_curl_output $TmpDir/$test_out" 0 "Process curl output file"
        rlAssertGrep "$group1" "$TmpDir/$test_out"
        rlPhaseEnd
	
	rlPhaseStartCleanup "Delete temporary dir and enable nonce"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        enable_ca_nonce $tomcat_name
        rlPhaseEnd
	
}
verify_cert()
{
        local serial_number=$1
        local request_dn=$2
        STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        CONV_LOW_VAL=${STRIP_HEX,,}
        rlRun "pki -h $tmp_ca_host -p $target_unsecure_port cert-show $serial_number > $cert_show_out" 0 "Executing pki cert-show $serial_number"
        rlAssertGrep "Serial Number: 0x$CONV_LOW_VAL" "$cert_show_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}
