#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca-tests/cert-enrollment/subca-ag-requests
#   Description: Subordiate CA Agent Requests 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following legacy test is being tested:
#   subca-ag-requests
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

run_subca-ag-requests_tests()
{

	# Creating Temporary Directory
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "export PYTHONPATH=$PYTHONPATH:/opt/rhqa_pki/"
        rlPhaseEnd

        # Disable Nonce
        rlPhaseStartSetup "Disable Nonce"
        local cs_Type=$1
        local cs_Role=$2
        get_topo_stack $cs_Role $TmpDir/topo_file
        if [ $cs_Role="MASTER" ]; then
                 SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
        local tomcat_name=$(eval echo \$${SUBCA_INST}_TOMCAT_INSTANCE_NAME)
        disable_ca_nonce $tomcat_name
        rlPhaseEnd

	#local variables
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
        local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local cert_show_out="$TmpDir/cert_show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
        local SSL_DIR=$CERTDB_DIR

	rlPhaseStartTest "pki_subca_ag-requests-001: CA Agent Page: List Requests try to display 100 requests and their details"
	local reqType='enrollment'
	local reqState='showWaiting'
	local lastEntryOnPage='0'
	local direction='first'
	local maxCount='100'
	local test_out='agent.out'
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"reqType=$reqType&reqState=$reqState&lastEntryOnPage=$lastEntryOnPage&direction=$direction&maxCount=$maxCount\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/queryReq\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"reqType=$reqType&reqState=$reqState&lastEntryOnPage=$lastEntryOnPage&direction=$direction&maxCount=$maxCount\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/queryReq\" > $TmpDir/$test_out"
	rlAssertGrep "record.callerName=\"$valid_agent_cert\"" "$TmpDir/$test_out"
	local no_of_records=$(cat $TmpDir/$test_out | grep record.subject | wc -l)
	rlAssertGreater "Verify No of records displayed is more than 1" $no_of_records 1
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlPhaseEnd

	rlPhaseStartSetup "Create certificate request for review"
        rlLog "Create a pkcs10 cert request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="foo$RANDOM"
        local usercn="foo$RANDOM"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test1.txt
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
        rlLog "cert_requestdn=$cert_requestdn"
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
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-002: CA Agent Page: view a particular profile based certificate request"
	rlLog "View certificate request details"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
	rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
	rlAssertGrep "inputList.inputVal=\"$useid\"" "$TmpDir/$test_out"
	rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
	rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
	rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-003: CA Agent Page: Approve Profile request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit certificate request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        local serial_number_without_hex=$(echo $serial_number | cut -dx -f2)
        local serial_number_without_hex_lower=${serial_number_without_hex,,}
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-004: CA Agent Page: Cancel Certificate request"	
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=cancel&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=cancel&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "cancel certificate request"
	rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
	rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
	rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
	rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
	rlAssertGrep "requestStatus=\"canceled\"" "$TmpDir/$test_out"
	rlPhaseEnd


	rlPhaseStartTest "pki_subca_ag-requests-005: CA Agent Page: Reject Certificate request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
	local action=reject
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "$action certificate request"
        rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"rejected\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-006: CA Agent Page: Assign Certificate request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
        local action=assign
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "$action certificate request"
        rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/$test_out"	
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-007: CA Agent Page: UnAssign Certificate request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
        local action=unassign
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "$action certificate request"
        rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/$test_out"
	rlPhaseEnd


	rlPhaseStartTest "pki_subca_ag-requests-008: CA Agent Page: Validate Certificate request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
        local action=validate
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "$action certificate request"
        rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-009: CA Agent Page: Update Certificate request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
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
        local action=update
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=$action&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "$action certificate request"
        rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-0010: Search certs with serial Number range"
	local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse="on"
        local serialFrom=0
        local serialTo=300
        local queryCertFilter="(&(certRecordId>=$serialFrom)(certRecordId<=$serialTo))"
	local statusInUse=''
	local cert_status='VALID'
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=''
	local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
	local profileInUse=''
	local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
	local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='10'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertEquals "Verify No of records displayed is equal to $maxCount" $no_of_records $maxResults
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ag-requests-0011: Search certs with status VALID"
        local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certStatus=VALID))"
        local statusInUse='on'
        local cert_status='VALID'
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=''
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $maxResults $no_of_records
        rlPhaseEnd


        rlPhaseStartTest "pki_subca_ag-requests-0012: Search certs with status REVOKED"
        local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certStatus=REVOKED))"
        local statusInUse='on'
        local cert_status='REVOKED'
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=''
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $maxResults $no_of_records
	rlAssertNotGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlPhaseEnd


	rlPhaseStartSetup "pki_subca_ag-requests-0013: Generate a profile which generates cert with 1 day validity period"
        local profile="caUserCert$RANDOM"
        local pki_user="pki_foo_bar$RANDOM"
        local pki_user_fullName="$pki_user User"
        local profilename="$profile Enrollment Profile"
        rlRun "python -m PkiLib.pkiprofilecli \
            --new user --profileId "$profile" \
            --profilename=\"$profilename\" \
            --notBefore 1 \
            --notAfter 1 \
            --validfor 1 \
            --maxvalidity 1  \
            --outputfile $TmpDir/$profile\.xml"
        rlLog "Add $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-add $TmpDir/$profile\.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$pki_user_fullName\" \
                subject_uid:$pki_user \
                subject_email:$pki_user@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
	local NotAfterDate="$(date +"%a %b %d %I:%M:%S" --date "1 day")"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
	rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
	rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
	rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
	rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
	rlLog "Add the $cn cert to $TEMP_NSS_DB NSS DB"
	rlRun "pki -d $TEMP_NSS_DB \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-c $TEMP_NSS_DB_PWD \
		-n \"$pki_user\" client-cert-import \
		--cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
	rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
	rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
	rlRun "pki -d $TEMP_NSS_DB \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-c $TEMP_NSS_DB_PWD \
		-n \"casigningcert\" client-cert-import \
		--ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
	rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"		
	local cur_date=$(date)
	local end_date=$(certutil -L -d $TEMP_NSS_DB -n $pki_user | grep "Not After" | awk -F ": " '{print $2}')
	rlLog "Current Date/Time: $(date)"
	rlLog "Current Date/Time: before modifying using chrony $(date)"
	rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Move system to $end_date + 1 day ahead"
	rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlRun "date"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after modifying using chrony: $(date)"
	rlLog "Restart $tomcat_name service to update cert status"
	rlRun "rhcs_stop_instance $tomcat_name"
	rlRun "rhcs_start_instance $tomcat_name"
	rlRun "sleep 30"
	rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --encoded > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: EXPIRED" "$cert_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-0014: Search certs with status EXPIRED"
        local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certStatus=EXPIRED))"
        local statusInUse='on'
        local cert_status='EXPIRED'
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=''
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
	for i in $(cat $TmpDir/$test_out | grep record.validNotBefore | cut -d"=" -f2 | tr -d "\"" | tr -d ";"); do if [ $i -ge $(date +%s) ]; then result="fail"; fi; done
	if [ $result == "fail" ]; then
		rlFail "Records contain entries with valid certs"
	else
		rlPass "Records Contain entries with expired certs"
	fi
	rlAssertGrep "record.subject=\"$cert_subject\"" "$TmpDir/$test_out"
	rlLog "Set the date back to it's original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"	
        rlRun "date"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlPhaseEnd


        rlPhaseStartTest "pki_subca_ag-requests-0015: Search certs with subject Name"
        local maxCount=1
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(&(|(x509Cert.subject=*CN=$pki_user_fullName,*)(x509Cert.subject=*CN=$pki_user_fullName))))"
        local statusInUse=''
        local cert_status='VALID'
        local subjectInUse='on'
        local eMail=''
        local commonName='$pki_user_fullName'
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=''
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertEquals "Verify No of records displayed is more than $maxCount" $maxCount $no_of_records
	rlAssertGrep "record.subject=\"$cert_subject\"" "$TmpDir/$test_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ag-requests-0016: Search certs with status REVOKED by Agent"
        local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certRevokedBy=$valid_agent_cert))"
        local statusInUse=''
        local cert_status=''
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy="$valid_agent_cert"
        local revokedByInUse='on'
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $no_of_records $maxCount
	rlAssertNotGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ag-requests-0017: Search certs with status REVOKED with reason unspecified"
        local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(x509cert.certRevoInfo=0))"
        local statusInUse=''
        local cert_status=''
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse='on'
        local revocationReason='0'
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $no_of_records $maxCount
	rlAssertNotGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ag-requests-0018: Search certs issued by valid agent"
        local maxCount=10
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certIssuedBy=$valid_agent_cert))"
        local statusInUse=''
        local cert_status=''
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse='on'
        local issuedBy="$valid_agent_cert"
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $no_of_records $maxCount
	rlAssertGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ag-requests-0019: Search certs with validity period of 1 day"
        local maxCount=1
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(x509cert.duration<=86400000))"
        local statusInUse=''
        local cert_status=''
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse='on'
        local validityOp='<='
        local count='1'
        local unit="86400000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxCount"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxCount"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $no_of_records $maxCount
	rlAssertGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-0020: Search certs with Basic Contraints"
        local maxCount=1
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(x509cert.BasicConstraints.isCA=on))"
        local statusInUse=''
        local cert_status=''
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse='on'
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertEquals "Verify No of records displayed is more than $maxCount" $maxCount $no_of_records
	rlAssertGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartSetup "Generate a profile with Netscape Extensions"
        local profile="caUserCert$RANDOM"
        local pki_user="pki_foo_bar$RANDOM"
        local pki_user_fullName="$pki_user User"
        local profilename="$profile Enrollment Profile"
        rlLog "Create Profile $profile"
        rlRun "python -m PkiLib.pkiprofilecli \
                --new user \
                --profileId $profile \
                --profilename \"$profilename\" \
                --netscapeextensions \"nsCertCritical,nsCertSSLClient,nsCertEmail\" \
                --outputfile $TmpDir/$profile\.xml"
        rlLog "Add Profile $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-add $TmpDir/$profile\.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlLog "Verify by creating a user cert using the profile"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$pki_user_fullName\" \
                subject_uid:$pki_user \
                subject_email:$pki_user@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$cert_out"
        rlAssertGrep "SSL Client" "$cert_out"
        rlAssertGrep "Secure Email" "$cert_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-requests-0021: Search certs of type SSLCLient"
        local maxCount=0
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(x509cert.nsExtension.SSLClient=on))"
        local statusInUse=''
        local cert_status=''
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedByInUse=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local profileInUse=''
        local profile=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local basicConstraintsInUse=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse='on'
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient='on'
        local SSLServer=''
        local maxResults='10'
        local timeLimit='5'
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&statusInUse=$statusInUse&status=$cert_status&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedByInUse=$revokedByInUse&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&profileInUse=$profileInUse&profile=$profile&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&basicConstraintsInUse=$basicConstraintsInUse&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/agent/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGreater "Verify No of records displayed is more than $maxCount" $no_of_records $maxCount
	rlAssertGrep "record.revokedOn=null" "$TmpDir/$test_out"
	rlAssertGrep "record.subject=\"$cert_subject\"" "$TmpDir/$test_out"
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
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Certificate,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}

