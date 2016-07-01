#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-ca-cert-request-submit
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mrniranjan@redhat.com>
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

run_pki-ca-cert-request-submit_tests()
{
	
	local cs_Type=$1
	local cs_Role=$2

	# Creating Temporary Directory for pki cert-show
        rlPhaseStartSetup "pki ca-cert-request-submit Temporary Directory"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="Secret123"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        rlPhaseEnd
	
	#local variables
	get_topo_stack $cs_Role $TmpDir/topo_file
	local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local invalid_serialNumber=$RANDOM
        local invalid_hex_serialNumber=0x$(echo "ibase=16;$invalid_serialNumber"|bc)
        local CA_agentV_user=$CA_INST\_agentV
        local CA_auditV_user=$CA_INST\_auditV
        local CA_operatorV_user=$CA_INST\_operatorV
        local CA_adminV_user=$CA_INST\_adminV
        local CA_agentR_user=$CA_INST\_agentR
        local CA_adminR_user=$CA_INST\_adminR
        local CA_adminE_user=$CA_INST\_adminE
        local CA_agentE_user=$CA_INST\_agentE
        local pkcs10_reqstatus
        local pkcs10_requestid
        local crmf_reqstatus
        local crmf_requestid
        local decimal_valid_serialNumber
        local rand=$RANDOM
        local cert_req_info="$TmpDir/cert_req_info.out"
        local target_host=$(eval echo \$${cs_Role})
        local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
	local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
	
	rlPhaseStartTest "pki_cert_cli-configtest: pki ca-cert-request-submit --help configuration test"
	rlRun "pki -h $target_host -p $target_port ca-cert-request-submit --help > $TmpDir/ca-cert-request-submit.out 2>&1" 0 "pki ca-cert-request-submit --help"
	rlAssertGrep "usage: ca-cert-request-submit <filename> \[OPTIONS...\]" "$TmpDir/ca-cert-request-submit.out"
	rlAssertGrep "    --help   Show help options" "$TmpDir/ca-cert-request-submit.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/ca-cert-request-submit.out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_submit-001: Submit anonymous pkcs10 request and verify by approving the request"
	local profile=caUserCert
	rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
		key_size:1024 subject_cn:\"Foo User1\" subject_uid:FooUser1 subject_email:FooUser1@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
	rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
		-c $TEMP_NSS_DB_PWD \
		cert-request-profile-show $profile \
		 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
	rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
	rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
	local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
	rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
	local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
	rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
	rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
	rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-002: Submit anonymous crmf request and verify by approving the request"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
		key_size:2048 subject_cn:\"Foo User2\" subject_uid:FooUser2 subject_email:FooUser2@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-crmf-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-crmf-approve-out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_submit-003: Test-1 Submit i18n characters request and verify by approving the request"
	local profile=caUserSMIMEcapCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@foobar.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-crmf-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-crmf-approve-out"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_ca_cert_request_submit-004: Test-2 Submit i18n characters request with Key Archival and verify by approving the request"
        local profile=caDualCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"Éric Têko\" subject_uid:Foobar subject_email:Foobar@example.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:true \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-crmf-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-crmf-approve-out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-005: Test-3 Submit i18n characters request and verify by approving the request"
        local profile=caTPSCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"éénentwintig dvidešimt.example.org\" subject_uid: subject_email:test@foobar.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD  cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-crmf-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-crmf-approve-out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-006: Test-4 Submit i18n characters request and verify by approving the request"
        local profile=caSignedLogCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"двадцять один тридцять.example.org\" subject_uid: subject_email:test@foobar.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-crmf-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-crmf-approve-out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-007: Test-5 Submit i18n characters request and verify by approving the request"
        local profile=caServerCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"kakskümmend üks.example.org\" subject_uid: subject_email:test@foobar.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD \
		cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-crmf-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-crmf-approve-out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_submit-008: Submit anonymous cert renewal request and very by approving the request" 
	local profile=caUserCert
	rlLog "Generate cert with validity period of 1 Day"
	rlRun "generate_modified_cert \
		validity_period:\"1 Day\" \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subjec_cn:\"Foo User3\" \
		uid:FooUser3 \
		email:FooUser3@example.org \
		ou:Foo_Example_IT \
		org:Foobar.Org \
		country:US \
		archive:false \
		host:$target_host \
		port:$target_port \
		profile:$profile \
		cert_db:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		admin_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info \
		expect_data:$exp" 
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)	
	rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
	local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
	rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
	rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $TmpDir/pki-ca-cert-request-submit.out" 0 "Submit renewal request"
	local REQUEST_ID=$(cat $TmpDir/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
	rlAssertGrep "Request ID: $REQUEST_ID" "$TmpDir/pki-ca-cert-request-submit.out"
	local REQUEST_SUBMIT_STATUS=$(cat $TmpDir/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
	rlAssertGrep "Type: renewal"  "$TmpDir/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TmpDir/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TmpDir/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"	
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-009: Submit a request using invalid xml file"
	local invalid_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	rlRun "echo $invalid_data > $TmpDir/$rand-cert-profile.xml"
	rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TmpDir/$rand-cert-profile.xml 2> $TmpDir/pki-ca-cert-request-submit.out" 255
	rlAssertGrep "Error: null" "$TmpDir/pki-ca-cert-request-submit.out"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_ca_cert_request_submit-0010: Submit request which doesn't satisfy constraints of profile"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:\"Foo User4\" subject_uid:FooUser4 subject_email:FooUser4@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile" 
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v \"\" $xml_profile_file"
        rlRun "pki -h $target_host -p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: rejected" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-0011: Submit pkcs10 request using valid agent cert and verify by approving the request"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:\"Foo User5\" subject_uid:FooUser5 subject_email:FooUser5@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request using $CA_agentV_user"
	local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-0012: Submit crmf request using Revoked agent cert"
	local profile=caDualCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"Foo User6\" subject_uid:FooUser6 subject_email:FooUser6@example.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US \
                archive:true cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentE_user\" \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 2> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 1,255 "Submit request using $CA_agentR_user"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-0013: Submit pkcs10 request using valid admin cert and verify by approving the request"
	local profile=caServerCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:fooserver1.fooBar.org subject_uid: subject_email: subject_ou:Foo_Example_IT \
                subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminV_user\" \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request using $CA_adminV_user"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-0014: Submit pkcs10 request using Revoked admin cert"
        local profile=caSignedLogCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:\"FooBar Log Signing Certificate\" subject_uid: subject_email: \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminE_user\" \
                -h $target_host \
		-p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 2> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 255 "Submit request using $CA_adminR_user"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-0015: Submit pkcs10 request using valid audit cert and verify by approving the request"
        local profile=caTPSCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:foo_TPS_server1.fooBar.org subject_uid: subject_email: \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_auditV_user\" \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request using $CA_auditV_user"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-0016: Submit pkcs10 request using valid operator cert and verify by approving the request"
        local profile=caServerCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:fooserver2.fooBar.org subject_uid: subject_email: subject_ou:Foo_Example_IT \
                subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_operatorV_user\" \
                -h $target_host \
		-p $target_port ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request using $CA_operatorV_user"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"

        rlPhaseStartTest "pki_ca_cert_request_submit-0017: Submit pkcs10 request using normal user without any privileges and verify by approving the request"
        local profile=caUserCert
        local pki_user="pki_user_$rand"
        local pki_user_fullName="Pki User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
		ca-user-add $pki_user \
                --fullName \"$pki_user_fullName\" \
                --password $pki_pwd" 0 "Create $pki_user User"
        rlLog "Generate cert for user $pki_user"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"$pki_user_fullName\" subject_uid:$pki_user \
                subject_email:$pki_user@example.org subject_ou: subject_o: subject_c: archive:false \
                req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $target_port \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $target_port \
                -n \"casigningcert\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"
	rlRun "pki -d $CERTDB_DIR \
                -n $CA_adminV_user \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -t ca user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn: subject_uid: subject_email: subject_ou:Foo_Example_IT \
                subject_org:FooBar.Org subject_country:US archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request using $pki_user_fullName"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-0018: Submit cert request using host URI parameter(http)"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:\"Foo User7\" subject_uid:FooUser7 subject_email:FooUser7@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-U http://$target_host:$target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_cert_request_submit-0019: Submit cert request using host URI parameter(https)"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:crmf algo:rsa \
                key_size:2048 subject_cn:\"Foo User8\" subject_uid:FooUser8 subject_email:FooUser8@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate crmf request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -U https://$target_host:$target_https_port \
                ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_submit-0020: submit cert request using valid user"
	local profile=caUserCert
	local pki_user="pki_Foouser_$rand"
	local pki_user_fullName="Pki FooUser $rand"
	local pki_pwd="Secret123"
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:1024 subject_cn:\"Foo User9\" subject_uid:FooUser9 subject_email:FooUser9@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
	rlRun "pki -d $CERTDB_DIR \
		-n \"$CA_adminV_user\" \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-user-add $pki_user \
		--fullName \"$pki_user_fullName\" \
		--password $pki_pwd" 0 "Create $pki_user User"
        rlRun "pki -d $CERTDB_DIR \
		-u $pki_user \
		-w $pki_pwd \
		-h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml \
		1> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 0 "Submit request for approval"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TEMP_NSS_DB/pki-ca-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-0021: submit cert request using in-valid user"
        local profile=caUserCert
        local pki_user="pki_invalid_user"
        local pki_pwd="Secret123"
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:1024 subject_cn:\"Foo User10\" subject_uid:FooUser10 subject_email:FooUser10@foobar.org \
		subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -d $CERTDB_DIR \
                -u $pki_user \
                -w $pki_pwd \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml \
		2> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 1,255 "Submit cert request for approval"
        rlAssertGrep "PKIException: Unauthorized" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-0022: Submit pkcs10 request using Expired admin cert"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:\"Foo User11\" subject_uid:FooUser11 subject_email:FooUser11@foobar.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n CA_adminE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminE_user\" \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml \
		2> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 255 "Submit request using $CA_adminE_user"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_submit-0023: Submit pkcs10 request using Expired agent cert"
        local profile=caUserCert
        rlRun "create_new_cert_request nss_db:$TEMP_NSS_DB nss_db_pwd:$TEMP_NSS_DB_PWD req_type:pkcs10 algo:rsa \
                key_size:2048 subject_cn:\"Foo User12\" subject_uid:FooUser12 subject_email:FooUser12@foobar.org \
                subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_country:US archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Generate pkcs10 request for $profile"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $target_port cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $profile xml with certificate request details"
        rlRun "generate_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n CA_agentE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentE_user\" \
                -h $target_host \
		-p $target_port \
		ca-cert-request-submit $TEMP_NSS_DB/$rand-profile.xml \
		2> $TEMP_NSS_DB/pki-ca-cert-request-submit.out" 255 "Submit request using $CA_agentE_user"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$TEMP_NSS_DB/pki-ca-cert-request-submit.out"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartCleanup "pki cert-show cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
generate_xml()
{
	cert_request_file=$1
	cert_subject_file=$2
	xml_profile_file=$3
	cert_profile=$4
	rlLog "cert_request_file=$cert_request_file"	
	rlLog "cert_subject_file=$cert_subject_file"
	rlLog "xml_profile_file=$xml_profile_file"
	rlLog "cert_profile=$cert_profile"

	local request_type=$(cat $cert_subject_file | grep RequestType: | cut -d: -f2)
	local subject_cn=$(cat $cert_subject_file | grep CN: | cut -d: -f2)
	local subject_uid=$(cat $cert_subject_file | grep UID: | cut -d: -f2)
	local subject_email=$(cat $cert_subject_file | grep Email: | cut -d: -f2)
	local subject_ou=$(cat $cert_subject_file | grep OU: | cut -d: -f2)
	local subject_org=$(cat $cert_subject_file | grep Org: | cut -d: -f2)
	local subject_c=$(cat $cert_subject_file | grep Country: | cut -d: -f2)


	if [ "$cert_profile" == "caUserCert" ]  || [ "$cert_profile" ==  "caUserSMIMEcapCert" ] || [ "$cert_profile" ==  "caDualCert" ];then
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v \"$subject_uid\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v \"$subject_ou\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v \"$subject_org\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v \"$subject_c\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
        fi

        if [ "$cert_profile" != "CaDualCert" ] && \
        [ "$cert_profile" != "caDirPinUserCert" ] && \
        [ "$cert_profile" != "caDirUserCert" ] && \
        [ "$cert_profile" != "caECDirUserCert" ] && \
        [ "$cert_profile" != "caAgentServerCert" ] && \
        [ "$cert_profile" != "caUserCert" ] &&
	[ "$cert_profile" != "caUserSMIMEcapCert" ]; then
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
        fi
}
