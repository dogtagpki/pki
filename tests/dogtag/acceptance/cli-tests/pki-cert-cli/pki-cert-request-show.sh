#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-cert-request-show
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

run_pki-cert-request-show-ca_tests()
{

	local cs_Type=$1
        local cs_Role=$2

	# Creating Temporary Directory for pki cert-show
        rlPhaseStartSetup "pki cert-request_show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd
	
	# Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local CA_agentV_user=$CA_INST\_agentV
        local CA_auditV_user=$CA_INST\_auditV
        local CA_operatorV_user=$CA_INST\_operatorV
        local CA_adminV_user=$CA_INST\_adminV
        local CA_agentR_user=$CA_INST\_agentR
        local CA_adminR_user=$CA_INST\_adminR
        local CA_adminE_user=$CA_INST\_adminE
        local CA_agentE_user=$CA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
	local invalid_requestid=$(cat /dev/urandom | tr -dc '0-9' | fold -w 10 | head -n 1)
	local junk_requestid=$(cat /dev/urandom | tr -dc 'a-bA-Z0-9' | fold -w 40 | head -n 1)
	local temp_cert_out="$TmpDir/cert-request.out"
	local hex_invalid_upp_reqid=$(echo "obase=16;$invalid_requestid"|bc)
	local hex_invalid_requestid=0x"${hex_invalid_upp_reqid,,}"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
	local temp_out="$TmpDir/cert-request-show.out"	
        local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$(eval echo \$${cs_Role})
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
	local profile=caUserCert


	# Config test of pki cert-request-show
	rlPhaseStartTest "pki_cert_cli-configtest: pki cert-request-show --help configuration test"
	rlRun "pki -h $target_host -p $target_port cert-request-show --help > $TmpDir/cert-show.out 2>&1" 0 "pki cert-request-show --help"
	rlAssertGrep "usage: cert-request-show <Request ID>" "$TmpDir/cert-show.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/cert-show.out"
	rlPhaseEnd

	# Create a Temporary NSS DB Directory and generate Certificate
	rlPhaseStartSetup "Generating temporary Cert to be used pki cert-show automation Tests"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:1024 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$tmp_new_user_profile \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info" 0 "Generate a pkcs10 Certificate"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
	local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
	local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlPhaseEnd

	# pki cert-request-show <valid requestId(decimal)
        rlPhaseStartTest "pki_cert_request_show-001: pki cert-request-show <valid requestid> should show certificate request details"
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: complete" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
	rlPhaseEnd

	# pki cert-request-show  <valid requestid(hexadecimal)>
	rlPhaseStartTest "pki_cert_request_show-002: pki cert-request-show <valid requestid> should show certificate request details"
	rlRun "pki -h $target_host -p $target_port cert-request-show $hex_valid_requestid > $temp_out" 0 "Executing pki cert-request-show $hex_valid_reqid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out" 
	rlAssertGrep "Request Status: complete" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
	rlPhaseEnd

	# pki cert-request-show <valid renewal_requestid>
	rlPhaseStartTest "pki_cert_request_show-003: pki cert-request-show should show request details of approved renewal requests"
	local profile=caUserCert
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Foo User1\" uid:FooUser1 email:FooUser1@example.org \
                ou:Foo_Example_IT org:Foobar.Org country:US archive:false host:$target_host port:$target_port \
                profile:$profile cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info expect_data:$exp"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $TmpDir/pki-cert-request-submit.out" 0 "Submit renewal request"
        local REQUEST_ID=$(cat $TmpDir/pki-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TmpDir/pki-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TmpDir/pki-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: renewal"  "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TmpDir/pki-cert-request-submit.out"
	rlRun "pki -h $target_host -p $target_port cert-request-show $REQUEST_ID > $temp_out" 0 "View a renewal request"
	rlAssertGrep "Certificate request \"$REQUEST_ID\"" "$temp_out"
        rlAssertGrep "Type: renewal" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
	rlAssertGrep "Approved certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlRun "pki -h $target_host -p $target_port cert-request-show $REQUEST_ID > $temp_out" 0 "View a renewal request"
        rlAssertGrep "Certificate request \"$REQUEST_ID\"" "$temp_out"
        rlAssertGrep "Type: renewal" "$temp_out"
	rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd

	# pki cert-request-show <valid renewal_requestid>
        rlPhaseStartTest "pki_cert_request_show-004: pki cert-request-show should show request details of rejected renewal requests"
        local profile=caUserCert
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Foo User2\" uid:FooUser2 email:FooUser2@example.org \
                ou:Foo_Example_IT org:Foobar.Org country:US archive:false host:$target_host port:$target_port \
                profile:$profile cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info expect_data:$exp"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^} 
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $TmpDir/pki-cert-request-submit.out" 0 "Submit renewal request"
        local REQUEST_ID=$(cat $TmpDir/pki-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TmpDir/pki-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TmpDir/pki-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: renewal"  "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TmpDir/pki-cert-request-submit.out"
        rlRun "pki -h $target_host -p $target_port cert-request-show $REQUEST_ID > $temp_out" 0 "View a renewal request"
        rlAssertGrep "Certificate request \"$REQUEST_ID\"" "$temp_out"
        rlAssertGrep "Type: renewal" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port ca-cert-request-review $REQUEST_ID \
                --action reject 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Rejected certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlRun "pki -h $target_host -p $target_port cert-request-show $REQUEST_ID > $temp_out" 0 "View a renewal request"
        rlAssertGrep "Certificate request \"$REQUEST_ID\"" "$temp_out"
        rlAssertGrep "Type: renewal" "$temp_out"
        rlAssertGrep "Request Status: rejected" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlPhaseEnd

	# pki cert-request-show <valid renewal_requestid>
        rlPhaseStartTest "pki_cert_request_show-005: pki cert-request-show should show request details of canceled renewal requests"
        local profile=caUserCert
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Foo User3\" uid:FooUser3 email:FooUser3@example.org \
                ou:Foo_Example_IT org:Foobar.Org country:US archive:false host:$target_host port:$target_port \
                profile:$profile cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info expect_data:$exp"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $TmpDir/pki-cert-request-submit.out" 0 "Submit renewal request"
        local REQUEST_ID=$(cat $TmpDir/pki-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TmpDir/pki-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TmpDir/pki-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: renewal"  "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TmpDir/pki-cert-request-submit.out"
        rlRun "pki -h $target_host -p $target_port cert-request-show $REQUEST_ID > $temp_out" 0 "View a renewal request"
        rlAssertGrep "Certificate request \"$REQUEST_ID\"" "$temp_out"
        rlAssertGrep "Type: renewal" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port ca-cert-request-review $REQUEST_ID \
                --action cancel 1> $TmpDir/$REQUEST_ID-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $REQUEST_ID"
        rlAssertGrep "Canceled certificate request $REQUEST_ID" "$TmpDir/$REQUEST_ID-pkcs10-approve-out"
        rlRun "pki -h $target_host -p $target_port cert-request-show $REQUEST_ID > $temp_out" 0 "View a renewal request"
        rlAssertGrep "Certificate request \"$REQUEST_ID\"" "$temp_out"
        rlAssertGrep "Type: renewal" "$temp_out"
        rlAssertGrep "Request Status: canceled" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlPhaseEnd
	
	# pki cert-request-show <invalid requestid(decimal)>
	rlPhaseStartTest "pki_cert_request_show-006: pki cert-request-show <invalid requestid(decimal)> should fail to display any request details"
	rlRun "pki -h $target_host -p $target_port cert-request-show $invalid_requestid 2> $temp_out" 1,255 "Executing pki cert-request-show $invalid_requestid"
	rlAssertGrep "RequestNotFoundException: Request ID $hex_invalid_requestid not found" "$temp_out"
	rlPhaseEnd
	
	#pki cert-request-show <invalid requestid(hexadecimal)>
	rlPhaseStartTest "pki_cert_request_show-007: pki cert-request-show <invalid requestid> should fail to display any request details"
	rlRun "pki -h $target_host -p $target_port cert-request-show $hex_invalid_requestid 2> $temp_out" 1,255 "Executing pki cert-request-show $hex_invalid_requestid"
	rlAssertGrep "RequestNotFoundException: Request ID $hex_invalid_requestid not found" "$temp_out"
	rlPhaseEnd
	
	#pki cert-request-show <junk chracters>
	rlPhaseStartTest "pki_cert_request_show-008: pki cert-request-show <Junk Characters(decimal)> should fail to display any request details"
	rlLog "Executing pki cert-request-show \"$junk_requestid~!@#$%^&*()_+|\""
	rlRun "pki -h $target_host -p $target_port cert-request-show \"$junk_requestid~\!@#$%^&*\(\)_+|\" 2> $temp_out" 1,255
	rlAssertGrep "Error: Invalid certificate request ID" "$temp_out"
	rlPhaseEnd

	#Pki cert-request-show Verify rejected Request Id is displayed correctly 
	rlPhaseStartTest "pki_cert_request_show-009: Verify rejected RequestId's status is displayed as Rejected"
	rlLog "Create Certificate request id"
        rlRun "create_new_cert_request \
                dir:$TEMP_NSS_DB \
                pass:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                size:2048 \
                cn:\"Idm User2\" \
                uid:IdmUser2 \
                email:IdmUser2@example.org \
                ou:\"IT Division\" \
                org:\"Example Org\" \
                country:\"US\" \
                archive:false \
                myreq:$TEMP_NSS_DB/$rand-request.pem \
                subj:$TEMP_NSS_DB/$rand-request-dn.txt" 0 "Create pkcs10 request"
	rlRun "submit_new_request dir:$TEMP_NSS_DB \
                pass:$TEMP_NSS_DB_PWD \
                cahost:$target_host \
                nickname: \
                protocol: \
                port:$target_port \
                url: \
                username: \
                userpwd: \
                profile:$profile \
                myreq:$TEMP_NSS_DB/$rand-request.pem \
                subj:$TEMP_NSS_DB/$rand-request-dn.txt \
                out:$TEMP_NSS_DB/$rand-request-result.txt" 0 "Submit request to CA"
        local ret_requestid=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        local ret_requestdn=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)	
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-review $ret_requestid \
		--action reject 1> $temp_cert_out" 0 "As $CA_AgentV_user Reject Certificate request"
	rlAssertGrep "Rejected certificate request $ret_requestid" "$temp_cert_out"
	rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid 1> $temp_out" 0 "Executing pki cert-request-show $ret_requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: rejected" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd

	#Pki cert-request-show Verify canceled Request Id is displayed correctly
	rlPhaseStartTest "pki_cert_request_show-0010: Verify canceled RequestId's status is displayed as canceled"
        rlRun "create_new_cert_request \
                dir:$TEMP_NSS_DB \
                pass:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                size:2048 \
                cn:\"Idm User3\" \
                uid:IdmUser3 \
                email:IdmUser3@example.org \
                ou:\"IT Division\" \
                org:\"Example Org\" \
                country:\"US\" \
                archive:false \
                myreq:$TEMP_NSS_DB/$rand-request.pem \
                subj:$TEMP_NSS_DB/$rand-request-dn.txt" 0 "Create pkcs10 request"
        rlRun "submit_new_request dir:$TEMP_NSS_DB \
                pass:$TEMP_NSS_DB_PWD \
                cahost:$target_host \
                nickname: \
                protocol: \
                port:$target_port \
                url: \
                username: \
                userpwd: \
                profile:$profile \
                myreq:$TEMP_NSS_DB/$rand-request.pem \
                subj:$TEMP_NSS_DB/$rand-request-dn.txt \
                out:$TEMP_NSS_DB/$rand-request-result.txt" 0 "Submit request to CA"
        local ret_requestid=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        local ret_requestdn=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)
	local ret_reqstatus=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_SUBMIT_STATUS" | cut -d":" -f2)
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-review $ret_requestid \
		--action cancel 1> $temp_cert_out" 0 "As $CA_agentV_user Cancel $ret_requestid"
	rlAssertGrep "Canceled certificate request $ret_requestid" "$temp_cert_out"
	rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid 1> $temp_out" 0 "Executing pki cert-request-show $ret_requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: canceled" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd
	
	#Pki cert-request-show Verify Updated Request Id is displayed as pending
	rlPhaseStartTest "pki_cert_request_show-0011: Verify updated RequestID's status is displayed as pending"
        rlRun "create_new_cert_request \
                dir:$TEMP_NSS_DB \
                pass:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                size:2048 \
                cn:\"Idm User4\" \
                uid:IdmUser4 \
                email:IdmUser4@example.org \
                ou:\"IT Division\" \
                org:\"Example Org\" \
                country:\"US\" \
                archive:false \
                myreq:$TEMP_NSS_DB/$rand-request.pem \
                subj:$TEMP_NSS_DB/$rand-request-dn.txt" 0 "Create pkcs10 request"
        rlRun "submit_new_request dir:$TEMP_NSS_DB \
                pass:$TEMP_NSS_DB_PWD \
                cahost:$target_host \
                nickname: \
                protocol: \
                port:$target_port \
                url: \
                username: \
                userpwd: \
                profile:$profile \
                myreq:$TEMP_NSS_DB/$rand-request.pem \
                subj:$TEMP_NSS_DB/$rand-request-dn.txt \
                out:$TEMP_NSS_DB/$rand-request-result.txt" 0 "Submit request to CA"
        local ret_requestid=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        local ret_requestdn=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)
        local ret_reqstatus=$(cat $TEMP_NSS_DB/$rand-request-result.txt | grep "REQUEST_SUBMIT_STATUS" | cut -d":" -f2)
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-review $ret_requestid \
		--action update 1> $temp_cert_out" 0 "As $CA_agentV_user update $ret_requestid"
	rlAssertGrep "Updated certificate request $ret_requestid" "$temp_cert_out"
	rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid 1> $temp_out" 0 "Executing pki cert-request-show $ret_requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: pending" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd
	
	#Pki cert-request-show Assign a Request Id & Verify request status is displayed as pending
	rlPhaseStartTest "pki_cert_request_show-0012: Assign a Pending Request & Verify Assigned RequestID's status is displayed as pending"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-review $ret_requestid \
		--action assign 1> $temp_cert_out" 0 "As $CA_agentV_user Assign $ret_requestid"
	rlAssertGrep "Assigned certificate request $ret_requestid" "$temp_cert_out"
	rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid 1> $temp_out" 0 "Executing pki cert-request-show $ret_requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: pending" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd

	#Pki cert-request-show Un-Assign a Pending Request & Verify request status is displayed as pending
	rlPhaseStartTest "pki_cert_request_show-0013: Un-Assign a Pending Request & Verify RequestID's status is displayed as pending"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-review $ret_requestid \
		--action unassign 1> $temp_cert_out" 0 "As $CA_agentV_user Un-Assign $ret_requestid"
	rlAssertGrep "Unassigned certificate request $ret_requestid" "$temp_cert_out"
	rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid 1> $temp_out" 0 "Executing pki cert-request-show $ret_requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: pending" "$temp_out" 
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd
	
	#pki cert-request-show Validate a pending request & verify request status is displayed as pending
	rlPhaseStartTest "pki_cert_request_show-0014: Validate a Pending Request & Verify Modified RequestID's status is displayed as pending"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		ca-cert-request-review $ret_requestid \
		--action validate 1> $temp_cert_out" 0 "As $CA_agentV_user Validate $ret_requestid"
	rlAssertGrep "Validated certificate request $ret_requestid" "$temp_cert_out"
	rlLog "Executing pki cert-request-show $ret_requestid"
	rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid 1> $temp_out" 0
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out"
	rlAssertGrep "Type: enrollment" "$temp_out"
	rlAssertGrep "Request Status: pending" "$temp_out"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
	rlPhaseEnd
	

	#pki cert-request-show Verify SerialNumber Displayed matches with SerialNumber assigned to Approved request
	rlPhaseStartTest "pki_cert_request_show-0015: Verify serialNumber displayed matches with serialNumber assigned to Approved request"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:1024 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$tmp_new_user_profile \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info" 0 "Generate a pkcs10 Certificate"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
	local valid_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $ret_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2) 
	local strip_hex_serialNo=$(echo $valid_serialNumber | cut -dx -f2)
        local conv_upp_sno=${strip_hex_serialNo^^}
	rlLog "Serial Number Displayed by pki cert-request-show $ret_requestid is $valid_serialNumber"
	rlLog "Get the serial Number assigned to the approve Request $ret_requestid using ldapsearch"
	local sno=$(ldapsearch -x -LLL 	-b "ou=certificateRepository,ou=ca,dc=pki-ca" \
		-D "$LDAP_ROOTDN" -w $LDAP_ROOTDNPWD -h $target_host -p 389 \
		"(metainfo=requestID:$ret_requestid)" cn | grep -v dn | awk -F ": " '{print $2}')
	local assigned_sno=$(echo "ibase=16;$conv_upp_sno"|bc)
	rlAssertEquals "Verify Displayed serialNumber Matches with serialNumber assigned to Approved Request" "$sno" "$assigned_sno"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0016: Test-1 pki cert-request-show should show Certificate Request Details with i18n characters"
	local profile=caUserCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"Örjan Äke\" \
		subject_uid:\"ÖrjanÄke\" \
                subject_email:test@example.org \
		subject_ou:Foo_Example_IT \
		subject_org:FooBar.Org \
		subject_c:US \
                archive:false \
		req_profile:$profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
              	cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info" 0 "Generate New certificate with Profile $profile"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0017: Test-2 pki cert-request-show should show Certificate Request Details with i18n characters"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"Éric Têko\" \
		subject_uid:Éric_Têko \
                subject_email:test@example.org \
		subject_ou:Foo_Example_IT \
		subject_org:FooBar.Org \
		subject_c:US \
                archive:false \
		req_profile:$profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
              	cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info" 0 "Generate New certificate with Profile $profile"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_request_show-0018: Test-3 pki cert-request-show should show Certificate Request Details with i18n characters"
	local profile=caUserSMIMEcapCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"éénentwintig dvidešimt\" \
		subject_uid:éénentwintig_dvidešimt \
                subject_email:test@example.org \
		subject_ou:Foo_Example_IT \
		subject_org:FooBar.Org \
		subject_c:US \
                archive:false \
		req_profile:$profile \
		target_host:$target_host \
		protocol: port:$target_port \
		cert_db_dir:$CERTDB_DIR \
              	cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info" 0 "Generate New certificate with Profile $profile"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0019: Test-4 pki cert-request-show should show Certificate Request Details with i18n characters"
	local profile=caServerCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"двадцять один тридцять Signed Log Certificate\" \
		subject_uid: \
                subject_email:test@example.org \
		subject_ou:Foo_Example_IT \
		subject_org:FooBar.Org \
		subject_c:US \
                archive:false \
		req_profile:$profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
              	cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info" 0 "Generate New certificate with Profile $profile"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0020: Test-5 pki cert-request-show should show Certificate Request Details with i18n characters"
	local profile=caUserCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"двадцять один тридцять\" \
		subject_uid:двадцять_один_тридцять \
                subject_email:test@example.org \
		subject_ou:Foo_Example_IT \
		subject_org:FooBar.Org \
		subject_c:US \
                archive:false \
		req_profile:$profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
              	cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info" 0 "Generate New certificate with Profile $profile"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0021: verify pki cert-request shows certificate request created for profile caUserSMIMEcapCert"
	local profile=caUserSMIMEcapCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Idm User1\" subject_uid:IdmUser1 \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_request_show-0022: verify pki cert-request shows certificate request created for profile caDualCert"
        local profile=caDualCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:crmf algo:rsa key_size:2048 subject_cn:\"Idm User2\" subject_uid:IdmUser2 \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:true req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd 
	
        rlPhaseStartTest "pki_cert_request_show-0023: verify pki cert-request shows certificate request created for profile caSignedLogCert"
        local profile=caSignedLogCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example Signed Log Certificate\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd 

        rlPhaseStartTest "pki_cert_request_show-0024: verify pki cert-request shows certificate request created for profile caServerCert"
        local profile=caServerCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"server1.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0025: verify pki cert-request shows certificate request created for profile caTPSCert"
        local profile=caTPSCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"TPS-server1.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0026: verify pki cert-request shows certificate request created for profile caSubsystemCert"
        local profile=caSubsystemCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example CA Subsystem\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0027: verify pki cert-request shows certificate request created for profile caOtherCert"
        local profile=caOtherCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"ExampleServer.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0028: verify pki cert-request shows certificate request created for profile caCACert"
        local profile=caCACert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example CA\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_cert_request_show-0029: verify pki cert-request shows certificate request created for profile caCrossSignedCACert"
        local profile=caCrossSignedCACert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example CA Cross Signed Certificate Manager\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0030: verify pki cert-request shows certificate request created for profile caRACert"
        local profile=caRACert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example RA Authority\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0031: verify pki cert-request shows certificate request created for profile caOCSPCert"
        local profile=caOCSPCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example OCSP Manager Signing Certificate\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0032: verify pki cert-request shows certificate request created for profile caStorageCert"
        local profile=caStorageCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example Data Recovery Manager Storage Certificate\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_show-0033: verify pki cert-request shows certificate request created for profile caTransportCert"
        local profile=caTransportCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Example Data Recovery Manager Transport Certificate\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local valid_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local ret_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local ret_requestid=$(cat $cert_info | grep cert_requestid | cut -d- -f2)
	local ret_reqstatus=$(cat $cert_info | grep cert_requeststatus | cut -d- -f2)
        local decimal_valid_serialNumber=$(cat $cert_info | grep decimal_valid_serialNumber | cut -d- -f2)
        local hex_valid_requestid=0x$(echo "obase=16;$ret_requestid"|bc)
        rlRun "pki -h $target_host -p $target_port cert-request-show $ret_requestid > $temp_out" 0 "command pki cert-request-show $requestid"
        rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out"
        rlAssertGrep "Type: enrollment" "$temp_out"
        rlAssertGrep "Request Status: complete" "$temp_out"
        rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out"
        rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out"
        rlPhaseEnd

	rlPhaseStartCleanup "pki cert-request-show cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
