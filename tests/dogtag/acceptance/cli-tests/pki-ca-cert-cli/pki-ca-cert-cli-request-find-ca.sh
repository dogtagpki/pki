#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-cert-cli
#   Description: PKI CA CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-ca-cert-request-find
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

run_pki-ca-cert-request-find-ca_tests()
{

        local cs_Type=$1
        local cs_Role=$2

	# Creating Temporary Directory for pki cert-request-find
        rlPhaseStartSetup "pki ca-cert-request-find Temporary Directory"
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
	local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
	local cert_info="$TmpDir/cert_info"
	local cert_request_find=$TmpDir/cert-request-find.out
	local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
	local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$(eval echo \$${cs_Role})
	local rand=$RANDOM
	local cert_request_submit="$TEMP_NSS_DB/pki-cert-request-submit.out"
	local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	local profile=caUserCert

	# Config test of pki ca-cert-request-find
	rlPhaseStartTest "pki_ca_cert_cli-configtest: pki ca-cert-request-find --help configuration test"
	rlRun "pki ca-cert-request-find --help > $cert_request_find" 0 "pki ca-cert-request-find --help"
	rlAssertGrep "usage: ca-cert-request-find \[OPTIONS...\]" "$cert_request_find"
	rlAssertGrep "    --help                      Show help options" "$cert_request_find"
	rlAssertGrep "    --maxResults <maxResults>   Maximum number of results" "$cert_request_find"
	rlAssertGrep "    --size <size>               Page size" "$cert_request_find"
	rlAssertGrep "    --start <start>             Page start" "$cert_request_find"
	rlAssertGrep "    --status <status>           Request status (pending, cancelled," "$cert_request_find"
	rlAssertGrep "                                rejected, complete, all)" "$cert_request_find"
	rlAssertGrep "    --timeout <maxTime>         Search timeout" "$cert_request_find"
	rlAssertGrep "    --type <type>               Request type (enrollment, renewal," "$cert_request_find"
	rlAssertGrep "                                revocation, all)" "$cert_request_find"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$cert_request_find"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-001: Search Enrollment requests with status pending"
	rlLog "Generate pkcs10 certificate request"
        rlRun "create_new_cert_request \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_password:$TEMP_NSS_DB_PWD \
		request_type:pkcs10 \
		request_algo:rsa \
		request_size:2048 \
		subject_cn: \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_organization: \
		subject_country: \
		subject_archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
	rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
	rlLog "Update $profile xml with certificate request details"
	rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
	rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
	rlAssertGrep "Request Status: pending" "$cert_request_submit"
	rlAssertGrep "Operation Result: success" "$cert_request_submit"
	local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Executing pki -d $CERTDB_DIR -n "$CA_agentV_user" -c $CERTDB_DIR_PASSWORD ca-cert-request-find --type enrollment --status pending --maxResults 1000"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n "$CA_agentV_user" \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--type enrollment \
		--status pending \
		--maxResults 1000 > $cert_request_find" 
	rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"
	rlAssertGrep "Request ID: $request_id" "$cert_request_find-grep"
	rlAssertGrep "Type: enrollment" "$cert_request_find-grep"
	rlAssertGrep "Request Status: pending" "$cert_request_find-grep"
	rlAssertNotGrep "Type: renewal" "$cert_request_find-grep"
	rlAssertNotGrep "Type: revocation" "$cert_request_find-grep"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-002: Search Enrollment requests with status canceled"
        rlLog "Generate pkcs10  certificate request"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_organization: \
                subject_country: \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
                --action cancel 1> $TmpDir/$request_id-pkcs10-approve-out" 0 "As $CA_agentV_user cancel certificate request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$TmpDir/$request_id-pkcs10-approve-out"	
	rlLog "Executing pki -d $CERTDB_DIR -n "$CA_agentV_user" -c $CERTDB_DIR_PASSWORD ca-cert-request-find --type enrollment --status canceled --maxResults 1000"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
		--status canceled \
                --size 1000 > $cert_request_find" 0 "search canceled requests"
	rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"
        rlAssertGrep "Request ID: $request_id" "$cert_request_find"
	rlAssertGrep "Type: enrollment"  "$cert_request_find"
	rlAssertGrep "Request Status: canceled" "$cert_request_find"
        rlAssertNotGrep "Type: renewal" "$cert_request_find"
        rlAssertNotGrep "Type: revocation" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-003: Search Enrollment requests with status rejected"
        rlLog "Generate pkcs10  certificate request"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_organization: \
                subject_country: \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
                --action reject 1> $TmpDir/$request_id-pkcs10-approve-out" 0 "As $CA_agentV_user cancel certificate request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$TmpDir/$request_id-pkcs10-approve-out"
        rlLog "Search Enrollment type requests with status rejected"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
		--status rejected \
                --size 1000 > $cert_request_find"
	rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"
        rlAssertGrep "Request ID: $request_id" "$cert_request_find"
        rlAssertGrep "Request Status: rejected" "$cert_request_find"
        rlAssertNotGrep "Type: renewal" "$cert_request_find"
        rlAssertNotGrep "Type: revocation" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-004: Search enrollment requests with status complete"
        rlLog "Generate pkcs10  certificate request"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_organization: \
                subject_country: \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
                --action approve 1> $TmpDir/$request_id-pkcs10-approve-out" 0 "As $CA_agentV_user cancel certificate request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$TmpDir/$request_id-pkcs10-approve-out"
        rlLog "Executing pki -d $CERTDB_DIR n "$CA_agentV_user" -c $CERTDB_DIR_PASSWORD ca-cert-request-find --type enrollment --status complete -size 1000"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
		--status complete \
                --size 1000 > $cert_request_find" 0 "Search pending requests of type Enrollment"
	rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"	
        rlAssertGrep "Request ID: $request_id" "$cert_request_find"
        rlAssertGrep "Request Status: complete" "$cert_request_find"
	rlAssertNotGrep "Request Status: canceled" "$cert_request_find"
	rlAssertNotGrep "Request Status: Rejected" "$cert_request_find"
        rlAssertNotGrep "Type: renewal" "$cert_request_find"
        rlAssertNotGrep "Type: revocation" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-005: Search requests of  type Enrollment with status all"
	rlLog "Executing pki -d $CERTDB_DIR -n "$CA_agentV_user" -c $CERTDB_DIR_PASSWORD \
		--type enrollment  --status all --size 1000"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--type enrollment \
		--status all \
		--size 1000 > $cert_request_find" 0 "Search Enrollment request type with all valid status"
	rlAssertGrep "Request Status: pending" "$cert_request_find"	
	rlAssertGrep "Request Status: complete" "$cert_request_find"
        rlAssertGrep "Request Status: canceled" "$cert_request_find"
        rlAssertGrep "Request Status: rejected" "$cert_request_find"
        rlAssertNotGrep "Type: renewal" "$cert_request_find"
        rlAssertNotGrep "Type: revocation" "$cert_request_find"
	rlAssertGrep "Type: enrollment" "$cert_request_find"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-006: search pending enrollment requests with --maxResults 1"
	local tmp_max_results=1
	rlLog "Executing pki -d $CERTDB_DIR \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find\
		--type enrollment \
		--status pending \
		--maxResults $tmp_max_results" 
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--type enrollment \
		--status pending \
		--maxResults $tmp_max_results > $cert_request_find" 0 "Return only  $tmp_max_results of pending enrollment requests"
	rlAssertGrep "Number of entries returned $tmp_max_results" "$cert_request_find"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-007: search enrollment requests with --start and --size"
        local tmp_max_results=3
        local tmp_start=$(expr $request_id - 3)
        rlLog "Executing pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find\
                --type enrollment \
                --size $tmp_max_results \
                --start $tmp_start"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
                --size $tmp_max_results \
                --start $tmp_start > $cert_request_find" \
                0 "search enrollment requests starting from $tmp_start and return only $tmp_max_results"
        local check_result=$(cat $cert_request_find | grep "Request ID" | head -n 1 | awk -F ": " '{print $2}')
        if [ "$check_result" -ne "$tmp_start" ]; then
                rlFail "Search request results have not started from $tmp_start Request ID"
        fi
                rlLog "Search request results have requests starting from $tmp_start"
	rlAssertGrep "Number of entries returned $tmp_max_results" "$cert_request_find"
        rlAssertGrep "Request ID: $tmp_start" "$cert_request_find"
        rlAssertNotGrep "Type: renewal" "$cert_request_find"
        rlAssertNotGrep "Type: revocation" "$cert_request_find"
        rlAssertGrep "Type: enrollment" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-008: Search renewal requests with status pending"
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn: \
		uid: \
		email: \
                ou: \
		org: \
		country: \
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
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $cert_request_submit" 0 "Submit renewal request"
        local renewal_request_id=$(cat $cert_request_submit  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $renewal_request_id" "$cert_request_submit"
        rlLog "Search pending requests"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type renewal \
                --status pending \
                --maxResults 1000 > $cert_request_find" 
        rlRun "cat $cert_request_find | grep \"Request ID: $renewal_request_id\" -A 4 > $cert_request_find-grep"
        rlAssertGrep "Request ID: $renewal_request_id" "$cert_request_find-grep"
	rlAssertGrep "Type: renewal" "$cert_request_find-grep"
	rlAssertGrep "Request Status: pending" "$cert_request_find-grep"
	rlAssertGrep "Operation Result: success" "$cert_request_find-grep"
        rlAssertNotGrep "Type: enrollment" "$cert_request_find-grep"
        rlAssertNotGrep "Type: revocation" "$cert_request_find-grep"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-009: Search renewal requests with status canceled"
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                uid: \
                email: \
                ou: \
                org: \
                country: \
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
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $cert_request_submit" 0 "Submit renewal request"
        local request_id=$(cat $cert_request_submit  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
                --action cancel 1> $TmpDir/$request_id-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $request_id"
	rlAssertGrep "Canceled certificate request $request_id" "$TmpDir/$request_id-pkcs10-approve-out"
        rlLog "Search cancelled requests"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type renewal \
                --status canceled \
                --size 1000 > $cert_request_find"
        rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"
        rlAssertGrep "Request ID: $request_id" "$cert_request_find-grep"
        rlAssertGrep "Type: renewal" "$cert_request_find-grep"
        rlAssertGrep "Request Status: canceled" "$cert_request_find-grep"
        rlAssertGrep "Operation Result: success" "$cert_request_find-grep"
        rlAssertNotGrep "Type: enrollment" "$cert_request_find-grep"
        rlAssertNotGrep "Type: revocation" "$cert_request_find-grep"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0010: Search renewal requests with status rejected"
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                uid: \
                email: \
                ou: \
                org: \
                country: \
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
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $cert_request_submit" 0 "Submit renewal request"
        local request_id=$(cat $cert_request_submit  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
                --action reject 1> $TmpDir/$request_id-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$TmpDir/$request_id-pkcs10-approve-out"
        rlLog "Search rejected requests"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type renewal \
                --status rejected \
                --size 1000 > $cert_request_find"
        rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"
        rlAssertGrep "Request ID: $request_id" "$cert_request_find-grep"
        rlAssertGrep "Type: renewal" "$cert_request_find-grep"
        rlAssertGrep "Request Status: rejected" "$cert_request_find-grep"
        rlAssertGrep "Operation Result: success" "$cert_request_find-grep"
        rlAssertNotGrep "Type: enrollment" "$cert_request_find-grep"
        rlAssertNotGrep "Type: revocation" "$cert_request_find-grep"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0011: Search renewal requests with status complete"
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                uid: \
                email: \
                ou: \
                org: \
                country: \
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
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $cert_request_submit" 0 "Submit renewal request"
        local request_id=$(cat $cert_request_submit  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
                --action approve 1> $TmpDir/$request_id-pkcs10-approve-out" 0 "As $CA_agentV_user Approve certificate request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$TmpDir/$request_id-pkcs10-approve-out"
        rlLog "Search Approved renewal requests"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type renewal \
                --status complete \
                --size 1000 > $cert_request_find"
        rlRun "cat $cert_request_find | grep \"Request ID: $request_id\" -A 4 > $cert_request_find-grep"
        rlAssertGrep "Request ID: $request_id" "$cert_request_find-grep"
        rlAssertGrep "Type: renewal" "$cert_request_find-grep"
        rlAssertGrep "Request Status: complete" "$cert_request_find-grep"
        rlAssertGrep "Operation Result: success" "$cert_request_find-grep"
        rlAssertNotGrep "Type: enrollment" "$cert_request_find-grep"
        rlAssertNotGrep "Type: revocation" "$cert_request_find-grep"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0012: Search renewal request with status all"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n "$CA_agentV_user" \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--type renewal \
		--status all \
		--size 1000 > $cert_request_find" 0 "Search renewal request type with all valid status"
        rlAssertGrep "Request Status: pending" "$cert_request_find"     
        rlAssertGrep "Request Status: complete" "$cert_request_find"
        rlAssertGrep "Request Status: canceled" "$cert_request_find"
        rlAssertGrep "Request Status: rejected" "$cert_request_find"
        rlAssertGrep "Type: renewal" "$cert_request_find"
        rlAssertNotGrep "Type: revocation" "$cert_request_find"
        rlAssertNotGrep "Type: enrollment" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0013: search pending renewal requests with --maxResults 1"
        local tmp_max_results=1
        local tmp_start=$renewal_request_id
        rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type renewal --status pending --maxResults $tmp_max_results"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--status pending \
                --type renewal \
                --maxResults $tmp_max_results > $cert_request_find" 0 "search pending renewal requests"
	rlAssertGrep "Number of entries returned $tmp_max_results" "$cert_request_find"
        rlAssertGrep "Type: renewal" "$cert_request_find"
	rlAssertNotGrep "Type: revocation" "$cert_request_find"
	rlAssertNotGrep "Type: enrollment" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0014: Search revocation requests with status complete"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn: \
		subject_uid: \
                subject_email: \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
                req_profile: \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_requestid=$(cat $cert_info  | grep cert_requestid | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason unspecified 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlLog "Search completed Revocation requests"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--type revocation \
		--status complete > $cert_request_find"
	rlAssertGrep "Type: revocation" "$cert_request_find"
	rlAssertGrep "Request Status: complete" "$cert_request_find"
	rlAssertGrep "Operation Result: success" "$cert_request_find"
	rlAssertNotGrep "Type: enrollment" "$cert_request_find"
	rlAssertNotGrep "Type: renewal" "$cert_request_find"
	rlAssertNotGrep "Request Status: pending" "$cert_request_find"
	rlAssertNotGrep "Request Status: rejected" "$cert_request_find"
	rlLog "PKI TICKET::https://fedorahosted.org/pki/ticket/1073"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0015:  Issue pki ca-cert-request-find  with --start 5 and verify search results are returned"
	local tmp_start_value=5
	rlLog "Executing pki ca-cert-request-find with --start <valid-input>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --start $tmp_start_value > $cert_request_find" 0
	local check_start=$(cat $cert_request_find | grep  "Request ID:" | head -n 1 | cut -d" " -f5)
	if [ "$tmp_start_value" -ne "$check_start" ]; then
		rlFail "search results do not start with Request ID: $tmp_start_value"
	fi
	rlAssertGrep "Request ID: $tmp_start_Value" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0016:  Issue pki ca-cert-request-find with --start 5 and --size 5 , which should return 5 results"
        local tmp_start_value=5
	local tmp_size_value=5
        rlLog "Executing pki ca-cert-request-find with --start <valid-input>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --start $tmp_start_value \
		--size $tmp_size_value > $cert_request_find" 0
        local check_start=$(cat $cert_request_find | grep  "Request ID:" | head -n 1 | cut -d" " -f5)
        if [ "$tmp_start_value" -ne "$check_start" ]; then
                rlFail "search results do not start with Request ID: $tmp_start_value"
        fi
        rlAssertGrep "Request ID: $tmp_start_value" "$cert_request_find"
	rlAssertGrep "Number of entries returned $tmp_size_value" "$cert_request_find"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0017:  Issue pki ca-cert-request-find  with --start <junk data> and verify no search results are returned"
	rlLog "Executing pki ca-cert-request-find with --start <junk value>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --start \"aaa\" > $cert_request_find 2>&1" 1,255
	rlAssertGrep "NumberFormatException: For input string: \"aaa\"" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0018:  Issue pki ca-cert-request-find  with --start <negative value> and verify no search results are returned"
	rlLog "Executing pki ca-cert-request-find with --start <negative value>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --start -1 > $cert_request_find" 
	rlAssertGrep "Number of entries returned 19" "$cert_request_find"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1070"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0019:  Issue pki ca-cert-request-find with --start <novalue> and verify command help is returned"
	rlLog "Executing pki ca-cert-request-find --start <no-value>"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --start > $cert_request_find 2>&1" 1,255
	rlAssertNotGrep "entries found" "$cert_request_find"
	rlAssertGrep "Error: Missing argument for option: start" "$cert_request_find"
        rlAssertGrep "usage: ca-cert-request-find \[OPTIONS...\]" "$cert_request_find"
        rlAssertGrep "    --help                      Show help options" "$cert_request_find"
        rlAssertGrep "    --maxResults <maxResults>   Maximum number of results" "$cert_request_find"
        rlAssertGrep "    --size <size>               Page size" "$cert_request_find"
        rlAssertGrep "    --start <start>             Page start" "$cert_request_find"
        rlAssertGrep "    --status <status>           Request status (pending, cancelled," "$cert_request_find"
        rlAssertGrep "                                rejected, complete, all)" "$cert_request_find"
        rlAssertGrep "    --timeout <maxTime>         Search timeout" "$cert_request_find"
        rlAssertGrep "    --type <type>               Request type (enrollment, renewal," "$cert_request_find"
        rlAssertGrep "                                revocation, all)" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0020:  Issue pki ca-cert-request-find with --start <Maximum integer value>"
        local tmp_large_number1="1234567890987654321123456789987654321123456789012327809893343437654321"
        rlLog "Executing pki ca-cert-request-find --start $tmp_large_number1"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n "$CA_agentV_user" \
		-c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--start $tmp_large_number1 > $cert_request_find 2>&1" 1,255
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_large_number1\"" "$cert_request_find"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1070"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0021:  Issue pki ca-cert-request-find with --maxResults 1 and verify search results are returned"
	rlLog "Executing pki ca-cert-request-find with --maxResults <valid-input>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
		--type enrollment \
		--status pending \
                --maxResults 1 > $cert_request_find" 
	rlAssertGrep "Number of entries returned 1" "$cert_request_find"
        rlPhaseEnd	
 
        rlPhaseStartTest "pki_ca_cert_request_find-0022:  Issue pki ca-cert-request-find with --maxResults <junk data> and verify no search results are returned"
	rlLog "Executing pki ca-cert-request-find with --maxResults <junk-data>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
                --status pending \
                --maxResults $tmp_junk_data > $cert_request_find 2>&1" 1,255
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$cert_request_find"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_find-0023:  Issue pki ca-cert-request-find with --maxResults <no value> and verify command help is returned"
	rlLog "Executing pki ca-cert-request-find with --maxResults <no-value>"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
                --status pending \
                --maxResults  > $cert_request_find 2>&1" 1,255
        rlAssertNotGrep "entries found" "$cert_request_find"
        rlAssertGrep "Error: Missing argument for option: maxResults" "$cert_request_find"
        rlAssertGrep "usage: ca-cert-request-find \[OPTIONS...\]" "$cert_request_find"
        rlAssertGrep "    --help                      Show help options" "$cert_request_find"
        rlAssertGrep "    --maxResults <maxResults>   Maximum number of results" "$cert_request_find"
        rlAssertGrep "    --size <size>               Page size" "$cert_request_find"
        rlAssertGrep "    --start <start>             Page start" "$cert_request_find"
        rlAssertGrep "    --status <status>           Request status (pending, cancelled," "$cert_request_find"
        rlAssertGrep "                                rejected, complete, all)" "$cert_request_find"
        rlAssertGrep "    --timeout <maxTime>         Search timeout" "$cert_request_find"
        rlAssertGrep "    --type <type>               Request type (enrollment, renewal," "$cert_request_find"
        rlAssertGrep "                                revocation, all)" "$cert_request_find"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0024:  Issue pki ca-cert-request-find with --maxResults <maximum Integer value>"
	local tmp_large_number1="12345678901234567890098765432113467908248614908601"
        rlLog "Executing pki ca-cert-request-find with --maxResults <no-value>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --type enrollment \
                --status pending \
                --maxResults $tmp_large_number1 > $cert_request_find 2>&1" 1,255
	rlAssertGrep "NumberFormatException: For input string: \"$tmp_large_number1\"" "$cert_request_find"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0025:  Issue pki ca-cert-request-find  with --size <valid-data> and verify search results are returned"
        local tmp_size_value=5
	rlLog "Executing pki ca-cert-request-find with --size <valid-input>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --size $tmp_size_value > $cert_request_find" 0
        rlAssertGrep "Number of entries returned $tmp_size_Value" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0026:  Issue pki ca-cert-request-find  with --size <junk data> and verify no search results are returned"
	rlLog "Executing pki ca-cert-request-find with --size <junk-data>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --size \"$tmp_junk_data\" > $cert_request_find 2>&1" 1,255
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0027:  Issue pki ca-cert-request-find  with --size <negative value> and verify no search results are returned"
	rlLog "Executing pki ca-cert-request-find with --size <negative value>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --size -1 > $cert_request_find"
        rlAssertGrep "Number of entries returned 19" "$cert_request_find"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1070"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0028:  Issue pki ca-cert-request-find with --size <novalue> and verify command help is returned"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --size > $cert_request_find 2>&1" 1,255
        rlAssertNotGrep "entries found" "$cert_request_find"
        rlAssertGrep "Error: Missing argument for option: size" "$cert_request_find"
        rlAssertGrep "usage: ca-cert-request-find \[OPTIONS...\]" "$cert_request_find"
        rlAssertGrep "    --help                      Show help options" "$cert_request_find"
        rlAssertGrep "    --maxResults <maxResults>   Maximum number of results" "$cert_request_find"
        rlAssertGrep "    --size <size>               Page size" "$cert_request_find"
        rlAssertGrep "    --start <start>             Page start" "$cert_request_find"
        rlAssertGrep "    --status <status>           Request status (pending, cancelled," "$cert_request_find"
        rlAssertGrep "                                rejected, complete, all)" "$cert_request_find"
        rlAssertGrep "    --timeout <maxTime>         Search timeout" "$cert_request_find"
        rlAssertGrep "    --type <type>               Request type (enrollment, renewal," "$cert_request_find"
        rlAssertGrep "                                revocation, all)" "$cert_request_find"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_cert_request_find-0029:  Issue pki ca-cert-request-find with --size <maximum Integer value>"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n "$CA_agentV_user" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-find \
                --size $tmp_large_number1 > $cert_request_find 2>&1" 1,255
	rlAssertGrep "NumberFormatException: For input string: \"$tmp_large_number1\"" "$cert_request_find"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0030:  Issue pki ca-cert-request-find using valid agent cert"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-request-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-request-find 1> $cert_request_find"
        rlAssertGrep "Number of entries returned 20" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0031:  Issue pki ca-cert-request-find using revoked Agent cert and verify no search results are returned"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentR_user\" cert-request-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_agentR_user\" cert-request-find >> $cert_request_find 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0032:  Issue pki ca-cert-request-find using valid admin cert and verify no search results are returned"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_adminV_user\" cert-request-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_adminV_user\" ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "ForbiddenException: Authorization Error" "$cert_request_find"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_cert_request_find-0033:  Issue pki ca-cert-request-find using Expired admin cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_adminE_user | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_adminE_user\" ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_find"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0034:  Issue pki ca-cert-request-find using Expired agent cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_agentE_user | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentE_user\" \
                ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_find"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_cert_request_find-0035:  Issue pki ca-cert-request-find using valid audit cert"
        rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_auditV_user\" cert-request-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_auditV_user\" ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "ForbiddenException: Authorization Error" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0036:  Issue pki ca-cert-request-find using valid operator cert"
        rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_operatorV_user\" cert-request-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_operatorV_user\" ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "ForbiddenException: Authorization Error" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0037:  Issue pki ca-cert-request-find using normal user cert(without any privileges)"
        local pki_user="idm1_user_$rand"
        local pki_user_fullName="Idm1 User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n \"$CA_adminV_user\" \
                -c $CERTDB_DIR_PASSWORD \
                ca-user-add $pki_user \
                --fullName \"$pki_user_fullName\" \
                --password $pki_pwd" 0 "Create $pki_user User"
        rlLog "Generate cert for user $pki_user"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa key_size:2048 \
                subject_cn:\"$pki_user_fullName\" \
                subject_uid:$pki_user \
                subject_email:$pki_user@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"casigningcert\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n $CA_adminV_user \
                -c $CERTDB_DIR_PASSWORD \
                -t ca user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
       rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
                ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "ForbiddenException: Authorization Error" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_find-0038:  Issue pki ca-cert-request-find using host URI parameter(https)"
	rlLog "Executing pki -d $CERTDB_DIR U https://$target_host:$target_https_port cert-request-find"
        rlRun "pki -d $CERTDB_DIR \
                -U https://$target_host:$target_https_port \
                ca-cert-request-find > $cert_request_find 2>&1" 1,255 
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0039:  Issue pki ca-cert-request-find using valid user"
        rlLog "Executing pki ca-cert-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $pki_user \
                -w $pki_pwd \
                ca-cert-request-find > $cert_request_find 2>&1" 1,255
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$cert_request_find"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_find-0040:  Issue pki ca-cert-request-find using in-valid user"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki ca-cert-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                ca-cert-request-find > $cert_request_find 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_find"
        rlPhaseEnd

	rlPhaseStartCleanup "pki ca-cert-request-find cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
