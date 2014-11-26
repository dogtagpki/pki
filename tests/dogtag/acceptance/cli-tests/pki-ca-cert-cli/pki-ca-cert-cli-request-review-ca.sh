#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-ca-cert-request-review
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

run_pki-ca-cert-request-review-ca_tests()
{

	local cs_Type=$1
        local cs_Role=$2

	# Creating Temporary Directory for pki ca-cert-request-review
        rlPhaseStartSetup "pki ca-cert-request-review Temporary Directory"
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
	local cert_request_review=$TmpDir/ca-cert-request-review.out
	local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
	local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$tmp_ca_host
        local rand=$RANDOM
	local i18n_array=("Örjan Äke:Örjan_Äke" "Éric Têko:Éric_Têko" "éénentwintig dvidešimt:éénentwintig_dvidešimt" "kakskümmend üks:kakskümmend_üks" "двадцять один тридцять:двадцять_один_тридцять")
	local cert_request_submit="$TEMP_NSS_DB/pki-cert-request-submit.out"
	local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
	local admin_cert_nickname="caadmincert"
	local profile=caUserCert
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123

	# Config test of pki ca-cert-request-review
	rlPhaseStartTest "pki_cert_cli-configtest: pki ca-cert-request-review --help configuration test"
	rlRun "pki ca-cert-request-review --help > $cert_request_review" 0 "pki cert-request-find --help"
	rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
	rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
	rlAssertGrep "                        assign, unassign" "$cert_request_review"
	rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
	rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
	rlAssertGrep "                        read in from file." "$cert_request_review"
	rlAssertGrep "    --help              Show help options" "$cert_request_review"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-001: Approve enrollment request using Agent Cert(CA_agentV)"
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
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve enrollment request $request_id"
	rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-002: Reject enrollment request using Agent Cert(CA_agentV)"
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
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-003: Cancel enrollment request using Agent Cert(CA_agentV)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "Cancel enrollment request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-004: Update enrollment request using Agent Cert(CA_agentV)"
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
	local tmp_validity_period="1 day"
	local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "Updated certificate request $request_id" "$expout"
	rlLog "Verify the updated xml by approving the request"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Approved certificate request $request_id" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-005: Validate enrollment request by modifying request to have validity date beyond the default validity period(using CA_agentV) "
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
        local tmp_validity_period="900 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Rejected - Validity Out of Range 899 days" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-006: Assign enrollment request to caadmin User(Member of Certificate Manager Agents)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign 1> $cert_request_review" 0 "Assign enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "Assigned certificate request $request_id" "$cert_request_review"
	rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin(Member of Certificate Manager Agents)"
	rlRun "ldapsearch -x -LLL -b \"dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
		-h $target_host -p 389 cn=$request_id requestOwner > $TmpDir/$request_id-ldap.out"
	rlAssertGrep "dn: cn=$request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$request_id-ldap.out"
	rlAssertGrep "caadmin" "$TmpDir/$request_id-ldap.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-007: Unassign enrollment request assigned to caadmin(Member of Certificate Manager Agents)"
	rlLog "Un assign $ret_requestid"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$admin_cert_nickname\" \
                ca-cert-request-review $request_id \
               --action unassign 1> $cert_request_review" 0 "Assign enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "Unassigned certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-008: Approve enrollment request containg i18n characters using Agent Cert(CA_agentV)"
        rlLog "Generate pkcs10 certificate request"
	for i in "${i18n_array[@]}"; do
	local i18n_cn=$(echo ${i}|cut -d: -f1)
	local i18n_uid=$(echo ${i}|cut -d: -f2)
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"$i18n_cn\" \
                subject_uid:$i18n_uid \
                subject_email:test@example.org \
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
        local i18n_request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $i18n_request_id \
               --action approve 1> $cert_request_review" 0 "Approve enrollment request $i18n_request_id"
        rlAssertGrep "Approved certificate request $i18n_request_id" "$cert_request_review"
	done
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-009: Approve renewal requests using Agent Cert(CA_agentV)"
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
	rlAssertGrep "Type: renewal" "$cert_request_submit"
	rlAssertGrep "Request Status: pending" "$cert_request_submit"
	rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action approve 1> $cert_request_review" 
        rlAssertGrep "Approved certificate request $renewal_request_id" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0010: Reject renewal requests using Agent Cert(CA_agentV)"
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $renewal_request_id \
               --action reject 1> $cert_request_review" 0 "Reject Cert renwal request $renewal_request_id"
        rlAssertGrep "Rejected certificate request $renewal_request_id" "$cert_request_review"	
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0011: Cancel renewal requests using Agent Cert(CA_agentV)"
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action cancel 1> $cert_request_review"
        rlAssertGrep "Canceled certificate request $renewal_request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0012: Update renewal request using Agent Cert(CA_agentV)"
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local tmp_validity_period="2 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$renewal_requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Updated certificate request $renewal_request_id" "$expout"
        rlLog "Verify the updated xml by approving the request"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Approved certificate request $renewal_request_id" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0013: Validate renewal request by modifying request to have validity date beyond the default validity period(using CA_agentV) "
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local renewal_request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        local tmp_validity_period="900 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$renewal_requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Rejected - Validity Out of Range 899 days" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0014: Assign renewal request to caadmin User(Member of Certificate Manager Agents)"
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
        local cert_serialNumbe =$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $cert_request_submit" 0 "Submit renewal request"
        local renewal_request_id=$(cat $cert_request_submit  | grep "Request ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action assign 1> $cert_request_review" 0 "Assign Enrollment request $renewal_request_id to $admin_cert_nickname"
        rlAssertGrep "Assigned certificate request $renewal_request_id" "$cert_request_review"
        rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin"
        rlRun "ldapsearch -x -LLL -b \"ou=ca,ou=requests,dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
                -h $target_host -p 389 cn=$renewal_request_id requestOwner > $TmpDir/$renewal_request_id-ldap.out"
        rlAssertGrep "dn: cn=$renewal_request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$renewal_request_id-ldap.out"
        rlAssertGrep "caadmin" "$TmpDir/$renewal_request_id-ldap.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0015: Unassign renewal request assigned using caadmin(Member of Certificate Manager Agents) "
        rlLog "Un assign $renewal_request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action unassign 1> $cert_request_review" 0 "Un-Assign renewal request $renewal_request_id using $admin_cert_nickname cert"
        rlAssertGrep "Unassigned certificate request $renewal_request_id" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0016: Approve renewal requests containg i18n characters using Agent Cert(CA_agentV)"
	rlLog "Generate cert with validity period of 1 Day"
        for i in "${i18n_array[@]}"; do
        local i18n_cn=$(echo ${i}|cut -d: -f1)
        local i18n_uid=$(echo ${i}|cut -d: -f2)
        rlLog "Generate cert with validity period of 1 Day"
        rlRun "generate_modified_cert validity_period:\"1 Day\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$i18n_cn\" \
                uid:$i18n_uid \
                email:test@example.org \
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action approve 1> $cert_request_review" 
        rlAssertGrep "Approved certificate request $renewal_request_id" "$cert_request_review"
	done
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0017: Approving a approved Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlLog "Approve already approved request $request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 1,255
	rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0018: Approving a approved Enrollment request should fail with --file option"
        rlLog "Approving an already approved Enrollment request $request_id with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0019: Approving a approved renewal request should fail"
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action approve 1> $cert_request_review" 
        rlAssertGrep "Approved certificate request $renewal_request_id" "$cert_request_review"
	rlLog "Approving an already approved Renewal request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action approve > $cert_request_review 2>&1" 255,1 "Approving already approved renewal request $renewal_request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0020: Approving a approved renewal request should fail with --file option"
        rlLog "Approving an already approved renewal request $renewal_request_id with --file option"
        rlLog "Execuing pki ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0021: Approving a non-existent request should fail"
        local request_id=$request_id$rand
	local hex_requestid=$(echo "obase=16;$request_id"|bc)
	local conv_lower_val=${hex_requestid,,}
	local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 1,255 "Approve non-existent request id $request_id"
	rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0022: Approving a non-existent request should fail with --file option"
        rlLog "Approving an non-existent Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_review-0023: Approving a rejected Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                 ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 1,255 "Approving rejected request $request_id"
	rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0024: Approving a canceled Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "Cancel Enrollment request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 1,255 "Approving rejected request $request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0025: Approving a canceled Enrollment request should fail with --file option"
        rlLog "Approving an rejected Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0026: Approving a rejected Enrollment request should fail with --file option"
	rlLog "Approving an rejected Enrollment request with --file option"
	rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0027: Verify pki ca-cert-request-review fails when no request-id is passed with --action approve"
	local request_id=" "
	rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
	rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0028: Approve an enrollment request as Valid Agent Cert assigned to caadmin user(Member of Certificate Manager Agents)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign 1> $cert_request_review" 0 "Assign enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "Assigned certificate request $request_id" "$cert_request_review"
        rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin"
        rlRun "ldapsearch -x -LLL -b \"ou=ca,ou=requests,dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
                -h $target_host -p 389 cn=$request_id requestOwner > $TmpDir/$request_id-ldap.out"
        rlAssertGrep "dn: cn=$request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$request_id-ldap.out"
        rlAssertGrep "caadmin" "$TmpDir/$request_id-ldap.out"
	rlLog "Approve $request_id as $CA_agentV_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 255,1 "Approve enrollment request $request_id"
        rlAssertGrep "PKIException: Problem approving request in CertRequestResource.assignRequest! Not authorized to do this operation." "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0029: Approve an unassigned Enrollment request"
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
        rlLog "Un assign $ret_requestid"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign 1> $cert_request_review" 0 "Assign enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "Unassigned certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve enrollment request $request_id"
	rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0030: Approve a validated Enrollment request"
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
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "Validated certificate request $request_id" "$expout"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve enrollment request $request_id"
	rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0031: Verify pki ca-cert-request-review fails when no request-id is passed with --file option"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --file $TmpDir/$rand\.xml  > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0032: Rejecting a approved Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 1,255 "Rejecting an approved request $request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0033: Rejecting a approved Enrollment request should fail with --file option"
        rlLog "Rejecting an approved Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"reject\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0034: Rejecting a approved renewal request should fail"
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action approve 1> $cert_request_review"
        rlAssertGrep "Approved certificate request $renewal_request_id" "$cert_request_review"
        rlLog "Rejecting already approved Renewal request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action reject > $cert_request_review 2>&1" 255,1 "Rejecting already approved renewal request $renewal_request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0035: Rejecting approved renewal request should fail with --file option"
        rlLog "Rejecting an already approved renewal request $renewal_request_id with --file option"
        rlLog "Execuing pki ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"reject\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0036: Rejecting an non-existent request should fail"
        local request_id=$request_id$rand
        local hex_requestid=$(echo "obase=16;$request_id"|bc)
        local conv_lower_val=${hex_requestid,,}
        local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 1,255 "Rejecting non-existent request id $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0037: Rejecting a non-existent request should fail with --file option"
        rlLog "Rejecting an non-existent Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"reject\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0038: Rejecting a rejected Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlLog "Rejecting already rejected request id $request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 1,255 "Rejecting $request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0039: Rejecting a rejected Enrollment request with --file option should fail"
        rlLog "Rejecting an already Rejected Enrollment request $request_id with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"reject\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0040: Verify pki ca-cert-request-review fails when no request-id is passed with --action reject"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0041: Cancelling a approved Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Cancel already approved request $request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0042: Cancelling a approved Enrollment request should fail with --file option"
        rlLog "Cancel an already approved Enrollment request $request_id with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"cancel\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0043: Canceling a approved renewal request should fail"
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
        rlAssertGrep "Type: renewal" "$cert_request_submit"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action approve 1> $cert_request_review"
        rlAssertGrep "Approved certificate request $renewal_request_id" "$cert_request_review"
        rlLog "Approving an already approved Renewal request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action cancel > $cert_request_review 2>&1" 255,1 "Canceling approved renewal request $renewal_request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0044: Canceling a approved renewal request should fail with --file option"
        rlLog "Canceling a approved renewal request $renewal_request_id with --file option"
        rlLog "Execuing pki ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $renewal_request_id --file $TEMP_NSS_DB/$renewal_request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"cancel\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0045: Cancel a non-existent request should fail"
        local request_id=$request_id$rand
        local hex_requestid=$(echo "obase=16;$request_id"|bc)
        local conv_lower_val=${hex_requestid,,}
        local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancel non-existent request id $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0046: cancelling a non-existent request should fail with --file option"
        rlLog "Cancellig an non-existent Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"cancel\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0047: Canceling a rejected Enrollment request should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancelling a rejected request $request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0048: Canceling a rejected Enrollment request should fail with --file option"
        rlLog "Cancelling an rejected Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"cancel\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0049: Verify pki ca-cert-request-review fails when no request-id is passed with --action cancel"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0050: update a approve Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
	 -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
	-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
	rlPhaseEnd


	rlPhaseStartTest "pki_ca_cert_request_review-0051: update a rejected Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
         -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
        -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"	
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0052: Updating a non-existent request should fail"
        local request_id=$request_id$rand
        local hex_requestid=$(echo "obase=16;$request_id"|bc)
        local conv_lower_val=${hex_requestid,,}
        local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action update > $cert_request_review 2>&1" 1,255 "Updating non-existent request id $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_cert_request_review-0053: Updating a non-existent request should fail with --file option"
        rlLog "Cancellig an non-existent Enrollment request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0054: Verify pki ca-cert-request-review fails when no request-id is passed with --action update"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action update > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0055: validate a approved Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        local tmp_validity_period="900 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertNotGrep "BadRequestException: Request Rejected - Validity Out of Range 899 days" "$expout"
	rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0056: validate a rejected Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        local tmp_validity_period="900 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertNotGrep "BadRequestException: Request Rejected - Validity Out of Range 899 days" "$expout"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$expout"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_ca_cert_request_review-0057: Validate a non-existent request should fail"
        local request_id=$request_id$rand
        local hex_requestid=$(echo "obase=16;$request_id"|bc)
        local conv_lower_val=${hex_requestid,,}
        local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action Validate > $cert_request_review 2>&1" 1,255 "Validating non-existent request id $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0058: Validating a non-existent request should fail with --file option"
        rlLog "Validating an non-existent Enrollment request with --file option"
        local tmp_validity_period="900 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
	rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0059: Verify pki ca-cert-request-review fails when no request-id is passed with --action validate"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action validate > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_cert_request_review-0060: Assign a approved Enrollment request to caadmin(Member of Certificate Manager Agents) user"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlLog "Assigning Approve certificate request $request_id to caadmin user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0061: assign a rejected Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlLog "Assigning rejected certificate request $request_id to $CA_agenV_user user"	
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign rejected Enrollment request $request_id to $CA_agentV_user"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0062: Assign a non-existent request should fail"
        local request_id=$request_id$rand
        local hex_requestid=$(echo "obase=16;$request_id"|bc)
        local conv_lower_val=${hex_requestid,,}
        local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assigning non-existent request id $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0063: Assigning a non-existent request should fail with --file option"
        rlLog "Assigning an non-existent request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"assign\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1 "Assign a non existant request id: $request_id"
	rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0064: Verify pki ca-cert-request-review fails when no request-id is passed with --action assign"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_cert_request_review-0065: Unassign a approved Enrollment request to caadmin(Member of Certificate Manager Agents) user"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign Enrollment request $request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0066: Unassign a rejected Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlLog "Unassign rejected certificate request $request_id to caadmin user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign rejected Enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0067: Unassign a non-existent request should fail"
        local request_id=$request_id$rand
        local hex_requestid=$(echo "obase=16;$request_id"|bc)
        local conv_lower_val=${hex_requestid,,}
        local tmp_request_id=0x$conv_lower_val
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassigning non-existent request id $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0069: Assigning a non-existent request should fail with --file option"
        rlLog "Unassigning a non-existent request with --file option"
        rlLog "Execuing pki ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$request_id-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"unassign\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1 "Assign a non existant request id: $request_id"
        rlAssertGrep "Request ID $tmp_request_id not found" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0069: Verify pki ca-cert-request-review fails when no request-id is passed with --action unassign"
        local request_id=" "
        rlLog "No request id is passed to pki ca-cert-request-review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "No request id is passed to pki ca-cert-request-review"
        rlAssertGrep "Error: Missing Certificate Request ID" "$cert_request_review"
        rlAssertGrep "usage: ca-cert-request-review <Request ID> \[OPTIONS...\]" "$cert_request_review"
        rlAssertGrep "    --action <action>   Action: approve, reject, cancel, update, validate," "$cert_request_review"
        rlAssertGrep "                        assign, unassign" "$cert_request_review"
        rlAssertGrep "    --file <filename>   File to store the retrieved certificate request." "$cert_request_review"
        rlAssertGrep "                        Action will be prompted for to run against request" "$cert_request_review"
        rlAssertGrep "                        read in from file." "$cert_request_review"
        rlAssertGrep "    --help              Show help options" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0070: Approve an Enrollment request using admin cert(CA_adminV)"
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
	rlLog "Approve Certificate request $request_id as $CA_adminV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 255 "Approve Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0071: Approve an Enrollment request using caadmin (Member of Certificate Manager Agents) cert"
        rlLog "Approve Certificate request $request_id as $admin_cert_nickname user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
	rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_cert_request_review-0072: Approve an Enrollment request using audit Cert(CA_auditV)"
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
        rlLog "Approve Certificate request $request_id as $CA_auditV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_auditV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 255 "Approve Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0073: Approve Enrollment request using operator Cert(CA_operatorV)"
        rlLog "Approve Certificate request $request_id as $CA_operatorV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_operatorV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 255 "Approve Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0074: Approve Enrollment request using Normal user cert who has no privileges"
        local profile=caUserCert
        local pki_user="idm1_user_$rand"
        local pki_user_fullName="Idm1 User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -n \"$CA_adminV_user\" \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
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
	rlLog "Approve $request_id as Normal user $pki_user"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 1,255 "Approve Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0075: Approve Enrollment request using valid user"
        rlLog "Approving $request_id using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -u $pki_user \
                -w $pki_pwd \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id --action approve > $cert_request_review 2>&1" 1,255 
	rlAssertGrep "Authentication method not allowed" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0076: Approve Enrollment request using in-valid user"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki cert-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id --action approve > $cert_request_review 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0077: Approve Enrollment request using Expired Admin cert"
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
	rlLog "Approve $request_id using $CA_adminE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminE_user\" ca-cert-request-review $request_id --action approve > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd 

	rlPhaseStartTest "pki_ca_cert_request_review-0078: Approve Enrollment request using Expired Agent cert"
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
        rlLog "Approve $request_id using $CA_agentE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentE_user\" \
		-h $target_host \
		-p $target_port ca-cert-request-review $request_id --action approve > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0079: Approve Enrollment request using Revoked agent cert"
	rlLog "Approve $request_id as Normal user $CA_adminR_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminR_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve > $cert_request_review 2>&1" 255 "Approve Enrollment request $request_id"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0080: Issue pki ca-cert-request-review using host URI parameter(https) and approve the request"
        rlRun "pki -d $CERTDB_DIR \
		-U  https://$target_host:$target_https_port \
		-c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlPhaseEnd


	rlPhaseStartTest "pki_ca_cert_request_review-0081: Reject an Enrollment request using admin cert(CA_adminV)"
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
	rlLog "Reject Enrollment request $request_id using $CA_adminV_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 1,255 "Reject Enrollment request $request_id"
	rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0082: Reject an Enrollment request using caadmin(Member of Certificate Manager Agents) cert"
        rlLog "Reject Enrollment request $request_id as $admin_cert_nickname user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
	rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0083: Reject an Enrollment request using audit Cert(CA_auditV)"
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
        rlLog "Reject Certificate request $request_id as $CA_auditV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_auditV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 255 "Reject Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0084: Reject Enrollment request using operator Cert(CA_operatorV)"
        rlLog "Reject Certificate request $request_id as $CA_operatorV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_operatorV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 255 "Reject Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0085: Reject Enrollment request using Normal user cert who has no privileges"
	rlLog "Reject $request_id as Normal user $pki_user"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 1,255 "Reject Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0086: Reject Enrollment request using valid user"
        rlLog "Rejecting $request_id using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $pki_user \
                -w $pki_pwd \
                ca-cert-request-review $request_id --action reject > $cert_request_review 2>&1" 1,255 
	rlAssertGrep "Authentication method not allowed" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0087: Reject Enrollment request using in-valid user"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Rejecting $request_id using $invalid_pki_user who does not exist"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                ca-cert-request-review $request_id --action reject > $cert_request_review 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0088: Reject Enrollment request using Expired Admin cert"
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
	rlLog "Reject $request_id using $CA_adminE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminE_user\" ca-cert-request-review $request_id \
		--action reject > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd 

	rlPhaseStartTest "pki_ca_cert_request_review-0089: Reject Enrollment request using Expired Agent cert"
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
        rlLog "Rejecting $request_id using $CA_agentE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentE_user\" ca-cert-request-review $request_id \
		--action reject> $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0090: Reject Enrollment request using Revoked agent cert"
	rlLog "Reject $request_id as Normal user $CA_adminR_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminR_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject > $cert_request_review 2>&1" 255 "Reject Enrollment request $request_id"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0091: Issue pki ca-cert-request-review using host URI parameter(https) and reject the request"
        rlRun "pki -d $CERTDB_DIR \
		-U  https://$target_host:$target_https_port \
		-c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action reject 1> $cert_request_review" 0 "Rejecting Enrollment request $request_id"
        rlAssertGrep "Rejected certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0092: Cancel Enrollment request using Admin Cert(CA_adminV)"
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
	rlLog "Cancel $request_id using $CA_adminV_user cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancel Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_review-0093: Cancel Enrollment request using Admin Cert(caadmin) having agent privileges"
	rlLog "Cancel $request_id using caadmin Cert having agent privileges"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "Cancel Enrollment request $request_id using caadmin having agent privileges"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0094: Cancel Enrollment request using Audit Cert(CA_auditV)"
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
        rlLog "Cancel $request_id using $CA_auditV_user cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_auditV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancel Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0095: Cancel Enrollment request using Operator Cert(CA_operatorV)"
        rlLog "Cancel $request_id using $CA_operatorV_user cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_operatorV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancel Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0096: Cancel Enrollment request using Normal user cert who has no privileges"
	rlLog "Cancel $request_id as Normal user $pki_user cert"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancel Enrollment request $request_id"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0097: Cancel Enrollment request using valid user"
        rlLog "Cancel $request_id using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $pki_user \
                -w $pki_pwd \
                ca-cert-request-review $request_id \
		--action cancel > $cert_request_review 2>&1" 1,255 "Cancel $request_id using $pki_user cert"
	rlAssertGrep "Authentication method not allowed" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0098: Cancel Enrollment request using in-valid user"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Cancel $request_id using invalid user $invalid_pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd ca-cert-request-review $request_id \
		--action cancel > $cert_request_review 2>&1" 1,255 "Cancel $request_id using invalid user"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0099: Cancel Enrollment request using Expired Admin cert"
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
	rlLog "Cancel $request_id using $CA_adminE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminE_user\" ca-cert-request-review $request_id --action cancel > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd 

	rlPhaseStartTest "pki_ca_cert_request_review-0100: Cancel Enrollment request using Expired Agent cert"
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
        rlLog "Cancel $request_id using $CA_agentE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentE_user\" ca-cert-request-review $request_id --action cancel > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0101: Cancel Enrollment request using Revoked agent cert"
	rlLog "Cancel $request_id as Normal user $CA_adminR_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminR_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 255 "Approve Enrollment request $request_id"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0102: Issue pki ca-cert-request-review using host URI parameter(https) and approve the request"
	rlLog "Canceling $request_id by connecting to CA using https port $https_port"
        rlRun "pki -d $CERTDB_DIR \
		-U  https://$target_host:$target_https_port \
		-c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "cancel Enrollment request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0103: Update Enrollment request using Admin Cert(CA_admiV)"
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
	rlLog "Update Enrollment request using $CA_adminV_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0104: Update Enrollment request using caadmin(Member of Certificate Manager Agents) cert"
	rlLog "Update Enrollment request using $admin_cert_nickname cert"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$admin_cert_nickname\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Updated certificate request $request_id" "$expout"
        rlLog "Verify the updated xml by approving the request"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Approved certificate request $request_id" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0105: Update Enrollment request using Audit Cert(CA_auditV)"
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
        rlLog "Update Enrollment request using $CA_auditV_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_auditV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0106: Update Enrollment request using operator Cert(CA_operatorV)"
        rlLog "Update Enrollment request $request_id using $CA_operatorV_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_operatorV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_review-0107: Update Enrollment request using Normal user cert with no privileges"
	rlLog "Update Enrollment request $request_id using $pki_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $TEMP_NSS_DB -h $target_host -p $target_port -n \"$pki_user\" \
                -c $TEMP_NSS_DB_PWD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0108: Update Enrollment request using valid user"
        rlLog "Update Enrollment request $request_id using $pki_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -u $pki_user \
                -w $pki_pwd ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authentication method not allowed" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0109: Update Enrollment request using in-valid user"
        rlLog "Update Enrollment request $request_id using $invalid_pki_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -u $invalid_pki_user \
                -w $invalid_pki_user_pwd ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "PKIException: Unauthorized" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0110: Update Enrollment request using Expired Agent cert"
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
        rlLog "Update $request_id using $CA_agentE_user"
	local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentE_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "ProcessingException: Unable to invoke request" "$expout"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0111: Update Enrollment request using Expired Admin cert"
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
        rlLog "Update $request_id using $CA_adminE_user"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminE_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "ProcessingException: Unable to invoke request" "$expout"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0112: Update Enrollment request using Revoked agent cert"
	rlLog "Update $request_id as Normal user $CA_adminR_user"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminR_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
	rlAssertGrep "PKIException: Unauthorized" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0113: Issue pki ca-cert-request-review using host URI parameter(https) and update the request"
	rlLog "Update $request_id by connecting to CA using https port $https_port"
        local tmp_validity_period="1 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -U https://$target_host:$target_https_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"update\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Updated certificate request $request_id" "$expout"
        rlLog "Verify the updated xml by approving the request"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -U https://$target_host:$target_https_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"approve\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Approved certificate request $request_id" "$expout"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0114: Validate Enrollment request using Admin Cert(CA_adminV) "
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
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
	rlLog "Validate $request_id using $CA_adminV_user"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0115: Validate Enrollment request using caadmin(Member of Certificate Manager Agents) cert"
	rlLog "Validate $request_id using $admin_cert_nickname"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$admin_cert_nickname\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Rejected - Validity Out of Range 899 days" "$expout"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0116: Validate Enrollment request using Audit Cert(CA_auditV) "
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
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        rlLog "Validate $request_id using $CA_auditV_user"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_auditV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_ca_cert_request_review-0117: Validate Enrollment request using Operator Cert(CA_operatorV)"
        rlLog "Validate $request_id using $CA_operatorV_user"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_operatorV_user\" \
                -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0118: Validate Enrollment request using normal user cert with no privileges"
        rlLog "Validate $request_id using $pki_user"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $TEMP_NSS_DB -h $target_host -p $target_port -n \"$pki_user\" \
                -c $TEMP_NSS_DB_PWD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authorization Error" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0119: Validate Enrollment request using valid user"
        rlLog "Validate $request_id using $pki_user"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -u $pki_user \
                -w $pki_pwd  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "Authentication method not allowed" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0120: Validate Enrollment request using In-valid user"
	local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Validate $request_id using $invalid_pki_user"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -u $invalid_pki_user \
                -w $invalid_pki_user_pwd  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "PKIException: Unauthorized" "$expout"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_cert_request_review-0121: Validate Enrollment request using Expired admin Cert"
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
        rlLog "Validate $request_id using $CA_adminE_user"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminE_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "ProcessingException: Unable to invoke request" "$expout"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0122: Validate Enrollment request using expired agent Cert"
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
        rlLog "Validate $request_id using $CA_agentE_user"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentE_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
        rlAssertGrep "ProcessingException: Unable to invoke request" "$expout"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0123: Validate Enrollment request using Revoked agent cert"
	rlLog "Update $request_id as Normal user $CA_adminR_user"
        local tmp_validity_period="900 day"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminR_user\" \
                -c $CERTDB_DIR_PASSWORD ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
                -v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 1
	rlAssertGrep "PKIException: Unauthorized" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0124: Issue pki ca-cert-request-review using host URI parameter(https) and validate the request"
	rlLog "Update $request_id by connecting to CA using https port $https_port"
        local tmp_validity_period="900 days"
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -U https://$target_host:$target_https_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" \
		-v \\\"$tmp_updated_date 00:00:10\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "BadRequestException: Request Rejected - Validity Out of Range 899 days" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0125: Assign Enrollment request using Admin Cert(CA_adminV)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$CA_adminV_user\" \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $CA_adminV_user"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0126: Assign an Enrollment request to CA_agentV user"
	rlLog "Assign Enrollment request as $CA_agentV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
               --action assign 1> $cert_request_review" 0 "Assign Enrollment request $request_id to $CA_agentV_user"
        rlAssertGrep "Assigned certificate request $request_id" "$cert_request_review"
        rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin"
        rlRun "ldapsearch -x -LLL -b \"ou=ca,ou=requests,dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
                -h $target_host -p 389 cn=$request_id requestOwner > $TmpDir/$request_id-ldap.out"
        rlAssertGrep "dn: cn=$request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$request_id-ldap.out"
        rlAssertGrep "$CA_agentV_user" "$TmpDir/$request_id-ldap.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0127: Assign an Enrollment request using Audit Cert(CA_auditV)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_auditV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $CA_auditV_user"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0128: Assign Enrollment request using operator cert(CA_operatorV)"
	rlLog "Assign Enrollment request using $CA_operatorV_user cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_OperatorV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $CA_operatorV_user"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_review-0129: Assign Enrollment request using normal user cert with no privileges"
        rlLog "Assign Enrollment request using $pki_user cert"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $pki_user"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0130: Assign Enrollment request using valid user"
        rlLog "Assign Enrollment request using $pki_user"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -u $pki_user \
                -w $pki_pwd \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $pki_user"
        rlAssertGrep "Authentication method not allowed" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0131: Assign Enrollment request using in-valid user"
        rlLog "Assign Enrollment request using $invalid_pki_user"
        rlRun "pki -d $TEMP_NSS_DB \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $request_id to $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0132: Assign Enrollment request using Expired Admin cert"
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
	rlLog "Assign $request_id using $CA_adminE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminE_user\" ca-cert-request-review $request_id \
		--action assign > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd 

	rlPhaseStartTest "pki_ca_cert_request_review-0133: Assign Enrollment request using Expired Agent cert"
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
        rlLog "Assign $request_id using $CA_agentE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentE_user\" ca-cert-request-review $request_id \
		--action assign > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0134: Assign Enrollment request using Revoked agent cert"
	rlLog "Assign $request_id as Normal user $CA_adminR_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminR_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign > $cert_request_review 2>&1" 255 "Assign Enrollment request $request_id"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0135: Issue pki ca-cert-request-review using host URI parameter(https) and assign the request"
        rlRun "pki -d $CERTDB_DIR \
		-U  https://$target_host:$target_https_port \
		-c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
               --action assign 1> $cert_request_review" 0 "Assign Enrollment request $request_id to $CA_agentV_user"
        rlAssertGrep "Assigned certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0136: Unassign Enrollment request using Admin Cert(CA_adminV)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign Enrollment request $request_id to $CA_adminV_user"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0137: Unassign an Enrollment request to CA_agentV user"
	rlLog "Unassign Enrollment request as $CA_agentV_user user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign 1> $cert_request_review" 0 "Unassign Enrollment request $request_id to $CA_agentV_user"
        rlAssertGrep "Unassigned certificate request $request_id" "$cert_request_review"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_cert_request_review-0138: Unassign an Enrollment request using Audit Cert(CA_auditV)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_auditV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign Enrollment request $request_id to $CA_auditV_user"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0139: Unassign Enrollment request using operator cert(CA_operatorV)"
	rlLog "Unassign Enrollment request using $CA_operatorV_user cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_OperatorV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign Enrollment request $request_id"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_request_review-0140: Unassign Enrollment request using normal user cert with no privileges"
        rlLog "Unassign Enrollment request using $pki_user cert"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign Enrollment request $request_id as $pki_user"
        rlAssertGrep "Authorization Error" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0141: Unassign Enrollment request using valid user"
        rlLog "Unassign Enrollment request using $pki_user"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -u $pki_user \
                -w $pki_pwd \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unssign Enrollment request $request_id as $pki_user"
        rlAssertGrep "Authentication method not allowed" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0142: Unassign Enrollment request using in-valid user"
        rlLog "Unassign Enrollment request using $invalid_pki_user"
        rlRun "pki -d $TEMP_NSS_DB \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 1,255 "Unassign Enrollment request $request_id as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0143: Unassign Enrollment request using Expired Admin cert"
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
	rlLog "Unassign $request_id using $CA_adminE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminE_user\" ca-cert-request-review $request_id \
		--action unassign > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd 

	rlPhaseStartTest "pki_ca_cert_request_review-0144: Unassign Enrollment request using Expired Agent cert"
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
        rlLog "Unassign $request_id using $CA_agentE_user"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentE_user\" ca-cert-request-review $request_id \
		--action unassign > $cert_request_review 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_review"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0145: Unassign Enrollment request using Revoked agent cert"
	rlLog "Unassign $request_id as Normal user $CA_adminR_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$CA_adminR_user\" \
                ca-cert-request-review $request_id \
               --action unassign > $cert_request_review 2>&1" 255 "Unassign Enrollment request $request_id"
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0146: Issue pki ca-cert-request-review using host URI parameter(https) and unassign the request"
        rlRun "pki -d $CERTDB_DIR \
		-U  https://$target_host:$target_https_port \
		-c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $request_id \
               --action unassign 1> $cert_request_review" 0 "Unassign Enrollment request $request_id to $CA_agentV_user"
        rlAssertGrep "Unassigned certificate request $request_id" "$cert_request_review"
	rlPhaseEnd


	rlPhaseStartTest "pki_cert_Request_review-0147: Approve Enrollment request from caDualCert profile"
	local tmp_profile=caDualCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:crmf \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM Test1\" \
                subject_uid:IDMTest1 \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:true \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
	rlLog "Verify Certificate has Key Encipherment extension added"
	rlLog "request_id = $request_id"
	local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
	rlLog "cert_serialNumber=$cert_serialNumber"
	rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Critical: yes\" > $TmpDir/cert-show.out "
	rlLog "Verify only Key Encipherment extension is only added"
	rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
	rlAssertNotGrep "Digital Signature" "$TmpDir/cert-show.out"
	rlAssertNotGrep "Non Repudiation" "$TmpDir/cert-show.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0148: Approve Enrollment request from caUserSMIMEcapCert profile"
        local tmp_profile=caUserSMIMEcapCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:crmf \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid:IDM-$tmp_profile \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 14 \"Critical: yes\" > $TmpDir/cert-show.out "
        rlLog "Verify only Key Encipherment extension is only added"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
	rlAssertGrep "Identifier: 1.2.840.113549.1.9.15" "$TmpDir/cert-show.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0149: Approve Enrollment request from AdminCert profile"
        local tmp_profile=AdminCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou: \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $tmp_profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 14 \"Critical: yes\" > $TmpDir/cert-show.out "
        rlLog "Verify only Key Encipherment extension is only added"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
	rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0150: Approve Enrollment request from caSignedLogCert profile"
        local tmp_profile=caSignedLogCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out "
        rlLog "Verify Digital Signature and Non-Encipherment extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertNotGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertNotGrep "Data Encipherment" "$TmpDir/cert-show.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_Request_review-0151: Approve Enrollment request from caTPSCert profile"
        local tmp_profile=caTPSCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
	rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
	rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
	rlLog "Verify Extended Key Usage extensions are added"
	rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
	rlAssertGrep "1.3.6.1.5.5.7.3.1" "$TmpDir/cert-show.out"
	rlAssertGrep "1.3.6.1.5.5.7.3.2" "$TmpDir/cert-show.out"
	rlAssertGrep "1.3.6.1.5.5.7.3.4" "$TmpDir/cert-show.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0152: Approve Enrollment request from caServerCert profile"
        local tmp_profile=caServerCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:$tmp_profile-$rand.foobar.org \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlLog "Verify Extended Key Usage extensions are added"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
        rlAssertGrep "1.3.6.1.5.5.7.3.1" "$TmpDir/cert-show.out"
        rlAssertGrep "1.3.6.1.5.5.7.3.2" "$TmpDir/cert-show.out"
        rlAssertNotGrep "1.3.6.1.5.5.7.3.4" "$TmpDir/cert-show.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0153: Approve Enrollment request from caSubsystemCert profile"
        local tmp_profile=caSubsystemCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlLog "Verify Extended Key Usage extensions are added"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
        rlAssertGrep "1.3.6.1.5.5.7.3.2" "$TmpDir/cert-show.out"
        rlAssertNotGrep "1.3.6.1.5.5.7.3.4" "$TmpDir/cert-show.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0154: Approve Enrollment request from caOtherCert profile"
        local tmp_profile=caOtherCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlLog "Verify Extended Key Usage extensions are added"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
        rlAssertGrep "1.3.6.1.5.5.7.3.2" "$TmpDir/cert-show.out"
        rlAssertNotGrep "1.3.6.1.5.5.7.3.4" "$TmpDir/cert-show.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0155: Approve Enrollment request from caCACert profile"
        local tmp_profile=caCACert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 15 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertNotGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertNotGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Key CertSign" "$TmpDir/cert-show.out"
        rlAssertGrep "Crl Sign" "$TmpDir/cert-show.out"
	rlAssertGrep "Is CA: yes" "$TmpDir/cert-show.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0156: Approve Enrollment request from caCrossSignedCACert profile"
        local tmp_profile=caCrossSignedCACert
        rlRun "create_new_cert_re1quest \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 15 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertNotGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertNotGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Key CertSign" "$TmpDir/cert-show.out"
        rlAssertGrep "Crl Sign" "$TmpDir/cert-show.out"
	rlAssertGrep "Is CA: yes" "$TmpDir/cert-show.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0157: Approve Enrollment request from caInstallCACert profile"
        local tmp_profile=caOCSPCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
        rlAssertGrep "OCSPSigning" "$TmpDir/cert-show.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0158: Approve Enrollment request from caStorageCert profile"
        local tmp_profile=caStorageCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlLog "Verify Extended Key Usage extensions are added"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
        rlAssertGrep "1.3.6.1.5.5.7.3.2" "$TmpDir/cert-show.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0159: Approve Enrollment request from caTransportCert profile"
        local tmp_profile=caTransportCert
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:pkcs10 \
                request_algo:rsa \
                request_size:2048 \
                subject_cn:\"IDM $tmp_profile Test1\" \
                subject_uid: \
                subject_email:idmtest@foobar.org \
                subject_ou:IDM \
                subject_organization:FooBar \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD cert-request-profile-show $tmp_profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlLog "Update $tmp_profile xml with certificate request details"
        rlRun "generate_cert_request_xml $TEMP_NSS_DB/$rand-request.pem $TEMP_NSS_DB/$rand-subject.out $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $target_host -p $target_port cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $cert_request_submit" 0 "Submit certificate request"
        rlAssertGrep "Request Status: pending" "$cert_request_submit"
        rlAssertGrep "Operation Result: success" "$cert_request_submit"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action approve 1> $cert_request_review" 0 "Approve Enrollment request $request_id"
        rlAssertGrep "Approved certificate request $request_id" "$cert_request_review"
        rlLog "Verify Certificate has Key Encipherment extension added"
        local cert_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $request_id | grep "Certificate ID:" | awk -F ": " '{print $2}')
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 5 \"Critical: yes\" > $TmpDir/cert-show.out"
        rlLog "Verify Key Usage extensions are added"
        rlAssertGrep "Digital Signature" "$TmpDir/cert-show.out"
        rlAssertGrep "Non Repudiation" "$TmpDir/cert-show.out"
        rlAssertGrep "Key Encipherment" "$TmpDir/cert-show.out"
        rlAssertGrep "Data Encipherment" "$TmpDir/cert-show.out"
        rlLog "Verify Extended Key Usage extensions are added"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty | grep  -A 4 \"Extended Key Usage:\" > $TmpDir/cert-show.out"
        rlAssertGrep "1.3.6.1.5.5.7.3.2" "$TmpDir/cert-show.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0160: Cancel a canceled Enrollment request"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "Reject Enrollment request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 "Cancelling a rejected request $request_id"
        rlAssertGrep "BadRequestException: Request Not In Pending State" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0161: canceling a Unassigned Enrollment request should fail"
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
        rlLog "Un assign $request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign 1> $cert_request_review" 0 "Unassign enrollment request $request_id"
        rlAssertGrep "Unassigned certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "Cancel certificate request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0162: canceling an enrollment request as CA_agentV assigned to caadmin(Member of Certificate Manager Agents) should fail"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign 1> $cert_request_review" 0 "Assign enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "Assigned certificate request $request_id" "$cert_request_review"
        rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin"
        rlRun "ldapsearch -x -LLL -b \"ou=ca,ou=requests,dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
                -h $target_host -p 389 cn=$request_id requestOwner > $TmpDir/$request_id-ldap.out"
        rlAssertGrep "dn: cn=$request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$request_id-ldap.out"
        rlAssertGrep "caadmin" "$TmpDir/$request_id-ldap.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel > $cert_request_review 2>&1" 1,255 
        rlAssertGrep "PKIException: Problem approving request in CertRequestResource.assignRequest! Not authorized to do this operation" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0163: cancel a validated Enrollment request"
	rlLog "validate enrollment request $request_id"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$admin_cert_nickname\" -c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "Validated certificate request $request_id" "$expout"
        local request_id=$(cat  $cert_request_submit | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action cancel 1> $cert_request_review" 0 "Cancel enrollment request $request_id"
        rlAssertGrep "Canceled certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_request_reivew-0164: validate a validated Enrollment request"
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
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn -noecho pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD  ca-cert-request-review $request_id --file $TEMP_NSS_DB/$requestid-req.xml" >> $exp
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $exp
        echo "send -- \"validate\r\"" >> $exp
        echo "expect eof" >> $exp
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "Validated certificate request $request_id" "$expout"
	rlLog "Validate the validated request $request_id"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" \
		-c $CERTDB_DIR_PASSWORD \
		ca-cert-request-review --action validate $request_id"
	rlAssertGrep "Validated certificate request $request_id" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0165: validate Enrollment request as CA_agentV assigned to caadmin(Member of Certificate Manager Agents)"
	rlLog "Assign $request_id to caadmin"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action assign 1> $cert_request_review" 0 "Assign enrollment request $request_id to $admin_cert_nickname"
        rlAssertGrep "Assigned certificate request $request_id" "$cert_request_review"
        rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin"
        rlRun "ldapsearch -x -LLL -b \"ou=ca,ou=requests,dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
                -h $target_host -p 389 cn=$request_id requestOwner > $TmpDir/$request_id-ldap.out"
        rlAssertGrep "dn: cn=$request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$request_id-ldap.out"
        rlAssertGrep "caadmin" "$TmpDir/$request_id-ldap.out"
        rlRun "pki -d $CERTDB_DIR \
                -h $target_host \
                -p $target_port \
                -n \"$CA_agentV_user\" \
                -c $CERTDB_DIR_PASSWORD \
                ca-cert-request-review --action validate $request_id > $cert_request_review 2>&1" 255,1
	rlAssertGrep "PKIException: Problem approving request in CertRequestResource.assignRequest! Not authorized to do this operation" "$cert_request_review"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_cert_request_review-0166: validate unassigned Enrollment request"
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
        rlLog "Un assign $request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert_nickname\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action unassign 1> $cert_request_review" 0 "Unassign enrollment request $request_id"
        rlAssertGrep "Unassigned certificate request $request_id" "$cert_request_review"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $request_id \
               --action validate 1> $cert_request_review" 0 "Cancel certificate request $request_id"
        rlAssertGrep "Validated certificate request $request_id" "$cert_request_review"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0167: Assign renewal request to CA_agentV User which was initially assigned to caadmin(Member of Certificate Manager Agents)"
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
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -n \"$admin_cert_nickname\" \
                ca-cert-request-review $renewal_request_id \
               --action assign 1> $cert_request_review" 0 "Assign Enrollment request $renewal_request_id to $admin_cert_nickname"
        rlAssertGrep "Assigned certificate request $renewal_request_id" "$cert_request_review"
        rlLog "Issue ldapsearch against CA Directory Server DB to verify if the request is assigned to caadmin"
        rlRun "ldapsearch -x -LLL -b \"ou=ca,ou=requests,dc=pki-ca\" -D \"cn=Directory Manager\" -w $LDAP_ROOTDNPWD \
                -h $target_host -p 389 cn=$renewal_request_id requestOwner > $TmpDir/$renewal_request_id-ldap.out"
        rlAssertGrep "dn: cn=$renewal_request_id,ou=ca,ou=requests,dc=pki-ca" "$TmpDir/$renewal_request_id-ldap.out"
        rlAssertGrep "caadmin" "$TmpDir/$renewal_request_id-ldap.out"
	rlLog "Assign $renewal_request_id to $CA_agentV_user"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action assign > $cert_request_review 2>&1" 1,255 "Assign Enrollment request $renewal_request_id to $CA_agentV_user"
	rlAssertGrep "PKIException: Problem approving request in CertRequestResource.assignRequest! Not authorized to do this operation" "$cert_request_review"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_cert_request_review-0168: Unassign renewal request assigned to CA_adminV using CA_agentV"
        rlLog "Un assign $renewal_request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                ca-cert-request-review $renewal_request_id \
               --action unassign > $cert_request_review 2>&1" 255,1 "Un-Assign renewal request $renewal_request_id using $CA_agentV_user cert"
	rlAssertGrep "PKIException: Problem approving request in CertRequestResource.assignRequest! Not authorized to do this operation" "$cert_request_review"
        rlPhaseEnd

	rlPhaseStartCleanup "pki ca-cert-request-review cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
