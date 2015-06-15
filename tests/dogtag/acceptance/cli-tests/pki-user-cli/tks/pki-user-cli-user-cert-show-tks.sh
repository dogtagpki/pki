#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-cert-show-tks    Show the certs assigned to users in the pki tks subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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

######################################################################################
#create_role_users.sh should be first executed prior to pki-user-cli-user-cert-show-tks.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-user-cli-user-cert-show-tks_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	caId=$4
	CA_HOST=$5
	##### Create temporary directory to save output files #####
	rlPhaseStartSetup "pki_user_cli_user_cert-show-tks-startup: Create temporary directory"
		rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
		rlRun "pushd $TmpDir"
	rlPhaseEnd
	get_topo_stack $MYROLE $TmpDir/topo_file
        local TKS_INST=$(cat $TmpDir/topo_file | grep MY_TKS | cut -d= -f2)
        tks_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$TKS_INST
                tks_instance_created=$(eval echo \$${TKS_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                        prefix=TKS1
                        tks_instance_created=$(eval echo \$${TKS_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                tks_instance_created=$(eval echo \$${TKS_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$tks_instance_created" = "TRUE" ] ;  then
TKS_HOST=$(eval echo \$${MYROLE})
TKS_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
CA_PORT=$(eval echo \$${caId}_UNSECURE_PORT)
ca_signing_cert_subj_name=$(eval echo \$${caId}_SIGNING_CERT_SUBJECT_NAME)

user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
local exp="$TmpDir/expfile.out"
local cert_info="$TmpDir/cert_info"
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
ROOTCA_agent_user=${caId}_agentV

	##### Tests to find certs assigned to TKS users ####

	##### Show certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-tks-002: Show certs assigned to a user - valid UserID and CertID"
        	rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
			   -t tks \
                            user-add --fullName=\"$user2fullname\" $user2"

		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
	        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        	organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
	        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        	certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
	        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
		local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
	        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_tks_user_cert_show_encoded_002pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        	rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_show_encoded_002pkcs10.out > $TmpDir/pki_tks_user_cert_show_validcert_002pkcs10.pem"

		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
	        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        	organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
	        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        	certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
	        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
		local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
	        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_tks_user_cert_show_encoded_002crmf.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        	rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_show_encoded_002crmf.out > $TmpDir/pki_tks_user_cert_show_validcert_002crmf.pem"
		rlLog "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user2 --input $TmpDir/pki_tks_user_cert_show_validcert_002pkcs10.pem"
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user2 --input $TmpDir/pki_tks_user_cert_show_validcert_002pkcs10.pem  > $TmpDir/pki_tks_user_cert_show_useraddcert_002.out" \
                            0 \
                            "Cert is added to the user $user2"
		rlLog "Executing pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_show_usershowcert_002.out" \
			0 \
			"Show cert assigned to $user2"

		rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_002.out"
        	rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_002.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_002.out"
        	rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_002.out"
        	rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_002.out"
        	rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_002.out"

		rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user2 --input $TmpDir/pki_tks_user_cert_show_validcert_002crmf.pem  > $TmpDir/pki_tks_user_cert_show_useraddcert_002crmf.out" \
                            0 \
                            "Cert is added to the user $user2"
                rlLog "Executing pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out" \
                        0 \
                        "Show cert assigned to $user2"

                rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_002crmf.out"

	rlPhaseEnd
	##### Show certs asigned to a user - invalid Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-003: pki user-cert-show should fail if an invalid Cert ID is provided"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '3;$valid_decimal_pkcs10_serialNumber;CN=ROOTCA Signing Cert,O=redhat Domain;UID=user2,E=user2@example.org,CN=user2fullname,OU=Eng,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when an invalid Cert ID is provided"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '3;$valid_decimal_crmf_serialNumber;CN=ROOTCA Signing Cert,O=redhat Domain;UID=user2,E=user2@example.org,CN=user2fullname,OU=Eng,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when an invalid Cert ID is provided"

        rlPhaseEnd

	##### Show certs asigned to a user - non-existing User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-004: pki user-cert-show should fail if a non-existing User ID is provided"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show testuser4 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="UserNotFoundException: User testuser4 not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when a non-existing User ID is provided"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show testuser4 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="UserNotFoundException: User testuser4 not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when a non existing User ID is provided"

        rlPhaseEnd

	##### Show certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-005: pki user-cert-show should fail is there is a mismatch of User ID and Cert ID"
		rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"$user1fullname\" $user1"

		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user1 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user1"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when there is a User ID and Cert ID mismatch"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user1 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user1"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when there is a User ID and Cert ID mismatch"
	rlPhaseEnd

	##### Show certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-006-tier1: pki user-cert-show should fail if User ID is not provided"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
	rlPhaseEnd

	##### Show certs asigned to a user - no Cert ID ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-007-tier1: pki user-cert-show should fail if Cert ID is not provided"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"New User1\" u16"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show u16"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when Cert ID is not provided"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del u16"
                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
	rlPhaseEnd

	##### Show certs asigned to a user - --encoded option #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-008: Show certs assigned to a user - --encoded option - Valid Cert ID and User ID"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded > $TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out" \
                        0 \
                        "Show cert assigned to $user2 with --encoded option"
		rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out"
		
		rlLog "$(cat $TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out | grep Subject | awk -F":" '{print $2}')"
                rlRun "openssl x509 -in $TmpDir/pki_tks_user_cert_show_usershowcert_008pkcs10.out -noout -serial 1> $TmpDir/temp_out-openssl_pkcs10" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_pkcs10| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_pkcs10_serialNumber ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                           user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded > $TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out" \
                        0 \
                        "Show cert assigned to $user2 with --encoded option"

		rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out"

                rlLog "$(cat $TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out | grep Subject | awk -F":" '{print $2}')"
                rlRun "openssl x509 -in $TmpDir/pki_tks_user_cert_show_usershowcert_008crmf.out -noout -serial 1> $TmpDir/temp_out-openssl_crmf" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_crmf_serialNumber ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
	rlPhaseEnd

	##### Show certs asigned to a user with --encoded option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-009: pki user-cert-show with --encoded option should fail if User ID is not provided"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --encoded"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --encoded option should throw an error when User ID is not provided for pkcs10 cert"

		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --encoded"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --encoded option should throw an error when User ID is not provided for crmf cert"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user with --encoded option - no Cert ID ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0010: pki user-cert-show with --encoded option should fail if Cert ID is not provided"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 --encoded"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --encoded option should throw an error when Cert ID is not provided"
                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0011: Show certs assigned to a user - --output <file> option - Valid Cert ID, User ID and file"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --output $TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --output $TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out > $TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out" \
                        0 \
                        "Show cert assigned to $user2 with --output option"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out"
		rlRun "openssl x509 -in $TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out -noout -serial 1> $TmpDir/temp_out-openssl_pkcs10" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_pkcs10| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_pkcs10_serialNumber ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
                rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011pkcs10.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                           user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --output $TmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --output $TmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out > $TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out" \
                        0 \
                        "Show cert assigned to $user2 with --output option"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out"
                rlRun "openssl x509 -in $TmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out -noout -serial 1> $TmpDir/temp_out-openssl_crmf" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_crmf_serialNumber ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
                rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0011crmf.out"

	rlPhaseEnd

	##### Show certs asigned to a user with --output option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-0012: pki user-cert-show with --output option should fail if User ID is not provided"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --output $TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when User ID is not provided for pkcs10 cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --output $TmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when User ID is not provided for crmf cert"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user with --output option - no Cert ID ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0013: pki user-cert-show with --output option should fail if Cert ID is not provided"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 --output $TmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when Cert ID is not provided"
                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd
	
	##### Show certs asigned to a user with --output option - Directory does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0014: pki user-cert-show with --output option should fail if directory does not exist"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --output /tmp/tmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out"
                errmsg="FileNotFoundException: /tmp/tmpDir/pki_tks_user_cert_show_usercertshow_pkcs10_output.out (No such file or directory)"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when directory does not exist"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --output /tmp/tmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out"
                errmsg="FileNotFoundException: /tmp/tmpDir/pki_tks_user_cert_show_usercertshow_crmf_output.out (No such file or directory)"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when directory does not exist"

        rlPhaseEnd

	##### Show certs asigned to a user with --output option - Missing argument for --output option #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0015: pki user-cert-show with --output option should fail if argument for --option is missing"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --output"
                errmsg="Error: Missing argument for option: output"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when argument for --option is missing"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --output"
                errmsg="Error: Missing argument for option: output"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --output option should throw an error when argument for --option is missing"

        rlPhaseEnd

	##### Show certs asigned to a user - --pretty option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0016: Show certs assigned to a user - --pretty option - Valid Cert ID, User ID"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
			   -t tks \
                           user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --pretty > $TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out" \
                        0 \
                        "Show cert assigned to $user2 with --pretty option"
                rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
		rlAssertGrep "Signature Algorithm" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Validity" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"
                rlAssertGrep "Signature" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016pkcs10.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --pretty > $TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out" \
                        0 \
                        "Show cert assigned to $user2 with --pretty option"
                rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Validity" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
                rlAssertGrep "Signature" "$TmpDir/pki_tks_user_cert_show_usershowcert_0016crmf.out"
	rlPhaseEnd

	##### Show certs asigned to a user with --pretty option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0017: pki user-cert-show with --pretty option should fail if User ID is not provided"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --pretty"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --pretty option should throw an error when User ID is not provided for pkcs10 cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' --pretty"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --pretty option should throw an error when User ID is not provided for crmf cert"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user with --pretty option - no Cert ID ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0018: pki user-cert-show with --pretty option should fail if Cert ID is not provided"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 --pretty" 
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show with --pretty option should throw an error when Cert ID is not provided"
                rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd
	
	##### Show certs asigned to a user - --pretty, --encoded and --output options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-0019-tier1: Show certs assigned to a user - --pretty, --encoded and --output options - Valid Cert ID, User ID and file"
                newuserid=newuser
                newuserfullname="New User"
                rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"$newuserfullname\" $newuserid"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname\" subject_uid:$newuserid subject_email:$newuserid@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                local valid_pkcs10_serialNumber_new=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_pkcs10_serialNumber_new=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10_new=$(echo $valid_pkcs10_serialNumber_new | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10_new=${STRIP_HEX_PKCS10_new^^}
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber_new --encoded > $TmpDir/pki_tks_user_cert_show_encoded_0019pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber_new"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_show_encoded_0019pkcs10.out > $TmpDir/pki_tks_user_cert_show_validcert_0019pkcs10.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname\" subject_uid:$newuserid subject_email:$newuserid@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                local valid_crmf_serialNumber_new=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber_new=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF_new=$(echo $valid_crmf_serialNumber_new | cut -dx -f2)
                local CONV_UPP_VAL_CRMF_new=${STRIP_HEX_CRMF_new^^}
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber_new --encoded > $TmpDir/pki_tks_user_cert_show_encoded_0019crmf.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber_new"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_show_encoded_0019crmf.out > $TmpDir/pki_tks_user_cert_show_validcert_0019crmf.pem"

		rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $newuserid --serial $valid_decimal_pkcs10_serialNumber_new"

		rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $newuserid --serial $valid_decimal_crmf_serialNumber_new"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $newuserid \"2;$valid_decimal_pkcs10_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --pretty --output $TmpDir/tks_user_cert_show_pkcs10_output0019"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $newuserid \"2;$valid_decimal_pkcs10_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --pretty --output $TmpDir/tks_user_cert_show_pkcs10_output0019 > $TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out" \
                        0 \
                        "Show cert assigned to $user2 with --pretty --encoded and --output options"
                rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber_new" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Subject: UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Validity" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "Signature" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019pkcs10.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/tks_user_cert_show_pkcs10_output0019"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/tks_user_cert_show_pkcs10_output0019"
                rlRun "openssl x509 -in $TmpDir/tks_user_cert_show_pkcs10_output0019 -noout -serial 1> $TmpDir/temp_out-openssl_pkcs10" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_pkcs10| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_pkcs10_serialNumber_new ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $newuserid \"2;$valid_decimal_crmf_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --pretty --output $TmpDir/tks_user_cert_show_crmf_output0019"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $newuserid \"2;$valid_decimal_crmf_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --pretty --output $TmpDir/tks_user_cert_show_crmf_output0019 > $TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out" \
                        0 \
                        "Show cert assigned to $user2 with --pretty --encoded and --output options"
                rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber_new;$ca_signing_cert_subj_name;UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber_new" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Subject: UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Validity" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "Signature" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0019crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/tks_user_cert_show_crmf_output0019"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/tks_user_cert_show_crmf_output0019"
                rlRun "openssl x509 -in $TmpDir/tks_user_cert_show_crmf_output0019 -noout -serial 1> $TmpDir/temp_out-openssl_crmf" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_crmf_serialNumber_new ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		 rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del $newuserid"
	rlPhaseEnd

	 ##### Show certs asigned to a user - as TKS_agentV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0020: Show certs assigned to a user - as TKS_agentV should fail"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a valid agent cert"

		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a valid agent cert"
	rlPhaseEnd

	##### Show certs asigned to a user - as TKS_auditorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0021: Show certs assigned to a user - as TKS_auditorV should fail"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a valid auditor cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a valid auditor cert"
        rlPhaseEnd

	##### Show certs asigned to a user - as TKS_adminE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0022: Show certs assigned to a user - as TKS_adminE should fail"
		rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with an expired admin cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with an expired admin cert"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	##### Show certs asigned to a user - as TKS_agentE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0023: Show certs assigned to a user - as TKS_agentE should fail"
                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with an expired agent cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with an expired agent cert"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	##### Show certs asigned to a user - as TKS_adminR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0024: Show certs assigned to a user - as TKS_adminR should fail"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a revoked admin cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a revoked admin cert"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlPhaseEnd

	##### Show certs asigned to a user - as TKS_agentR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0025: Show certs assigned to a user - as TKS_agentR should fail"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a revoked agent cert"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with a revoked agent cert"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlPhaseEnd

	##### Show certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0026: Show certs assigned to a user - as role_user_UTCA should fail"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show shouls fail when authenticating with an untrusted cert"

                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show shouls fail when authenticating with an untrusted cert"
        rlPhaseEnd

	##### Show certs asigned to a user - as TKS operator user ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0027: Show certs assigned to a user - as TKS operator user should fail"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with an operator user"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when authenticating with an operator user"
        rlPhaseEnd

	##### Show certs asigned to a user - --encoded and --output options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0028: Show certs assigned to a user - --encoded and --output options - Valid Cert ID, User ID and file"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --output $TmpDir/tks_user_cert_show_pkcs10_output0028"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --output $TmpDir/tks_user_cert_show_pkcs10_output0028 > $TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out" \
                        0 \
                        "Show cert assigned to $user2 with --encoded and --output options"
                rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028pkcs10.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/tks_user_cert_show_pkcs10_output0028"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/tks_user_cert_show_pkcs10_output0028"
                rlRun "openssl x509 -in $TmpDir/tks_user_cert_show_pkcs10_output0028 -noout -serial 1> $TmpDir/temp_out-openssl_pkcs10" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_pkcs10| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_pkcs10_serialNumber ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --output $TmpDir/tks_user_cert_show_crmf_output0028"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\" --encoded --output $TmpDir/tks_user_cert_show_crmf_output0028 > $TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out" \
                        0 \
                        "Show cert assigned to $user2 with --encoded and --output options"
                rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_tks_user_cert_show_usershowcert_0028crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/tks_user_cert_show_crmf_output0028"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/tks_user_cert_show_crmf_output0028"
                rlRun "openssl x509 -in $TmpDir/tks_user_cert_show_crmf_output0028 -noout -serial 1> $TmpDir/temp_out-openssl_crmf" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $valid_decimal_crmf_serialNumber ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
	rlPhaseEnd

	##### Show certs asigned to a user - as a user not associated with any role##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0029: Show certs assigned to a user - as a user not associated with any role, should fail"
		command="pki -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show shouls fail when authenticating with an user not associated with any role"

                command="pki -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show shouls fail when authenticating with an user not associated with any role"
	        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	##### Show certs asigned to a user - switch position of the required options#####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0030: Show certs assigned to a user - switch position of the required options"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show '2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US' $user2"
                errmsg="User Not Found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when required options are switched positions"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/968"
	rlPhaseEnd

	##### Show certs asigned to a user - incomplete Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-tks-0031: pki user-cert-show should fail if an incomplete Cert ID is provided"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_pkcs10_serialNumber;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when an incomplete Cert ID is provided"

                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-show $user2 '2;$valid_decimal_crmf_serialNumber;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should fail when an incomplete Cert ID is provided"
	rlPhaseEnd

	### Tests to show certs assigned to TKS users - i18n characters ####

	rlPhaseStartTest "pki_user_cli_user_cert-show-tks-032: Show certs assigned to user - Subject name has i18n Characters"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:$user1@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_tks_user_cert_show_encoded_0032pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_show_encoded_0032pkcs10.out > $TmpDir/pki_tks_user_cert_show_validcert_0032pkcs10.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:$user1@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_tks_user_cert_show_encoded_0032crmf.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_show_encoded_0032crmf.out > $TmpDir/pki_tks_user_cert_show_validcert_0032crmf.pem"

                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user1 --input $TmpDir/pki_tks_user_cert_show_validcert_0032pkcs10.pem  > $TmpDir/pki_tks_user_cert_show_useraddcert_0032.out" \
                            0 \
                            "Cert is added to the user $user1"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user1 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user1 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_show_usershowcert_0032.out" \
                        0 \
                        "Show cert assigned to $user1"
		rlAssertGrep "Certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_0032.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0032.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_0032.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_0032.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_0032.out"
                rlAssertGrep "Subject: UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_0032.out"
		
		rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user1 --input $TmpDir/pki_tks_user_cert_show_validcert_0032crmf.pem  > $TmpDir/pki_tks_user_cert_show_useraddcert_crmf_0032.out" \
                            0 \
                            "Cert is added to the user $user1"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user1 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-show $user1 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out" \
                        0 \
                        "Show cert assigned to $user1"
                rlAssertGrep "Certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out"
                rlAssertGrep "Issuer: $ca_signing_cert_subj_name" "$TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out"
                rlAssertGrep "Subject: UID=Örjan Äke,E=$user1@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_tks_user_cert_show_usershowcert_crmf_0032.out"

	rlPhaseEnd

	#===Deleting users===#
rlPhaseStartCleanup "pki_tks_user_cli_user_cleanup: Deleting role users"
        j=1
        while [ $j -lt 3 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                           user-del  $usr > $TmpDir/pki-user-del-tks-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-tks-user-symbol-00$j.out"
                let j=$j+1
        done

        #Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
else
	rlLog "TKS instance not created"
fi
}
