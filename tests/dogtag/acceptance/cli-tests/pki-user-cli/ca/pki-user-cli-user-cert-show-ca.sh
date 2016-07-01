#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-cert-show    Show the certs assigned to users in the pki ca subsystem.
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
#pki-user-cli-role-user-create-tests should be first executed prior to pki-user-cli-user-cert-show-ca.sh
######################################################################################

run_pki-user-cli-user-cert-show-ca_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3

	##### Create temporary directory to save output files #####
	rlPhaseStartSetup "pki_user_cli_user_cert-show-ca-startup: Create temporary directory"
		rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
		rlRun "pushd $TmpDir"
	rlPhaseEnd

	get_topo_stack $MYROLE $TmpDir/topo_file
	local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	ca_instance_created="False"
	if [ "$TOPO9" = "TRUE" ] ; then
        prefix=$CA_INST
        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
	elif [ "$MYROLE" = "MASTER" ] ; then
                if [[ $CA_INST == SUBCA* ]]; then
                        prefix=$CA_INST
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                else
                        prefix=ROOTCA
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                fi
        else
                prefix=$MYROLE
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
	fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})

if [ "$ca_instance_created" = "TRUE" ] ;  then
user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"
cert_info="$TmpDir/cert_info"
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
##### pki_user_cli_user_cert_show_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-show-configtest-001: pki user-cert-show configuration test"
        rlRun "pki -h $SUBSYSTEM_HOST user-cert-show --help > $TmpDir/pki_user_cert_show_cfg.out 2>&1" \
                0 \
                "User cert show configuration"
        rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_cfg.out"
        rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_user_cert_show_cfg.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Tests to find certs assigned to CA users ####

	##### Show certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-CA-002: Show certs assigned to a user - valid UserID and CertID"
                k=2	
        	rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                            user-add --fullName=\"$user2fullname\" $user2"

		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_show-CA_encoded_002pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show-CA_encoded_002pkcs10.out > $TmpDir/pki_user_cert_show-CA_validcert_002pkcs10.pem"

		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_show-CA_encoded_002crmf.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show-CA_encoded_002crmf.out > $TmpDir/pki_user_cert_show-CA_validcert_002crmf.pem"

                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_show-CA_validcert_002pkcs10.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_002.out" \
                            0 \
                            "Cert is added to the user $user2"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_002.out" \
			0 \
			"Show cert assigned to $user2"

		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"

		rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_show-CA_validcert_002crmf.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_002crmf.out" \
                            0 \
                            "Cert is added to the user $user2"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out" \
                        0 \
                        "Show cert assigned to $user2"

                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002crmf.out"

	rlPhaseEnd

	##### Show certs asigned to a user - invalid Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-003: pki user-cert-show should fail if an invalid Cert ID is provided"
                
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '3;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
	        errmsg="ResourceNotFoundException: No certificates found for $user2"
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when an invalid Cert ID is provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '3;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when an invalid Cert ID is provided"

	rlPhaseEnd

	##### Show certs asigned to a user - User does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-004: pki user-cert-show should fail if a non-existing User ID is provided"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show testuser4 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="UserNotFoundException: User testuser4 not found"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when a non existing user is provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show testuser4 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="UserNotFoundException: User testuser4 not found"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when a non existing user is provided"
        rlPhaseEnd

	##### Show certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-005: pki user-cert-show should fail is there is a mismatch of User ID and Cert ID"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                            user-add --fullName=\"$user1fullname\" $user1"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user1 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user1"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when there is a Cert ID and User ID mismatch"
		
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user1 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user1"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when there is a Cert ID and User ID mismatch"
        rlPhaseEnd

	##### Show certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-006-tier1: pki user-cert-show should fail if User ID is not provided"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;50;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=u16,E=u16@example.org,CN=New User1,OU=Engineering,O=Example,C=US'"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-007-tier1: pki user-cert-show should fail if Cert ID is not provided"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                            user-add --fullName=\"New User1\" u16"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show u16"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when Cert ID is not provided"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                            user-del u16"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --encoded option #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-CA-008: Show certs assigned to a user - --encoded option - Valid Cert ID and User ID"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
			   -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_008.out" \
                        0 \
                        "Show cert assigned to user - --encoded option"
		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"

		rlLog "$(cat $TmpDir/pki_user_cert_show_CA_usershowcert_008.out | grep Subject | awk -F":" '{print $2}')"
        	rlRun "openssl x509 -in $TmpDir/pki_user_cert_show_CA_usershowcert_008.out -noout -serial 1> $TmpDir/temp_out-openssl_008" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_008| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_pkcs10 ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out" \
                        0 \
                        "Show cert assigned to user - --encoded option"
                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out"

	        rlLog "$(cat $TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out | grep Subject | awk -F":" '{print $2}')"
        	rlRun "openssl x509 -in $TmpDir/pki_user_cert_show_CA_usershowcert_008crmf.out -noout -serial 1> $TmpDir/temp_out-openssl_crmf_008" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf_008| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_crmf ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
        	rlPhaseEnd
	
	  ##### Show certs asigned to a user - --encoded option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-009: pki user-cert-show should fail if User ID is not provided with --encoded option"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --encoded"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --encoded"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0010: pki user-cert-show should fail if Cert ID is not provided with --encoded option"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user1"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when Cert ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0011: Show certs assigned to a user - --output <file> option - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output.out"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
			   -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output_0011.out > $TmpDir/pki_user_cert_show_CA_usershowcert_0011.out" \
                        0 \
                        "Show cert assigned to user - --output <file> option"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usercertshow_output_0011.out"
        	rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usercertshow_output_0011.out"
		rlRun "openssl x509 -in $TmpDir/pki_user_cert_show_CA_usercertshow_output_0011.out -noout -serial 1> $TmpDir/temp_out-openssl_0011" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_0011| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_pkcs10 ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
	rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output_crmf.out"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output_crmf_0011.out > $TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out" \
                        0 \
                        "Show cert assigned to user - --output <file> option"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usercertshow_output_crmf_0011.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usercertshow_output_crmf_0011.out"
                rlRun "openssl x509 -in $TmpDir/pki_user_cert_show_CA_usercertshow_output_crmf_0011.out -noout -serial 1> $TmpDir/temp_out-openssl_crmf_0011" 0 "Run openssl to verify PEM output"
	openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf_0011| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_crmf ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
        rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011crmf.out"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0012: pki user-cert-show should fail if User ID is not provided with --output <file> option"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --output $TmpDir/user_cert_show_output0012"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --output $TmpDir/user_cert_show_output0012"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user - --output <file> option - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0013: pki user-cert-show should fail if Cert ID is not provided with --output <file> option"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user1 --output $TmpDir/user_cert_show_output0013"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when Cert ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - Directory does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0014: pki user-cert-show should fail if --output <file> directory does not exist"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --output /tmp/tmpDir/user_cert_show_output0014"
                errmsg="FileNotFoundException: /tmp/tmpDir/user_cert_show_output0014 (No such file or directory)"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when output file does not exist"
		
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --output /tmp/tmpDir/user_cert_show_output0014"
                errmsg="FileNotFoundException: /tmp/tmpDir/user_cert_show_output0014 (No such file or directory)"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when output file does not exist"

        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - without <file> argument #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0015: pki user-cert-show should fail if --output option file argument is not provided"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --output"
                errmsg="Error: Missing argument for option: output"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when output option does not have an argument"

        rlPhaseEnd
	##### Show certs asigned to a user - --pretty option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0016: Show certs assigned to a user - --pretty option - Valid Cert ID, User ID"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
			   -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0016.out" \
                        0 \
                        "Show cert assigned to user - --pretty option"
		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Signature Algorithm" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Validity" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Extensions" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Signature" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out" \
                        0 \
                        "Show cert assigned to user - --pretty option"
                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Validity" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
                rlAssertGrep "Signature" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016crmf.out"
        rlPhaseEnd

        ##### Show certs asigned to a user - --pretty option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0017: pki user-cert-show should fail if User ID is not provided with --pretty option"
		rlLog "$user2"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --pretty"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' --pretty"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when User ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user - --pretty option - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0018: pki user-cert-show should fail if Cert ID is not provided with --pretty option"
		 command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user1 --pretty"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when Cert ID is not provided"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --pretty, --encoded and --output options ##### 
        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0019-tier1: Show certs assigned to a user - --pretty, --encoded and --output options - Valid Cert ID, User ID and file"
		newuserid=newuser
		newuserfullname="New User"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                            user-add --fullName=\"$newuserfullname\" $newuserid"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname\" subject_uid:$newuserid subject_email:$newuserid@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_pkcs10_new=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10_new=$(echo $cert_serialNumber_pkcs10_new | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10_new=${STRIP_HEX_PKCS10_new^^}
                local decimal_valid_serialNumber_pkcs10_new=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10_new"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10_new --encoded > $TmpDir/pki_user_cert_show-CA_encoded_0019pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10_new"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show-CA_encoded_0019pkcs10.out > $TmpDir/pki_user_cert_show-CA_validcert_0019pkcs10.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname\" subject_uid:$newuserid subject_email:$newuserid@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_crmf_new=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF_new=$(echo $cert_serialNumber_crmf_new | cut -dx -f2)
                local CONV_UPP_VAL_CRMF_new=${STRIP_HEX_CRMF_new^^}
                local decimal_valid_serialNumber_crmf_new=$(echo "ibase=16;$CONV_UPP_VAL_CRMF_new"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf_new --encoded > $TmpDir/pki_user_cert_show-CA_encoded_0019crmf.out" 0 "Executing pki cert-show $cert_serialNumber_crmf_new"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show-CA_encoded_0019crmf.out > $TmpDir/pki_user_cert_show-CA_validcert_0019crmf.pem"

                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-add $newuserid --input $TmpDir/pki_user_cert_show-CA_validcert_0019pkcs10.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_0019.out" \
                            0 \
                            "Cert is added to the user $user2"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $newuserid \"2;$decimal_valid_serialNumber_pkcs10_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
			   -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $newuserid \"2;$decimal_valid_serialNumber_pkcs10_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019 > $TmpDir/pki_user_cert_show_CA_usershowcert_0019.out" \
                        0 \
                        "Show cert assigned to user - --pretty, --output and --encoded options"
		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10_new" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Subject: UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Validity" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Signature" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/user_cert_show_output0019"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/user_cert_show_output0019"
                rlRun "openssl x509 -in $TmpDir/user_cert_show_output0019 -noout -serial 1> $TmpDir/temp_out-openssl_0019" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_0019| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_pkcs10_new ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-add $newuserid --input $TmpDir/pki_user_cert_show-CA_validcert_0019crmf.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_0019crmf.out" \
                            0 \
                            "Cert is added to the user $newuserid"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $newuserid \"2;$decimal_valid_serialNumber_crmf_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019crmf"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $newuserid \"2;$decimal_valid_serialNumber_crmf_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019crmf > $TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out" \
                        0 \
                        "Show cert assigned to user - --pretty, --output and --encoded options"
                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_crmf_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf_new;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf_new" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Subject: UID=$newuserid,E=$newuserid@example.org,CN=$newuserfullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Validity" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "Signature" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/user_cert_show_output0019crmf"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/user_cert_show_output0019crmf"
                rlRun "openssl x509 -in $TmpDir/user_cert_show_output0019crmf -noout -serial 1> $TmpDir/temp_out-openssl_crmf_0019" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf_0019| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_crmf_new ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                            user-del $newuserid"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_agentV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0020: Show certs assigned to a user - as CA_agentV should fail"
		rlLog "$user2"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_agentV"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_agentV"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_auditorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0021: Show certs assigned to a user - as CA_auditorV should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_auditorV"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_auditorV"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_adminE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0022: Show certs assigned to a user - as CA_adminE should fail"

		rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_adminE"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_adminE"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	##### Show certs asigned to a user - incomplete Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0023: pki user-cert-show should fail if an incomplete Cert ID is provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;O=${prefix}_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when an incomplete Cert ID is provided"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;O=${prefix}_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: No certificates found for $user2"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when an incomplete Cert ID is provided"

        rlPhaseEnd

        ##### Show certs asigned to a user - as CA_agentE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0024: Show certs assigned to a user - as CA_agentE should fail"

                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_agentE"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_agentE"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

       ##### Show certs asigned to a user - as CA_adminR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0025: Show certs assigned to a user - as CA_adminR should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_adminR"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_adminR"

        rlPhaseEnd

       ##### Show certs asigned to a user - as CA_agentR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0026: Show certs assigned to a user - as CA_agentR should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_agentR"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_agentR"

        rlPhaseEnd

        ##### Show certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0027: Show certs assigned to a user - as role_user_UTCA should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as role_user_UTCA"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as role_user_UTCA"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0028: Show certs assigned to a user - as role_user_UTCA should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized""
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as role_user_UTCA"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized""
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as role_user_UTCA"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

        ##### Show certs asigned to a user - as CA_operatorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0029: Show certs assigned to a user - as CA_operatorV should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_operatorV"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as CA_operatorV"

        rlPhaseEnd

	##### Show certs asigned to a user - --encoded and --output options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0030: Show certs assigned to a user - --encoded and --output options - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --output $TmpDir/user_cert_show_output0030"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --output $TmpDir/user_cert_show_output0030 > $TmpDir/pki_user_cert_show_CA_usershowcert_0030.out 2>&1" \
                        0 \
                        "Show cert assigned to user - --output and --encoded options"
                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/user_cert_show_output0030"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/user_cert_show_output0030"
                rlRun "openssl x509 -in $TmpDir/user_cert_show_output0030 -noout -serial 1> $TmpDir/temp_out-openssl_0030" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_0030| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_pkcs10 ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --output $TmpDir/user_cert_show_output0030crmf"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --output $TmpDir/user_cert_show_output0030crmf > $TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out" \
                        0 \
                        "Show cert assigned to user - --output and --encoded options"
                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030crmf.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/user_cert_show_output0030crmf"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/user_cert_show_output0030crmf"
                rlRun "openssl x509 -in $TmpDir/user_cert_show_output0030crmf -noout -serial 1> $TmpDir/temp_out-openssl_crmf_0030" 0 "Run openssl to verify PEM output"
		openssl_out_serial=$(cat $TmpDir/temp_out-openssl_crmf_0030| grep serial | cut -d= -f2)
                dec_openssl_out_serial=$(echo "ibase=16;$openssl_out_serial"|bc)
                if [ $dec_openssl_out_serial = $decimal_valid_serialNumber_crmf ] ; then

                        rlPass "Serial number matches"
		else
                        rlFail "Serial number does not match"
                fi
        rlPhaseEnd

        ##### Show certs asigned to a user - as a user not associated with any role##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0031: Show certs assigned to a user - as as a user not associated with any role, should fail"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as $user1"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD user-cert-show $user2 '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when authenticating as $user1"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - switch position of the required options#####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0032: Show certs assigned to a user - switch position of the required options"
                
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-show '2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US' $user2"
                errmsg="User Not Found"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-show should throw an error when options are switched position"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/968"
        rlPhaseEnd

### Tests to show certs assigned to CA users - i18n characters ####

rlPhaseStartTest "pki_user_cli_user_cert-show-CA-033: Show certs assigned to user - Subject name has i18n Characters"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_show-CA_encoded_0033pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show-CA_encoded_0033pkcs10.out > $TmpDir/pki_user_cert_show-CA_validcert_0033pkcs10.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_show-CA_encoded_0033crmf.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show-CA_encoded_0033crmf.out > $TmpDir/pki_user_cert_show-CA_validcert_0033crmf.pem"

        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_show-CA_validcert_0033pkcs10.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_0033.out" \
                            0 \
                            "Cert is added to the user $user1"
	rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_useraddcert_0033.out"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                              -t ca \
                               user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\""
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                   -t ca \
                   user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_ca_0033.out" \
                    0 \
                    "Show certs assigned to $user1 with i18n chars"
	rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_ca_0033.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                -h $SUBSYSTEM_HOST \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_show-CA_validcert_0033crmf.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_0033crmf.out" \
                            0 \
                            "Cert is added to the user $user1"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_useraddcert_0033crmf.out"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                -h $SUBSYSTEM_HOST \
                              -t ca \
                               user-cert-show $user1 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\""
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                -h $SUBSYSTEM_HOST \
                   -t ca \
                   user-cert-show $user1 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_ca_0033crmf.out" \
                    0 \
                    "Show certs assigned to $user1 with i18n chars"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_ca_0033crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_ca_0033crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_show_ca_0033crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_show_ca_0033crmf.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_ca_0033crmf.out"	
        rlPhaseEnd


#===Deleting users===#
rlPhaseStartCleanup "pki_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 3 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 		-h $SUBSYSTEM_HOST \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
 else
	rlLog "CA instance not installed"
 fi
}
