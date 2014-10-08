#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-delete CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-cert-delete    Delete the certs assigned to users in the pki ca subsystem.
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
#pki-user-cli-role-user-create-tests should be first executed prior to pki-user-cli-user-cert-delete-ca.sh
######################################################################################
run_pki-user-cli-user-cert-delete-ca_tests(){
subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3

if [ "$TOPO9" = "TRUE" ] ; then
        ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
        prefix=$subsystemId
        CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
elif [ "$MYROLE" = "MASTER" ] ; then
        if [[ $subsystemId == SUBCA* ]]; then
                ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
                prefix=$subsystemId
                CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
        else
                ADMIN_CERT_LOCATION=$ROOTCA_ADMIN_CERT_LOCATION
                prefix=ROOTCA
                CLIENT_PKCS12_PASSWORD=$ROOTCA_CLIENT_PKCS12_PASSWORD
        fi
else
        ADMIN_CERT_LOCATION=$(eval echo \$${MYROLE}_ADMIN_CERT_LOCATION)
        prefix=$MYROLE
        CLIENT_PKCS12_PASSWORD=$(eval echo \$${MYROLE}_CLIENT_PKCS12_PASSWORD)
fi

SUBSYSTEM_HOST=$(eval echo \$${MYROLE})

        ##### Create temporary directory to save output files #####
    rlPhaseStartSetup "pki_user_cli_user_cert-del-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"
cert_info="$TmpDir/cert_info"
testname="pki_user_cert_del"
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
	##### pki_user_cli_user_cert_delete_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-del-configtest-001: pki user-cert-del configuration test"
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-cert-del --help > $TmpDir/pki_user_cert_del_cfg.out 2>&1" \
                0 \
                "User cert delete configuration"
        rlAssertGrep "usage: user-cert-del <User ID> <Cert ID>" "$TmpDir/pki_user_cert_del_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_user_cert_del_cfg.out"
	rlLog "FAIL:https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Tests to delete certs assigned to CA users ####

	##### Delete certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-del-CA-002-tier1: Delete cert assigned to a user - valid UserID and CertID"
		i=0
        	rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"$user1fullname\" $user1"
		 while [ $i -lt 4 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local decimal_valid_serialNumber_pkcs10=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                serialhexuser1[$i]=$cert_serialNumber_pkcs10
                serialdecuser1[$i]=$decimal_valid_serialNumber_pkcs10
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_ca_user_cert_del_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_002pkcs10$i.out > $TmpDir/pki_user_cert_del-CA_validcert_002pkcs10$i.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local decimal_valid_serialNumber_crmf=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                serialhexuser1_crmf[$i]=$cert_serialNumber_crmf
                serialdecuser1_crmf[$i]=$decimal_valid_serialNumber_crmf
		rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_ca_user_cert_del_encoded_002crmf$i.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_002crmf$i.out > $TmpDir/pki_user_cert_del-CA_validcert_002crmf$i.pem"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_002pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_002pkcs10$i.pem"

		rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_002crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_002crmf$i.pem"
                let i=$i+1
        	done
		i=0
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del $user1 \"2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))$@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del $user1 \"2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_CA_002.out" \
			0 \
			"Delete cert assigned to $user1"
		rlAssertGrep "Deleted certificate \"2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_002.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del $user1 \"2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))$@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del $user1 \"2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_CA_002crmf.out" \
                        0 \
                        "Delete cert assigned to $user1"
                rlAssertGrep "Deleted certificate \"2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_002crmf.out"
		
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del $user1"
	rlPhaseEnd

	##### Delete certs asigned to a user - invalid Cert ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-del-CA-003: pki user-cert-del should fail if an invalid Cert ID is provided"
                i=0
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"$user1fullname\" $user1"
                 while [ $i -lt 4 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local decimal_valid_serialNumber_pkcs10=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                serialhexuser1[$i]=$cert_serialNumber_pkcs10
                serialdecuser1[$i]=$decimal_valid_serialNumber_pkcs10
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_ca_user_cert_del_encoded_003pkcs10$i.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_003pkcs10$i.out > $TmpDir/pki_user_cert_del-CA_validcert_003pkcs10$i.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local decimal_valid_serialNumber_crmf=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                serialhexuser1_crmf[$i]=$cert_serialNumber_crmf
                serialdecuser1_crmf[$i]=$decimal_valid_serialNumber_crmf
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_ca_user_cert_del_encoded_003crmf$i.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_003crmf$i.out > $TmpDir/pki_user_cert_del-CA_validcert_003crmf$i.pem"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_003pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_003pkcs10$i.pem"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_003crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_003crmf$i.pem"
                let i=$i+1
		done
                i=1
                command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '3;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Failed to modify user."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if Invalid Cert ID is provided"

                command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '3;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Failed to modify user."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if Invalid Cert ID is provided"

        rlPhaseEnd
	##### Delete certs asigned to a user - User does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-004: pki user-cert-del should fail if a non-existing User ID is provided"
		i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del testuser4 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
	        errmsg="ResourceNotFoundException: User not found"
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - User not found message should be thrown when deleting certs assigned to a user that does not exist"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del testuser4 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: User not found"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - User not found message should be thrown when deleting certs assigned to a user that does not exist"

        rlPhaseEnd

	##### Delete certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-005: pki user-cert-del should fail is there is a mismatch of User ID and Cert ID"
		i=1
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"$user2fullname\" --password=Secret123 $user2"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del $user2 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: Certificate not found"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when there is a Cert ID and User ID mismatch"
		
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del $user2 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ResourceNotFoundException: Certificate not found"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when there is a Cert ID and User ID mismatch"

        rlPhaseEnd

	##### Delete certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-006-tier1: pki user-cert-del should fail if User ID is not provided"
		i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when User ID is missing"


		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when User ID is missing"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Delete certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-007-tier1: pki user-cert-del should fail if Cert ID is not provided"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del $user1"
                errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when Cert ID is missing"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd


	##### Delete certs asigned to a user - as CA_agentV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-008: Delete certs assigned to a user - as CA_agentV should fail"
		i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication usinf cert CA_agentV"

		 command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_agentV"
        rlPhaseEnd

	##### Delete certs asigned to a user - as CA_auditorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-009: Delete certs assigned to a user - as CA_auditorV should fail"
		i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_auditorV"
		
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_auditorV"

        rlPhaseEnd

	##### Delete certs asigned to a user - as CA_adminE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0010: Delete certs assigned to a user - as CA_adminE"
		i=1
		rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_adminE"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_adminE"

		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

 ##### Delete certs asigned to a user - as CA_agentE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0011: Delete certs assigned to a user - as CA_agentE"
		i=1
                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_agentE"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_agentE"

		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

        ##### Delete certs asigned to a user - as CA_adminR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0012: Delete certs assigned to a user - as CA_adminR should fail"
		i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_adminR"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_adminR"

        rlPhaseEnd

        ##### Delete certs asigned to a user - as CA_agentR ##### 
	
        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0013: Delete certs assigned to a user - as CA_agentR should fail"
		i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_agentR"
		
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_agentR"

        rlPhaseEnd

        ##### Delete certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0014: Delete certs assigned to a user - as role_user_UTCA should fail"
                i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert role_user_UTCA"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert role_user_UTCA"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	 ##### Delete certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0015: Delete certs assigned to a user - as role_user_UTCA should fail"
                i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert role_user_UTCA"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert role_user_UTCA"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

        ##### Delete certs asigned to a user - as CA_operatorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0016: Delete certs assigned to a user - as CA_operatorV should fail"
                i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_operatorV"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication using cert CA_operatorV"

        rlPhaseEnd

	##### Delete certs asigned to a user - as a user not assigned to any role ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0017: Delete certs assigned to a user - as a user not assigned to any role should fail"
                i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -u $user2 -w Secret123 -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authentication method not allowed."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication as a user not assigned to any role"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -u $user2 -w Secret123 -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authentication method not allowed."
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication as a user not assigned to any role"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

        ##### Delete certs asigned to a user - switch positions of the required options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0018: Delete certs assigned to a user - switch positions of the required options"
                i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US' $user1"
                errmsg="Error:"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when switching positions of required options"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-del '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US' $user1"
                errmsg="Error:"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when switching positions of required options"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/969"
        rlPhaseEnd

### Tests to delete certs assigned to CA users - i18n characters ####

rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0019: Delete certs assigned to user - Subject name has i18n Characters"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_valid_serialNumber_pkcs10=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0019pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0019pkcs10.out > $TmpDir/pki_user_cert_del-CA_validcert_0019pkcs10.pem"

        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_del-CA_validcert_0019pkcs10.pem  > $TmpDir/pki_user_cert_del_CA_useraddcert_0019.out" \
                            0 \
                            "Cert is added to the user $user1"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_useraddcert_0019.out"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-del $user1 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\""
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-del $user1 \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_ca_0019.out" \
                    0 \
                    "Delete certs assigned to $user1 with i18n chars"
	rlAssertGrep "Deleted certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_ca_0019.out"

        rlPhaseEnd

##### Delete certs asigned to a user - using a cert not assigned to any role ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0020: Delete certs assigned to a user - using a cert not assigned to any role should fail"
                i=1
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n $user1$i-pkcs10 -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authenticating using a cert not assigned to any role"

		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n $user1$i-crmf -c $CERTDB_DIR_PASSWORD user-cert-del $user1 '2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US'"
                errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authenticating using a cert not assigned to any role"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

        ##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail #####

rlPhaseStartTest "pki_user_cli_user_cert-del-CA-0021: Add an Admin user \"admin_user\", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail"
        k=21
        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"Admin User\" --password=Secret123 admin_user"

        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-add Administrators admin_user > $TmpDir/pki-user-cert-delete-ca-group0021.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"Admin User1\" --password=Secret123 admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-add Administrators admin_user1 > $TmpDir/pki-user-cert-delete-ca-group00211.out"

	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Admin User\" subject_uid:\"admin_user\" subject_email:admin_user@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_valid_serialNumber_pkcs10=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0021pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0021pkcs10.out > $TmpDir/pki_user_cert_del-CA_validcert_0021pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Admin User1\" subject_uid:\"admin_user1\" subject_email:admin_user1@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_valid_serialNumber_crmf=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_del-CA_encoded_0021crmf.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_del-CA_encoded_0021crmf.out > $TmpDir/pki_user_cert_del-CA_validcert_0021crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_del-CA_validcert_0021pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_del-CA_validcert_0021pkcs10.pem  > $TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out" \
                            0 \
                            "Cert is added to the user admin_user"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out"
        rlAssertGrep "Subject: UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021.out"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"CA Signing Certificate - $(eval echo \$${prefix}_DOMAIN) Security Domain\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
	rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin_user-pkcs10\" -i $TmpDir/pki_user_cert_del-CA_validcert_0021pkcs10.pem  -t "u,u,u""
        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin_user-pkcs10 \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -c $TEMP_NSS_DB_PASSWD \
                            user-add --fullName=\"New Test User3\" new_test_user3"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin_user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"New Test User3\" new_test_user3 > $TmpDir/pki_user_cert_delete_CA_useradd_0021.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user3\"" "$TmpDir/pki_user_cert_delete_CA_useradd_0021.out"
        rlAssertGrep "User ID: new_test_user3" "$TmpDir/pki_user_cert_delete_CA_useradd_0021.out"
        rlAssertGrep "Full name: New Test User3" "$TmpDir/pki_user_cert_delete_CA_useradd_0021.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del admin_user \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del admin_user \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_CA_0021.out" \
                        0 \
                        "Delete cert assigned to admin_user"
                rlAssertGrep "Deleted certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_0021.out"

	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $TEMP_NSS_DB -n admin_user-pkcs10 -c $TEMP_NSS_DB_PASSWD user-add --fullName='New Test User5' new_test_user5"
        rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user-pkcs10 after deleting the cert from the user"


        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add admin_user1 --input $TmpDir/pki_user_cert_del-CA_validcert_0021crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add admin_user1 --input $TmpDir/pki_user_cert_del-CA_validcert_0021crmf.pem  > $TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out" \
                            0 \
                            "Cert is added to the user admin_user1"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out"
        rlAssertGrep "Subject: UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_delete_CA_useraddcert_0021crmf.out"
	rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin_user1-crmf\" -i $TmpDir/pki_user_cert_del-CA_validcert_0021crmf.pem  -t "u,u,u""
        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin_user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"New Test User4\" new_test_user4"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin_user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"New Test User4\" new_test_user4 > $TmpDir/pki_user_cert_delete_CA_useradd_0021crmf.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user1"
        rlAssertGrep "Added user \"new_test_user4\"" "$TmpDir/pki_user_cert_delete_CA_useradd_0021crmf.out"
        rlAssertGrep "User ID: new_test_user4" "$TmpDir/pki_user_cert_delete_CA_useradd_0021crmf.out"
        rlAssertGrep "Full name: New Test User4" "$TmpDir/pki_user_cert_delete_CA_useradd_0021crmf.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del admin_user1 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del admin_user1 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_CA_00212.out" \
                        0 \
                        "Delete cert assigned to admin_user1"
                rlAssertGrep "Deleted certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_00212.out"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $TEMP_NSS_DB -n admin_user1-crmf -c $TEMP_NSS_DB_PASSWD user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user1-crmf after deleting the cert from the user"
	rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-del Administrators admin_user"

        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-del Administrators admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-del admin_user"

        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-del admin_user1"

rlPhaseEnd

        ##### Add an Agent user "agent_user", add a cert to agent_user, approve a cert request as agent_user" #####

rlPhaseStartTest "pki_user_cli_user_cert-delete-CA-0022: Add an Agent user agent_user, add a cert to agent_user, approve a cert request as agent_user, delete the cert from agent_user and approving a new cert request should fail"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"Agent User\" --type=\"Certificate Manager Agents\" agent_user"

                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-add \"Certificate Manager Agents\" agent_user > $TmpDir/pki-user-cert-delete-ca-group0020.out"

		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"Agent User1\" --type=\"Certificate Manager Agents\" agent_user1"

                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-add \"Certificate Manager Agents\" agent_user1 > $TmpDir/pki-user-cert-delete-ca-group00201.out"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"Agent User\" subject_uid:agent_user subject_email:agent_user@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_delete-CA_encoded_0022pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_delete-CA_encoded_0022pkcs10.out > $TmpDir/pki_user_cert_del-CA_validcert_0022pkcs10.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"Agent User1\" subject_uid:agent_user1 subject_email:agent_user1@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_del-CA_encoded_0022crmf.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_del-CA_encoded_0022crmf.out > $TmpDir/pki_user_cert_del-CA_validcert_0022crmf.pem"

		rlRun "certutil -d $TEMP_NSS_DB -A -n \"agentuserpkcs10\" -i $TmpDir/pki_user_cert_del-CA_validcert_0022pkcs10.pem  -t "u,u,u""
                rlRun "certutil -d $TEMP_NSS_DB -A -n \"agent-user1-crmf\" -i $TmpDir/pki_user_cert_del-CA_validcert_0022crmf.pem  -t "u,u,u""

                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                           -t ca \
                            user-cert-add agent_user --input $TmpDir/pki_user_cert_del-CA_validcert_0022pkcs10.pem  > $TmpDir/pki_user_cert_delete_CA_useraddcert_0022.out" \
                           0 \
                            "Add cert to agent_user"

		rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                           -t ca \
                            user-cert-add agent_user1 --input $TmpDir/pki_user_cert_del-CA_validcert_0022crmf.pem  > $TmpDir/pki_user_cert_delete_CA_useraddcert_0022.out" \
                           0 \
                            "Add cert to agent_user1"

		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
                organizationalunit: organization: country: archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
                certdb_nick:\"agentuserpkcs10\" cert_info:$cert_info" 0 "Successfully approved a cert request as agentuserpkcs10"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
                organizationalunit: organization: country: archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
                certdb_nick:\"agent-user1-crmf\" cert_info:$cert_info" 0 "Successfully approved a cert request as agent-user1-crmf"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del agent_user \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del agent_user \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_CA_0022.out" \
                        0 \
                        "Delete cert assigned to agent_user"
                rlAssertGrep "Deleted certificate \"2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_0022.out"
		
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del agent_user1 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-del agent_user1 \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_del_CA_0022crmf.out" \
                        0 \
                        "Delete cert assigned to agent_user1"
                rlAssertGrep "Deleted certificate \"2;$decimal_valid_serialNumber_crmf;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_del_CA_0022crmf.out"

                rlRun "run_req_action_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agentuserpkcs10\" cert_info:$cert_info" 0 "Cert approval by agentuserpkcs10 should fail"

        rlAssertGrep "PKIException: Unauthorized" "$cert_info"

        rlRun "run_req_action_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agent-user1-crmf\" cert_info:$cert_info" 0 "Cert approval by agent-user1-crmf should fail"

        rlAssertGrep "PKIException: Unauthorized" "$cert_info"

		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-del \"Certificate Manager Agents\" agent_user"


        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-del agent_user"

	rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            group-member-del \"Certificate Manager Agents\" agent_user1"


        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                -h $SUBSYSTEM_HOST \
                -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-del agent_user1"

	rlPhaseEnd


#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 3 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
	j=3
        while [ $j -lt 5 ] ; do
               eval usr="new_test_user$j"
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  $usr > $TmpDir/pki-user-del-ca-new-user-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-new-user-00$j.out"
                let j=$j+1
        done
	#Delete temporary directory
        rlRun "popd"
        #rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd

}
