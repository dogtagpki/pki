#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-cert-find    Finding the certs assigned to users in the pki ca subsystem.
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
#pki-user-cli-role-user-create-tests should be first executed prior to pki-user-cli-user-cert-find-ca.sh
######################################################################################

run_pki-user-cli-user-cert-find-ca_tests(){

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
ca_instance_created="False"
if [ "$TOPO9" = "TRUE" ] ; then
        prefix=$subsystemId
	ca_instance_created=$(eval echo \$${subsystemId}_INSTANCE_CREATED_STATUS)
elif [ "$MYROLE" = "MASTER" ] ; then
        if [[ $subsystemId == SUBCA* ]]; then
                prefix=$subsystemId
		ca_instance_created=$(eval echo \$${subsystemId}_INSTANCE_CREATED_STATUS)
        else
                prefix=ROOTCA
		ca_instance_created=$ROOTCA_INSTANCE_CREATED_STATUS
        fi
else
        prefix=$MYROLE
	ca_instance_created=$(eval echo \$${MYROLE}_INSTANCE_CREATED_STATUS)
fi

SUBSYSTEM_HOST=$(eval echo \$${MYROLE})

if [ "$ca_instance_created" = "TRUE" ] ;  then

	#####Create temporary dir to save the output files #####
    rlPhaseStartSetup "pki_user_cli_user_cert-find-ca-startup: Create temporary directory"
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
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
##### pki_user_cli_user_cert_find_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-find-configtest-001: pki user-cert-find configuration test"
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-cert-find --help > $TmpDir/pki_user_cert_find_cfg.out 2>&1" \
                0 \
                "User cert find configuration"
        rlAssertGrep "usage: user-cert-find <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_find_cfg.out"
        rlAssertGrep "--size <size>     Page size" "$TmpDir/pki_user_cert_find_cfg.out"
        rlAssertGrep "--start <start>   Page start" "$TmpDir/pki_user_cert_find_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_user_cert_find_cfg.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Find certs assigned to a CA user - with userid argument - this user has only a single page of certs ####
	
rlPhaseStartTest "pki_user_cli_user_cert-find-CA-002: Find the certs of a user in CA --userid only - single page of certs"
        i=0
        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"$user1fullname\" $user1"
        while [ $i -lt 2 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_find-CA_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_002pkcs10$i.out > $TmpDir/pki_user_cert_find-CA_validcert_002pkcs10$i.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_find-CA_encoded_002crmf$i.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_002crmf$i.out > $TmpDir/pki_user_cert_find-CA_validcert_002crmf$i.pem"

                serialhexuser1[$i]=$cert_serialNumber_pkcs10
                serialdecuser1[$i]=$decimal_valid_serialNumber_pkcs10

                serialhexuser1_crmf[$i]=$cert_serialNumber_crmf
                serialdecuser1_crmf[$i]=$decimal_valid_serialNumber_crmf
                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find-CA_validcert_002pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find-CA_validcert_002pkcs10$i.pem  > $TmpDir/useraddcert__002_$i.out" \
                            0 \
                            "Cert is added to the user $user1"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find-CA_validcert_002crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find-CA_validcert_002crmf$i.pem  > $TmpDir/useraddcert__002_$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                let i=$i+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 > $TmpDir/pki_user_cert_find_ca_002.out" \
                    0 \
                    "Finding certs assigned to $user1"
        let numcertsuser1=($i*2)
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_002.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_002.out"
        i=0
        while [ $i -lt 2 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Serial Number: ${serialhexuser1[$i]}" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_002.out"

                rlAssertGrep "Cert ID: 2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Serial Number: ${serialhexuser1_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_002.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_002.out"

               let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with userid argument - this user has multiple pages of certs ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-003: Find the certs of a user in CA --userid only - multiple pages of certs"
        i=0
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   user-add --fullName=\"$user2fullname\" $user2"
        while [ $i -lt 12 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname$(($i+1))\" subject_uid:$user2$(($i+1)) subject_email:$user2$(($i+1))@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_find-CA_encoded_003pkcs10$i.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_003pkcs10$i.out > $TmpDir/pki_user_cert_find-CA_validcert_003pkcs10$i.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname$(($i+1))\" subject_uid:$user2$(($i+1)) subject_email:$user2$(($i+1))@example.org \
        organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
        target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_find-CA_encoded_003crmf$i.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_003crmf$i.out > $TmpDir/pki_user_cert_find-CA_validcert_003crmf$i.pem"

                serialhexuser2[$i]=$cert_serialNumber_pkcs10
                serialdecuser2[$i]=$decimal_valid_serialNumber_pkcs10
                serialhexuser2_crmf[$i]=$cert_serialNumber_crmf
                serialdecuser2_crmf[$i]=$decimal_valid_serialNumber_crmf
	
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_find-CA_validcert_003pkcs10$i.pem  > $TmpDir/useraddcert__003_$i.out" \
                            0 \
                            "Cert is added to the user $user2"
		rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_find-CA_validcert_003crmf$i.pem  > $TmpDir/useraddcert__003crmf_$i.out" \
                            0 \
                            "Cert is added to the user $user2"
                let i=$i+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
		   user-cert-find $user2 > $TmpDir/pki_user_cert_find_ca_003.out" \
                    0 \
                    "Finding certs assigned to $user2"
	let numcertsuser2=($i*2)
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_003.out"
        i=0
        while [ $i -lt 10 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$i]}" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_003.out"
	rlAssertGrep "Cert ID: 2;${serialdecuser2_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Serial Number: ${serialhexuser2_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_003.out"

                let i=$i+1
        done
	rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlPhaseEnd

##### Find certs assigned to a CA user - with userid argument - user id does not exist ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-004: Find the certs of a user in CA --userid only - user does not exist"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-find tuser"
        errmsg="UserNotFoundException: User tuser not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - User not found message should be thrown when finding certs assigned to a user that does not exist"
rlPhaseEnd

##### Find certs assigned to a CA user - with userid argument - no certs added to the user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-005: Find the certs of a user in CA --userid only - no certs added to the user"

	rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-add $user3 --fullName=\"$user3fullname\""
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user3"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user3 > $TmpDir/pki_user_cert_find_ca_005.out" \
                    0 \
                    "Finding certs assigned to $user3"
        rlAssertGrep "0 entries matched" "$TmpDir/pki_user_cert_find_ca_005.out"

rlPhaseEnd

##### Find certs assigned to a CA user - with --size option having an argument that is less than the actual number of certs assigned to the user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-006: Find the certs of a user in CA --size - a number less than the actual number of certs"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --size=2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --size=2 > $TmpDir/pki_user_cert_find_ca_006.out" \
                    0 \
                    "Finding certs assigned to $user1 - --size=2"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_006.out"
	rlAssertGrep "Number of entries returned 2" "$TmpDir/pki_user_cert_find_ca_006.out"
	i=0
        	rlAssertGrep "Cert ID: 2;${serialdecuser1[0]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Serial Number: ${serialhexuser1[0]}" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_006.out"
		rlAssertGrep "Cert ID: 2;${serialdecuser1_crmf[0]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_006.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_006.out"
                rlAssertGrep "Serial Number: ${serialhexuser1_crmf[0]}" "$TmpDir/pki_user_cert_find_ca_006.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_006.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_006.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=0 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-007: Find the certs of a user in CA --size=0"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --size=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --size=0 > $TmpDir/pki_user_cert_find_ca_007.out" \
                    0 \
                    "Finding certs assigned to $user1 - --size=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_007.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_user_cert_find_ca_007.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=-1 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-008: Find the certs of a user in CA --size=-1"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-find $user1 --size=-1"
        errmsg="The value for size shold be greater than or equal to 0"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - the value for --size should not be less than 0"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size option having an argument that is greater than the actual number of certs assigned to the user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-009: Find the certs of a user in CA --size - a number greater than number of certs assigned to the user"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --size=50"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --size=50 > $TmpDir/pki_user_cert_find_ca_009.out" \
                    0 \
                    "Finding certs assigned to $user1 - --size=50"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_009.out"
	i=0
        while [ $i -lt 2 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Serial Number: ${serialhexuser1[$i]}" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
	rlAssertGrep "Cert ID: 2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Serial Number: ${serialhexuser1_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
                let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with --start option having an argument that is less than the actual number of certs assigned to the user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-010: Find the certs of a user in CA --start - a number less than the actual number of certs"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --start=2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --start=2 > $TmpDir/pki_user_cert_find_ca_010.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=2"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_010.out"
	let newnumcerts=$numcertsuser1-2
        rlAssertGrep "Number of entries returned $newnumcerts" "$TmpDir/pki_user_cert_find_ca_010.out"
	i=1
	 while [ $i -lt 2 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Serial Number: ${serialhexuser1[$i]}" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_010.out"
		rlAssertGrep "Cert ID: 2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Serial Number: ${serialhexuser1_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_010.out"
		let i=$i+1
	done
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-011: Find the certs of a user in CA --start=0"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --start=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --start=0 > $TmpDir/pki_user_cert_find_ca_011.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_011.out"
	i=0
        while [ $i -lt 2 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Serial Number: ${serialhexuser1[$i]}" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_011.out"
	rlAssertGrep "Cert ID: 2;${serialdecuser1_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Serial Number: ${serialhexuser1_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_011.out"
                let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0, the user has multiple pages of certs ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-012: Find the certs of a user in CA --start=0 - multiple pages"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user2 --start=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user2 --start=0 > $TmpDir/pki_user_cert_find_ca_012.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=0"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_user_cert_find_ca_012.out"
	i=0
        while [ $i -lt 10 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$i]}" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_012.out"
	rlAssertGrep "Cert ID: 2;${serialdecuser2_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Serial Number: ${serialhexuser2_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_012.out"

                let i=$i+1
        done
rlPhaseEnd
##### Find certs assigned to a CA user - with --start=-1 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-013: Find the certs of a user in CA --start=-1"
	 command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-find $user1 --start=-1"
        rlLog "Executing : $command"
        errmsg="The value for start shold be greater than or equal to 0"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - the value for --start should not be less than 0"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/929"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=50 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-014: Find the certs of a user in CA --start - a number greater than number of certs assigned to the user"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --start=50"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --start=50 > $TmpDir/pki_user_cert_find_ca_014.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=50"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_014.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_user_cert_find_ca_014.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0 and size=0 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-015: Find the certs of a user in CA --start=0 --size=0"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1 --start=0 --size=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 --start=0 --size=0 > $TmpDir/pki_user_cert_find_ca_015.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=0 --size=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_015.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_user_cert_find_ca_015.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=1 and --start=1 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-016-tier1: Find the certs of a user in CA --start=1 --size=1"
	newuserid=newuser
	newuserfullname="New User"
	i=0
        rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"$newuserfullname\" $newuserid"
        while [ $i -lt 2 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname$(($i+1))\" subject_uid:$newuserid$(($i+1)) subject_email:$newuserid$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_find-CA_encoded_0016pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_0016pkcs10.out > $TmpDir/pki_user_cert_find-CA_validcert_0016pkcs10$i.pem"
                serialhexuser1[$i]=$cert_serialNumber_pkcs10
                serialdecuser1[$i]=$decimal_valid_serialNumber_pkcs10

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname$(($i+1))\" subject_uid:$newuserid$(($i+1)) subject_email:$newuserid$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_crmf --encoded > $TmpDir/pki_user_cert_find-CA_encoded_0016crmf.out" 0 "Executing pki cert-show $cert_serialNumber_crmf"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_0016crmf.out > $TmpDir/pki_user_cert_find-CA_validcert_0016crmf$i.pem"
                serialhexuser1_crmf[$i]=$cert_serialNumber_crmf
                serialdecuser1_crmf[$i]=$decimal_valid_serialNumber_crmf
                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $newuserid --input $TmpDir/pki_user_cert_find-CA_validcert_0016pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $newuserid --input $TmpDir/pki_user_cert_find-CA_validcert_0016pkcs10$i.pem  > $TmpDir/useraddcert__0016_$i.out" \
                            0 \
                            "Cert is added to the user $newuserid"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $newuserid --input $TmpDir/pki_user_cert_find-CA_validcert_0016crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $newuserid --input $TmpDir/pki_user_cert_find-CA_validcert_0016crmf$i.pem  > $TmpDir/useraddcert__0016_$i.out" \
                            0 \
                            "Cert is added to the user $newuserid"
                let i=$i+1
        done

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $newuserid --start=1 --size=1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $newuserid --start=1 --size=1 > $TmpDir/pki_user_cert_find_ca_016.out" \
                    0 \
                    "Finding certs assigned to $newuserid - --start=1 --size=1"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki_user_cert_find_ca_016.out"
	i=1
	rlAssertGrep "Cert ID: 2;${serialdecuser1_crmf[0]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid$i,E=$newuserid$i@example.org,CN=$newuserfullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Serial Number: ${serialhexuser1_crmf[0]}" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Subject: UID=$newuserid$i,E=$newuserid$i@example.org,CN=$newuserfullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_016.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-del $newuserid"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=-1 and size=-1 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-017: Find the certs of a user in CA --start=-1 --size=-1"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-find $user1 --start=-1 --size=-1"
        errmsg="The value for start and size should be greater than or equal to 0"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - the value for --size and --start should not be less than 0"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/929"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=20 and size=20 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-018: Find the certs of a user in CA --start --size equal to page size - default page size=20 entries"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user2 --start=20 --size=20"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user2 --start=20 --size=20 > $TmpDir/pki_user_cert_find_ca_018.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=20 --size=20"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Number of entries returned 4" "$TmpDir/pki_user_cert_find_ca_018.out"
	i=10
        while [ $i -lt 12 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$i]}" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_018.out"
	rlAssertGrep "Cert ID: 2;${serialdecuser2_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Serial Number: ${serialhexuser2_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_018.out"
                let i=$i+1
        done 
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0 and --size has an argument greater that default page size (20 certs) ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-019: Find the certs of a user in CA --start=0 --size greater than default page size - default page size=20 entries"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user2 --start=0 --size=22"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user2 --start=0 --size=22 > $TmpDir/pki_user_cert_find_ca_019.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=0 --size=22"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Number of entries returned 22" "$TmpDir/pki_user_cert_find_ca_019.out"
        i=0
        while [ $i -lt 11 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$i]}" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_019.out"
	rlAssertGrep "Cert ID: 2;${serialdecuser2_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Serial Number: ${serialhexuser2_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_019.out"
                let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=1 and --start has a value greater than the default page size ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-020: Find the certs of a user in CA --start - values greater than default page size --size=1"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user2 --start=22 --size=1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user2 --start=22 --size=1 > $TmpDir/pki_user_cert_find_ca_020.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=22 --size=1"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki_user_cert_find_ca_020.out"
        i=11
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$i]}" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_020.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start has argument greater than default page size and size has an argument greater than the certs available from the --start value ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-021: Find the certs of a user in CA --start - values greater than default page size --size - value greater than the available number of certs from the start value"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user2 --start=40 --size=10"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user2 --start=22 --size=10 > $TmpDir/pki_user_cert_find_ca_021.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=40 --size=10"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_021.out"
        rlAssertGrep "Number of entries returned 2" "$TmpDir/pki_user_cert_find_ca_021.out"
        i=11
	while [ $i -lt 12 ] ; do
        	rlAssertGrep "Cert ID: 2;${serialdecuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Serial Number: ${serialhexuser2[$i]}" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_021.out"
		rlAssertGrep "Cert ID: 2;${serialdecuser2_crmf[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_021.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_021.out"
                rlAssertGrep "Serial Number: ${serialhexuser2_crmf[$i]}" "$TmpDir/pki_user_cert_find_ca_021.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_021.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_021.out"

		let i=$i+1
	done
rlPhaseEnd

##### Tests to find certs assigned to CA users - i18n characters ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-022: Find certs assigned to user - Subject Name has i18n Characters"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                organizationalunit:Engineering organization:Example country:US archive:false req_profile:caUserCert \
                target_host:$SUBSYSTEM_HOST protocol: port:$(eval echo \$${subsystemId}_UNSECURE_PORT) cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $cert_serialNumber_pkcs10 --encoded > $TmpDir/pki_user_cert_find-CA_encoded_0022pkcs10.out" 0 "Executing pki cert-show $cert_serialNumber_pkcs10"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find-CA_encoded_0022pkcs10.out > $TmpDir/pki_user_cert_find-CA_validcert_0022pkcs10.pem"

        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find-CA_validcert_0022pkcs10.pem  > $TmpDir/useraddcert__0022.out" \
                            0 \
                            "Cert is added to the user $user1"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n ${prefix}_adminV \
                              -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                              -t ca \
                               user-cert-find $user1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                   user-cert-find $user1 > $TmpDir/pki_user_cert_find_ca_022.out" \
                    0 \
                    "Finding certs assigned to $user1"
        let numcertsuser1=$numcertsuser1+1
        i=4
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_022.out"

        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_022.out"

        rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a valid agent user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-023: Find the certs of a user as CA_agentV should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as a valid agent user"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a valid auditor user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-024: Find the certs of a user as CA_auditorV should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as a valid auditor user"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a admin user with expired cert ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-025: Find the certs of a user as CA_adminE"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        errmsg="ForbiddenException: Authorization Error"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an admin user with expired cert"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as an agent user with expired cert ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-026: Find the certs of a user as CA_agentE"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        errmsg="ForbiddenException: Authorization Error"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an agent user with expired cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as an admin user with revoked cert  ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-027: Find the certs of a user as CA_adminR should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an admin user with a revoked cert"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as an agent user with revoked cert ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-028: Find the certs of a user as CA_agentR should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an agent user with a revoked cert"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a user whose CA cert has not been trusted ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-029: Find the certs of a user as role_user_UTCA should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as role_user_UTCA"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a user whose CA cert has not been trusted ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-030: Find the certs of a user as role_user_UTCA should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as role_user_UTCA"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a valid operator user ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-031: Find the certs of a user as CA_operatorV should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as CA_operatorV"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a user not associated with any role ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-032: Find the certs of a user as a user not associated with any role, should fail"
	command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as a user not assigned to any role"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

#### Find certs assigned to a CA user - userid is missing ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-033-tier1: Find the certs of a user missing User ID"
        command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-find"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when no User ID provided"
rlPhaseEnd

#### Find certs assigned to a CA user - user id missing with --start and --size options ###

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-034: Find the certs of a user missing User ID with --size and --start options"
        command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-cert-find --size=1 --start=1"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when no User ID provided"
rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

	j=1
        while [ $j -lt 4 ] ; do
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

	#Delete temporary directory
	rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
 else
	rlLog "CA subsystem is not installed"
 fi
}
