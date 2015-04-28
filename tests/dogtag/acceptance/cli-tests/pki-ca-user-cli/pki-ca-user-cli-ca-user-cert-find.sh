#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-user-cli
#   Description: PKI ca-user-cert-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-user-cli-ca-user-cert-find    Finding the certs assigned to users in the pki ca subsystem.
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
#create_role_users.sh should be first executed prior to pki-ca-user-cli-ca-user-cert-find-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-ca-user-cli-ca-user-cert-find_tests(){

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

if [ "$ca_instance_created" = "TRUE" ] ;  then
 CA_HOST=$(eval echo \$${MYROLE})
 CA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)

	#####Create temporary dir to save the output files#####
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
local exp="$TmpDir/expfile.out"
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
eval ${subsystemId}_signing_cert_subj=${subsystemId}_SIGNING_CERT_SUBJECT_NAME
admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
##### pki_user_cli_user_cert_find_ca-configtest ####
     rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-configtest-001: pki ca-user-cert-find configuration test"
        rlRun "pki ca-user-cert-find --help > $TmpDir/pki_ca_user_cert_find_cfg.out 2>&1" \
                0 \
                "User cert find configuration"
        rlAssertGrep "usage: ca-user-cert-find <User ID> \[OPTIONS...\]" "$TmpDir/pki_ca_user_cert_find_cfg.out"
        rlAssertGrep "--size <size>     Page size" "$TmpDir/pki_ca_user_cert_find_cfg.out"
        rlAssertGrep "--start <start>   Page start" "$TmpDir/pki_ca_user_cert_find_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_ca_user_cert_find_cfg.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

     ##### Find certs assigned to a CA user - with userid argument - this user has only a single page of certs ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-002: Find the certs of a user in CA --userid only - single page of certs"
        i=0
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$user1fullname\" $user1"
        while [ $i -lt 2 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
	        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
        	organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
	        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        	certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
	        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
		serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
		serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
	        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        	rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_002pkcs10$i.out > $TmpDir/pki_ca_user_cert_find_validcert_002pkcs10$i.pem"

		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
		serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
                serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_002crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_002crmf$i.out > $TmpDir/pki_ca_user_cert_find_validcert_002crmf$i.pem"

                rlLog "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                   	   -c $CERTDB_DIR_PASSWORD \
                   	   -h $CA_HOST \
                   	   -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_find_validcert_002pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_find_validcert_002pkcs10$i.pem  > $TmpDir/useraddcert__002_$i.out" \
                            0 \
                            "Cert is added to the user $user1"

                rlLog "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_find_validcert_002crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_find_validcert_002crmf$i.pem  > $TmpDir/useraddcert__002_$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                let i=$i+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
			      -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1"
        rlRun "pki -d $CERTDB_DIR/ \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 > $TmpDir/pki_ca_user_cert_find_002.out" \
                    0 \
                    "Finding certs assigned to $user1"
        let numcertsuser1=($i*2)
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_002.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_ca_user_cert_find_002.out"
        i=0
        while [ $i -lt 2 ] ; do
		rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user1[$i]}" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_002.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser1[$i]}" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_002.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_002.out"

               let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with userid argument - this user has multiple pages of certs ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-003: Find the certs of a user in CA --userid only - multiple pages of certs"
	i=0
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$user2fullname\" $user2"
        while [ $i -lt 12 ] ; do
                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"$user2fullname$(($i+1))\" subject_uid:$user2$(($i+1)) subject_email:$user2$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                serialhexpkcs10user2[$i]=$valid_pkcs10_serialNumber
                serialdecimalpkcs10user2[$i]=$valid_decimal_pkcs10_serialNumber
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_003pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_003pkcs10$i.out > $TmpDir/pki_ca_user_cert_find_validcert_003pkcs10$i.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$user2fullname$(($i+1))\" subject_uid:$user2$(($i+1)) subject_email:$user2$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                serialhexcrmfuser2[$i]=$valid_crmf_serialNumber
                serialdecimalcrmfuser2[$i]=$valid_decimal_crmf_serialNumber
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_003crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_003crmf$i.out > $TmpDir/pki_ca_user_cert_find_validcert_003crmf$i.pem"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_ca_user_cert_find_validcert_003pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_ca_user_cert_find_validcert_003pkcs10$i.pem  > $TmpDir/useraddcert__003_$i.out" \
                            0 \
                            "Cert is added to the user $user2"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_ca_user_cert_find_validcert_003crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_ca_user_cert_find_validcert_003crmf$i.pem  > $TmpDir/useraddcert__003_$i.out" \
                            0 \
                            "Cert is added to the user $user2"
                let i=$i+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user2 > $TmpDir/pki_ca_user_cert_find_003.out" \
                    0 \
                    "Finding certs assigned to $user2"
        let numcertsuser2=($i*2)
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_ca_user_cert_find_003.out"
        i=0
        while [ $i -lt 10 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user2[$i]}" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_003.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser2[$i]}" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_003.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_003.out"

               let i=$i+1
        done
	rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_ca_user_cert_find_003.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with userid argument - user id does not exist ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-004: Find the certs of a user in CA --userid only - user does not exist"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-find tuser"
        errmsg="UserNotFoundException: User tuser not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - User not found message should be thrown when finding certs assigned to a user that does not exist"
rlPhaseEnd

##### Find certs assigned to a CA user - with userid argument - no certs added to the user ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-005: Find the certs of a user in CA --userid only - no certs added to the user"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$user3fullname\" $user3"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user3"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user3 > $TmpDir/pki_ca_user_cert_find_005.out" \
                    0 \
                    "Finding certs assigned to $user3"
	rlAssertGrep "0 entries matched" "$TmpDir/pki_ca_user_cert_find_005.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size option having an argument that is less than the actual number of certs assigned to the user ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-006: Find the certs of a user in CA --size - a number less than the actual number of certs"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1 --size=2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --size=2 > $TmpDir/pki_ca_user_cert_find_006.out" \
                    0 \
                    "Finding certs assigned to $user1"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_006.out"
	i=0
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user1[0]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user1[0]}" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_006.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser1[0]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser1[0]}" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_006.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_006.out"

        rlAssertGrep "Number of entries returned 2" "$TmpDir/pki_ca_user_cert_find_006.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=0 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-007: Find the certs of a user in CA --size=0"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1 --size=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --size=0 > $TmpDir/pki_ca_user_cert_find_007.out" \
                    0 \
                    "Finding certs assigned to $user1"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_007.out"
	rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_ca_user_cert_find_007.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=-1 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-008: Find the certs of a user in CA --size=-1"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-find $user1 --size=-1"
        errmsg="The value for size shold be greater than or equal to 0"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - the value for --size should not be less than 0"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size option having an argument that is greater than the actual number of certs assigned to the user ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-009: Find the certs of a user in CA --size - a number greater than number of certs assigned to the user"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1 --size=50"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --size=50 > $TmpDir/pki_ca_user_cert_find_009.out" \
                    0 \
                    "Finding certs assigned to $user1 --size=50"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_009.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_ca_user_cert_find_009.out"
        i=0
        while [ $i -lt 2 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user1[$i]}" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_009.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser1[$i]}" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_009.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_009.out"

               let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with --start option having an argument that is less than the actual number of certs assigned to the user ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-0010: Find the certs of a user in CA --start - a number less than the actual number of certs"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $ruser1 --start=2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --start=2 > $TmpDir/pki_ca_user_cert_find_0010.out" \
                    0 \
                    "Finding certs assigned to $user1"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_0010.out"
	let newnumcerts=$numcertsuser1-2
        i=1
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user1[1]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user1[1]}" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0010.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser1[1]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser1[1]}" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0010.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0010.out"

        rlAssertGrep "Number of entries returned $newnumcerts" "$TmpDir/pki_ca_user_cert_find_0010.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-011: Find the certs of a user in CA --start=0"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1 --start=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --start=0 > $TmpDir/pki_ca_user_cert_find_0011.out" \
                    0 \
                    "Finding certs assigned to $user1 --start=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_0011.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_ca_user_cert_find_0011.out"
        i=0
        while [ $i -lt 2 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user1[$i]}" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0011.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser1[$i]}" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0011.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0011.out"

               let i=$i+1
        done
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0, the user has multiple pages of certs ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-012: Find the certs of a user in CA --start=0 - multiple pages"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user2 --start=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user2 --start=0 > $TmpDir/pki_ca_user_cert_find_0012.out" \
                    0 \
                    "Finding certs assigned to $user2 --start=0"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_ca_user_cert_find_0012.out"
        i=0
        while [ $i -lt 10 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user2[$i]}" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0012.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser2[$i]}" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0012.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0012.out"

               let i=$i+1
        done
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_ca_user_cert_find_0012.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=-1 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-0013: Find the certs of a user in CA --start=-1"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-find $user1 --start=-1"
        errmsg="The value for size shold be greater than or equal to 0"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - the value for --start should not be less than 0"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=50 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-0014: Find the certs of a user in CA --start=50"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1 --start=50"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --start=50 > $TmpDir/pki_ca_user_cert_find_0014.out" \
                    0 \
                    "Finding certs assigned to $user1 --start=50"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_0014.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_ca_user_cert_find_0014.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0 and size=0 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-0015: Find the certs of a user in CA --start=0 and size=0"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1 --start=0 --size=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user1 --start=0 --size=0 > $TmpDir/pki_ca_user_cert_find_0015.out" \
                    0 \
                    "Finding certs assigned to $user1 --start=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_0015.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_ca_user_cert_find_0015.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=1 and --start=1 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-0016: Find the certs of a user in CA --start=1 --size=1"
	newuserid=newuser
        newuserfullname="New User"
        i=0
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$newuserfullname\" $newuserid"
        while [ $i -lt 2 ] ; do
                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname$(($i+1))\" subject_uid:$newuserid$(($i+1)) subject_email:$newuserid$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                serialhexpkcs10newuser[$i]=$valid_pkcs10_serialNumber
                serialdecimalpkcs10newuser[$i]=$valid_decimal_pkcs10_serialNumber
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_0016pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_0016pkcs10$i.out > $TmpDir/pki_ca_user_cert_find_validcert_0016pkcs10$i.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$newuserfullname$(($i+1))\" subject_uid:$newuserid$(($i+1)) subject_email:$newuserid$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                serialhexcrmfnewuser[$i]=$valid_crmf_serialNumber
                serialdecimalcrmfnewuser[$i]=$valid_decimal_crmf_serialNumber
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_0016crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_0016crmf$i.out > $TmpDir/pki_ca_user_cert_find_validcert_0016crmf$i.pem"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $newuserid --input $TmpDir/pki_ca_user_cert_find_validcert_0016pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $newuserid --input $TmpDir/pki_ca_user_cert_find_validcert_0016pkcs10$i.pem  > $TmpDir/useraddcert__0016_$i.out" \
                            0 \
                            "Cert is added to the user $newuserid"

                rlLog "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
			   ca-user-cert-add $newuserid --input $TmpDir/pki_ca_user_cert_find_validcert_0016crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $newuserid --input $TmpDir/pki_ca_user_cert_find_validcert_0016crmf$i.pem  > $TmpDir/useraddcert__0016_$i.out" \
                            0 \
                            "Cert is added to the user $newuserid"
                let i=$i+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $newuserid"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $newuserid > $TmpDir/pki_ca_user_cert_find_0016.out" \
                    0 \
                    "Finding certs assigned to $newuserid"
        let numcertsuser1=($i*2)
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_0016.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_ca_user_cert_find_0016.out"
        i=0
        while [ $i -lt 2 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10newuser[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid$(($i+1)),E=$newuserid$(($i+1))@example.org,CN=$newuserfullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10newuser[$i]}" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Subject: UID=$newuserid$(($i+1)),E=$newuserid$(($i+1))@example.org,CN=$newuserfullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0016.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfnewuser[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$newuserid$(($i+1)),E=$newuserid$(($i+1))@example.org,CN=$newuserfullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfnewuser[$i]}" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0016.out"
                rlAssertGrep "Subject: UID=$newuserid$(($i+1)),E=$newuserid$(($i+1))@example.org,CN=$newuserfullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0016.out"

               let i=$i+1
        done
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    user-del $newuserid"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=-1 and size=-1 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-0017: Find the certs of a user in CA --start=-1 and size=-1"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-find $user1 --start=-1 --size=-1"
        errmsg="The value for size and start should be greater than or equal to 0"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - the value for --start and --size should not be less than 0"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/929"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=20 and size=20 ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-018: Find the certs of a user in CA --start --size equal to page size - default page size=20 entries"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user2 --start=20 --size=20"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user2 --start=20 --size=20 > $TmpDir/pki_ca_user_cert_find_0018.out" \
                    0 \
                    "Finding certs assigned to $user2"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_ca_user_cert_find_0018.out"
        i=10
        while [ $i -lt 12 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user2[$i]}" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0018.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser2[$i]}" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0018.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0018.out"

               let i=$i+1
        done
        rlAssertGrep "Number of entries returned 4" "$TmpDir/pki_ca_user_cert_find_0018.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start=0 and --size has an argument greater that default page size (20 certs) ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-019: Find the certs of a user in CA --start=0 --size greater than default page size - default page size=20 entries"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user2 --start=0 --size=20"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user2 --start=0 --size=20 > $TmpDir/pki_ca_user_cert_find_0019.out" \
                    0 \
                    "Finding certs assigned to $user2"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_ca_user_cert_find_0019.out"
        i=0
        while [ $i -lt 10 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user2[$i]}" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0019.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser2[$i]}" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0019.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0019.out"

               let i=$i+1
        done
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_ca_user_cert_find_0019.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --size=1 and --start has a value greater than the default page size ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-020: Find the certs of a user in CA --start - values greater than default page size --size=1"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user2 --start=22 --size=1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user2 --start=22 --size=1 > $TmpDir/pki_ca_user_cert_find_0020.out" \
                    0 \
                    "Finding certs assigned to $user2"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_ca_user_cert_find_0020.out"
	i=11
	rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0020.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0020.out"
        rlAssertGrep "Serial Number: ${serialhexpkcs10user2[$i]}" "$TmpDir/pki_ca_user_cert_find_0020.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0020.out"
        rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0020.out"
	rlAssertGrep "Number of entries returned 1" "$TmpDir/pki_ca_user_cert_find_0020.out"
rlPhaseEnd

##### Find certs assigned to a CA user - with --start has argument greater than default page size and size has an argument greater than the certs available from the --start value ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-021: Find the certs of a user in CA --start - values greater than default page size --size - value greater than the available number of certs from the start value"
	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user2 --start=22 --size=10"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-find $user2 --start=22 --size=10 > $TmpDir/pki_ca_user_cert_find_0021.out" \
                    0 \
                    "Finding certs assigned to $user2"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_ca_user_cert_find_0021.out"
	i=11
        while [ $i -lt 12 ] ; do
		rlAssertGrep "Cert ID: 2;${serialdecimalpkcs10user2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Serial Number: ${serialhexpkcs10user2[$i]}" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0021.out"

                rlAssertGrep "Cert ID: 2;${serialdecimalcrmfuser2[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Serial Number: ${serialhexcrmfuser2[$i]}" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0021.out"
                rlAssertGrep "Subject: UID=$user2$(($i+1)),E=$user2$(($i+1))@example.org,CN=$user2fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0021.out"

		let i=$i+1
        done
rlPhaseEnd

##### Tests to find certs assigned to CA users - i18n characters ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-022: Find certs assigned to user - Subject Name has i18n Characters"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test_pkcs10@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_0022pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_0022pkcs10.out > $TmpDir/pki_ca_user_cert_find_validcert_0022pkcs10.pem"

                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test_crmf@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_find_encoded_0022crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_find_encoded_0022crmf.out > $TmpDir/pki_ca_user_cert_find_validcert_0022crmf.pem"

                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_find_validcert_0022pkcs10.pem  > $TmpDir/useraddcert__0022.out" \
                            0 \
                            "Cert is added to the user $user1"

                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_find_validcert_0022crmf.pem  > $TmpDir/useraddcert__0022.out" \
                            0 \
                            "Cert is added to the user $user1"
		let numcertsuser1=$numcertsuser1+2
		rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                              ca-user-cert-find $user1"
        	rlRun "pki -d $CERTDB_DIR/ \
                	   -n $(eval echo \$${subsystemId}_adminV_user) \
                	   -c $CERTDB_DIR_PASSWORD \
                   	-h $CA_HOST \
                  	 -p $CA_PORT \
                   	ca-user-cert-find $user1 > $TmpDir/pki_ca_user_cert_find_0022.out" \
                    	0 \
                   	 "Finding certs assigned to $user1"
	
		rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test_pkcs10@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Subject: UID=Örjan Äke,E=test_pkcs10@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0022.out"

                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test_crmf@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_ca_user_cert_find_0022.out"
                rlAssertGrep "Subject: UID=Örjan Äke,E=test_crmf@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_ca_user_cert_find_0022.out"
		rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_ca_user_cert_find_0022.out"
 	       rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_ca_user_cert_find_0022.out"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a valid agent user ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-023: Find the certs of a user as CA_agentV should fail"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as a valid agent user"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a valid auditor user ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-024: Find the certs of a user as CA_auditorV should fail"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as a valid auditor user"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a admin user with expired cert ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-025: Find the certs of a user as CA_adminE should fail"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an admin user with an expired cert"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as an admin user with revoked cert  ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-026: Find the certs of a user as CA_adminR should fail"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an admin user with a revoked cert"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as an agent user with revoked cert ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-027: Find the certs of a user as CA_agentR should fail"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an agent user with a revoked cert"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as an agent user with expired cert ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-028: Find the certs of a user as CA_agentE should fail"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an agent user with an expired cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a user whose CA cert has not been trusted ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-029: Find the certs of a user as role_user_UTCA should fail"
        command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as an admin user with untrusted cert"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a valid operator user ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-030: Find the certs of a user as operatorV should fail"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as operatorV"
rlPhaseEnd

#### Find certs assigned to a CA user - authenticating as a user not associated with any role ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-031: Find the certs of a user as a user not associated with any role, should fail"
        command="pki -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find $user2"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail when authenticated as a user not assigned to any role"
rlPhaseEnd

#### Find certs assigned to a CA user - userid is missing ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-032: Find the certs of a user - userid missing"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail without User ID"
rlPhaseEnd

#### Find certs assigned to a CA user - user id missing with --start and --size options ###

rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-find-033: Find the certs of a user - userid missing with --start and --size options"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT user-cert-find --start=1 --size=1"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - user-cert-find should fail without User ID"
rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 4 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                              -c $CERTDB_DIR_PASSWORD \
                              -h $CA_HOST \
                              -p $CA_PORT \
                           ca-user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
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
	rlLog "CA instance is not installed"
fi
}
