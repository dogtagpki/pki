#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-delete CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-cert-delete-tks    Delete the certs assigned to users in the pki tks subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2015 Red Hat, Inc. All rights reserved.
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
#create_role_users.sh should be first executed prior to pki-user-cli-user-cert-delete-tks.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-user-cli-user-cert-delete-tks_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	caId=$4
	CA_HOST=$5
        ##### Create temporary directory to save output files#####
	rlPhaseStartSetup "pki_user_cli_user_cert-del-tks-startup: Create temporary directory"
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
ca_signing_cert_subj_name=$(eval echo \$${caId}_SIGNING_CERT_SUBJECT_NAME)
	##### Tests to delete certs assigned to TKS users ####

	##### Delete certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-del-tks-002-tier1: Delete cert assigned to a user - valid UserID and CertID"
		i=0
        	rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"$user1fullname\" $user1"
		 while [ $i -lt 4 ] ; do
			rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
	                algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
        	        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                	target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
	                certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        	        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                	local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	                local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
        	        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
			serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
	                serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
                	rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
	                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_002pkcs10$i.out > $TmpDir/pki_tks_user_cert_del_validcert_002pkcs10$i.pem"

        	        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                	algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
	                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        	        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                	certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
	                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                	local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
	                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
			serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
	                serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
        	        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_002crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                	rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_002crmf$i.out > $TmpDir/pki_tks_user_cert_del_validcert_002crmf$i.pem"


			rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user1 --input $TmpDir/pki_tks_user_cert_del_validcert_002pkcs10$i.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_pkcs10_002$i.out" \
                            0 \
                            "Cert is added to the user $user1"
			
			rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user1 --input $TmpDir/pki_tks_user_cert_del_validcert_002crmf$i.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_crmf_002$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                	let i=$i+1
        	done
		i=0
		rlLog "Executing pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user1 \"2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))$@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user1 \"2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_del_002pkcs10.out" \
			0 \
			"Delete cert assigned to $user1"
		rlAssertGrep "Deleted certificate \"2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_del_002pkcs10.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user1 \"2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))$@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user1 \"2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_del_002crmf.out" \
                        0 \
                        "Delete cert assigned to $user1"
                rlAssertGrep "Deleted certificate \"2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_del_002crmf.out"
		
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del $user1"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - invalid Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-003: pki user-cert-del should fail if an invalid Cert ID is provided"
		i=0
                rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"$user1fullname\" $user1"
                 while [ $i -lt 4 ] ; do
                        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                        serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
                        serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_002pkcs10$i.out > $TmpDir/pki_tks_user_cert_del_validcert_002pkcs10$i.pem"

                        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                        serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
                        serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_002crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_002crmf$i.out > $TmpDir/pki_tks_user_cert_del_validcert_002crmf$i.pem"


                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user1 --input $TmpDir/pki_tks_user_cert_del_validcert_002pkcs10$i.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_pkcs10_002$i.out" \
                            0 \
                            "Cert is added to the user $user1"

                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user1 --input $TmpDir/pki_tks_user_cert_del_validcert_002crmf$i.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_crmf_002$i.out" \
                            0 \
			   "Cert is added to the user $user1"
                        let i=$i+1
                done
                i=0

		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '3;1000;CN=ROOTCA Signing Cert,O=redhat domain;UID=$user1,E=$user1@example.org,CN=$user1fullname,OU=Eng,O=Example,C=UK'"
		rlLog "Executing: $command"
                errmsg="PKIException: Failed to modify user."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if Invalid Cert ID is provided"
		
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '3;1000;CN=ROOTCA Signing Cert,O=redhat domain;UID=$user1,E=$user1@example.org,CN=$user1fullname,OU=Eng,O=Example,C=UK'"
                rlLog "Executing: $command"
                errmsg="PKIException: Failed to modify user."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if Invalid Cert ID is provided"
	
	rlPhaseEnd

	##### Delete certs asigned to a user - User does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-004: pki user-cert-del should fail if a non-existing User ID is provided"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del testuser4 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: User not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if a non-existing User ID is provided"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del testuser4 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: User not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if a non-existing User ID is provided"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-005: pki user-cert-del should fail is there is a mismatch of User ID and Cert ID"
		i=1
		rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"$user2fullname\" $user2"
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user2 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: Certificate not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if there is a Cert ID and User ID mismatch"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user2 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: Certificate not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if there is a Cert ID and User ID mismatch"
	rlPhaseEnd

	##### Delete certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-006-tier1: pki user-cert-del should fail if User ID is not provided"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if User ID is not provided"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if User ID is not provided"
	rlPhaseEnd
	
	##### Delete certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-007-tier1: pki user-cert-del should fail if Cert ID is not provided"
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1"
                rlLog "Executing: $command"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if Cert ID is not provided"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - as TKS_agentV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-008: Delete certs assigned to a user - as TKS_agentV should fail"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki tks-user-cert-del should fail if authenticating using a valid agent cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a valid agent cert"
	rlPhaseEnd

	##### Delete certs asigned to a user - as TKS_auditorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-009: Delete certs assigned to a user - as TKS_auditorV should fail"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a valid auditor cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a valid auditor cert"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	##### Delete certs asigned to a user - as TKS_adminE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0010: Delete certs assigned to a user - as TKS_adminE"
		i=1
		rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using an expired admin cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using an expired admin cert"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - as TKS_agentE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0011: Delete certs assigned to a user - as TKS_agentE"
                i=1
                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using an expired agent cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using an expired agent cert"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	 ##### Delete certs asigned to a user - as TKS_adminR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0012: Delete certs assigned to a user - as TKS_adminR should fail"
                i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a revoked admin cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a revoked admin cert"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlPhaseEnd

	 ##### Delete certs asigned to a user - as TKS_agentR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0013: Delete certs assigned to a user - as TKS_agentR should fail"
                i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a revoked agent cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a revoked agent cert"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlPhaseEnd

	##### Delete certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0014: Delete certs assigned to a user - as role_user_UTCA should fail"
                i=1
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using an untrusted cert"

                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using an untrusted cert"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Delete certs asigned to a user - as TKS_operatorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-TKS-0015: Delete certs assigned to a user - as TKS_operatorV should fail"
                i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a valid operator cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if authenticating using a valid operator cert"
        rlPhaseEnd

	##### Delete certs asigned to a user - as a user not assigned to any role ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0016: Delete certs assigned to a user - as a user not assigned to any role should fail"
		i=1
                command="pki -d $CERTDB_DIR/ -n $user2 -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication as a user not assigned to any role"

                command="pki -d $CERTDB_DIR/ -n $user2 -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication as a user not assigned to any role"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - switch positions of the required options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0017: Delete certs assigned to a user - switch positions of the required options"
		i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del '2;${serialdecimalpkcs10user1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US' $user1"
                rlLog "Executing: $command"
                errmsg="Error:"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if the required options are switched positions"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $TKS_HOST -p $TKS_PORT -t tks user-cert-del '2;${serialdecimalcrmfuser1[$i]};$ca_signing_cert_subj_name;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US' $user1"
                rlLog "Executing: $command"
                errmsg="Error:"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki user-cert-del should fail if the required options are switched positions"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/969"
	rlPhaseEnd

	### Tests to delete certs assigned to TKS users - i18n characters ####

	rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0019: Delete certs assigned to user - Subject name has i18n Characters"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                        serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
                        serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_0019pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_0019pkcs10.out > $TmpDir/pki_tks_user_cert_del_validcert_0019pkcs10.pem"

                        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
                        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                        serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
                        serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_0019crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_0019crmf.out > $TmpDir/pki_tks_user_cert_del_validcert_0019crmf.pem"


                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
			   -t tks \
                            user-cert-add $user2 --input $TmpDir/pki_tks_user_cert_del_validcert_0019pkcs10.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_pkcs10_0019.out" \
                            0 \
                            "Cert is added to the user $user2"

                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add $user2 --input $TmpDir/pki_tks_user_cert_del_validcert_0019crmf.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_crmf_0019.out" \
                            0 \
                            "Cert is added to the user $user1"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user2 \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_del_0019pkcs10.out" \
                        0 \
                        "Delete cert assigned to $user2"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_del_0019pkcs10.out"

                rlLog "Executing pki -d $CERTDB_DIR/ \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del $user2 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_del_0019crmf.out" \
                        0 \
                        "Delete cert assigned to $user2"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_del_0019crmf.out"
	rlPhaseEnd

	##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail #####

	rlPhaseStartTest "pki_user_cli_user_cert-del-tks-0020: Add an Admin user \"admin_user\", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail"
		rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"Admin User\" --password=Secret123 admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            group-member-add Administrators admin_user > $TmpDir/pki-user-add-tks-group0019.out"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"Admin User1\" --password=Secret123 admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            group-member-add Administrators admin_user1 > $TmpDir/pki-user-add-tks-group00191.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Admin User\" subject_uid:\"admin_user\" subject_email:admin_user@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_0020pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_0020pkcs10.out > $TmpDir/pki_tks_user_cert_del_validcert_0020pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Admin User1\" subject_uid:\"admin_user1\" subject_email:admin_user1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_tks_user_cert_del_encoded_0020crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_tks_user_cert_del_encoded_0020crmf.out > $TmpDir/pki_tks_user_cert_del_validcert_0020crmf.pem"

        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			    -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_del_validcert_0020pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add admin_user --input $TmpDir/pki_tks_user_cert_del_validcert_0020pkcs10.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_0020pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user admin_user"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user-pkcs10\" -i $TmpDir/pki_tks_user_cert_del_validcert_0020pkcs10.pem  -t "u,u,u""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"New Test User1\" new_test_user1"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"New Test User1\" new_test_user1 > $TmpDir/pki_tks_user_cert_del_useradd_0020.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user1\"" "$TmpDir/pki_tks_user_cert_del_useradd_0020.out"
        rlAssertGrep "User ID: new_test_user1" "$TmpDir/pki_tks_user_cert_del_useradd_0020.out"
        rlAssertGrep "Full name: New Test User1" "$TmpDir/pki_tks_user_cert_del_useradd_0020.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del admin_user \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_del_0020pkcs10.out" \
                        0 \
                        "Delete cert assigned to admin_user"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_del_0020pkcs10.out"

        command="pki -d $TEMP_NSS_DB -n admin-user-pkcs10 -c $TEMP_NSS_DB_PASSWD -h $TKS_HOST -p $TKS_PORT -t tks user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user-pkcs10 after deleting the cert from the user"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add admin_user1 --input $TmpDir/pki_tks_user_cert_del_validcert_0020crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-add admin_user1 --input $TmpDir/pki_tks_user_cert_del_validcert_0020crmf.pem  > $TmpDir/pki_tks_user_cert_del_useraddcert_0020crmf.out" \
                            0 \
			   "CRMF Cert is added to the user admin_user1"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user1-crmf\" -i $TmpDir/pki_tks_user_cert_del_validcert_0020crmf.pem  -t "u,u,u""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-add --fullName=\"New Test User2\" new_test_user2"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                           user-add --fullName=\"New Test User2\" new_test_user2 > $TmpDir/pki_tks_user_cert_del_useradd_0020crmf.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user1"
        rlAssertGrep "Added user \"new_test_user2\"" "$TmpDir/pki_tks_user_cert_del_useradd_0020crmf.out"
        rlAssertGrep "User ID: new_test_user2" "$TmpDir/pki_tks_user_cert_del_useradd_0020crmf.out"
        rlAssertGrep "Full name: New Test User2" "$TmpDir/pki_tks_user_cert_del_useradd_0020crmf.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-cert-del admin_user1 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_tks_user_cert_del_0020crmf.out" \
                        0 \
                        "Delete cert assigned to admin_user1"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_tks_user_cert_del_0020crmf.out"

	command="pki -d $TEMP_NSS_DB -n admin-user1-crmf -c $TEMP_NSS_DB_PASSWD  -h $TKS_HOST -p $TKS_PORT -t tks user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user1-crmf after deleting the cert from the user"

	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            group-member-del Administrators admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            group-member-del Administrators admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del admin_user1"
        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del new_test_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $TKS_HOST \
                           -p $TKS_PORT \
                           -t tks \
                            user-del new_test_user2"
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
