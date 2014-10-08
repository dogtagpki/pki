#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-user-cli
#   Description: PKI user-cert-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-user-cli-user-cert-add    Finding the certs assigned to users in the pki ca subsystem.
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
#create_role_users.sh should be first executed prior to pki-user-cli-user-add-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-ca-user-cli-user-cert-add_tests(){

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

CA_HOST=$(eval echo \$${MYROLE})
CA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)

	##### Create a temporary directory to save output files  and initializing host/port variables #####
   rlPhaseStartSetup "pki_user_cli_user_cert-add-ca-startup: Create temporary directory and initializing host/port variables"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

local cert_info="$TmpDir/cert_info"
user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
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
admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
NEWCA_LDAP_PORT="1807"
NEWCA_LDAP_INSTANCE_NAME="pki-newca"
NEWCA_LDAP_DB_SUFFIX="dc=pki-newca"
NEWCA_SUBSYSTEM_NAME="NEWCA"
NEWCA_INSTANCE_CFG="/tmp/newca_instance.inf"
NEWCA_INSTANCE_OUT="/tmp/newca_instance_create.out"
NEWCA_TOMCAT_INSTANCE_NAME="pki-new"
NEWCA_ADMIN_PASSWORD="Secret123"
NEWCA_CLIENT_PKCS12_PASSWORD="Secret123"
NEWCA_HTTP_PORT="30061"
NEWCA_HTTPS_PORT="30060"
NEWCA_TOMCAT_SERVER_PORT="30062"
NEWCA_SEC_DOMAIN_HTTPS_PORT="30060"
NEWCA_SEC_DOMAIN_PASSWORD="Secret123"
NEWCA_LDAP_ROOTDN="cn=Directory Manager1"
NEWCA_LDAP_ROOTDNPWD="Secret123"
NEWCA_ADMIN_CERT_NICKNAME="newcaadmincert"
NEWCA_CLIENT_DIR="/tmp/rhqa_pki"
NEWCA_CERTDB_DIR="/tmp/rhqa_pki/certdb"
NEWCA_CERTDB_DIR_PASSWORD="Secret123"
ROOTCA_ROOT="/var/lib/pki/pki-master/ca"
ROOTCA_ALIAS="/var/lib/pki/pki-master/ca/alias"
NEWCA_ROOT="/var/lib/pki/pki-new/ca"
NEWCA_ALIAS="/var/lib/pki/pki-new/ca/alias"
##### pki_user_cli_user_cert_add_ca-configtest ####
     rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-add-configtest-001: pki ca-user-cert-add configuration test"
        rlRun "pki ca-user-cert-add --help > $TmpDir/pki_ca_user_cert_add_cfg.out 2>&1" \
                0 \
                "User cert add configuration"
        rlAssertGrep "ca-user-cert-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_ca_user_cert_add_cfg.out"
        rlAssertGrep "--input <file>             Input file" "$TmpDir/pki_ca_user_cert_add_cfg.out"
	rlAssertGrep "--serial <serial number>   Serial number of certificate in CA" "$TmpDir/pki_ca_user_cert_add_cfg.out"
	rlAssertGrep "--help                     Show help options" "$TmpDir/pki_ca_user_cert_add_cfg.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Tests to add certs to CA users ####
	
        ##### Add one cert to a user #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-002-tier1: Add one cert to a user should succeed"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                   	   -p $CA_PORT \
                            ca-user-add --fullName=\"$user2fullname\" $user2"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_002pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_002pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_002pkcs10.pem"
	
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                   	   -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                   	   -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
	
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_002crmf.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_002crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_002crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"

	rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                   	   -p $CA_PORT \
                            ca-user-del $user2"
	rlPhaseEnd

##### Add multiple certs to a user #####

    rlPhaseStartTest "pki_ca_user_cli_user_cert-add-003: Add multiple certs to a user should succeed"
        i=0
        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$user1fullname\" $user1"
        while [ $i -lt 4 ] ; do
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        	algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
        	organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        	target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        	certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        	local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        	rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_003pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        	rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_003pkcs10$i.out > $TmpDir/pki_user_cert_add-CA_validcert_003pkcs10$i.pem"

        	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003pkcs10$i.pem"
        	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003pkcs10$i.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out" \
                            0 \
                            "PKCS10 Cert is added to the user $user1"
        	rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out"
        	rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out"
        	rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out"
        	rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out"
        	rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10$i.out"
		
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_003crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_003crmf$i.out > $TmpDir/pki_user_cert_add-CA_validcert_003crmf$i.pem"

                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003crmf$i.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out 2>&1" \
                            0 \
                            "CRMF Cert is added to the user $user1"
               rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out"
                rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out"
                rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out"
                rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf$i.out"
	
        	let i=$i+1
        done
	rlPhaseEnd

	        ##### Add expired cert to a user #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-004: Adding expired cert to a user should fail"
        rlRun "pki -d $CERTDB_DIR \
		    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
		    user-add --fullName=\"$user2fullname\" $user2"
	local validityperiod="1 day"
        rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD \
                req_type:pkcs10 algo:rsa key_size:2048 cn: uid: email: ou: org: country: archive:false host:$CA_HOST port:$CA_PORT profile: \
                cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info expect_data:$exp"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cur_date=$(date) # Save current date
        rlLog "Date & Time before Modifying system date: $cur_date"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlRun "chronyc -a -m 'offline' 'settime $cert_end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_004pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_004pkcs10.out > $TmpDir/pki_user_cert_add-CA_expiredcert_004pkcs10.pem"

	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_expiredcert_004pkcs10.pem"
        errmsg="BadRequestException: Certificate expired"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding an expired cert to a user should fail"
	rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after running chrony: $(date)"
	
	rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD \
                req_type:crmf algo:rsa key_size:2048 cn: uid: email: ou: org: country: archive:false host:$CA_HOST port:$CA_PORT profile: \
                cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info expect_data:$exp"
        cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        cur_date=$(date) # Save current date
        rlLog "Date & Time before Modifying system date: $cur_date"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlRun "chronyc -a -m 'offline' 'settime $cert_end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_004crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_004crmf.out > $TmpDir/pki_user_cert_add-CA_expiredcert_004crmf.pem"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_expiredcert_004crmf.pem"
        errmsg="BadRequestException: Certificate expired"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding an expired cert to a user should fail"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after running chrony: $(date)"

rlPhaseEnd

#### Add a revoked cert to a user ###

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-005: Add revoked cert to a user should succeed"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_005pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_005pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_005pkcs10.pem"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n \"$admin_cert_nickname\" \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                           -p $CA_PORT \
                            cert-revoke $valid_pkcs10_serialNumber --force > $TmpDir/pki_user_cert_add-CA_revokecert_005pkcs10.out"
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_005crmf.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_005crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_005crmf.pem"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n \"$admin_cert_nickname\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            cert-revoke $valid_crmf_serialNumber --force > $TmpDir/pki_user_cert_add-CA_revokecert_005pkcs10.out"
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
			   -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"

rlPhaseEnd

        ##### Add one cert to a user - User ID missing #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-006-tier1: Add one cert to a user should fail when USER ID is missing"
		
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD myreq_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: subject_ou: org: country: archive:false \
        req_profile: target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info" 0 "Generate certificate based on pkcs10 request"
	local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_006pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_006pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_006pkcs10.pem"

	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD myreq_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: subject_ou: org: country: archive:false \
        req_profile: target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info" 0 "Generate certificate based on crmf request"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_006crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_006crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_006crmf.pem"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_006pkcs10.pem"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - USER ID missing"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_006crmf.pem"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - USER ID missing"
rlPhaseEnd

        ##### Add one cert to a user - --input parameter missing #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-007-tier1: Add one cert to a user should fail when --input parameter is missing"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   user-add --fullName=\"New User1\" u1"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2"
        errmsg="Error: Missing input file or serial number."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Input parameter missing"
        rlRun "pki -d $CERTDB_DIR \
		    -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   user-del u1"
rlPhaseEnd

##### Add one cert to a user - argument for --input parameter missing #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-008: Add one cert to a user should fail when argument for the --input param is missing"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2 --input"
        errmsg="Error: Missing argument for option: input"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Argument for input parameter is missing"
rlPhaseEnd

        ##### Add one cert to a user - Invalid cert #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-009: Add one cert to a user should fail when the cert is invalid"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD myreq_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: subject_ou: org: country: archive:false \
        req_profile: target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info" 0 "Generate certificate based on pkcs10 request"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_009pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_009pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_009pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD myreq_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: subject_ou: org: country: archive:false \
        req_profile: target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info" 0 "Generate certificate based on crmf request"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_009crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_009crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_009crmf.pem"

        rlRun "sed -i -e 's/-----BEGIN CERTIFICATE-----/BEGIN CERTIFICATE-----/g' $TmpDir/pki_user_cert_add-CA_validcert_009pkcs10.pem"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_009pkcs10.pem"
        errmsg="PKIException: Certificate exception"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Invalid Certificate cannot be added to a user"

        rlRun "sed -i -e 's/-----BEGIN CERTIFICATE-----/BEGIN CERTIFICATE-----/g' $TmpDir/pki_user_cert_add-CA_validcert_009crmf.pem"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_009crmf.pem"
        errmsg="PKIException: Certificate exception"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Invalid Certificate cannot be added to a user"
rlPhaseEnd

        ##### Add one cert to a user - Input file does not exist #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0010: Add one cert to a user should fail when Input file does not exist "
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $user2 --input $TmpDir/tempfile.pem"
                errmsg="FileNotFoundException: File '$TmpDir/tempfile.pem' does not exist"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Input file does not exist"
rlPhaseEnd
	
	##### Add one cert to a user - i18n characters in the Subject name of the cert #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0011: Add one cert to a user - Should be able to add certs with i18n characters in the Subject name of the cert"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0011pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0011pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0011pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=$user2@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=$user2@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=$user2@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0011crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0011crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0011crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
			   -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=$user2@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=$user2@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=$user2@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
rlPhaseEnd

##### Add one cert to a user - User type 'Auditors' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0012: Add cert to a user of type 'Auditors'"
        local userid="Auditor_user"
        local userFullname="Auditor User"
	rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=Auditors $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0012pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0012pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0012pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0012crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0012crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0012crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
			   -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Add one cert to a user - User type 'Certificate Manager Agents' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0013: Add cert to a user of type 'Certificate Manager Agents'"
        local userid="Certificate_Manager_Agents"
        local userFullname="Certificate Manager Agents"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=\"Certificate Manager Agents\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0013pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0013pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0013pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0013crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0013crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0013crmf.pem"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Add one cert to a user - User type 'Registration Manager Agents' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0014: Add cert to a user of type 'Registration Manager Agents'"
        local userid="Registration_Manager_Agent_user"
        local userFullname="Registration Manager Agent User"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=\"Registration Manager Agents\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0014pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0014pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0014pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0014crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0014crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0014crmf.pem"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Add one cert to a user - User type 'Subsystem Group' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0015: Add cert to a user of type 'Subsystem Group'"
        local userid="Subsystem_group_user"
        local userFullname="Subsystem Group User"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=\"Subsystem Group\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0015pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0015pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0015pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0015crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0015crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0015crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
			-n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Add one cert to a user - User type 'Security Domain Administrators' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0016: Add cert to a user of type 'Security Domain Administrators'"
        local userid="Security_Domain_Administrators_user"
        local userFullname="Security Domain Administrators User"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=\"Security Domain Administrators\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0016pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0016pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0016pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0016crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0016crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0016crmf.pem"
	
	rlLog "Executing pki -d $CERTDB_DIR/ \
                        -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Add one cert to a user - User type 'ClonedSubsystems' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0017: Add cert to a user of type 'ClonedSubsystems'"
        local userid="ClonedSubsystems_user"
        local userFullname="ClonedSubsystems User"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=\"ClonedSubsystems\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0017pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0017pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0017pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0017crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0017crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0017crmf.pem"
        
        rlLog "Executing pki -d $CERTDB_DIR/ \
			-n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Add one cert to a user - User type 'Trusted Managers' #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0018: Add cert to a user of type 'Trusted Managers'"
        local userid="Trusted_Managers_user"
        local userFullname="Trusted Managers User"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$userFullname\" --type=\"Trusted Managers\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0018pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0018pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0018pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$userFullname\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0018crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0018crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0018crmf.pem"
        
        rlLog "Executing pki -d $CERTDB_DIR/ \
			 -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

##### Usability Tests #####

        ##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0019: Add an Admin user \"admin_user\", add a cert to admin_user, add a new user as admin_user"
        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Admin User\" --password=Secret123 admin_user"

        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add Administrators admin_user > $TmpDir/pki-user-add-ca-group0019.out"

        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Admin User1\" --password=Secret123 admin_user1"

        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add Administrators admin_user1 > $TmpDir/pki-user-add-ca-group00191.out"

	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Admin User\" subject_uid:\"admin_user\" subject_email:admin_user@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0019pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0019pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0019pkcs10.pem"

	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Admin User1\" subject_uid:\"admin_user1\" subject_email:admin_user1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0019crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0019crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0019crmf.pem"

	rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user --input $TmpDir/pki_user_cert_add-CA_validcert_0019pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user --input $TmpDir/pki_user_cert_add-CA_validcert_0019pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user admin_user"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out"
        rlAssertGrep "Subject: UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019pkcs10.out"
	rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user-pkcs10\" -i $TmpDir/pki_user_cert_add-CA_validcert_0019pkcs10.pem  -t "u,u,u""

	rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"New Test User1\" new_test_user1"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"New Test User1\" new_test_user1 > $TmpDir/pki_user_cert_add_CA_useradd_0019.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user1\"" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
        rlAssertGrep "User ID: new_test_user1" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
        rlAssertGrep "Full name: New Test User1" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0019crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0019crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out" \
                            0 \
                            "CRMF Cert is added to the user admin_user"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Subject: UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user1-crmf\" -i $TmpDir/pki_user_cert_add-CA_validcert_0019crmf.pem  -t "u,u,u""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"New Test User2\" new_test_user2"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
			   ca-user-add --fullName=\"New Test User2\" new_test_user2 > $TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user2\"" "$TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out"
        rlAssertGrep "User ID: new_test_user2" "$TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out"
        rlAssertGrep "Full name: New Test User2" "$TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out"

	rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del Administrators admin_user"

        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del Administrators admin_user1"

        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del admin_user"

        rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del admin_user1"
	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del new_test_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del new_test_user2"
rlPhaseEnd

##### Add an Agent user "agent_user", add a cert to agent_user, approve a cert request as agent_user" #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0020: Add an Agent user agent_user, add a cert to agent_user, approve a cert request as agent_user"
	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Agent User\" --type=\"Certificate Manager Agents\" agent_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add \"Certificate Manager Agents\" agent_user > $TmpDir/pki-user-add-ca-group0020.out"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Certificate Manager Agents\" agent_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add \"Certificate Manager Agents\" agent_user1 > $TmpDir/pki-user-add-ca-group00201.out"

	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Agent User\" subject_uid:\"agent_user\" subject_email:agent_user@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0020pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0020pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0020pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Agent User1\" subject_uid:\"agent_user1\" subject_email:agent_user1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0020crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0020crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0020crmf.pem"

	rlRun "certutil -d $TEMP_NSS_DB -A -n \"agentuserpkcs10\" -i $TmpDir/pki_user_cert_add-CA_validcert_0020pkcs10.pem  -t "u,u,u""
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"agent-user1-crmf\" -i $TmpDir/pki_user_cert_add-CA_validcert_0020crmf.pem  -t "u,u,u""

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user --input $TmpDir/pki_user_cert_add-CA_validcert_0020pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user --input $TmpDir/pki_user_cert_add-CA_validcert_0020pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0020pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user agent_user"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0020crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0020crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out" \
                            0 \
                            "CRMF Cert is added to the user agent_user1"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agentuserpkcs10\" cert_info:$cert_info" 0 "Successfully approved a cert by agent-user-pkcs10"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agent-user1-crmf\" cert_info:$cert_info" 0 "Successfully approved a cert by agent-user1-crmf" 

	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del \"Certificate Manager Agents\" agent_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del \"Certificate Manager Agents\" agent_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del agent_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del agent_user1"
rlPhaseEnd

##### Add one cert to a user - authenticating as a valid agent user #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-CA-0021: Adding a cert as CA_agentV should fail"
        local userid="new_user1"
        local userFullname="New User1"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0021pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0021pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0021pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0021crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0021crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0021crmf.pem"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0021pkcs10.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentV"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0021crmf.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentV"
	
rlPhaseEnd

##### Add one cert to a user - authenticating as a valid auditor user #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0022: Adding a cert as CA_auditorV should fail"
        local userid="new_user2"
        local userFullname="New User2"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"
	
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
	
	local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0022pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0022pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0022pkcs10.pem"

	local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0022crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0022crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0022crmf.pem"

	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0022pkcs10.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_auditorV"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0022crmf.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_auditorV"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

##### Add one cert to a user - authenticating as an admin user with expired cert #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0023: Adding a cert as CA_adminE should fail"
        local userid="new_user3"
        local userFullname="New User3"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0023pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0023pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0023pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0023crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0023crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0023crmf.pem"

	rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date"
	
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0023pkcs10.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminE"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0023crmf.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminE"

	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

##### Adding a cert as an CA_adminR #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0024: Adding a cert as CA_adminR should fail"
	local userid="new_user4"
        local userFullname="New User4"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0024pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0024pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0024pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0024crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0024crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0024crmf.pem"

	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0024pkcs10.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminR"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0024crmf.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminR"

rlPhaseEnd

##### Adding a cert as an CA_agentR #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0025: Adding a cert as CA_agentR should fail"
	local userid="new_user5"
        local userFullname="New User5"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0025pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0025pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0025pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0025crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0025crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0025crmf.pem"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0025pkcs10.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentR"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0025crmf.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentR"
rlPhaseEnd

        ##### Adding a cert as an CA_agentE #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0026: Adding a cert as CA_agentE should fail"
	local userid="new_user6"
        local userFullname="New User6"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0026pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0026pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0026pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0026crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0026crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0026crmf.pem"

        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0026pkcs10.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentE"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0026crmf.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentE"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

##### Adding a cert as CA_adminUTCA #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0027: Adding a cert as CA_adminUTCA should fail"
	local userid="new_user7"
        local userFullname="New User7"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0027pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0027pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0027pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0027crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0027crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0027crmf.pem"

        command="pki -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0027pkcs10.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminUTCA"

        command="pki -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0027crmf.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminUTCA"
	
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

##### Adding a cert as CA_agentUTCA #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0028: Adding a cert as CA_agentUTCA should fail"
        local userid="new_user9"
        local userFullname="New User9"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0028pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0028pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0028pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0028crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0028crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0028crmf.pem"

        command="pki -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0028pkcs10.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentUTCA"

        command="pki -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0028crmf.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentUTCA"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

##### Adding a cert as an CA_operatorV #####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0029: Adding a cert as CA_operatorV should fail"
	local userid="new_user8"
        local userFullname="New User8"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0029pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0029pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0029pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0029crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0029crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0029crmf.pem"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0029pkcs10.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_operatorV"

        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0029crmf.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_operatorV"

rlPhaseEnd

        ##### Adding a cert as a user not associated with any group#####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0030: Adding a cert as user not associated with an group, should fail"
	local userid="new_user10"
        local userFullname="New User10"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-add --fullName=\"$userFullname\" $userid"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"

        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0030pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0030pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0030pkcs10.pem"

        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0030crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0030crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0030crmf.pem"

	command="pki -d $CERTDB_DIR -n $userid -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0030pkcs10.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid as a user not associated with any group"

        command="pki -d $CERTDB_DIR -n $userid -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0030crmf.pem"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid as a user not associated with any group"

	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd

##### Add one cert to a user - switching position of options #####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0031: Add one cert to a user - switching position of options should succeed"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0031pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0031pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0031pkcs10.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031pkcs10.pem $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031pkcs10.pem $user2 > $TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0031crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0031crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0031crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031crmf.pem $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031crmf.pem $user2 > $TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"

rlPhaseEnd

#### Add a cert to a user using --serial option with hexadecimal value" ####
rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0032: Add one cert to a user with --serial option hex"
        local userid="testuser4"
        local username="Test User4"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$username\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$username\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_pkcs10_serialNumber"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_pkcs10_serialNumber  > $TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$username\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_crmf_serialNumber"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_crmf_serialNumber > $TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0032crmf.out"
       rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

#### Add a cert to a user using --serial option with decimal value" ####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0033: Add one cert to a user with --serial option decimal"
        local userid="testuser4"
        local username="Test User4"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$username\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$username\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_decimal_pkcs10_serialNumber"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_decimal_pkcs10_serialNumber  > $TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out"
        rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033pkcs10.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$username\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_decimal_crmf_serialNumber"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_decimal_crmf_serialNumber > $TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out"
        rlAssertGrep "Cert ID: 2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out"
        rlAssertGrep "Serial Number: $valid_crmf_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out"
        rlAssertGrep "Issuer: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$username,OU=Engineering,O=Example.Inc,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0033crmf.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

#### Add one cert to a user with both --serial and --input options ####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0034: Add one cert to a user with --serial and --input options should fail"
        local userid="testuser4"
        local username="Test User4"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$username\" $userid"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$username\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0034pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0034pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0034pkcs10.pem"
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_decimal_pkcs10_serialNumber --input=$TmpDir/pki_user_cert_add-CA_validcert_0034pkcs10.pem"
        command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --serial=$valid_decimal_pkcs10_serialNumber --input=$TmpDir/pki_user_cert_add-CA_validcert_0034pkcs10.pem"
        errmsg="Error: Conflicting options: --input and --serial."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid with both --serial and --input options"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"$username\" subject_uid:$userid subject_email:$userid@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0034crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0034crmf.out > $TmpDir/pki_user_cert_add-CA_validcert_0034crmf.pem"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $userid --serial=$valid_decimal_crmf_serialNumber --input=$TmpDir/pki_user_cert_add-CA_validcert_0034crmf.pem"
        command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --serial=$valid_decimal_crmf_serialNumber --input=$TmpDir/pki_user_cert_add-CA_validcert_0034crmf.pem"
        errmsg="Error: Conflicting options: --input and --serial."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid with both --serial and --input options"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
        rlPhaseEnd

#### --serial option with negative number ####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0035: Add one cert to a user with negative serial should fail"
        local userid="testuser4"
        local username="Test User4"
        local dectohex="0x"$(echo "obase=16;-100"|bc)
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$username\" $userid"
        command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --serial=-100"
        errmsg="CertNotFoundException: Certificate ID $dectohex not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid with negative serial number"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
rlPhaseEnd

#### Missing argument for --serial option ####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0036: Add one cert to a user with missing argument for --serial"
        local userid="testuser4"
        local username="Test User4"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$username\" $userid"
        command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --serial"
        errmsg="Error: Missing argument for option: serial"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid with no argument for --serial option"

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
rlPhaseEnd

#### --serial option with argument with characters ####

rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0037: Add one cert to a user with character passed as argument to --serial"
        local userid="testuser4"
        local username="Test User4"
        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$username\" $userid"
        command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-add $userid --serial='abc'"
        errmsg="NumberFormatException: For input string: \"abc\""
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message -  Adding cert to $userid with characters passed as argument to --serial "

        rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $userid"
rlPhaseEnd
#rlPhaseStartTest "pki_ca_user_cli_user_cert-add-0038: client cert authentication using cross certification"
#	local userid="new_adminV"
#        local username="NEW CA Admin User"
#        cat /etc/redhat-release | grep "Fedora"
#        if [ $? -eq 0 ] ; then
#               FLAVOR="Fedora"
#               rlLog "Automation is running against Fedora"
#        else
#                FLAVOR="RHEL"
#                rlLog "Automation is running against RHEL"
#        fi
#        rhcs_install_set_ldap_vars
#        rlRun "mkdir $NEWCA_CLIENT_DIR"
#        rlRun "mkdir $NEWCA_CERTDB_DIR"
#        rlRun "rhds_install $NEWCA_LDAP_PORT $NEWCA_LDAP_INSTANCE_NAME \"$NEWCA_LDAP_ROOTDN\" $NEWCA_LDAP_ROOTDNPWD $NEWCA_LDAP_DB_SUFFIX $NEWCA_SUBSYSTEM_NAME"
#        rlRun "sleep 10"
#        echo "[DEFAULT]" > $NEWCA_INSTANCE_CFG
#        echo "pki_instance_name=$NEWCA_TOMCAT_INSTANCE_NAME" >> $NEWCA_INSTANCE_CFG
#        echo "pki_https_port=$NEWCA_HTTPS_PORT" >> $NEWCA_INSTANCE_CFG
#        echo "pki_http_port=$NEWCA_HTTP_PORT" >> $NEWCA_INSTANCE_CFG
#        echo "pki_tomcat_server_port=$NEWCA_TOMCAT_SERVER_PORT" >> $NEWCA_INSTANCE_CFG
#        echo "pki_admin_password=$NEWCA_ADMIN_PASSWORD" >> $NEWCA_INSTANCE_CFG
#        echo "pki_client_pkcs12_password=$NEWCA_CLIENT_PKCS12_PASSWORD" >> $NEWCA_INSTANCE_CFG
#        echo "pki_client_database_dir=$NEWCA_CERTDB_DIR" >> $NEWCA_INSTANCE_CFG
#        echo "pki_client_database_password=$NEWCA_CERTDB_DIR_PASSWORD" >> $NEWCA_INSTANCE_CFG
#        echo "pki_ds_database=$NEWCA_LDAP_INSTANCE_NAME" >> $NEWCA_INSTANCE_CFG
#        echo "pki_ds_ldap_port=$NEWCA_LDAP_PORT" >> $NEWCA_INSTANCE_CFG
#        echo "pki_ds_base_dn=$NEWCA_LDAP_DB_SUFFIX" >> $NEWCA_INSTANCE_CFG
#        echo "pki_ds_bind_dn=$NEWCA_LDAP_ROOTDN" >> $NEWCA_INSTANCE_CFG
#        echo "pki_ds_password=$NEWCA_LDAP_ROOTDNPWD" >> $NEWCA_INSTANCE_CFG
#        echo "pki_security_domain_https_port=$NEWCA_SEC_DOMAIN_HTTPS_PORT" >> $NEWCA_INSTANCE_CFG
#        echo "pki_security_domain_password=$NEWCA_SEC_DOMAIN_PASSWORD" >> $NEWCA_INSTANCE_CFG
#        echo "pki_admin_nickname=$NEWCA_ADMIN_CERT_NICKNAME" >> $NEWCA_INSTANCE_CFG
#        echo "pki_client_dir=$NEWCA_CLIENT_DIR" >> $NEWCA_INSTANCE_CFG
#        echo "pki_client_admin_cert_p12=$NEWCA_CLIENT_DIR/$NEWCA_ADMIN_CERT_NICKNAME.p12" >> $NEWCA_INSTANCE_CFG
#        rlRun "pkispawn -s CA -v -f $NEWCA_INSTANCE_CFG > $NEWCA_INSTANCE_OUT 2>&1"
#        rlRun "install_and_trust_CA_cert $NEWCA_ROOT $NEWCA_CERTDB_DIR"
#        rlRun "sleep 10"
#        rlRun "install_and_trust_CA_cert $NEWCA_ROOT $ROOTCA_ALIAS"
#        rlRun "sleep 10"
#        rlRun "install_and_trust_CA_cert $ROOTCA_ROOT $NEWCA_ALIAS"
#        rlRun "sleep 10"
#        rlLog "Executing: pki -d $NEWCA_CERTDB_DIR -n \"PKI Administrator for $ROOTCA_DOMAIN\" -c $NEWCA_CERTDB_DIR_PASSWORD -h $CA_HOST -t $SUBSYSTEM_TYPE -p $NEWCA_HTTP_PORT user-add --fullName=\"$username\" $userid"
#        rlRun "pki -d $NEWCA_CERTDB_DIR \
#                          -n \"PKI Administrator for $ROOTCA_DOMAIN\" \
#                          -c $NEWCA_CERTDB_DIR_PASSWORD \
#                          -h $CA_HOST \
#                          -t $SUBSYSTEM_TYPE \
#                          -p $NEWCA_HTTP_PORT \
#                           user-add --fullName=\"$username\" $userid > $TmpDir/newcanewuser.out 2>&1" 0 "Added a user to new CA"
#
#        rlRun "pki -d $NEWCA_CERTDB_DIR \
#                           -n \"PKI Administrator for $ROOTCA_DOMAIN\" \
#                           -c $NEWCA_CERTDB_DIR_PASSWORD \
#                           -h $CA_HOST \
#                           -t $SUBSYSTEM_TYPE \
#                           -p $NEWCA_HTTP_PORT \
#                            group-member-add Administrators $userid > $TmpDir/pki-user-add-newca-group001.out 2>&1"  \
#                            0 \
#                            "Add user $userid to Administrators group"
#
#        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
#        algo:rsa key_size:2048 subject_cn:\"$user2fullname\" subject_uid:$user2 subject_email:$user2@example.org \
#        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
#        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
#        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
#        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
#        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
#        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_user_cert_add-CA_encoded_0038pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
#        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add-CA_encoded_0038pkcs10.out > $TmpDir/pki_user_cert_add-CA_validcert_0038pkcs10.pem"

#        rlRun "pki -d $NEWCA_CERTDB_DIR \
#                           -n \"PKI Administrator for $ROOTCA_DOMAIN\" \
#                           -c $NEWCA_CERTDB_DIR_PASSWORD \
#                           -h $CA_HOST \
#                           -t $SUBSYSTEM_TYPE \
#                           -p $NEWCA_HTTP_PORT \
#                          ca-user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0038pkcs10.pem > $TmpDir/pki-ca_user-cert-add-newca.out 2>&1"  \
#                            0 \
#                            "Added cert to user $userid"

#        rlRun "certutil -d $NEWCA_CERTDB_DIR -A -n \"$userid\" -i $TmpDir/pki_user_cert_add-CA_validcert_0038pkcs10.pem -t "u,u,u""
#        rlRun "sleep 10"
#        rlRun "certutil -d $CERTDB_DIR -A -n \"$userid\" -i $TmpDir/pki_user_cert_add-CA_validcert_0038pkcs10.pem -t "u,u,u""
#        rlRun "sleep 10"

#        rlRun "install_and_trust_CA_cert $NEWCA_ROOT $CERTDB_DIR"
#        rlRun "sleep 10"
#        rlRun "install_and_trust_CA_cert $ROOTCA_ROOT $NEWCA_CERTDB_DIR"
#        rlRun "sleep 10"

#        rlRun "systemctl restart pki-tomcatd@pki-new.service"
#        rlRun "sleep 10"
#        rlRun "systemctl restart pki-tomcatd@pki-master.service"
#        rlRun "sleep 10"
#        rlRun "pki -d $NEWCA_CERTDB_DIR \
#                          -n $userid \
#                          -c $NEWCA_CERTDB_DIR_PASSWORD \
#                          -h $CA_HOST \
#                          -t $SUBSYSTEM_TYPE \
#                          -p $NEWCA_HTTP_PORT \
#                           user-add --fullName=\"New Test User\" new_test_user > /tmp/newcanewuser.out 2>&1" 0 "Added a user to new CA"

#        rlRun "certutil -D -d $CERTDB_DIR -n \"caSigningCert cert-pki-new CA\""
#        rlRun "certutil -D -d $ROOTCA_ALIAS -n \"caSigningCert cert-pki-new CA\""
#        rlRun "certutil -D -d $CERTDB_DIR -n \"$userid\""

#        rlRun "pkidestroy -s CA -i pki-new"
#        rlRun "sleep 10"
#        rlRun "remove-ds.pl -f -i slapd-pki-newca"
#        rlRun "sleep 10"
#        rlRun "rm -rf $NEWCA_CLIENT_DIR"
#        rlFail "PKI ticket: https://fedorahosted.org/pki/ticket/1171"
#rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 3 ] ; do
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
        j=1
        while [ $j -lt 11 ] ; do
               eval usr="new_user$j"
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                           ca-user-del  $usr > $TmpDir/pki-user-del-ca-new-user-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-new-user-00$j.out"
                let j=$j+1
        done

        #Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}

