#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-user-cli
#   Description: PKI kra-user-cert-delete CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-kra-user-cli-kra-user-cert-delete    Delete the certs assigned to users in the pki kra subsystem.
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
#create_role_users.sh should be first executed prior to pki-kra-user-cli-kra-user-cert-delete.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-kra-user-cli-kra-user-cert-delete_tests(){

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
caId=$4
CA_HOST=$5
KRA_HOST=$(eval echo \$${MYROLE})
KRA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
CA_PORT=$(eval echo \$${caId}_UNSECURE_PORT)

        ##### Create temporary directory to save output files#####
    rlPhaseStartSetup "pki_kra_user_cli_kra_user_cert-del-startup: Create temporary directory"
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
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
ca_signing_cert_subj_name=$(eval echo \$${caId}_SIGNING_CERT_SUBJECT_NAME)
ROOTCA_agent_user=${caId}_agentV

	##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail #####

	rlPhaseStartTest "pki_kra_user_cli_kra_user_cert-del-0020: Add an Admin user \"admin_user\", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail"
		rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-add --fullName=\"Admin User\" --password=Secret123 admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-group-member-add Administrators admin_user > $TmpDir/pki-user-add-kra-group0019.out"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-add --fullName=\"Admin User1\" --password=Secret123 admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-group-member-add Administrators admin_user1 > $TmpDir/pki-user-add-kra-group00191.out"


        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Admin User\" subject_uid:\"admin_user\" subject_email:admin_user@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_kra_user_cert_del_encoded_0020pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_kra_user_cert_del_encoded_0020pkcs10.out > $TmpDir/pki_kra_user_cert_del_validcert_0020pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Admin User1\" subject_uid:\"admin_user1\" subject_email:admin_user1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_kra_user_cert_del_encoded_0020crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_kra_user_cert_del_encoded_0020crmf.out > $TmpDir/pki_kra_user_cert_del_validcert_0020crmf.pem"

        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			    -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-cert-add admin_user --input $TmpDir/pki_user_cert_del_validcert_0020pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-cert-add admin_user --input $TmpDir/pki_kra_user_cert_del_validcert_0020pkcs10.pem  > $TmpDir/pki_kra_user_cert_del_useraddcert_0020pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user admin_user"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user-pkcs10\" -i $TmpDir/pki_kra_user_cert_del_validcert_0020pkcs10.pem  -t \"u,u,u\""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-add --fullName=\"New Test User1\" new_test_user1"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-add --fullName=\"New Test User1\" new_test_user1 > $TmpDir/pki_kra_user_cert_del_useradd_0020.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user1\"" "$TmpDir/pki_kra_user_cert_del_useradd_0020.out"
        rlAssertGrep "User ID: new_test_user1" "$TmpDir/pki_kra_user_cert_del_useradd_0020.out"
        rlAssertGrep "Full name: New Test User1" "$TmpDir/pki_kra_user_cert_del_useradd_0020.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-cert-del admin_user \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_kra_user_cert_del_0020pkcs10.out" \
                        0 \
                        "Delete cert assigned to admin_user"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_pkcs10_serialNumber;$ca_signing_cert_subj_name;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_kra_user_cert_del_0020pkcs10.out"

        command="pki -d $TEMP_NSS_DB -n admin-user-pkcs10 -c $TEMP_NSS_DB_PASSWD -h $KRA_HOST -p $KRA_PORT kra-user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user-pkcs10 after deleting the cert from the user"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-cert-add admin_user1 --input $TmpDir/pki_kra_user_cert_del_validcert_0020crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-cert-add admin_user1 --input $TmpDir/pki_kra_user_cert_del_validcert_0020crmf.pem  > $TmpDir/pki_kra_user_cert_del_useraddcert_0020crmf.out" \
                            0 \
			   "CRMF Cert is added to the user admin_user1"
	rlLog "certutil -d $TEMP_NSS_DB -A -n \"admin-user1-crmf\" -i $TmpDir/pki_kra_user_cert_del_validcert_0020crmf.pem  -t \"u,u,u\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user1-crmf\" -i $TmpDir/pki_kra_user_cert_del_validcert_0020crmf.pem  -t \"u,u,u\""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-add --fullName=\"New Test User2\" new_test_user2"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                           kra-user-add --fullName=\"New Test User2\" new_test_user2 > $TmpDir/pki_kra_user_cert_del_useradd_0020crmf.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user1"
        rlAssertGrep "Added user \"new_test_user2\"" "$TmpDir/pki_kra_user_cert_del_useradd_0020crmf.out"
        rlAssertGrep "User ID: new_test_user2" "$TmpDir/pki_kra_user_cert_del_useradd_0020crmf.out"
        rlAssertGrep "Full name: New Test User2" "$TmpDir/pki_kra_user_cert_del_useradd_0020crmf.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-cert-del admin_user1 \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_kra_user_cert_del_0020crmf.out" \
                        0 \
                        "Delete cert assigned to admin_user1"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_crmf_serialNumber;$ca_signing_cert_subj_name;UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_kra_user_cert_del_0020crmf.out"

	command="pki -d $TEMP_NSS_DB -n admin-user1-crmf -c $TEMP_NSS_DB_PASSWD  -h $KRA_HOST -p $KRA_PORT kra-user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user1-crmf after deleting the cert from the user"

	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-group-member-del Administrators admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-group-member-del Administrators admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-del admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-del admin_user1"
        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-del new_test_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                            kra-user-del new_test_user2"
	rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_kra_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 3 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $KRA_HOST \
                           -p $KRA_PORT \
                           kra-user-del  $usr > $TmpDir/pki-user-del-kra-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-kra-user-symbol-00$j.out"
                let j=$j+1
        done
        #Delete temporary directory
        #rlRun "popd"
        #rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
