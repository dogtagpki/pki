#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-kra-group-cli
#   Description: PKI kra-group-member-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-kra-group-cli-kra-group-member-show   Show groups members
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <rpattath@redhat.com>
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
#create_role_users.sh should be first executed prior to pki-kra-group-cli-kra-group-member-show.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-kra-group-cli-kra-group-member-show_tests(){
    #local variables
    group1=test_group
    group1desc="Test Group"
    group2=test_group2
    group2desc="Test Group 2"
    group3=test_group3
    group3desc="Test Group 3"
    rlPhaseStartSetup "pki_kra_group_cli_kra_group_member_show-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
caId=$4
CA_HOST=$5
KRA_HOST=$(eval echo \$${MYROLE})
KRA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
CA_PORT=$(eval echo \$${caId}_UNSECURE_PORT)
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
cert_info="$TmpDir/cert_info"
ROOTCA_agent_user=${caId}_agentV
    rlPhaseStartTest "pki_kra_group_member_show-configtest: pki kra-group-member-show configuration test"
        rlRun "pki kra-group-member-show --help > $TmpDir/pki_kra_group_member_show_cfg.out 2>&1" \
               0 \
               "pki kra-group-member-show"
        rlAssertGrep "usage: kra-group-member-show <Group ID> <Member ID> \[OPTIONS...\]" "$TmpDir/pki_kra_group_member_show_cfg.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_kra_group_member_show_cfg.out"
    rlPhaseEnd

     ##### Tests to show KRA groups ####
    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-001: Add group to KRA using KRA_adminV, add a user to the group and show group member"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-add --description=\"$group1desc\" $group1" \
		    0 \
                    "Add group $group1 using KRA_adminV"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-user-add --fullName=\"User1\" u1" \
                    0 \
                    "Add user u1 using KRA_adminV"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-add $group1 u1" \
                    0 \
                    "Add user u1 to group $group1 using KRA_adminV"
	rlLog "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group1 u1"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group1 u1 > $TmpDir/pki_kra_group_member_show_groupshow001.out" \
                    0 \
                    "Show group members of $group1"
	rlAssertGrep "Group member \"u1\"" "$TmpDir/pki_kra_group_member_show_groupshow001.out"
	rlAssertGrep "User: u1" "$TmpDir/pki_kra_group_member_show_groupshow001.out"
	rlPhaseEnd


    #Negative Cases
    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-002: Missing required option group id"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show u1" 
        errmsg="Error: Incorrect number of arguments specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members without group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-003: Missing required option member id"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1"
        errmsg="Error: Incorrect number of arguments specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members without member id"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-004: A non existing member ID"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 user1"
        errmsg="ResourceNotFoundException: Group member user1 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members with a non-existing member id"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-005: A non existing group ID"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show group1 u1"
        errmsg="GroupNotFoundException: Group group1 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members with a non-existing group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-006: Checking if member id case sensitive "
	rlLog "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group1 U1"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group1 U1 > $TmpDir/pki-kra-group-member-show-006.out 2>&1" \
                    0 \
                    "Member ID is not case sensitive"
	rlAssertGrep "User \"U1\"" "$TmpDir/pki-kra-group-member-show-006.out"
        rlAssertGrep "User: u1" "$TmpDir/pki-kra-group-member-show-006.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/1069"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-007: Checking if group id case sensitive "
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show TEST_GROUP u1 > $TmpDir/pki-kra-group-member-show-007.out 2>&1" \
                    0 \
                    "Group ID is not case sensitive"
        rlAssertGrep "Group member \"u1\"" "$TmpDir/pki-kra-group-member-show-007.out"
        rlAssertGrep "User: u1" "$TmpDir/pki-kra-group-member-show-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-008: Should not be able to show group member using a revoked cert KRA_adminR"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a admin having revoked cert"
	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-009: Should not be able to show group member using an agent with revoked cert KRA_agentR"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a agent having revoked cert"
	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-010: Should not be able to show group members using a valid agent KRA_agentV user"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-011: Should not be able to show group members using admin user with expired cert KRA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using an expired admin cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/934"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-012: Should not be able to show group members using KRA_agentE cert"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members g7 using a agent cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/934"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-013: Should not be able to show group members using a KRA_auditV"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a audit cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-014: Should not be able to show group members using a KRA_operatorV"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a operator cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-015: Should not be able to show group members using a cert created from a untrusted KRA KRA_adminUTCA"
	command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group1 u1"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using KRA_adminUTCA"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-016: Should not be able to show group members using a user cert"
	#Create a user cert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"pki User1\" subject_uid:pkiUser1 subject_email:pkiuser1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_kra_group_member_show_encoded_0029pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_kra_group_member_show_encoded_0029pkcs10.out > $TmpDir/pki_kra_group_member_show_encoded_0029pkcs10.pem"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $TmpDir/pki_kra_group_member_show_encoded_0029pkcs10.pem  -t "u,u,u""
        rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c $TEMP_NSS_DB_PASSWD \
                   -h $KRA_HOST \
                   -p $KRA_PORT \
                    kra-group-member-show $group1 u1"
        rlRun "pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c $TEMP_NSS_DB_PASSWD \
                   -h $KRA_HOST \
                   -p $KRA_PORT \
                    kra-group-member-show $group1 u1 >  $TmpDir/pki-kra-group-member-show-pkiUser1-002.out 2>&1" 255 "Should not be able to show group members using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-kra-group-member-show-pkiUser1-002.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-017: group id with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-add --description=test 'ÖrjanÄke' > $TmpDir/pki-kra-group-member-show-001_56.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-user-add --fullName=test u3 > $TmpDir/pki-kra-group-member-show-001_57.out 2>&1" \
                    0 \
                    "Adding user id u3"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-add 'ÖrjanÄke' u3 > $TmpDir/pki-kra-group-member-show-001_56.out 2>&1" \
                    0 \
                    "Adding user u3 to group ÖrjanÄke"
	rlLog "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show 'ÖrjanÄke' u3"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show 'ÖrjanÄke' u3 > $TmpDir/pki-kra-group-member-show-001_56_2.out" \
                    0 \
                    "Show group member'ÖrjanÄke'"
        rlAssertGrep "Group member \"u3\"" "$TmpDir/pki-kra-group-member-show-001_56_2.out"
        rlAssertGrep "User: u3" "$TmpDir/pki-kra-group-member-show-001_56_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-018: Add group to KRA using KRA_adminV, add a user to the group, delete the group member and show the group member"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-add --description=\"$group2desc\" $group2" \
                    0 \
                    "Add group $group2 using KRA_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-user-add --fullName=\"User2\" u2" \
                    0 \
                    "Add user u2 using KRA_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-add $group2 u2" \
                    0 \
                    "Add user u2 to group $group2 using KRA_adminV"
        rlLog "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group2 u2"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group2 u2 > $TmpDir/pki_kra_group_member_show_groupshow019.out" \
                    0 \
                    "Show group members of $group2"
        rlAssertGrep "Group member \"u2\"" "$TmpDir/pki_kra_group_member_show_groupshow019.out"
        rlAssertGrep "User: u2" "$TmpDir/pki_kra_group_member_show_groupshow019.out"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-del $group2 u2"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group2 u2"
        errmsg="ResourceNotFoundException: Group member u2 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - kra-group-member show should throw and error if the group member is deleted"

        rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-019: Add group to KRA using KRA_adminV, add a user to the group, delete the user and show the group member"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-add --description=\"$group3desc\" $group3" \
                    0 \
                    "Add group $group3 using KRA_adminV"
	rlLog "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-user-add --fullName=\"User4\" u4"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-user-add --fullName=\"User4\" u4" \
                    0 \
                    "Add user u3 using KRA_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-add $group3 u4" \
                    0 \
                    "Add user u4 to group $group3 using KRA_adminV"
        rlLog "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group3 u4"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-group-member-show $group3 u4 > $TmpDir/pki_kra_group_member_show_groupshow020.out" \
                    0 \
                    "Show group members of $group3"
        rlAssertGrep "Group member \"u4\"" "$TmpDir/pki_kra_group_member_show_groupshow020.out"
        rlAssertGrep "User: u4" "$TmpDir/pki_kra_group_member_show_groupshow020.out"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    kra-user-del u4"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show $group3 u4"
	errmsg="ResourceNotFoundException: Group member u4 not found"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - kra-group-member show should throw and error if the member user is deleted"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show-021: A non existing member ID and group ID"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-show group1 user1"
        errmsg="GroupNotFoundException: Group group1 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members with a non-existing member id and group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_group_cli_kra_group_member_show_cleanup-022: Deleting the temp directory and groups"

        #===Deleting groups(symbols) created using KRA_adminV cert===#
        j=1
        while [ $j -lt 4 ] ; do
               eval grp=\$group$j
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                           kra-group-del  $grp > $TmpDir/pki-group-del-kra-group-symbol-00$j.out" \
                           0 \
                           "Deleted group $grp"
                rlAssertGrep "Deleted group \"$grp\"" "$TmpDir/pki-group-del-kra-group-symbol-00$j.out"
                let j=$j+1
        done

	j=1
        while [ $j -lt 4 ] ; do
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                           kra-user-del  u$j > $TmpDir/pki-user-del-kra-group-symbol-00$j.out" \
                           0 \
                           "Deleted user u$j"
                rlAssertGrep "Deleted user \"u$j\"" "$TmpDir/pki-user-del-kra-group-symbol-00$j.out"
                let j=$j+1
        done

	#===Deleting i18n groups created using KRA_adminV cert===#
        rlRun "pki -d $CERTDB_DIR \
		-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                kra-group-del 'ÖrjanÄke' > $TmpDir/pki-group-del-kra-group-i18n_1.out" \
                0 \
                "Deleted group ÖrjanÄke"
        rlAssertGrep "Deleted group \"ÖrjanÄke\"" "$TmpDir/pki-group-del-kra-group-i18n_1.out"
	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
