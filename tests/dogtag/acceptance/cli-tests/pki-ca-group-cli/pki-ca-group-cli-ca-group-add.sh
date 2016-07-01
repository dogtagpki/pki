#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-ca-group-cli
#   Description: PKI ca-group-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-group-cli-ca-group-add    Add group to pki subsystems.
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
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

########################################################################
#create-role-users.sh should be first executed prior to pki-ca-group-cli-ca-group-add.sh
########################################################################

########################################################################
# Test Suite Globals
########################################################################
run_pki-ca-group-cli-ca-group-add_tests(){

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3

if [ "$TOPO9" = "TRUE" ] ; then
        prefix=$subsystemId
elif [ "$MYROLE" = "MASTER" ] ; then
        if [[ $subsystemId == SUBCA* ]]; then
                prefix=$subsystemId
        else
                prefix=ROOTCA
        fi
else
        prefix=$MYROLE
fi

CA_HOST=$(eval echo \$${MYROLE})
CA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)

	#### Create Temporary directory ####	

     rlPhaseStartSetup "pki_ca_group_cli_ca_group_add-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"

	#### pki ca-group configuration test ####

     rlPhaseStartTest "pki_ca_group_cli-configtest: pki ca-group --help configuration test"
        rlRun "pki ca-group --help > $TmpDir/pki_ca_group_cfg.out 2>&1" \
               0 \
               "pki ca-group --help"
        rlAssertGrep "ca-group-find           Find groups" "$TmpDir/pki_ca_group_cfg.out"
        rlAssertGrep "ca-group-show           Show group" "$TmpDir/pki_ca_group_cfg.out"
        rlAssertGrep "ca-group-add            Add group" "$TmpDir/pki_ca_group_cfg.out"
        rlAssertGrep "ca-group-mod            Modify group" "$TmpDir/pki_ca_group_cfg.out"
        rlAssertGrep "ca-group-del            Remove group" "$TmpDir/pki_ca_group_cfg.out"
	rlAssertGrep "ca-group-member         Group member management commands" "$TmpDir/pki_ca_group_cfg.out"
        rlAssertNotGrep "Error: Invalid module \"ca-group---help\"." "$TmpDir/pki_ca_group_cfg.out"
     rlPhaseEnd

	#### pki ca-group-add configuration test ####

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-configtest: pki ca-group-add configuration test"
        rlRun "pki ca-group-add --help > $TmpDir/pki_ca_group_add_cfg.out 2>&1" \
               0 \
               "pki ca-group-add --help"
        rlAssertGrep "usage: ca-group-add <Group ID> \[OPTIONS...\]" "$TmpDir/pki_ca_group_add_cfg.out"
        rlAssertGrep "\--description <description>   Description" "$TmpDir/pki_ca_group_add_cfg.out"
        rlAssertGrep "\--help                        Show help options" "$TmpDir/pki_ca_group_add_cfg.out"
    rlPhaseEnd

     ##### Tests to add CA groups using a user of admin group with a valid cert####
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-001: Add a group to CA using CA_adminV"
	group1=new_group1
	group_desc1="New Group1"
        rlLog "Executing: pki -d $CERTDB_DIR \
		    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
		    ca-group-add --description=\"$group_desc1\" $group1"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
		    ca-group-add --description=\"$group_desc1\" $group1 > $TmpDir/pki-ca-group-add-001.out" \
		    0 \
		    "Add group $group1 to CA"
        rlAssertGrep "Added group \"$group1\"" "$TmpDir/pki-ca-group-add-001.out"
        rlAssertGrep "Group ID: $group1" "$TmpDir/pki-ca-group-add-001.out"
        rlAssertGrep "Description: $group_desc1" "$TmpDir/pki-ca-group-add-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-002:maximum length of group id"
	group2=$(openssl rand -hex 2048 |  perl -p -e 's/\n//')
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=\"Test Group\" \"$group2\" > $TmpDir/pki-ca-group-add-001_1.out" \
                    0 \
                    "Added group using CA_adminV with maximum group id length"
	actual_groupid_string=`cat $TmpDir/pki-ca-group-add-001_1.out | grep 'Group ID:' | xargs echo`
        expected_groupid_string="Group ID: $group2"                       
        if [[ $actual_groupid_string = $expected_groupid_string ]] ; then
                rlPass "Group ID: $group2 found"
        else
                rlFail "Group ID: $group2 not found"
        fi
        rlAssertGrep "Description: Test Group" "$TmpDir/pki-ca-group-add-001_1.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-003:Group id with # character"
	group3=abc#
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
		    ca-group-add --description test $group3 > $TmpDir/pki-ca-group-add-001_2.out" \
                    0 \
                    "Added group using CA_adminV, group id with # character"
        rlAssertGrep "Added group \"$group3\"" "$TmpDir/pki-ca-group-add-001_2.out"
        rlAssertGrep "Group ID: $group3" "$TmpDir/pki-ca-group-add-001_2.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ca-group-add-001_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-004:Group id with $ character"
	group4=abc$
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
		    ca-group-add --description=test $group4 > $TmpDir/pki-ca-group-add-001_3.out" \
                    0 \
                    "Added group using CA_adminV, group id with $ character"
        rlAssertGrep "Added group \"$group4\"" "$TmpDir/pki-ca-group-add-001_3.out"
        rlAssertGrep "Group ID: abc\\$" "$TmpDir/pki-ca-group-add-001_3.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ca-group-add-001_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-005:Group id with @ character"
	group5=abc@
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test $group5 > $TmpDir/pki-ca-group-add-001_4.out " \
                    0 \
                    "Added group using CA_adminV, group id with @ character"
        rlAssertGrep "Added group \"$group5\"" "$TmpDir/pki-ca-group-add-001_4.out"
        rlAssertGrep "Group ID: $group5" "$TmpDir/pki-ca-group-add-001_4.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ca-group-add-001_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-006:Group id with ? character"
	group6=abc?
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test $group6 > $TmpDir/pki-ca-group-add-001_5.out " \
                    0 \
                    "Added group using CA_adminV, group id with ? character"
        rlAssertGrep "Added group \"$group6\"" "$TmpDir/pki-ca-group-add-001_5.out"
        rlAssertGrep "Group ID: $group6" "$TmpDir/pki-ca-group-add-001_5.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ca-group-add-001_5.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-007:Group id as 0"
	group7=0
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test $group7 > $TmpDir/pki-ca-group-add-001_6.out " \
                    0 \
                    "Added group using CA_adminV, group id 0"
        rlAssertGrep "Added group \"$group7\"" "$TmpDir/pki-ca-group-add-001_6.out"
        rlAssertGrep "Group ID: $group7" "$TmpDir/pki-ca-group-add-001_6.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ca-group-add-001_6.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-008:--description with maximum length"
	groupdesc=$(openssl rand -hex 2048 |  perl -p -e 's/\n//')
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=\"$groupdesc\" g1 2>&1> $TmpDir/pki-ca-group-add-001_7.out" \
                    0 \
                    "Added group using CA_adminV with maximum --description length"
        rlAssertGrep "Added group \"g1\"" "$TmpDir/pki-ca-group-add-001_7.out"
        rlAssertGrep "Group ID: g1" "$TmpDir/pki-ca-group-add-001_7.out"
        rlAssertGrep "Description: $groupdesc" "$TmpDir/pki-ca-group-add-001_7.out"
	actual_desc_string=`cat $TmpDir/pki-ca-group-add-001_7.out | grep Description: | xargs echo`
        expected_desc_string="Description: $groupdesc"
        if [[ $actual_desc_string = $expected_desc_string ]] ; then
                rlPass "Description: $groupdesc found"
        else
                rlFail "Description: $groupdesc not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-009:--desccription with maximum length and symbols"
	rand_groupdesc=$(openssl rand -base64 2048 |  perl -p -e 's/\n//')
        groupdesc=$(echo $rand_groupdesc | sed 's/\///g')
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description='$groupdesc' g2 > $TmpDir/pki-ca-group-add-001_8.out" \
                    0 \
                    "Added group using CA_adminV with maximum --desc length and character symbols in it"
        rlAssertGrep "Added group \"g2\"" "$TmpDir/pki-ca-group-add-001_8.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-ca-group-add-001_8.out"
	actual_desc_string=`cat $TmpDir/pki-ca-group-add-001_8.out | grep Description: | xargs echo`
        expected_desc_string="Description: $groupdesc"
        if [[ $actual_desc_string = $expected_desc_string ]] ; then
                rlPass "Description: $groupdesc found"
        else
                rlFail "Description: $groupdesc not found"
        fi
    rlPhaseEnd


    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-010: Add a duplicate group to CA"
         command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='Duplicate Group' $group1"
         errmsg="ConflictingOperationException: Entry already exists."
	 errorcode=255
	 rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki group-add should fail on an attempt to add a duplicate group"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-011: Add a group to CA with -t option"
	desc="Test Group"
        rlLog "Executing: pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                   -t ca \
                    ca-group-add --description=\"$desc\" g3"

        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                   -t ca \
                    ca-group-add --description=\"$desc\"  g3 > $TmpDir/pki-ca-group-add-0011.out" \
                    0 \
                    "Add group g3 to CA"
        rlAssertGrep "Added group \"g3\"" "$TmpDir/pki-ca-group-add-0011.out"
        rlAssertGrep "Group ID: g3" "$TmpDir/pki-ca-group-add-0011.out"
        rlAssertGrep "Description: $desc" "$TmpDir/pki-ca-group-add-0011.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-012:  Add a group -- missing required option group id"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$group1'"
	errmsg="Error: No Group ID specified."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- missing required option group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-013:  Add a group -- missing required option --description"
	rlLog "pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add g7"
        rlRun "pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add g7 > $TmpDir/pki-ca-group-add-0013.out" 0 "Successfully added group without description option"
	rlAssertGrep "Added group \"g7\"" "$TmpDir/pki-ca-group-add-0013.out"
        rlAssertGrep "Group ID: g7" "$TmpDir/pki-ca-group-add-0013.out"
    rlPhaseEnd

   
        ##### Tests to add groups using revoked cert#####
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-014: Should not be able to add group using a revoked cert CA_adminR"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using a revoked admin cert CA_adminR"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-015: Should not be able to add group using a agent with revoked cert CA_agentR"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-add --description='$desc' $group1"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using a revoked agent cert CA_agentR"
    rlPhaseEnd


        ##### Tests to add groups using an agent user#####
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-016: Should not be able to add group using a valid agent CA_agentV user"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using a valid agent cert CA_agentV"
    rlPhaseEnd


    ##### Tests to add groups using expired cert#####
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-017: Should not be able to add group using admin user with expired cert CA_adminE"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using an expired admin cert CA_adminE"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-018: Should not be able to add group using CA_agentE cert"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using an expired agent cert CA_agentE"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

	##### Tests to add groups using audit users#####
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-019: Should not be able to add group using a CA_auditV"
	command="pki -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using a valid auditor cert CA_auditorV"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

	##### Tests to add groups using operator user###
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-020: Should not be able to add group using a CA_operatorV"
	command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using CA_operatorV"
    rlPhaseEnd


	 ##### Tests to add groups using CA_adminUTCA and CA_agentUTCA  user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-021: Should not be able to add group using a cert created from a untrusted CA"
	command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description='$desc' $group1"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- using CA_adminUTCA"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-022: group id length exceeds maximum limit defined in the schema"
	group_length_exceed_max=$(openssl rand -hex 10000 |  perl -p -e 's/\n//')
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-group-add --description=test '$group_length_exceed_max'"
	errmsg="ClientResponseFailure: ldap can't save, exceeds max length"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Add Group -- group id exceeds max limit"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/842"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-023: description with i18n characters"
	rlLog "ca-group-add description Örjan Äke with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \ 
                    ca-group-add --description='Örjan Äke' g4"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description='Örjan Äke' g4 > $TmpDir/pki-ca-group-add-001_51.out 2>&1" \
                    0 \
                    "Adding g4 with description Örjan Äke"
	rlAssertGrep "Added group \"g4\"" "$TmpDir/pki-ca-group-add-001_51.out"
        rlAssertGrep "Group ID: g4" "$TmpDir/pki-ca-group-add-001_51.out"
        rlAssertGrep "Description: Örjan Äke" "$TmpDir/pki-ca-group-add-001_51.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-024: description with i18n characters"
	rlLog "ca-group-add description Éric Têko with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description='Éric Têko' g5"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description='Éric Têko' g5 > $TmpDir/pki-ca-group-add-001_52.out 2>&1" \
                    0 \
                    "Adding g5 with description Éric Têko"
        rlAssertGrep "Added group \"g5\"" "$TmpDir/pki-ca-group-add-001_52.out"
        rlAssertGrep "Group ID: g5" "$TmpDir/pki-ca-group-add-001_52.out"
        rlAssertGrep "Description: Éric Têko" "$TmpDir/pki-ca-group-add-001_52.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-025: description with i18n characters"
	rlLog "ca-group-add description éénentwintig dvidešimt with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description='éénentwintig dvidešimt' g6"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description='éénentwintig dvidešimt' g6 > $TmpDir/pki-ca-group-add-001_53.out 2>&1" \
                    0 \
                    "Adding description éénentwintig dvidešimt with i18n characters"
        rlAssertGrep "Added group \"g6\"" "$TmpDir/pki-ca-group-add-001_53.out"
        rlAssertGrep "Description: éénentwintig dvidešimt" "$TmpDir/pki-ca-group-add-001_53.out"
        rlAssertGrep "Group ID: g6" "$TmpDir/pki-ca-group-add-001_53.out"
	rlLog "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-show g6"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-show g6 > $TmpDir/pki-ca-group-add-001_53_2.out 2>&1" \
                    0 \
                    "Show group g6 with description éénentwintig dvidešimt in i18n characters"
        rlAssertGrep "Group \"g6\"" "$TmpDir/pki-ca-group-add-001_53_2.out"
        rlAssertGrep "Description: éénentwintig dvidešimt" "$TmpDir/pki-ca-group-add-001_53_2.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-026: group id with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test 'ÖrjanÄke' > $TmpDir/pki-ca-group-add-001_56.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
        rlAssertGrep "Added group \"ÖrjanÄke\"" "$TmpDir/pki-ca-group-add-001_56.out"
        rlAssertGrep "Group ID: ÖrjanÄke" "$TmpDir/pki-ca-group-add-001_56.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_group_cli_ca_group_add-027: groupid with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test 'ÉricTêko'"
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                    ca-group-add --description=test 'ÉricTêko' > $TmpDir/pki-ca-group-add-001_57.out 2>&1" \
                    0 \
                    "Adding group id ÉricTêko with i18n characters"
        rlAssertGrep "Added group \"ÉricTêko\"" "$TmpDir/pki-ca-group-add-001_57.out"
        rlAssertGrep "Group ID: ÉricTêko" "$TmpDir/pki-ca-group-add-001_57.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_ca_group_cli_ca_group_cleanup: Deleting groups"

        #===Deleting groups created using CA_adminV cert===#
        i=1
        while [ $i -lt 8 ] ; do
               rlRun "pki -d $CERTDB_DIR \
			  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                           ca-group-del  g$i > $TmpDir/pki-ca-group-del-group-00$i.out" \
                           0 \
                           "Deleted group  g$i"
                rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-ca-group-del-group-00$i.out"
                let i=$i+1
        done
        #===Deleting groups(symbols) created using CA_adminV cert===#
        j=1
        while [ $j -lt 8 ] ; do
               eval grp=\$group$j
               rlRun "pki -d $CERTDB_DIR \
			  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                           ca-group-del  '$grp' > $TmpDir/pki-ca-group-del-group-symbol-00$j.out" \
                           0 \
                           "Deleted group $grp"
		actual_delete_group_string=`cat $TmpDir/pki-ca-group-del-group-symbol-00$j.out | grep 'Deleted group' | xargs echo`
        	expected_delete_group_string="Deleted group $grp"
		if [[ $actual_delete_group_string = $expected_delete_group_string ]] ; then
                	rlPass "Deleted group \"$grp\" found in $TmpDir/pki-ca-group-del-group-symbol-00$j.out"
        	else
                	rlFail "Deleted group \"$grp\" not found in $TmpDir/pki-ca-group-del-group-symbol-00$j.out" 
        	fi
                let j=$j+1
        done
        #===Deleting i18n groups created using CA_adminV cert===#
	rlRun "pki -d $CERTDB_DIR \
		-n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
		ca-group-del 'ÖrjanÄke' > $TmpDir/pki-ca-group-del-group-i18n_1.out" \
		0 \
		"Deleted group ÖrjanÄke"
	rlAssertGrep "Deleted group \"ÖrjanÄke\"" "$TmpDir/pki-ca-group-del-group-i18n_1.out"
	
	rlRun "pki -d $CERTDB_DIR \
		-n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                ca-group-del 'ÉricTêko' > $TmpDir/pki-ca-group-del-group-i18n_2.out" \
                0 \
                "Deleted group ÉricTêko"
        rlAssertGrep "Deleted group \"ÉricTêko\"" "$TmpDir/pki-ca-group-del-group-i18n_2.out"

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
