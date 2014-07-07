#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-show   Show groups 
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
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-group-cli-group-show-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-group-cli-group-show-ca_tests(){
    #local variables
    group1=test_group
    group1desc="Test Group"
    group2=abcdefghijklmnopqrstuvwxyx12345678
    group3=abc#
    group4=abc$
    group5=abc@
    group6=abc?
    group7=0

    rlPhaseStartSetup "pki_group_cli_group_show-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_show-configtest: pki group-show configuration test"
        rlRun "pki group-show --help > $TmpDir/pki_group_show_cfg.out 2>&1" \
               0 \
               "pki group-show"
        rlAssertGrep "usage: group-show <Group ID> \[OPTIONS...\]" "$TmpDir/pki_group_show_cfg.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_group_show_cfg.out"
    rlPhaseEnd

     ##### Tests to show CA  groups ####
    rlPhaseStartTest "pki_group_cli_group_show-CA-001: Add group to CA using CA_adminV and show group"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"$group1desc\" $group1" \
		    0 \
                    "Add group $group1 using CA_adminV"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group1 > $TmpDir/pki-group-show-ca-001.out" \
		    0 \
		    "Show group $group1"
        rlAssertGrep "Group \"$group1\"" "$TmpDir/pki-group-show-ca-001.out"
        rlAssertGrep "Group ID: $group1" "$TmpDir/pki-group-show-ca-001.out"
        rlAssertGrep "Description: $group1desc" "$TmpDir/pki-group-show-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-002: maximum length of group id"
	group2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test $group2" \
		    0 \
                    "Add group $group2 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group2 > $TmpDir/pki-group-show-ca-001_1.out" \
                    0 \
                    "Show $group2 group"
        rlAssertGrep "Group \"$group2\"" "$TmpDir/pki-group-show-ca-001_1.out"
	actual_groupid_string=`cat $TmpDir/pki-group-show-ca-001_1.out | grep 'Group ID:' | xargs echo`
        expected_groupid_string="Group ID: $group2"
        if [[ $actual_groupid_string = $expected_groupid_string ]] ; then
                rlPass "Group ID: $group2 found"
        else
                rlFail "Group ID: $group2 not found"
        fi
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_1.out"
	
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-003: Group id with # character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test $group3" \
		    0 \
                    "Add group $group3 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group3 > $TmpDir/pki-group-show-ca-001_2.out" \
                    0 \
                    "Show $group3 group"
        rlAssertGrep "Group \"$group3\"" "$TmpDir/pki-group-show-ca-001_2.out"
        rlAssertGrep "Group ID: $user3" "$TmpDir/pki-group-show-ca-001_2.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-004: Group id with $ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test $group4" \
		    0 \
                    "Add group $group4 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group4 > $TmpDir/pki-group-show-ca-001_3.out" \
                    0 \
                    "Show $group4 group"
        rlAssertGrep "Group \"$group4\"" "$TmpDir/pki-group-show-ca-001_3.out"
        rlAssertGrep "Group ID: abc\\$" "$TmpDir/pki-group-show-ca-001_3.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-005: Group id with @ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test $group5" \
                    0 \
                    "Add $group5 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group5 > $TmpDir/pki-group-show-ca-001_4.out" \
                    0 \
                    "Show $group5 group"
        rlAssertGrep "Group \"$group5\"" "$TmpDir/pki-group-show-ca-001_4.out"
        rlAssertGrep "Group ID: $group5" "$TmpDir/pki-group-show-ca-001_4.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-006: Group id with ? character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test $group6" \
                    0 \
                    "Add $group6 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group6 > $TmpDir/pki-group-show-ca-001_5.out" \
                    0 \
                    "Show $group6 group"
        rlAssertGrep "Group \"$group6\"" "$TmpDir/pki-group-show-ca-001_5.out"
        rlAssertGrep "Group ID: $group6" "$TmpDir/pki-group-show-ca-001_5.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_5.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-007: Group id as 0"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test $group7" \
                    0 \
                    "Add group $group7 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group7 > $TmpDir/pki-group-show-ca-001_6.out" \
                    0 \
                    "Show group $group7"
        rlAssertGrep "Group \"$group7\"" "$TmpDir/pki-group-show-ca-001_6.out"
        rlAssertGrep "Group ID: $group7" "$TmpDir/pki-group-show-ca-001_6.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_6.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-008: --description with maximum length"
	desc=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description='$desc' g1" \
		    0 \
		    "Added group using CA_adminV with maximum --description length"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g1 > $TmpDir/pki-group-show-ca-001_7.out" \
                    0 \
                    "Show group g1"
        rlAssertGrep "Group \"g1\"" "$TmpDir/pki-group-show-ca-001_7.out"
        rlAssertGrep "Group ID: g1" "$TmpDir/pki-group-show-ca-001_7.out"
	actual_desc_string=`cat $TmpDir/pki-group-show-ca-001_7.out | grep Description: | xargs echo`
        expected_desc_string="Description: $desc"
        if [[ $actual_desc_string = $expected_desc_string ]] ; then
                rlPass "Description: $desc found"
        else
                rlFail "Description: $desc not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-009: --description with maximum length and symbols"
	desc=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description='$desc' g2" \
		    0 \
		    "Added group using CA_adminV with maximum --description length and character symbols in it"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-001_8.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-001_8.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-001_8.out"
	actual_desc_string=`cat $TmpDir/pki-group-show-ca-001_8.out | grep Description: | xargs echo`
        expected_desc_string="Description: $desc"
        if [[ $actual_desc_string = $expected_desc_string ]] ; then
                rlPass "Description: $desc found"
        else
                rlFail "Description: $desc not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-010: --description with # character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=# g3" \
                    0 \
                    "Add group g3 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g3 > $TmpDir/pki-group-show-ca-001_9.out" \
		     0 \
                    "Add group g3"
        rlAssertGrep "Group \"g3\"" "$TmpDir/pki-group-show-ca-001_9.out"
        rlAssertGrep "Group ID: g3" "$TmpDir/pki-group-show-ca-001_9.out"
        rlAssertGrep "Description: #" "$TmpDir/pki-group-show-ca-001_9.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-011: --description with * character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=*  g4" \
		    0 \
                    "Add group g4 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g4 > $TmpDir/pki-group-show-ca-001_10.out" \
                    0 \
                    "Show group g4 using CA_adminV"
        rlAssertGrep "Group \"g4\"" "$TmpDir/pki-group-show-ca-001_10.out"
        rlAssertGrep "Group ID: g4" "$TmpDir/pki-group-show-ca-001_10.out"
        rlAssertGrep "Description: *" "$TmpDir/pki-group-show-ca-001_10.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-012: --description with $ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=$  g5" \
		    0 \
                    "Add group g5 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g5 > $TmpDir/pki-group-show-ca-001_11.out" \
                    0 \
                    "Show group g5 using CA_adminV"
        rlAssertGrep "Group \"g5\"" "$TmpDir/pki-group-show-ca-001_11.out"
        rlAssertGrep "Group ID: g5" "$TmpDir/pki-group-show-ca-001_11.out"
        rlAssertGrep "Description: \\$" "$TmpDir/pki-group-show-ca-001_11.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-013: --description as number 0"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=0 g6" \
		    0 \
                    "Add group g6 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g6 > $TmpDir/pki-group-show-ca-001_12.out" \
                    0 \
                    "Show group g6 using CA_adminV"
        rlAssertGrep "Group \"g6\"" "$TmpDir/pki-group-show-ca-001_12.out"
        rlAssertGrep "Group ID: g6" "$TmpDir/pki-group-show-ca-001_12.out"
        rlAssertGrep "Description: 0" "$TmpDir/pki-group-show-ca-001_12.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-014: Show group with -t ca option"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-add --description=test g7" \
		    0 \
                    "Adding group g7 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-show g7 > $TmpDir/pki-group-show-ca-001_32.out" \
                    0 \
                    "Show group g7 using CA_adminV"
        rlAssertGrep "Group \"g7\"" "$TmpDir/pki-group-show-ca-001_32.out"
        rlAssertGrep "Group ID: g7" "$TmpDir/pki-group-show-ca-001_32.out"
        rlAssertGrep "Description: $test" "$TmpDir/pki-group-show-ca-001_32.out"
    rlPhaseEnd


    #Negative Cases
    rlPhaseStartTest "pki_group_cli_group_show-CA-015: Missing required option group id"
	command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca group-show" 
        errmsg="Error: No Group ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group without group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-016: Checking if group id case sensitive "
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-show G7 > $TmpDir/pki-group-show-ca-001_35.out 2>&1" \
                    0 \
                    "Group ID is not case sensitive"
	rlAssertGrep "Group \"G7\"" "$TmpDir/pki-group-show-ca-001_35.out"
        rlAssertGrep "Group ID: g7" "$TmpDir/pki-group-show-ca-001_35.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-group-show-ca-001_35.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-017: Should not be able to show group using a revoked cert CA_adminR"
        command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a admin having revoked cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-018: Should not be able to show group using an agent with revoked cert CA_agentR"
        command="pki -d $CERTDB_DIR  -n CA_agentR -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a agent having revoked cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-019: Should not be able to show group using a valid agent CA_agentV user"
        command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-020: Should not be able to show group using a CA_agentR user"
        command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a revoked agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-021: Should not be able to show group using admin user with expired cert CA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using an expired admin cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-022: Should not be able to show group using CA_agentE cert"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a agent cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-023: Should not be able to show group using a CA_auditV"
        command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a audit cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-024: Should not be able to show group using a CA_operatorV"
        command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD group-show g7"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a operator cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-025: Should not be able to show group using a cert created from a untrusted CA CA_adminUTCA"
	command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password group-show g7"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using CA_adminUTCA"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-ca-026: Should not be able to show group using a user cert"
        #Create a user cert
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"pki User1\" \"pkiUser1\" \
                \"pkiuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        rlLog "pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
        rlRun "pki cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
        rlLog "valid_serialNumber=$valid_serialNumber"
        #Import user certs to $TEMP_NSS_DB
        rlRun "pki cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $temp_out  -t "u,u,u""
        local expfile="$TmpDir/expfile_pkiuser1.out"
        rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c Password \
                    group-show g7"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password group-show g7" > $expfile
        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        echo "send -- \"\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-group-show-ca-pkiUser1-002.out 2>&1" 255 "Should not be able to show groups using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-group-show-ca-pkiUser1-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-027: group id length exceeds maximum limit defined in the schema"
        group_length_exceed_max=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10000 | head -n 1`
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show  '$group_length_exceed_max'"
	errmsg="ClientResponseFailure: ldap can't save, exceeds max length"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Show group using CA_adminV with group id length exceed maximum defined in ldap schema should fail"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/842"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-028: group id with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test 'ÖrjanÄke' > $TmpDir/pki-group-show-ca-001_56.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show 'ÖrjanÄke' > $TmpDir/pki-group-show-ca-001_56_2.out" \
                    0 \
                    "Show group 'ÖrjanÄke'"
        rlAssertGrep "Group \"ÖrjanÄke\"" "$TmpDir/pki-group-show-ca-001_56_2.out"
        rlAssertGrep "Group ID: ÖrjanÄke" "$TmpDir/pki-group-show-ca-001_56_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_show-CA-029: groupid with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test 'ÉricTêko' > $TmpDir/pki-group-show-ca-001_57.out 2>&1" \
                    0 \
                    "Adding group id ÉricTêko with i18n characters"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show 'ÉricTêko'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show 'ÉricTêko' > $TmpDir/pki-group-show-ca-001_57_2.out" \
                    0 \
                    "Show group 'ÉricTêko'"
        rlAssertGrep "Group \"ÉricTêko\"" "$TmpDir/pki-group-show-ca-001_57_2.out"
        rlAssertGrep "Group ID: ÉricTêko" "$TmpDir/pki-group-show-ca-001_57_2.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_group_cli_group_cleanup-046: Deleting the temp directory and groups"

        #===Deleting groups created using CA_adminV cert===#
        i=1
        while [ $i -lt 8 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  g$i > $TmpDir/pki-group-del-ca-group-00$i.out" \
                           0 \
                           "Deleted group g$i"
                rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-group-del-ca-group-00$i.out"
                let i=$i+1
        done
        #===Deleting groups(symbols) created using CA_adminV cert===#
        j=1
        while [ $j -lt 8 ] ; do
               eval grp=\$group$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  $grp > $TmpDir/pki-group-del-ca-group-symbol-00$j.out" \
                           0 \
                           "Deleted group $grp"
                rlAssertGrep "Deleted group \"$grp\"" "$TmpDir/pki-group-del-ca-group-symbol-00$j.out"
                let j=$j+1
        done

	#===Deleting i18n groups created using CA_adminV cert===#
        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                group-del 'ÖrjanÄke' > $TmpDir/pki-group-del-ca-group-i18n_1.out" \
                0 \
                "Deleted group ÖrjanÄke"
        rlAssertGrep "Deleted group \"ÖrjanÄke\"" "$TmpDir/pki-group-del-ca-group-i18n_1.out"

        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
               group-del 'ÉricTêko' > $TmpDir/pki-group-del-ca-group-i18n_2.out" \
                0 \
                "Deleted group ÉricTêko"
        rlAssertGrep "Deleted group \"ÉricTêko\"" "$TmpDir/pki-group-del-ca-group-i18n_2.out"

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
