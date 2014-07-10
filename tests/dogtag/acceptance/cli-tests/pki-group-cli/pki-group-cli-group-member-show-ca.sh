#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-member-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-member-show   Show groups members
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
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-group-cli-group-member-show-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-group-cli-group-member-show-ca_tests(){
    #local variables
    group1=test_group
    group1desc="Test Group"
    group2=test_group2
    group2desc="Test Group 2"
    group3=test_group3
    group3desc="Test Group 3"
    rlPhaseStartSetup "pki_group_cli_group_member_show-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_member_show-configtest: pki group-member-show configuration test"
        rlRun "pki group-member-show --help > $TmpDir/pki_group_member_show_cfg.out 2>&1" \
               0 \
               "pki group-member-show"
        rlAssertGrep "usage: group-member-show <Group ID> <Member ID> \[OPTIONS...\]" "$TmpDir/pki_group_member_show_cfg.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_group_member_show_cfg.out"
    rlPhaseEnd

     ##### Tests to show CA  groups ####
    rlPhaseStartTest "pki_group_cli_group_member_show-CA-001: Add group to CA using CA_adminV, add a user to the group and show group member"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"$group1desc\" $group1" \
		    0 \
                    "Add group $group1 using CA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"User1\" u1" \
                    0 \
                    "Add user u1 using CA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-add $group1 u1" \
                    0 \
                    "Add user u1 to group $group1 using CA_adminV"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show $group1 u1"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show $group1 u1 > $TmpDir/pki_group_member_show_groupshow001.out" \
                    0 \
                    "Show group members of $group1"
	rlAssertGrep "Group member \"u1\"" "$TmpDir/pki_group_member_show_groupshow001.out"
	rlAssertGrep "User: u1" "$TmpDir/pki_group_member_show_groupshow001.out"
	rlPhaseEnd


    #Negative Cases
    rlPhaseStartTest "pki_group_cli_group_member_show-CA-002: Missing required option group id"
	command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca group-member-show u1" 
        errmsg="Error: Incorrect number of arguments specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members without group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-003: Missing required option member id"
        command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca group-member-show $group1"
        errmsg="Error: Incorrect number of arguments specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members without member id"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-004: A non existing member ID"
        command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca group-member-show $group1 user1"
        errmsg="ResourceNotFoundException: Group member user1 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members with a non-existing member id"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-005: A non existing group ID"
        command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca group-member-show group1 u1"
        errmsg="GroupNotFoundException: Group group1 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members with a non-existing group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-006: Checking if member id case sensitive "
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-member-show $group1 U1 > $TmpDir/pki-group-member-show-ca-006.out 2>&1" \
                    0 \
                    "Member ID is not case sensitive"
	rlAssertGrep "User \"U1\"" "$TmpDir/pki-group-member-show-ca-006.out"
        rlAssertGrep "User: u1" "$TmpDir/pki-group-member-show-ca-006.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/1069"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-007: Checking if group id case sensitive "
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-member-show TEST_GROUP u1 > $TmpDir/pki-group-member-show-ca-007.out 2>&1" \
                    0 \
                    "Group ID is not case sensitive"
        rlAssertGrep "Group member \"u1\"" "$TmpDir/pki-group-member-show-ca-007.out"
        rlAssertGrep "User: u1" "$TmpDir/pki-group-member-show-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-008: Should not be able to show group member using a revoked cert CA_adminR"
        command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a admin having revoked cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-009: Should not be able to show group member using an agent with revoked cert CA_agentR"
        command="pki -d $CERTDB_DIR  -n CA_agentR -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a agent having revoked cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-010: Should not be able to show group members using a valid agent CA_agentV user"
        command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-011: Should not be able to show group members using a CA_agentR user"
        command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a revoked agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-012: Should not be able to show group members using admin user with expired cert CA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using an expired admin cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-013: Should not be able to show group members using CA_agentE cert"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members g7 using a agent cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-014: Should not be able to show group members using a CA_auditV"
        command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a audit cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-015: Should not be able to show group members using a CA_operatorV"
        command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD group-member-show $group1 u1"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using a operator cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-016: Should not be able to show group members using a cert created from a untrusted CA CA_adminUTCA"
	command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password group-member-show $group1 u1"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group members using CA_adminUTCA"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-ca-017: Should not be able to show group members using a user cert"
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
                    group-member-show g7"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password group-member-show $group1 u1" > $expfile
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


    rlPhaseStartTest "pki_group_cli_group_member_show-CA-018: group id with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test 'ÖrjanÄke' > $TmpDir/pki-group-member-show-ca-001_56.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÉricTêko' > $TmpDir/pki-group-member-show-ca-001_57.out 2>&1" \
                    0 \
                    "Adding user id ÉricTêko with i18n characters"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-add 'ÖrjanÄke' 'ÉricTêko'> $TmpDir/pki-group-member-show-ca-001_56.out 2>&1" \
                    0 \
                    "Adding user ÉricTêko to group ÖrjanÄke"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show 'ÖrjanÄke' 'ÉricTêko'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show 'ÖrjanÄke' 'ÉricTêko'> $TmpDir/pki-group-member-show-ca-001_56_2.out" \
                    0 \
                    "Show group member'ÖrjanÄke'"
        rlAssertGrep "Group member \"ÉricTêko\"" "$TmpDir/pki-group-member-show-ca-001_56_2.out"
        rlAssertGrep "User: ÉricTêko" "$TmpDir/pki-group-member-show-ca-001_56_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_member_show-CA-019: Add group to CA using CA_adminV, add a user to the group, delete the group member and show the group member"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"$group2desc\" $group2" \
                    0 \
                    "Add group $group2 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"User2\" u2" \
                    0 \
                    "Add user u2 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-add $group2 u2" \
                    0 \
                    "Add user u2 to group $group2 using CA_adminV"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show $group2 u2"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show $group2 u2 > $TmpDir/pki_group_member_show_groupshow019.out" \
                    0 \
                    "Show group members of $group2"
        rlAssertGrep "Group member \"u2\"" "$TmpDir/pki_group_member_show_groupshow019.out"
        rlAssertGrep "User: u2" "$TmpDir/pki_group_member_show_groupshow019.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-del $group2 u2"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-member-show $group2 u2"
        errmsg="ResourceNotFoundException: Group member u2 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - group-member show should throw and error if the group member is deleted"

        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member_show-CA-020: Add group to CA using CA_adminV, add a user to the group, delete the user and show the group member"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"$group3desc\" $group3" \
                    0 \
                    "Add group $group3 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"User3\" u3" \
                    0 \
                    "Add user u3 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-add $group3 u3" \
                    0 \
                    "Add user u3 to group $group3 using CA_adminV"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show $group3 u3"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-member-show $group3 u3 > $TmpDir/pki_group_member_show_groupshow020.out" \
                    0 \
                    "Show group members of $group3"
        rlAssertGrep "Group member \"u3\"" "$TmpDir/pki_group_member_show_groupshow020.out"
        rlAssertGrep "User: u3" "$TmpDir/pki_group_member_show_groupshow020.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u3"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-member-show $group3 u3"
	errmsg="ResourceNotFoundException: Group member u3 not found"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - group-member show should throw and error if the member user is deleted"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member_show-CA-021: A non existing member ID and group ID"
        command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca group-member-show group1 user1"
        errmsg="GroupNotFoundException: Group group1 not found"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group members with a non-existing member id and group id"
    rlPhaseEnd


    rlPhaseStartTest "pki_group_cli_group_member_show_cleanup-021: Deleting the temp directory and groups"

        #===Deleting groups(symbols) created using CA_adminV cert===#
        j=1
        while [ $j -lt 4 ] ; do
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

	j=1
        while [ $j -lt 3 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$j > $TmpDir/pki-user-del-ca-group-symbol-00$j.out" \
                           0 \
                           "Deleted user u$j"
                rlAssertGrep "Deleted user \"u$j\"" "$TmpDir/pki-user-del-ca-group-symbol-00$j.out"
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
               user-del 'ÉricTêko' > $TmpDir/pki-user-del-ca-group-i18n_2.out" \
                0 \
                "Deleted user ÉricTêko"
        rlAssertGrep "Deleted user \"ÉricTêko\"" "$TmpDir/pki-user-del-ca-group-i18n_2.out"

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
