#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-del CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-del   Delete pki subsystem groups.
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


########################################################################
# Test Suite Globals
########################################################################

run_pki-group-cli-group-del-ca_tests(){

    rlPhaseStartSetup "pki_group_cli_group_del-CA-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-ca-configtest-001: pki group-del --help configuration test"
        rlRun "pki group-del --help > $TmpDir/group_del.out 2>&1" 0 "pki group-del --help"
        rlAssertGrep "usage: group-del <Group ID>" "$TmpDir/group_del.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/group_del.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-ca-configtest-002: pki group-del configuration test"
        rlRun "pki group-del > $TmpDir/group_del_2.out 2>&1" 255 "pki group-del"
        rlAssertGrep "usage: group-del <Group ID>" "$TmpDir/group_del_2.out"
        rlAssertGrep " --help   Show help options" "$TmpDir/group_del_2.out"
	rlAssertNotGrep "ResteasyIOException: IOException" "$TmpDir/group_del_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-003: Delete valid groups" 
	group1=ca_group
	group1desc="Test group"
	group2=abcdefghijklmnopqrstuvwxyx12345678
	group3=abc#
	group4=abc$
	group5=abc@
	group6=abc?
	group7=0
	#positive test cases
	#Add groups to CA using CA_adminV cert
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-add --description=test_group g$i"
                let i=$i+1
        done

	#===Deleting groups created using CA_adminV cert===#
	i=1
	while [ $i -lt 25 ] ; do
	       rlLog "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  g$i"
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  g$i > $TmpDir/pki-group-del-ca-group1-00$i.out" \
                           0 \
                           "Deleted group g$i"
		rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-group-del-ca-group1-00$i.out"
	   	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show g$i"
		errmsg="GroupNotFoundException: Group g$i not found"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group should not exist"
                let i=$i+1
        done
	#Add groups to CA using CA_adminV cert
        i=1
        while [ $i -lt 8 ] ; do
	       eval grp=\$group$i
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-add --description=test_group $grp"
                let i=$i+1
        done

        #===Deleting groups(symbols) created using CA_adminV cert===#
	j=1
        while [ $j -lt 8 ] ; do
	       eval grp=\$group$j
	       rlLog "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del $grp "
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del $grp > $TmpDir/pki-group-del-ca-group2-00$j.out" \
			   0 \
			   "Deleted group $grp"
		rlAssertGrep "Deleted group \"$grp\"" "$TmpDir/pki-group-del-ca-group2-00$j.out"
	   	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show $grp"
		errmsg="GroupNotFoundException: Group $grp not found"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group should not exist"
                let j=$j+1
        done
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-004: Case sensitive groupid"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-add --description=test_group group_abc"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  GROUP_ABC > $TmpDir/pki-group-del-ca-group-002_1.out" \
                           0 \
                           "Deleted group GROUP_ABC groupid is not case sensitive"
        rlAssertGrep "Deleted group \"GROUP_ABC\"" "$TmpDir/pki-group-del-ca-group-002_1.out"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show group_abc"
	errmsg="GroupNotFoundException: Group group_abc not found"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group group_abc should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-005: Delete group when required option group id is missing"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  > $TmpDir/pki-group-del-ca-group-003_1.out 2>&1" \
                           255 \
                           "Cannot delete a group without groupid"
        rlAssertGrep "usage: group-del <Group ID>" "$TmpDir/pki-group-del-ca-group-003_1.out"
    rlPhaseEnd
  
    rlPhaseStartTest "pki_group_cli_group_del-CA-006: Maximum length of group id"
	group2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test \"$group2\" > $TmpDir/pki-group-add-ca-001_1.out" \
                    0 \
                    "Added group using CA_adminV with maximum group id length"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del \"$group2\" > $TmpDir/pki-group-del-ca-group-006.out" \
                           0 \
                           "Deleting group with maximum group id length using CA_adminV"
	actual_groupid_string=`cat $TmpDir/pki-group-del-ca-group-006.out | grep 'Deleted group' | xargs echo`
        expected_groupid_string="Deleted group $group2"  
	if [[ $actual_groupid_string = $expected_groupid_string ]] ; then
                rlPass "Deleted group \"$group2\" found"
        else
                rlFail "Deleted group \"$group2\" not found"
        fi
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show \"$group2\""
        errmsg="GroupNotFoundException: Group \"$group2\" not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group with max length should not exist"
    rlPhaseEnd 
    
    rlPhaseStartTest "pki_group_cli_group_del-CA-007: groupid with maximum length and symbols"
	groupid=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test '$groupid' > $TmpDir/pki-group-add-ca-001_8.out" \
                    0 \
                    "Added group using CA_adminV with maximum groupid length and character symbols in it"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del '$groupid' > $TmpDir/pki-group-del-ca-group-007.out" \
                           0 \
                           "Deleting group with maximum group id length and character symbols using CA_adminV"	
	actual_groupid_string=`cat $TmpDir/pki-group-del-ca-group-007.out| grep 'Deleted group' | xargs echo`
        expected_groupid_string="Deleted group $groupid"
	if [[ $actual_groupid_string = $expected_groupid_string ]] ; then
                rlPass "Deleted group $groupid found"
        else
                rlFail "Deleted group $groupid not found"
        fi
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-show '$groupid'  > $TmpDir/pki-group-del-ca-group-007_2.out 2>&1" \
                           255 \
                           "Verify expected error message - deleted group with max length and character symbols should not exist"
        actual_error_string=`cat $TmpDir/pki-group-del-ca-group-007_2.out| grep 'GroupNotFoundException:' | xargs echo`
        expected_error_string="GroupNotFoundException: Group $groupid not found"
	if [[ $actual_error_string = $expected_error_string ]] ; then
                rlPass "GroupNotFoundException: Group $groupid not found message found"
        else
                rlFail "GroupNotFoundException: Group $groupid not found message not found"
        fi
     rlPhaseEnd
    
    rlPhaseStartTest "pki_group_cli_group_del-CA-008: Delete group from CA with -t option"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"g1description\" g1 > $TmpDir/pki-group-add-ca-009.out" \
                    0 \
                    "Add group g1 to CA"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-del g1 > $TmpDir/pki-group-del-ca-group-009.out" \
                    0 \
                    "Deleting group g1 using -t ca option" 
	rlAssertGrep "Deleted group \"g1\"" "$TmpDir/pki-group-del-ca-group-009.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show g1"
        errmsg="GroupNotFoundException: Group g1 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group g1 should not exist"	
    rlPhaseEnd 
     
    rlPhaseStartTest "pki_group_cli_group_del-CA-009: Should not be able to delete group using a revoked cert CA_adminR"
	#Add a group
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"g2description\" g2 > $TmpDir/pki-group-add-ca-010.out" \
                    0 \
                    "Add group g2 to CA"
	command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a admin having a revoked cert"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-001.out" \
		    0 \
		    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-001.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-001.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-010: Should not be able to delete group using a agent with revoked cert CA_agentR"
	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a agent having a revoked cert"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-002.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-002.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-002.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-011: Should not be able to delete group using a valid agent CA_agentV user"
	command="pki -d $CERTDB_DIR -n CA_agentV  -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a valid agent cert"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-003.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-003.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-003.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-003.out"
    rlPhaseEnd
    
    rlPhaseStartTest "pki_group_cli_group_del-CA-012: Should not be able to delete group using a admin user with expired cert CA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="PKIException: Unauthorized" 
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using an expired admin cert"
	#Set datetime back on original
        rlRun "date --set='-2 days'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-004.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-004.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-004.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-004.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_group_cli_group_del-CA-013: Should not be able to delete a group using CA_agentE cert"
	rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
        rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="ClientResponseFailure: Error status 401 Unauthorized returned"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a agent cert"

        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='-2 days'" 0 "Set System back to the present day"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-005.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-005.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-005.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-005.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_group_cli_group_del-CA-014: Should not be able to delete group using a CA_auditV"
	command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a audit cert"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-006.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-006.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-006.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-006.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-015: Should not be able to delete group using a CA_operatorV"
	command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD group-del g2"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a operator cert"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-007.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-007.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-007.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-016: Should not be able to delete group using a cert created from a untrusted CA CA_adminUTCA"
	command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password group-del g2"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete group g2 using a untrusted cert"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-008.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-008.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-008.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-017: Should not be able to delete group using a user cert"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        #Create a user cert
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
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $temp_out  -t \"u,u,u\""
        local expfile="$TmpDir/expfile_pkiuser1.out"
        rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c Password \
                    group-del g2"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password group-del g2" > $expfile
        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        echo "send -- \"\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        cat $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-group-del-ca-pkiUser1-002.out 2>&1" 255 "Should not be able to delete groups using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-group-del-ca-pkiUser1-002.out"
	#Make sure group is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show g2 > $TmpDir/pki-group-show-ca-009.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-group-show-ca-009.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-show-ca-009.out"
        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-show-ca-009.out"	

	#Cleanup:delete group g2
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-del g2 > $TmpDir/pki-group-del-ca-018.out 2>&1"	
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-018: delete group id with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test 'ÖrjanÄke' > $TmpDir/pki-group-add-ca-001_19.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
        rlAssertGrep "Added group \"ÖrjanÄke\"" "$TmpDir/pki-group-add-ca-001_19.out"
        rlAssertGrep "Group ID: ÖrjanÄke" "$TmpDir/pki-group-add-ca-001_19.out"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-del 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-del 'ÖrjanÄke' > $TmpDir/pki-group-del-ca-001_19_3.out 2>&1" \
                    0 \
                    "Deleted gid ÖrjanÄke with i18n characters"
	rlAssertGrep "Deleted group \"ÖrjanÄke\""  "$TmpDir/pki-group-del-ca-001_19_3.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show 'ÖrjanÄke'"
        errmsg="GroupNotFoundException: Group ÖrjanÄke not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group 'ÖrjanÄke' should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_del-CA-020: delete groupid with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test 'ÉricTêko' > $TmpDir/pki-group-add-ca-001_20.out 2>&1" \
                    0 \
                    "Adding group id ÉricTêko with i18n characters"
        rlAssertGrep "Added group \"ÉricTêko\"" "$TmpDir/pki-group-add-ca-001_20.out"
        rlAssertGrep "Group ID: ÉricTêko" "$TmpDir/pki-group-add-ca-001_20.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show 'ÉricTêko' > $TmpDir/pki-group-add-ca-001_20_2.out" \
                    0 \
                    "Show group 'ÉricTêko'"
        rlAssertGrep "Group \"ÉricTêko\"" "$TmpDir/pki-group-add-ca-001_20_2.out"
        rlAssertGrep "Group ID: ÉricTêko" "$TmpDir/pki-group-add-ca-001_20_2.out"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-del 'ÉricTêko'"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-del 'ÉricTêko' > $TmpDir/pki-group-del-ca-001_20_3.out 2>&1" \
                    0 \
                    "Delete gid ÉricTêko with i18n characters"
	rlAssertGrep "Deleted group \"ÉricTêko\""  "$TmpDir/pki-group-del-ca-001_20_3.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-show 'ÉricTêko'"
        errmsg="GroupNotFoundException: Group ÉricTêko not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted group 'ÉricTêko' should not exist"
    rlPhaseEnd 

    rlPhaseStartTest "pki_group_cli_group_del-CA_cleanup-004: Deleting the temp directory"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
