#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-del CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-del   Delete pki subsystem users.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
#   	    Laxmi Sunkara <lsunkara@redhat.com>
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

run_pki-user-cli-user-del-ca_tests(){

    rlPhaseStartSetup "pki_user_cli_user_del-CA-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-ca-configtest-001: pki user-del --help configuration test"
        rlRun "pki user-del --help > $TmpDir/user_del.out 2>&1" 0 "pki user-del --help"
        rlAssertGrep "usage: user-del <User ID>" "$TmpDir/user_del.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/user_del.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-ca-configtest-002: pki user-del configuration test"
        rlRun "pki user-del > $TmpDir/user_del_2.out 2>&1" 255 "pki user-del"
        rlAssertGrep "usage: user-del <User ID>" "$TmpDir/user_del_2.out"
        rlAssertGrep " --help   Show help options" "$TmpDir/user_del_2.out"
	rlAssertNotGrep "ResteasyIOException: IOException" "$TmpDir/user_del_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-003: Delete valid users" 
	user1=ca_agent2
	user1fullname="Test ca_agent"
	user2=abcdefghijklmnopqrstuvwxyx12345678
	user3=abc#
	user4=abc$
	user5=abc@
	user6=abc?
	user7=0
	#positive test cases
	#Add users to CA using CA_adminV cert
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user u$i"
                let i=$i+1
        done

	#===Deleting users created using CA_adminV cert===#
	i=1
	while [ $i -lt 25 ] ; do
	       rlLog "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i"
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user1-00$i.out" \
                           0 \
                           "Deleted user  u$i"
		rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user1-00$i.out"
	   	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD	user-show u$i"
		errmsg="UserNotFoundException: User u$i not found"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user should not exist"
                let i=$i+1
        done
	#Add users to CA using CA_adminV cert
        i=1
        while [ $i -lt 8 ] ; do
	       eval usr=\$user$i
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user $usr"
                let i=$i+1
        done

        #===Deleting users(symbols) created using CA_adminV cert===#
	j=1
        while [ $j -lt 8 ] ; do
	       eval usr=\$user$j
	       rlLog "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del $usr "
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del $usr > $TmpDir/pki-user-del-ca-user2-00$j.out" \
			   0 \
			   "Deleted user  $usr"
		rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user2-00$j.out"
	   	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD	user-show $usr"
		errmsg="UserNotFoundException: User $usr not found"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user should not exist"
                let j=$j+1
        done
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-004: Case sensitive userid"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user user_abc"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  USER_ABC > $TmpDir/pki-user-del-ca-user-002_1.out" \
                           0 \
                           "Deleted user USER_ABC userid is not case sensitive"
        rlAssertGrep "Deleted user \"USER_ABC\"" "$TmpDir/pki-user-del-ca-user-002_1.out"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD	user-show user_abc"
	errmsg="UserNotFoundException: User user_abc not found"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user user_abc should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-005: Delete user when required option user id is missing"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  > $TmpDir/pki-user-del-ca-user-003_1.out 2>&1" \
                           255 \
                           "Cannot delete a user without userid"
        rlAssertGrep "usage: user-del <User ID>" "$TmpDir/pki-user-del-ca-user-003_1.out"
    rlPhaseEnd
  
    rlPhaseStartTest "pki_user_cli_user_del-CA-006: Maximum length of user id"
	user2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test \"$user2\" > $TmpDir/pki-user-add-ca-001_1.out" \
                    0 \
                    "Added user using CA_adminV with maximum user id length"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del \"$user2\" > $TmpDir/pki-user-del-ca-user-006.out" \
                           0 \
                           "Deleting user with maximum user id length using CA_adminV"
	actual_userid_string=`cat $TmpDir/pki-user-del-ca-user-006.out | grep 'Deleted user' | xargs echo`
        expected_userid_string="Deleted user $user2"  
	if [[ $actual_userid_string = $expected_userid_string ]] ; then
                rlPass "Deleted user \"$user2\" found"
        else
                rlFail "Deleted user \"$user2\" not found"
        fi
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD user-show \"$user2\""
        errmsg="UserNotFoundException: User \"$user2\" not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user with max length should not exist"
    rlPhaseEnd 
    
    rlPhaseStartTest "pki_user_cli_user_del-CA-007: userid with maximum length and symbols"
	userid=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test '$userid' > $TmpDir/pki-user-add-ca-001_8.out" \
                    0 \
                    "Added user using CA_adminV with maximum userid length and character symbols in it"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del '$userid' > $TmpDir/pki-user-del-ca-user-007.out" \
                           0 \
                           "Deleting user with maximum user id length and character symbols using CA_adminV"	
	actual_userid_string=`cat $TmpDir/pki-user-del-ca-user-007.out| grep 'Deleted user' | xargs echo`
        expected_userid_string="Deleted user $userid"
	if [[ $actual_userid_string = $expected_userid_string ]] ; then
                rlPass "Deleted user $userid found"
        else
                rlFail "Deleted user $userid not found"
        fi
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-show '$userid'  > $TmpDir/pki-user-del-ca-user-007_2.out 2>&1" \
                           255 \
                           "Verify expected error message - deleted user with max length and character symbols should not exist"
        actual_error_string=`cat $TmpDir/pki-user-del-ca-user-007_2.out| grep 'UserNotFoundException:' | xargs echo`
        expected_error_string="UserNotFoundException: User $userid not found"
	if [[ $actual_error_string = $expected_error_string ]] ; then
                rlPass "UserNotFoundException: User $userid not found message found"
        else
                rlFail "UserNotFoundException: User $userid not found message not found"
        fi
     rlPhaseEnd
    
     rlPhaseStartTest "pki_user_cli_user_del-CA-008: delete user that has all attributes and a certificate"
	user1="testuser1"
	user1fullname="Test ca_agent"
	email="ca_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"	
	pem_file="$TmpDir/testuser1.pem"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  \
		    --email $email \
		    --password $user_password \
		    --phone $phone \
		    --state $state \
		    --type $type \
		     $user1 >  $TmpDir/pki-user-add-ca-008.out" \
                    0 \
                    "Add user $user1 to CA -- all options provided"
	#Add certificate to the user
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"$user1\" \"$user1fullname\" \
                \"$user1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        rlLog "pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
        rlRun "pki cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
        rlLog "valid_serialNumber=$valid_serialNumber"
        rlRun "pki cert-show $valid_serialNumber --output $pem_file" 0 "command pki cert-show $valid_serialNumber --output"
	rlLog "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-cert-add $user1 --input $pem_file" 
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-cert-add $user1 --input $pem_file  > $TmpDir/pki_user_cert_add_CA_useraddcert_008.out" \
                    0 \
                    "Cert is added to the user $user1"
	#Add user to Administrator's group
	gid="Administrators"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-membership-add $user1 \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-ca-008.out" \
                    0 \
                    "Adding user $user1 to group \"$gid\""	
	#Delete user
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  $user1 > $TmpDir/pki-user-del-ca-user-008.out" \
                           0 \
                           "Deleting user $user1 with all attributes and a certificate"
        rlAssertGrep "Deleted user \"$user1\"" "$TmpDir/pki-user-del-ca-user-008.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD user-show $user1"
        errmsg="UserNotFoundException: User $user1 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user $user1 should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-009: Delete user from CA with -t option"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"u22fullname\"  u22 > $TmpDir/pki-user-add-ca-009.out" \
                    0 \
                    "Add user u22 to CA"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-del u22 > $TmpDir/pki-user-del-ca-user-009.out" \
                    0 \
                    "Deleting user u22 using -t ca option" 
	rlAssertGrep "Deleted user \"u22\"" "$TmpDir/pki-user-del-ca-user-009.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD user-show u22"
        errmsg="UserNotFoundException: User u22 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user u22 should not exist"	
    rlPhaseEnd 
     
    rlPhaseStartTest "pki_user_cli_user_del-CA-010: Should not be able to delete user using a revoked cert CA_adminR"
	#Add a user
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"u23fullname\"  u23 > $TmpDir/pki-user-add-ca-010.out" \
                    0 \
                    "Add user u23 to CA"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a admin having a revoked cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-001.out" \
		    0 \
		    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-001.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-001.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-011: Should not be able to delete user using a agent with revoked cert CA_agentR"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a agent having a revoked cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-002.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-002.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-002.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-012: Should not be able to delete user using a valid agent CA_agentV user"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_agentV  -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a valid agent cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-003.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-003.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-003.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-003.out"
    rlPhaseEnd
    
    rlPhaseStartTest "pki_user_cli_user_del-CA-013: Should not be able to delete user using a admin user with expired cert CA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="PKIException: Unauthorized" 
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using an expired admin cert"
	#Set datetime back on original
        rlRun "date --set='-2 days'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-004.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-004.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-004.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-004.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_user_cli_user_del-CA-014: Should not be able to delete a user using CA_agentE cert"
	rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
        rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="ClientResponseFailure: Error status 401 Unauthorized returned"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a agent cert"

        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='-2 days'" 0 "Set System back to the present day"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-005.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-005.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-005.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-005.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_user_cli_user_del-CA-015: Should not be able to delete user using a CA_auditV"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a audit cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-006.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-006.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-006.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-006.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-016: Should not be able to delete user using a CA_operatorV"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23"
	command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD user-del u23"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a operator cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-007.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-007.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-007.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-017: Should not be able to delete user using a cert created from a untrusted CA CA_adminUTCA"
        rlLog "Executing: pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-del u23"
	command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password user-del u23"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a untrusted cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-008.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-008.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-008.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-018: Should not be able to delete user using a user cert"
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
                    user-del u23"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password user-del u23" > $expfile
        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        echo "send -- \"\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        cat $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-user-del-ca-pkiUser1-002.out 2>&1" 255 "Should not be able to delete users using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-user-del-ca-pkiUser1-002.out"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u23 > $TmpDir/pki-user-show-ca-009.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-009.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-009.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-user-show-ca-009.out"	

	#Cleanup:delete user u23
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del u23 > $TmpDir/pki-user-del-ca-018.out 2>&1"	
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-019: delete user id with i18n characters"
	rlLog "user-add userid ÖrjanÄke with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÖrjanÄke' > $TmpDir/pki-user-add-ca-001_19.out 2>&1" \
                    0 \
                    "Adding uid ÖrjanÄke with i18n characters"
        rlAssertGrep "Added user \"ÖrjanÄke\"" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-user-add-ca-001_19.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÖrjanÄke' > $TmpDir/pki-user-add-ca-001_19_2.out" \
                    0 \
                    "Show user 'ÖrjanÄke'"
	rlAssertGrep "User \"ÖrjanÄke\"" "$TmpDir/pki-user-add-ca-001_19_2.out"
        rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-user-add-ca-001_19_2.out"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del 'ÖrjanÄke' > $TmpDir/pki-user-del-ca-001_19_3.out 2>&1" \
                    0 \
                    "Delete uid ÖrjanÄke with i18n characters"
	rlAssertGrep "Deleted user \"ÖrjanÄke\""  "$TmpDir/pki-user-del-ca-001_19_3.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD user-show 'ÖrjanÄke'"
        errmsg="UserNotFoundException: User 'ÖrjanÄke' not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user 'ÖrjanÄke' should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_del-CA-020: delete userid with i18n characters"
        rlLog "user-add userid ÉricTêko with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÉricTêko' > $TmpDir/pki-user-add-ca-001_20.out 2>&1" \
                    0 \
                    "Adding user id ÉricTêko with i18n characters"
        rlAssertGrep "Added user \"ÉricTêko\"" "$TmpDir/pki-user-add-ca-001_20.out"
        rlAssertGrep "User ID: ÉricTêko" "$TmpDir/pki-user-add-ca-001_20.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÉricTêko' > $TmpDir/pki-user-add-ca-001_20_2.out" \
                    0 \
                    "Show user 'ÉricTêko'"
        rlAssertGrep "User \"ÉricTêko\"" "$TmpDir/pki-user-add-ca-001_20_2.out"
        rlAssertGrep "User ID: ÉricTêko" "$TmpDir/pki-user-add-ca-001_20_2.out"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del 'ÉricTêko'"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-del 'ÉricTêko' > $TmpDir/pki-user-del-ca-001_20_3.out 2>&1" \
                    0 \
                    "Delete uid ÉricTêko with i18n characters"
	rlAssertGrep "Deleted user \"ÉricTêko\""  "$TmpDir/pki-user-del-ca-001_20_3.out"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD user-show 'ÉricTêko'"
        errmsg="UserNotFoundException: User 'ÉricTêko' not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user 'ÉricTêko' should not exist"
    rlPhaseEnd 

    rlPhaseStartTest "pki_user_cli_user_del-CA_cleanup-004: Deleting the temp directory"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
