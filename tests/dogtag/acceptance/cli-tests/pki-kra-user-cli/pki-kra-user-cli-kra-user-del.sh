#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI kra-user-del CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-kra-user-del   Delete pki subsystem KRA users.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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
#create_role_users.sh should be first executed prior to pki-user-cli-kra-user-del.sh
########################################################################

run_pki-kra-user-cli-kra-user-del_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	caId=$4
	CA_HOST=$5
	prefix=$subsystemId

	# Creating Temporary Directory for pki user-kra
        rlPhaseStartSetup "pki user-kra Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $MYROLE $TmpDir/topo_file
        local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
        kra_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$KRA_INST
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                prefix=KRA3
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
  if [ "$kra_instance_created" = "TRUE" ] ;  then
    rlPhaseStartTest "pki_kra_user_cli_kra_kra_user_del-configtest-001: pki kra-user-del --help configuration test"
        rlRun "pki kra-user-del --help > $TmpDir/user_del.out 2>&1" 0 "pki kra-user-del --help"
        rlAssertGrep "usage: kra-user-del <User ID>" "$TmpDir/user_del.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/user_del.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_kra_user_del-configtest-002: pki kra-user-del configuration test"
        rlRun "pki kra-user-del > $TmpDir/user_del_2.out 2>&1" 255 "pki kra-user-del"
        rlAssertGrep "usage: kra-user-del <User ID>" "$TmpDir/user_del_2.out"
        rlAssertGrep " --help   Show help options" "$TmpDir/user_del_2.out"
	rlAssertNotGrep "ResteasyIOException: IOException" "$TmpDir/user_del_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-003: Delete valid users" 
	user1=ca_agent2
	user1fullname="Test ca_agent"
	user2=abcdefghijklmnopqrstuvwxyx12345678
	user3=abc#
	user4=abc$
	user5=abc@
	user6=abc?
	user7=0
	#positive test cases
	#Add users to CA using ${prefix}_adminV cert
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-add --fullName=test_user u$i"
                let i=$i+1
        done

	#===Deleting users created using ${prefix}_adminV cert===#
	i=1
	while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		  	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-del  u$i > $TmpDir/pki-kra-user-del-kra-user1-00$i.out" \
                           0 \
                           "Deleted user  u$i"
		rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-kra-user-del-kra-user1-00$i.out"
	   	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT)  kra-user-show u$i"
		errmsg="UserNotFoundException: User u$i not found"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user should not exist"
                let i=$i+1
        done
	#Add users to CA using ${prefix}_adminV cert
        i=1
        while [ $i -lt 8 ] ; do
	       eval usr=\$user$i
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-add --fullName=test_user $usr"
                let i=$i+1
        done

        #===Deleting users(symbols) created using ${prefix}_adminV cert===#
	j=1
        while [ $j -lt 8 ] ; do
	       eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-del $usr > $TmpDir/pki-kra-user-del-kra-user2-00$j.out" \
			   0 \
			   "Deleted user  $usr"
		rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-kra-user-del-kra-user2-00$j.out"
	   	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show $usr"
		errmsg="UserNotFoundException: User $usr not found"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user should not exist"
                let j=$j+1
        done
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-004: Case sensitive userid"
	rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-add --fullName=test_user user_abc"
	rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-del  USER_ABC > $TmpDir/pki-kra-user-del-kra-user-002_1.out" \
                           0 \
                           "Deleted user USER_ABC userid is not case sensitive"
        rlAssertGrep "Deleted user \"USER_ABC\"" "$TmpDir/pki-kra-user-del-kra-user-002_1.out"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show user_abc"
	errmsg="UserNotFoundException: User user_abc not found"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user user_abc should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-005: Delete user when required option user id is missing"
	rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-del  > $TmpDir/pki-kra-user-del-kra-user-003_1.out 2>&1" \
                           255 \
                           "Cannot delete a user without userid"
        rlAssertGrep "usage: kra-user-del <User ID>" "$TmpDir/pki-kra-user-del-kra-user-003_1.out"
    rlPhaseEnd
  
    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-006: Maximum length of user id"
	user2=$(openssl rand -base64 30000 | strings | grep -io [[:alnum:]] | head -n 2047 | tr -d '\n')
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 	   	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName=test \"$user2\" > $TmpDir/pki-kra-user-add-kra-001_1.out" \
                    0 \
                    "Added user using ${prefix}_adminV with maximum user id length"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del \"$user2\" > $TmpDir/pki-kra-user-del-kra-user-006.out" \
                    0 \
                    "Deleting user with maximum user id length using ${prefix}_adminV"
	actual_userid_string=`cat $TmpDir/pki-kra-user-del-kra-user-006.out | grep 'Deleted user' | xargs echo`
        expected_userid_string="Deleted user $user2"  
	if [[ $actual_userid_string = $expected_userid_string ]] ; then
                rlPass "Deleted user \"$user2\" found"
        else
                rlFail "Deleted user \"$user2\" not found"
        fi
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show \"$user2\""
        errmsg="UserNotFoundException: User \"$user2\" not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user with max length should not exist"
    rlPhaseEnd 
    
    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-007: userid with maximum length and symbols"
	specialcharacters="!?@~#*^_+$"
	userid=$(openssl rand -base64 30000 | strings | grep -io [[:alnum:]] | head -n 2037 | tr -d '\n')
	userid=$userid$specialcharacters
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName=test '$userid' > $TmpDir/pki-kra-user-add-kra-001_8.out" \
                    0 \
                    "Added user using ${prefix}_adminV with maximum userid length and character symbols in it"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del '$userid' > $TmpDir/pki-kra-user-del-kra-user-007.out" \
                    0 \
                    "Deleting user with maximum user id length and character symbols using ${prefix}_adminV"	
	actual_userid_string=`cat $TmpDir/pki-kra-user-del-kra-user-007.out| grep 'Deleted user' | xargs echo`
        expected_userid_string="Deleted user $userid"
	if [[ $actual_userid_string = $expected_userid_string ]] ; then
                rlPass "Deleted user $userid found"
        else
                rlFail "Deleted user $userid not found"
        fi
	rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   	  -h $SUBSYSTEM_HOST \
 			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           kra-user-show '$userid'  > $TmpDir/pki-kra-user-del-kra-user-007_2.out 2>&1" \
                           255 \
                           "Verify expected error message - deleted user with max length and character symbols should not exist"
        actual_error_string=`cat $TmpDir/pki-kra-user-del-kra-user-007_2.out| grep 'UserNotFoundException:' | xargs echo`
        expected_error_string="UserNotFoundException: User $userid not found"
	if [[ $actual_error_string = $expected_error_string ]] ; then
                rlPass "UserNotFoundException: User $userid not found message found"
        else
                rlFail "UserNotFoundException: User $userid not found message not found"
        fi
     rlPhaseEnd
    
     rlPhaseStartTest "pki_kra_user_cli_kra_user_del-008: delete user that has all attributes and a certificate"
	user1="testuser1"
	user1fullname="Test kra_agent"
	email="kra_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"	
	pem_file="$TmpDir/testuser1.pem"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName=\"$user1fullname\"  \
		    --email $email \
		    --password $user_password \
		    --phone $phone \
		    --state $state \
		    --type $type \
		     $user1 >  $TmpDir/pki-kra-user-add-kra-008.out" \
                    0 \
                    "Add user $user1 to KRA -- all options provided"
	#Add certificate to the user
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"$user1\" \"$user1fullname\" \
                \"$user1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $CA_HOST $(eval echo \$${caId}_UNSECURE_PORT)" 0 "Generating  pkcs10 Certificate Request"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                --action approve 1"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        rlLog "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
        rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
        rlLog "valid_serialNumber=$valid_serialNumber"
        rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-show $valid_serialNumber --output $pem_file" 0 "command pki cert-show $valid_serialNumber --output"
	rlLog "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-cert-add $user1 --input $pem_file" 
        rlRun "pki -d $CERTDB_DIR/ \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-cert-add $user1 --input $pem_file  > $TmpDir/pki_user_cert_add_${prefix}_useraddcert_008.out" \
                    0 \
                    "Cert is added to the user $user1"
	#Add user to Administrator's group
	gid="Administrators"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-membership-add $user1 \"$gid\" > $TmpDir/pki-kra-user-membership-add-groupadd-kra-008.out" \
                    0 \
                    "Adding user $user1 to group \"$gid\""	
	#Delete user
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del  $user1 > $TmpDir/pki-kra-user-del-kra-user-008.out" \
                    0 \
                   "Deleting user $user1 with all attributes and a certificate"
        rlAssertGrep "Deleted user \"$user1\"" "$TmpDir/pki-kra-user-del-kra-user-008.out"
        command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show $user1"
        errmsg="UserNotFoundException: User $user1 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user $user1 should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-009: Delete user from CA with -t option"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName=\"u22fullname\"  u22 > $TmpDir/pki-kra-user-add-kra-009.out" \
                    0 \
                    "Add user u22 to CA"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t kra \
                    kra-user-del u22 > $TmpDir/pki-kra-user-del-kra-user-009.out" \
                    0 \
                    "Deleting user u22 using -t kra option" 
	rlAssertGrep "Deleted user \"u22\"" "$TmpDir/pki-kra-user-del-kra-user-009.out"
        command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show u22"
        errmsg="UserNotFoundException: User u22 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user u22 should not exist"	
    rlPhaseEnd 
     
    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-010: Should not be able to delete user using a revoked cert KRA_adminR"
	#Add a user
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName=\"u23fullname\"  u23 > $TmpDir/pki-kra-user-add-kra-010.out" \
                    0 \
                    "Add user u23 to CA"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT)  kra-user-del u23"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a admin having a revoked cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u23 > $TmpDir/pki-kra-user-show-kra-001.out" \
		    0 \
		    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-kra-user-show-kra-001.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-kra-user-show-kra-001.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-kra-user-show-kra-001.out"
	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-011: Should not be able to delete user using a agent with revoked cert KRA_agentR"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u23"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u23 using a agent having a revoked cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u23 > $TmpDir/pki-kra-user-show-kra-002.out" \
                    0 \
                    "Show user u23"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-kra-user-show-kra-002.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-kra-user-show-kra-002.out"
        rlAssertGrep "Full name: u23fullname" "$TmpDir/pki-kra-user-show-kra-002.out"
	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"

	#Cleanup:delete user u23
        rlRun "pki -d $CERTDB_DIR \
		   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $SUBSYSTEM_HOST \
                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del u23 > $TmpDir/pki-kra-user-del-kra-002_2.out 2>&1"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-012: Should not be able to delete user using a valid agent KRA_agentV user"
	#Add a user
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $SUBSYSTEM_HOST \
                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName=\"u24fullname\"  u24 > $TmpDir/pki-kra-user-add-kra-012.out" \
                    0 \
                    "Add user u24 to CA"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentV  -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u24"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u24 using a valid agent cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-003.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-003.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-003.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-003.out"
    rlPhaseEnd
    
    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-013: Should not be able to delete user using a admin user with expired cert KRA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u24"
	errmsg="PKIException: Unauthorized" 
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u24 using an expired admin cert"
	#Set datetime back on original
        rlRun "date --set='-2 days'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/962"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-004.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-004.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-004.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-004.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-014: Should not be able to delete a user using KRA_agentE cert"
	rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
        rlRun "date"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u24"
	errmsg="ClientResponseFailure: Error status 401 Unauthorized returned"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u24 using a agent cert"

        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='-2 days'" 0 "Set System back to the present day"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-005.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-005.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-005.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-005.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-015: Should not be able to delete user using a KRA_auditV"
	command="pki -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u24"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u24 using a audit cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-006.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-006.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-006.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-006.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-016: Should not be able to delete user using a KRA_operatorV"
	command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u24"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u24 using a operator cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-007.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-007.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-007.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-017: Should not be able to delete user using a cert created from a untrusted CA role_user_UTCA"
        rlLog "Executing: pki -d $UNTRUSTED_CERT_DB_LOCATION \
                   -n role_user_UTCA \
                   -c $UNTRUSTED_CERT_DB_PASSWORD \
		   -h $SUBSYSTEM_HOST \
                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del u24"
	command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-del u24"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to delete user u24 using a untrusted cert"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
	  	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-008.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-008.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-008.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-018: Should not be able to delete user using a user cert"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        #Create a user cert
        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"pki User1\" \"pkiUser1\" \
                \"pkiuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $CA_HOST $(eval echo \$${caId}_UNSECURE_PORT)" 0 "Generating  pkcs10 Certificate Request"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                --action approve 1"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate request"
        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        rlLog "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
        rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
        rlLog "valid_serialNumber=$valid_serialNumber"
        #Import user certs to $TEMP_NSS_DB
        rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $temp_out  -t \"u,u,u\""
        local expfile="$TmpDir/expfile_pkiuser1.out"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT)  kra-user-del u24" > $expfile
        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on '$(eval echo \$${subsystemId}_SSL_SERVER_CERT_SUBJECT_NAME)' indicates a non-trusted CA cert '$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:8080/ca\]: \"" >> $expfile
        echo "send -- \"http://$HOSTNAME:$(eval echo \$${caId}_UNSECURE_PORT)/ca\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        cat $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-kra-user-del-kra-pkiUser1-002.out 2>&1" 255 "Should not be able to delete users using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-kra-user-del-kra-pkiUser1-002.out"
	#Make sure user is not deleted
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-show u24 > $TmpDir/pki-kra-user-show-kra-009.out" \
                    0 \
                    "Show user u24"
        rlAssertGrep "User \"u24\"" "$TmpDir/pki-kra-user-show-kra-009.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-kra-user-show-kra-009.out"
        rlAssertGrep "Full name: u24fullname" "$TmpDir/pki-kra-user-show-kra-009.out"

	#Cleanup:delete user u24
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del u24 > $TmpDir/pki-kra-user-del-kra-018.out 2>&1"	
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-019: delete user name with i18n characters"
	rlLog "kra-user-add username ÖrjanÄke with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName='ÖrjanÄke' u19 > $TmpDir/pki-kra-user-add-kra-001_19.out 2>&1" \
                    0 \
                    "Adding user name  ÖrjanÄke with i18n characters"
        rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-kra-user-add-kra-001_19.out"
        rlAssertGrep "User ID: u19" "$TmpDir/pki-kra-user-add-kra-001_19.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del u19 > $TmpDir/pki-kra-user-del-kra-001_19_3.out 2>&1" \
                    0 \
                    "Delete user with name ÖrjanÄke i18n characters"
	rlAssertGrep "Deleted user \"u19\""  "$TmpDir/pki-kra-user-del-kra-001_19_3.out"
        command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show u19"
        errmsg="UserNotFoundException: User u19 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user id with name 'ÖrjanÄke' should not exist"
    rlPhaseEnd

    rlPhaseStartTest "pki_kra_user_cli_kra_user_del-020: delete username with i18n characters"
        rlLog "kra-user-add username ÉricTêko with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-add --fullName='ÉricTêko' u20 > $TmpDir/pki-kra-user-add-kra-001_20.out 2>&1" \
                    0 \
                    "Adding user name ÉricTêko with i18n characters"
        rlAssertGrep "Added user \"u20\"" "$TmpDir/pki-kra-user-add-kra-001_20.out"
        rlAssertGrep "User ID: u20" "$TmpDir/pki-kra-user-add-kra-001_20.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    kra-user-del u20 > $TmpDir/pki-kra-user-del-kra-001_20_3.out 2>&1" \
                    0 \
                    "Delete user with name ÉricTêko i18n characters"
	rlAssertGrep "Deleted user \"u20\""  "$TmpDir/pki-kra-user-del-kra-001_20_3.out"
        command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) kra-user-show u20"
        errmsg="UserNotFoundException: User u20 not found"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - deleted user id with name 'ÉricTêko' should not exist"
    rlPhaseEnd 

    rlPhaseStartCleanup "pki_kra_user_cli_kra_user_del_cleanup: Deleting the temp directory"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
 else
	rlLog "KRA instance not installed"
 fi
}
