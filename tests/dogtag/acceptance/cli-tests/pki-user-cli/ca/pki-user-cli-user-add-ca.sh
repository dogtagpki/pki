#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-add    Add users to pki subsystems.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com> and Laxmi Sunkara <lsunkara@redhat.com>
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
########################################################################

########################################################################
# Test Suite Globals
########################################################################
run_pki-user-cli-user-add-ca_tests(){
     rlPhaseStartTest "pki_user_cli-configtest: pki user --help configuration test"
        rlRun "pki user --help > $TmpDir/pki_user_cfg.out 2>&1" \
               0 \
               "pki user --help"
        rlAssertGrep "user-find               Find users" "$TmpDir/pki_user_cfg.out"
        rlAssertGrep "user-show               Show user" "$TmpDir/pki_user_cfg.out"
        rlAssertGrep "user-add                Add user" "$TmpDir/pki_user_cfg.out"
        rlAssertGrep "user-mod                Modify user" "$TmpDir/pki_user_cfg.out"
        rlAssertGrep "user-del                Remove user" "$TmpDir/pki_user_cfg.out"
        rlAssertGrep "user-cert               User certificate management commands" "$TmpDir/pki_user_cfg.out"
        rlAssertGrep "user-membership         User membership management commands" "$TmpDir/pki_user_cfg.out"
        rlAssertNotGrep "Error: Invalid module \"user---help\"." "$TmpDir/pki_user_cfg.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/519"
     rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-configtest: pki user-add configuration test"
        rlRun "pki user-add --help > $TmpDir/pki_user_add_cfg.out 2>&1" \
               0 \
               "pki user-add --help"
        rlAssertGrep "usage: user-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--email <email>         Email" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--fullName <fullName>   Full name" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--password <password>   Password" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--phone <phone>         Phone" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--state <state>         State" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--type <type>           Type" "$TmpDir/pki_user_add_cfg.out"
        rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_user_add_cfg.out"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/519"
    rlPhaseEnd

     ##### Tests to add CA users using a user of admin group with a valid cert####
    rlPhaseStartTest "pki_user_cli_user_add-CA-001: Add a user to CA using CA_adminV"
	user1=ca_agent2
	user1fullname="Test ca_agent"
        rlLog "Executing: pki -d $CERTDB_DIR \
		   -n CA_adminV \
		   -c $CERTDB_DIR_PASSWORD \
		    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
		   -n CA_adminV \
		   -c $CERTDB_DIR_PASSWORD \
		    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-001.out" \
		    0 \
		    "Add user $user1 to CA_adminV"
        rlAssertGrep "Added user \"$user1\"" "$TmpDir/pki-user-add-ca-001.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ca-001.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-002:maximum length of user id"
	user2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test \"$user2\" > $TmpDir/pki-user-add-ca-001_1.out" \
                    0 \
                    "Added user using CA_adminV with maximum user id length"
	actual_userid_string=`cat $TmpDir/pki-user-add-ca-001_1.out | grep 'User ID:' | xargs echo`
        expected_userid_string="User ID: $user2"                       
        if [[ $actual_userid_string = $expected_userid_string ]] ; then
                rlPass "User ID: $user2 found"
        else
                rlFail "User ID: $user2 not found"
        fi
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_1.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-003:User id with # character"
	user3=abc#
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
			    user-add --fullName=test $user3 > $TmpDir/pki-user-add-ca-001_2.out" \
                    0 \
                    "Added user using CA_adminV, user id with # character"
        rlAssertGrep "Added user \"$user3\"" "$TmpDir/pki-user-add-ca-001_2.out"
        rlAssertGrep "User ID: $user3" "$TmpDir/pki-user-add-ca-001_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-004:User id with $ character"
	user4=abc$
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
			    user-add --fullName=test $user4 > $TmpDir/pki-user-add-ca-001_3.out" \
                    0 \
                    "Added user using CA_adminV, user id with $ character"
        rlAssertGrep "Added user \"$user4\"" "$TmpDir/pki-user-add-ca-001_3.out"
        rlAssertGrep "User ID: abc\\$" "$TmpDir/pki-user-add-ca-001_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-005:User id with @ character"
	user5=abc@
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user5 > $TmpDir/pki-user-add-ca-001_4.out " \
                    0 \
                    "Added user using CA_adminV, user id with @ character"
        rlAssertGrep "Added user \"$user5\"" "$TmpDir/pki-user-add-ca-001_4.out"
        rlAssertGrep "User ID: $user5" "$TmpDir/pki-user-add-ca-001_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-006:User id with ? character"
	user6=abc?
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user6 > $TmpDir/pki-user-add-ca-001_5.out " \
                    0 \
                    "Added user using CA_adminV, user id with ? character"
        rlAssertGrep "Added user \"$user6\"" "$TmpDir/pki-user-add-ca-001_5.out"
        rlAssertGrep "User ID: $user6" "$TmpDir/pki-user-add-ca-001_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_5.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-007:User id as 0"
	user7=0
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user7 > $TmpDir/pki-user-add-ca-001_6.out " \
                    0 \
                    "Added user using CA_adminV, user id 0"
        rlAssertGrep "Added user \"$user7\"" "$TmpDir/pki-user-add-ca-001_6.out"
        rlAssertGrep "User ID: $user7" "$TmpDir/pki-user-add-ca-001_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_6.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-008:--email with maximum length"
	email=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=\"$email\" u1 > $TmpDir/pki-user-add-ca-001_7.out" \
                    0 \
                    "Added user using CA_adminV with maximum --email length"
        rlAssertGrep "Added user \"u1\"" "$TmpDir/pki-user-add-ca-001_7.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-user-add-ca-001_7.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_7.out"
	actual_email_string=`cat $TmpDir/pki-user-add-ca-001_7.out | grep Email: | xargs echo`
        expected_email_string="Email: $email"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "Email: $email found"
        else
                rlFail "Email: $email not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-009:--email with maximum length and symbols"
	email=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email='$email' u2 > $TmpDir/pki-user-add-ca-001_8.out" \
                    0 \
                    "Added user using CA_adminV with maximum --email length and character symbols in it"
        rlAssertGrep "Added user \"u2\"" "$TmpDir/pki-user-add-ca-001_8.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-user-add-ca-001_8.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_8.out"
	actual_email_string=`cat $TmpDir/pki-user-add-ca-001_8.out | grep Email: | xargs echo`
        expected_email_string="Email: $email"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "Email: $email found"
        else
                rlFail "Email: $email not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-010:--email with # character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=#  u3 > $TmpDir/pki-user-add-ca-001_9.out" \
                    0 \
                    "Added user using CA_adminV with --email # character"
        rlAssertGrep "Added user \"u3\"" "$TmpDir/pki-user-add-ca-001_9.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-user-add-ca-001_9.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_9.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-add-ca-001_9.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-011:--email with * character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=*  u4 > $TmpDir/pki-user-add-ca-001_10.out" \
                    0 \
                    "Added user using CA_adminV with --email * character"
        rlAssertGrep "Added user \"u4\"" "$TmpDir/pki-user-add-ca-001_10.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-user-add-ca-001_10.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_10.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-add-ca-001_10.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-012:--email with $ character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=$  u5 > $TmpDir/pki-user-add-ca-001_11.out" \
                    0 \
                    "Added user using CA_adminV with --email $ character"
        rlAssertGrep "Added user \"u5\"" "$TmpDir/pki-user-add-ca-001_11.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-user-add-ca-001_11.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_11.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-add-ca-001_11.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-013:--email as number 0"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=0  u6 > $TmpDir/pki-user-add-ca-001_12.out " \
                    0 \
                    "Added user using CA_adminV with --email 0"
        rlAssertGrep "Added user \"u6\"" "$TmpDir/pki-user-add-ca-001_12.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-user-add-ca-001_12.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_12.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-add-ca-001_12.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-014:--state with maximum length"
	state=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=\"$state\" u7 > $TmpDir/pki-user-add-ca-001_13.out" \
                    0 \
                    "Added user using CA_adminV with maximum --state length"
        rlAssertGrep "Added user \"u7\"" "$TmpDir/pki-user-add-ca-001_13.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-user-add-ca-001_13.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_13.out"
	actual_state_string=`cat $TmpDir/pki-user-add-ca-001_13.out | grep State: | xargs echo`
        expected_state_string="State: $state"
        if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "State: $state found in $TmpDir/pki-user-add-ca-001_13.out"
        else
                rlFail "State: $state not found in $TmpDir/pki-user-add-ca-001_13.out"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-015:--state with maximum length and symbols"
	state=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state='$state'  u8 > $TmpDir/pki-user-add-ca-001_14.out" \
                    0 \
                    "Added user using CA_adminV with maximum --state length and character symbols in it"
        rlAssertGrep "Added user \"u8\"" "$TmpDir/pki-user-add-ca-001_14.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-user-add-ca-001_14.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_14.out"
	actual_state_string=`cat $TmpDir/pki-user-add-ca-001_14.out | grep State: | xargs echo`
        expected_state_string="State: $state"
        if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "State: $state found in $TmpDir/pki-user-add-ca-001_14.out"
        else
                rlFail "State: $state not found in $TmpDir/pki-user-add-ca-001_14.out"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-016:--state with # character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=#  u9 > $TmpDir/pki-user-add-ca-001_15.out" \
                    0 \
                    "Added user using CA_adminV with --state # character"
        rlAssertGrep "Added user \"u9\"" "$TmpDir/pki-user-add-ca-001_15.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-user-add-ca-001_15.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_15.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-add-ca-001_15.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-017:--state with * character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=*  u10 > $TmpDir/pki-user-add-ca-001_16.out" \
                    0 \
                    "Added user using CA_adminV with --state * character"
        rlAssertGrep "Added user \"u10\"" "$TmpDir/pki-user-add-ca-001_16.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-add-ca-001_16.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_16.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-add-ca-001_16.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-018:--state with $ character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=$  u11 > $TmpDir/pki-user-add-ca-001_17.out" \
                    0 \
                    "Added user using CA_adminV with --state $ character"
        rlAssertGrep "Added user \"u11\"" "$TmpDir/pki-user-add-ca-001_17.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-user-add-ca-001_17.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_17.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-add-ca-001_17.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-019:--state as number 0"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=0  u12 > $TmpDir/pki-user-add-ca-001_18.out " \
                    0 \
                    "Added user using CA_adminV with --state 0"
        rlAssertGrep "Added user \"u12\"" "$TmpDir/pki-user-add-ca-001_18.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-user-add-ca-001_18.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_18.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-add-ca-001_18.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-020:--phone with maximum length"
	phone=`cat /dev/urandom | tr -dc '0-9' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=\"$phone\" u13 > $TmpDir/pki-user-add-ca-001_19.out" \
                    0 \
                    "Added user using CA_adminV with maximum --phone length"
        rlAssertGrep "Added user \"u13\"" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-add-ca-001_19.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-021:--phone with maximum length and symbols"
	phone=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone='$phone'  usr1 > $TmpDir/pki-user-add-ca-001_20.out  2>&1"\
                    1 \
                    "Should not be able to add user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "ClientResponseFailure: Error status 4XX" "$TmpDir/pki-user-add-ca-001_20.out"
        rlAssertNotGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_20.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/833#comment:1"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-022:--phone with # character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=#  usr2 > $TmpDir/pki-user-add-ca-001_21.out  2>&1" \
                    1 \
                    "Should not be able to add user using CA_adminV --phone with character #"
        rlAssertGrep "ClientResponseFailure: Error status 4XX" "$TmpDir/pki-user-add-ca-001_21.out"
        rlAssertNotGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_21.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/833#comment:1"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-023:--phone with * character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=*  usr3 > $TmpDir/pki-user-add-ca-001_22.out 2>&1" \
                    1 \
                    "Should not be able to add user using CA_adminV --phone with character *"
        rlAssertGrep "ClientResponseFailure: Error status 4XX" "$TmpDir/pki-user-add-ca-001_22.out"
        rlAssertNotGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_22.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/833#comment:1"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-024:--phone with $ character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=$  usr4 > $TmpDir/pki-user-add-ca-001_23.out 2>&1" \
                    1 \
                    "Should not be able to add user using CA_adminV --phone with character $"
        rlAssertGrep "ClientResponseFailure: Error status 4XX" "$TmpDir/pki-user-add-ca-001_23.out"
        rlAssertNotGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_23.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/833#comment:1"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-025:--phone as negative number -1230"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=-1230  u14 > $TmpDir/pki-user-add-ca-001_24.out " \
                    0 \
                    "Added user using CA_adminV with --phone -1230"
        rlAssertGrep "Added user \"u14\"" "$TmpDir/pki-user-add-ca-001_24.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-user-add-ca-001_24.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_24.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-add-ca-001_24.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-026:--type as Auditors"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=Auditors u15 > $TmpDir/pki-user-add-ca-001_25.out" \
                    0 \
                    "Added user using CA_adminV with  --type Auditors"
        rlAssertGrep "Added user \"u15\"" "$TmpDir/pki-user-add-ca-001_25.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-user-add-ca-001_25.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_25.out"
        rlAssertGrep "Type: Auditors" "$TmpDir/pki-user-add-ca-001_25.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-027:--type Certificate Manager Agents"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Certificate Manager Agents\" u16 > $TmpDir/pki-user-add-ca-001_26.out" \
                    0 \
                    "Added user using CA_adminV  --type Certificate Manager Agents"
        rlAssertGrep "Added user \"u16\"" "$TmpDir/pki-user-add-ca-001_26.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-add-ca-001_26.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_26.out"
        rlAssertGrep "Type: Certificate Manager Agents" "$TmpDir/pki-user-add-ca-001_26.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-028:--type Registration Manager Agents"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Registration Manager Agents\"  u17 > $TmpDir/pki-user-add-ca-001_27.out" \
                    0 \
                    "Added user using CA_adminV with --type Registration Manager Agents"
        rlAssertGrep "Added user \"u17\"" "$TmpDir/pki-user-add-ca-001_27.out"
        rlAssertGrep "User ID: u17" "$TmpDir/pki-user-add-ca-001_27.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_27.out"
        rlAssertGrep "Type: Registration Manager Agents" "$TmpDir/pki-user-add-ca-001_27.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-029:--type Subsytem Group"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Subsytem Group\"  u18 > $TmpDir/pki-user-add-ca-001_28.out" \
                    0 \
                    "Added user using CA_adminV with --type Subsytem Group"
        rlAssertGrep "Added user \"u18\"" "$TmpDir/pki-user-add-ca-001_28.out"
        rlAssertGrep "User ID: u18" "$TmpDir/pki-user-add-ca-001_28.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_28.out"
        rlAssertGrep "Type: Subsytem Group" "$TmpDir/pki-user-add-ca-001_28.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-030:--type Security Domain Administrators"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Security Domain Administrators\" u19 > $TmpDir/pki-user-add-ca-001_29.out" \
                    0 \
                    "Added user using CA_adminV with --type Security Domain Administrators"
        rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-user-add-ca-001_29.out"
        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-add-ca-001_29.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_29.out"
        rlAssertGrep "Type: Security Domain Administrators" "$TmpDir/pki-user-add-ca-001_29.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-031:--type ClonedSubsystems"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=ClonedSubsystems u20 > $TmpDir/pki-user-add-ca-001_30.out" \
                    0 \
                    "Added user using CA_adminV with --type ClonedSubsystems"
        rlAssertGrep "Added user \"u20\"" "$TmpDir/pki-user-add-ca-001_30.out"
        rlAssertGrep "User ID: u20" "$TmpDir/pki-user-add-ca-001_30.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_30.out"
        rlAssertGrep "Type: ClonedSubsystems" "$TmpDir/pki-user-add-ca-001_30.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-032:--type Trusted Managers"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Trusted Managers\" u21 > $TmpDir/pki-user-add-ca-001_31.out" \
                    0 \
                    "Added user using CA_adminV with --type Trusted Managers"
        rlAssertGrep "Added user \"u21\"" "$TmpDir/pki-user-add-ca-001_31.out"
        rlAssertGrep "User ID: u21" "$TmpDir/pki-user-add-ca-001_31.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_31.out"
        rlAssertGrep "Type: Trusted Managers" "$TmpDir/pki-user-add-ca-001_31.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-033:--type Dummy Group"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Dummy Group\" u25 > $TmpDir/pki-user-add-ca-001_33.out 2>&1 "  \
                    1 \
                    "Adding user using CA_adminV with --type Dummy Group"
        rlAssertNotGrep "Added user \"u25\"" "$TmpDir/pki-user-add-ca-001_33.out"
        rlAssertNotGrep "User ID: u25" "$TmpDir/pki-user-add-ca-001_33.out"
        rlAssertNotGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_33.out"
        rlAssertNotGrep "Type: Dummy Group" "$TmpDir/pki-user-add-ca-001_33.out"
        rlAssertGrep "ClientResponseFailure: Error status 4XX" "$TmpDir/pki-user-add-ca-001_33.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/704"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-034: Add a duplicate user to CA"
         command="pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"New user\" $user1 > $TmpDir/pki-user-add-ca-002.out 2>&1 "

         rlLog "Command=$command"
         expmsg="ConflictingOperationException: Entry already exists."
         rlRun "$command" 1 "Add duplicate user"
         rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-035: Add a user to CA with -t option"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  u22"

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  u22 > $TmpDir/pki-user-add-ca-003.out" \
                    0 \
                    "Add user u22 to CA"
        rlAssertGrep "Added user \"u22\"" "$TmpDir/pki-user-add-ca-003.out"
        rlAssertGrep "User ID: u22" "$TmpDir/pki-user-add-ca-003.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ca-003.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-036:  Add a user -- missing required option user id"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\" "

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\" > $TmpDir/pki-user-add-ca-004.out" \
                     1\
                    "Add user -- missing required option user id"
        rlAssertGrep "usage: user-add <User ID> \[OPTIONS...\]" "$TmpDir/pki-user-add-ca-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-037:  Add a user -- missing required option --fullName"
        command="pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add $user1 > $TmpDir/pki-user-add-ca-005.out 2>&1"
        expmsg="Error: Missing required option: fullName"
        rlLog "Executing: $command"
        rlRun "$command" 1 "Add a user -- missing required option --fullName"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ca-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-038:  Add a user -- all options provided"
        email="ca_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                    --type $type \
                     u23"

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
		     u23 >  $TmpDir/pki-user-add-ca-006_1.out" \
                    0 \
                    "Add user u23 to CA -- all options provided"
        rlAssertGrep "Added user \"u23\"" "$TmpDir/pki-user-add-ca-006_1.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-add-ca-006_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ca-006_1.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-add-ca-006_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-add-ca-006_1.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-add-ca-006_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-add-ca-006_1.out"
    rlPhaseEnd

   rlPhaseStartTest "pki_user_cli_user_add-CA-039:  Add user to multiple groups"
       user=u24
       userfullname="Multiple Group User"
       email="multiplegroup@myemail.com"
       user_password="admin2Password"
       phone="1234567890"
       state="NC"
       rlLog "Executing: pki -d $CERTDB_DIR \
                  -n CA_adminV \
                  -c $CERTDB_DIR_PASSWORD \
                  -t ca \
                   user-add --fullName=\"$userfullname\"  \
                   --email $email \
                   --password $user_password \
                   --phone $phone \
                   --state $state \
                    $user"

       rlRun "pki -d $CERTDB_DIR \
                  -n CA_adminV \
                  -c $CERTDB_DIR_PASSWORD \
                  -t ca \
                   user-add --fullName=\"$userfullname\"  \
                   --email $email \
                   --password $user_password \
                   --phone $phone \
                   --state $state \
                    $user > $TmpDir/pki-user-add-ca-006.out " \
                   0 \
                   "Add user $user using CA_adminV"
        rlAssertGrep "Added user \"u24\"" "$TmpDir/pki-user-add-ca-006.out"
        rlAssertGrep "User ID: u24" "$TmpDir/pki-user-add-ca-006.out"
        rlAssertGrep "Full name: $userfullname" "$TmpDir/pki-user-add-ca-006.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-add-ca-006.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-add-ca-006.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-add-ca-006.out"

       rlRun "pki -d $CERTDB_DIR \
                  -n CA_adminV \
                  -c $CERTDB_DIR_PASSWORD \
                  -t ca \
                   group-member-add Administrators $user > $TmpDir/pki-user-add-ca-007_1.out"  \
                   0 \
                   "Add user $user to Administrators group"

       rlAssertGrep "Added group member \"$user\"" "$TmpDir/pki-user-add-ca-007_1.out"
       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ca-007_1.out"

       rlRun "pki -d $CERTDB_DIR \
                  -n CA_adminV \
                  -c $CERTDB_DIR_PASSWORD \
                  -t ca \
                   group-member-find Administrators > $TmpDir/pki-user-add-ca-007.out" \
                   0 \
                   "Show pki group-member-find Administrators"
       rlRun "pki -d $CERTDB_DIR \
                  -n CA_adminV \
                  -c $CERTDB_DIR_PASSWORD \
                  -t ca \
                   group-member-add \"Certificate Manager Agents\"  $user > $TmpDir/pki-user-add-ca-007_1_1.out"  \
                   0 \
                   "Add user $user to Administrators group"

       rlAssertGrep "Added group member \"$user\"" "$TmpDir/pki-user-add-ca-007_1_1.out"
       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ca-007_1_1.out"

       rlRun "pki -d $CERTDB_DIR \
                  -n CA_adminV \
                  -c $CERTDB_DIR_PASSWORD \
                  -t ca \
                   group-member-find \"Certificate Manager Agents\"  > $TmpDir/pki-user-add-ca-007_2.out" \
                   0 \
                   "Show pki group-member-find Administrators"

       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ca-007_2.out"
   rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-040: Add user with --password less than 8 characters"
        userpw="pass"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-add-ca-008.out 2>&1"
        expmsg="PKIException: The password must be at least 8 characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
		   -t ca \
                    user-add --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-add-ca-008.out 2>&1" \
                    1 \
                    "Add a user --must be at least 8 characters --password"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ca-008.out"

    rlPhaseEnd

        ##### Tests to add users using revoked cert#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-041: Should not be able to add user using a revoked cert CA_adminR"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-revoke-adminR-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-revoke-adminR-002.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/821"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-042: Should not be able to add user using a agent with revoked cert CA_agentR"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-revoke-agentR-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-revoke-agentR-002.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/821"
    rlPhaseEnd


        ##### Tests to add users using an agent user#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-043: Should not be able to add user using a valid agent CA_agentV user"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentV-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a agent cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-agentV-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-044: Should not be able to add user using a CA_agentR user"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentR-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a agent cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-agentR-002.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/821"
    rlPhaseEnd

    ##### Tests to add users using expired cert#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-045: Should not be able to add user using admin user with expired cert CA_adminE"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-adminE-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a agent cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-adminE-002.out"
        rlAssertNotGrep "ResteasyIOException: IOException" "$TmpDir/pki-user-add-ca-adminE-002.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/821"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-046: Should not be able to add user using CA_agentE cert"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentE-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a agent cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-agentE-002.out"
        rlAssertNotGrep "ResteasyIOException: IOException" "$TmpDir/pki-user-add-ca-agentE-002.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/821"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

	##### Tests to add users using audit users#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-047: Should not be able to add user using a CA_auditV"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-auditV-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a audit cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-auditV-002.out"
    rlPhaseEnd

	##### Tests to add users using operator user###
    rlPhaseStartTest "pki_user_cli_user_add-CA-048: Should not be able to add user using a CA_operatorV"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-operatorV-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a operator cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-operatorV-002.out"
    rlPhaseEnd


	 ##### Tests to add users using CA_adminUTCA and CA_agentUTCA  user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-049: Should not be able to add user using a cert created from a untrusted CA CA_adminUTCA"

        rlLog "Executing: pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-adminUTCA-002.out 2>&1" \
                    1 \
                    "Should not be able to add user $user1 using a untrusted cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-adminUTCA-002.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/821"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-050: user id length exceeds maximum limit defined in the schema"
	user_length_exceed_max=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10000 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test \"$user_length_exceed_max\""
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test \"$user_length_exceed_max\" > $TmpDir/pki-user-add-ca-001_50.out 2>&1" \
                    1 \
                    "Adding user using CA_adminV with user id length exceed maximum defined in ldap schema"
        rlAssertGrep "ClientResponseFailure: ldap can't save, exceeds max length" "$TmpDir/pki-user-add-ca-001_50.out"
        rlAssertNotGrep "ClientResponseFailure: Error status 500 Internal Server Error returned" "$TmpDir/pki-user-add-ca-001_50.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/842"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-051: fullname with i18n characters"
	rlLog "user-add fullname Örjan Äke with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='Örjan Äke' u26"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='Örjan Äke' u26 > $TmpDir/pki-user-add-ca-001_51.out 2>&1" \
                    0 \
                    "Adding u26 with full name Örjan Äke"
	rlAssertGrep "Added user \"u26\"" "$TmpDir/pki-user-add-ca-001_51.out"
        rlAssertGrep "User ID: u26" "$TmpDir/pki-user-add-ca-001_51.out"
        rlAssertGrep "Full name: Örjan Äke" "$TmpDir/pki-user-add-ca-001_51.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-052: fullname with i18n characters"
	rlLog "user-add fullname Éric Têko with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='Éric Têko' u27"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='Éric Têko' u27 > $TmpDir/pki-user-add-ca-001_52.out 2>&1" \
                    0 \
                    "Adding u27 with full Éric Têko"
        rlAssertGrep "Added user \"u27\"" "$TmpDir/pki-user-add-ca-001_52.out"
        rlAssertGrep "User ID: u27" "$TmpDir/pki-user-add-ca-001_52.out"
        rlAssertGrep "Full name: Éric Têko" "$TmpDir/pki-user-add-ca-001_52.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_user_cli_user_add-CA-053: fullname with i18n characters"
	rlLog "user-add fullname éénentwintig dvidešimt with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='éénentwintig dvidešimt' u28"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='éénentwintig dvidešimt' u28 > $TmpDir/pki-user-add-ca-001_53.out 2>&1" \
                    0 \
                    "Adding fullname éénentwintig dvidešimt with i18n characters"
        rlAssertGrep "Added user \"u28\"" "$TmpDir/pki-user-add-ca-001_53.out"
        rlAssertGrep "Full name: éénentwintig dvidešimt" "$TmpDir/pki-user-add-ca-001_53.out"
        rlAssertGrep "User ID: u28" "$TmpDir/pki-user-add-ca-001_53.out"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u28"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
		   -c $CERTDB_DIR_PASSWORD \
                    user-show u28 > $TmpDir/pki-user-add-ca-001_53_2.out 2>&1" \
                    0 \
                    "Show user u28 with fullname éénentwintig dvidešimt in i18n characters"
        rlAssertGrep "User \"u28\"" "$TmpDir/pki-user-add-ca-001_53_2.out"
        rlAssertGrep "Full name: éénentwintig dvidešimt" "$TmpDir/pki-user-add-ca-001_53_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-054: fullname with i18n characters"
	rlLog "user-add fullname kakskümmend üks with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='kakskümmend üks' u29"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='kakskümmend üks' u29 > $TmpDir/pki-user-add-ca-001_54.out 2>&1" \
                    0 \
                    "Adding fillname kakskümmend üks with i18n characters"
        rlAssertGrep "Added user \"u29\"" "$TmpDir/pki-user-add-ca-001_54.out"
        rlAssertGrep "Full name: kakskümmend üks" "$TmpDir/pki-user-add-ca-001_54.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u29 > $TmpDir/pki-user-add-ca-001_54_2.out" \
                    0 \
                    "Show user u29 with fullname kakskümmend üks in i18n characters"
        rlAssertGrep "User \"u29\"" "$TmpDir/pki-user-add-ca-001_54_2.out"
        rlAssertGrep "Full name: kakskümmend üks" "$TmpDir/pki-user-add-ca-001_54_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-055: fullname with i18n characters"
	rlLog "user-add fullname двадцять один тридцять with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='двадцять один тридцять' u30"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName='двадцять один тридцять' u30 > $TmpDir/pki-user-add-ca-001_55.out 2>&1" \
                    0 \
                    "Adding fillname двадцять один тридцять with i18n characters"
        rlAssertGrep "Added user \"u30\"" "$TmpDir/pki-user-add-ca-001_55.out"
        rlAssertGrep "Full name: двадцять один тридцять" "$TmpDir/pki-user-add-ca-001_55.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u30 > $TmpDir/pki-user-add-ca-001_55_2.out" \
                    0 \
                    "Show user u30 with fullname двадцять один тридцять in i18n characters"
        rlAssertGrep "User \"u30\"" "$TmpDir/pki-user-add-ca-001_55_2.out"
        rlAssertGrep "Full name: двадцять один тридцять" "$TmpDir/pki-user-add-ca-001_55_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-056: user id with i18n characters"
	rlLog "user-add userid ÖrjanÄke with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÖrjanÄke' > $TmpDir/pki-user-add-ca-001_56.out 2>&1" \
                    0 \
                    "Adding uid ÖrjanÄke with i18n characters"
        rlAssertGrep "Added user \"ÖrjanÄke\"" "$TmpDir/pki-user-add-ca-001_56.out"
        rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-user-add-ca-001_56.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÖrjanÄke' > $TmpDir/pki-user-add-ca-001_56_2.out" \
                    0 \
                    "Show user 'ÖrjanÄke'"
	rlAssertGrep "User \"ÖrjanÄke\"" "$TmpDir/pki-user-add-ca-001_56_2.out"
        rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-user-add-ca-001_56_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-057: userid with i18n characters"
	rlLog "user-add userid ÉricTêko with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÉricTêko'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÉricTêko' > $TmpDir/pki-user-add-ca-001_57.out 2>&1" \
                    0 \
                    "Adding user id ÉricTêko with i18n characters"
        rlAssertGrep "Added user \"ÉricTêko\"" "$TmpDir/pki-user-add-ca-001_57.out"
        rlAssertGrep "User ID: ÉricTêko" "$TmpDir/pki-user-add-ca-001_57.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÉricTêko' > $TmpDir/pki-user-add-ca-001_57_2.out" \
                    0 \
                    "Show user 'ÉricTêko'"
        rlAssertGrep "User \"ÉricTêko\"" "$TmpDir/pki-user-add-ca-001_57_2.out"
        rlAssertGrep "User ID: ÉricTêko" "$TmpDir/pki-user-add-ca-001_57_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-058: email address with i18n characters"
	rlLog "user-add email address negyvenkettő@qetestsdomain.com with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email='negyvenkettő@qetestsdomain.com' u31"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test  --email='negyvenkettő@qetestsdomain.com' u31 > $TmpDir/pki-user-add-ca-001_58.out 2>&1" \
                    0 \
                    "Adding email negyvenkettő@qetestsdomain.com with i18n characters"
        rlAssertGrep "Added user \"u31\"" "$TmpDir/pki-user-add-ca-001_58.out"
	rlAssertGrep "Email: gyvenkettő@qetestsdomain.com" "$TmpDir/pki-user-add-ca-001_58.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u31 > $TmpDir/pki-user-add-ca-001_58_2.out" \
                    0 \
                    "Show user u31 with email in i18n characters"
        rlAssertGrep "User \"u31\"" "$TmpDir/pki-user-add-ca-001_58_2.out"
	rlAssertGrep "Email: negyvenkettő@qetestsdomain.com" "$TmpDir/pki-user-add-ca-001_58_2.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/860"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-059: email address with i18n characters"
	rlLog "user-add email address četrdesmitdivi@qetestsdomain.com with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email='četrdesmitdivi@qetestsdomain.com' u32"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email='četrdesmitdivi@qetestsdomain.com' u32 > $TmpDir/pki-user-add-ca-001_59.out 2>&1" \
                    0 \
                    "Adding email četrdesmitdivi@qetestsdomain.com with i18n characters"
        rlAssertGrep "Added user \"u32\"" "$TmpDir/pki-user-add-ca-001_59.out"
	rlAssertGrep "Email: četrdesmitdivi@qetestsdomain.com" "$TmpDir/pki-user-add-ca-001_59.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u32 > $TmpDir/pki-user-add-ca-001_59_2.out" \
                    0 \
                    "Show user u32 with email četrdesmitdivi@qetestsdomain.com in i18n characters"
        rlAssertGrep "User \"u32\"" "$TmpDir/pki-user-add-ca-001_59_2.out"
	rlAssertGrep "Email: četrdesmitdivi@qetestsdomain.com" "$TmpDir/pki-user-add-ca-001_59_2.out"
        rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/860"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-060: password with i18n characters"
	rlLog "user-add password šimtaskolmkümmend with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --password='šimtaskolmkümmend' u33"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --password='šimtaskolmkümmend' u33 > $TmpDir/pki-user-add-ca-001_60.out 2>&1" \
                    0 \
                    "Adding password šimtaskolmkümmend with i18n characters"
        rlAssertGrep "Added user \"u33\"" "$TmpDir/pki-user-add-ca-001_60.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u33 > $TmpDir/pki-user-add-ca-001_60_2.out" \
                    0 \
                    "Show user u33 with password šimtaskolmkümmend in i18n characters"
        rlAssertGrep "User \"u33\"" "$TmpDir/pki-user-add-ca-001_60_2.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_user_cli_user_add-CA-061: password with i18n characters"
	rlLog "user-add password двадцяттридцять with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --password='двадцяттридцять' u34"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --password='двадцяттридцять' u34 > $TmpDir/pki-user-add-ca-001_61.out 2>&1" \
                    0 \
                    "Adding password двадцяттридцять with i18n characters"
        rlAssertGrep "Added user \"u34\"" "$TmpDir/pki-user-add-ca-001_61.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u34 > $TmpDir/pki-user-add-ca-001_61_2.out" \
                    0 \
                    "Show user u34 with password двадцяттридцять in i18n characters"
        rlAssertGrep "User \"u34\"" "$TmpDir/pki-user-add-ca-001_61_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-062: type with i18n characters"
	rlLog "user-add type tjugo-tvåhetvenhét with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type='tjugo-tvåhetvenhét' u35"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type='tjugo-tvåhetvenhét' u35 > $TmpDir/pki-user-add-ca-001_62.out 2>&1" \
                    0 \
                    "Adding type tjugo-tvåhetvenhét with i18n characters"
        rlAssertGrep "Added user \"u35\"" "$TmpDir/pki-user-add-ca-001_62.out"
	rlAssertGrep "Type: tjugo-tvåhetvenhét" "$TmpDir/pki-user-add-ca-001_62.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u35 > $TmpDir/pki-user-add-ca-001_62_2.out" \
                    0 \
                    "Show user u35 with type tjugo-tvåhetvenhét in i18n characters"
        rlAssertGrep "User \"u35\"" "$TmpDir/pki-user-add-ca-001_62_2.out"
	rlAssertGrep "Type: tjugo-tvåhetvenhét" "$TmpDir/pki-user-add-ca-001_62_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-063: type with i18n characters"
	rlLog "user-add type мiльйонтридцять with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type='мiльйонтридцять' u36"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type='мiльйонтридцять' u36 > $TmpDir/pki-user-add-ca-001_63.out 2>&1" \
                    0 \
                    "Adding type мiльйонтридцять with i18n characters"
        rlAssertGrep "Added user \"u36\"" "$TmpDir/pki-user-add-ca-001_63.out"
        rlAssertGrep "Type: мiльйонтридцять" "$TmpDir/pki-user-add-ca-001_63.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u36 > $TmpDir/pki-user-add-ca-001_63_2.out" \
                    0 \
                    "Show user u36 with type мiльйонтридцять in i18n characters"
        rlAssertGrep "User \"u36\"" "$TmpDir/pki-user-add-ca-001_63_2.out"
        rlAssertGrep "Type: мiльйонтридцять" "$TmpDir/pki-user-add-ca-001_63_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-064: state with i18n characters"
	rlLog "user-add state čå with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state='čå' u37"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state='čå' u37 > $TmpDir/pki-user-add-ca-001_64.out 2>&1" \
                    0 \
                    "Adding state 'čå' with i18n characters"
        rlAssertGrep "Added user \"u37\"" "$TmpDir/pki-user-add-ca-001_64.out"
        rlAssertGrep "State: čå" "$TmpDir/pki-user-add-ca-001_64.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u37 > $TmpDir/pki-user-add-ca-001_64_2.out" \
                    0 \
                    "Show user u37 with state čå in i18n characters"
        rlAssertGrep "User \"u37\"" "$TmpDir/pki-user-add-ca-001_64_2.out"
        rlAssertGrep "State: čå" "$TmpDir/pki-user-add-ca-001_64_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-065: state with i18n characters"
	rlLog "user-add state йč with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state='йč' u38"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state='йč' u38 > $TmpDir/pki-user-add-ca-001_65.out 2>&1" \
                    0 \
                    "Adding state 'йč' with i18n characters"
        rlAssertGrep "Added user \"u38\"" "$TmpDir/pki-user-add-ca-001_65.out"
        rlAssertGrep "State: йč" "$TmpDir/pki-user-add-ca-001_65.out"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u38 > $TmpDir/pki-user-add-ca-001_65_2.out" \
                    0 \
                    "Show user u38 with state йč in i18n characters"
        rlAssertGrep "User \"u38\"" "$TmpDir/pki-user-add-ca-001_65_2.out"
        rlAssertGrep "State: йč" "$TmpDir/pki-user-add-ca-001_65_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting users"

        #===Deleting users created using CA_adminV cert===#
        i=1
        while [ $i -lt 39 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user-00$i.out" \
                           0 \
                           "Deleted user  u$i"
                rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-00$i.out"
                let i=$i+1
        done
        #===Deleting users(symbols) created using CA_adminV cert===#
        j=1
        while [ $j -lt 8 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  '$usr' > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
		actual_delete_user_string=`cat $TmpDir/pki-user-del-ca-user-symbol-00$j.out | grep 'Deleted user' | xargs echo`
        	expected_delete_user_string="Deleted user $usr"
		if [[ $actual_delete_user_string = $expected_delete_user_string ]] ; then
                	rlPass "Deleted user \"$usr\" found in $TmpDir/pki-user-del-ca-user-symbol-00$j.out"
        	else
                	rlFail "Deleted user \"$usr\" not found in $TmpDir/pki-user-del-ca-user-symbol-00$j.out" 
        	fi
                let j=$j+1
        done
        #===Deleting i18n users created using CA_adminV cert===#
	rlRun "pki -d $CERTDB_DIR \
		-n CA_adminV \
		-c $CERTDB_DIR_PASSWORD \
		user-del 'ÖrjanÄke' > $TmpDir/pki-user-del-ca-user-i18n_1.out" \
		0 \
		"Deleted user ÖrjanÄke"
	rlAssertGrep "Deleted user \"ÖrjanÄke\"" "$TmpDir/pki-user-del-ca-user-i18n_1.out"
	
	rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                user-del 'ÉricTêko' > $TmpDir/pki-user-del-ca-user-i18n_2.out" \
                0 \
                "Deleted user ÉricTêko"
        rlAssertGrep "Deleted user \"ÉricTêko\"" "$TmpDir/pki-user-del-ca-user-i18n_2.out"
    rlPhaseEnd
}
