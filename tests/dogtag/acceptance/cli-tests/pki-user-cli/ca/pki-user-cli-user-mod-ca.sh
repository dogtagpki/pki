#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-mod CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-mod    Modify existing users in the pki ca subsystem.
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-user-cli-user-mod-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
user1=ca_agent2
user1fullname="Test ca agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0
user1_mod_fullname="Test ca agent Modified"
user1_mod_email="testcaagent@myemail.com"
user1_mod_passwd="Secret1234"
user1_mod_state="NC"
user1_mod_phone="1234567890"
randsym=""
run_pki-user-cli-user-mod-ca_tests(){

##### pki_user_cli_user_mod-configtest ####
     rlPhaseStartTest "pki_user_cli_user_mod-configtest: pki user-mod configuration test"
        rlRun "pki user-mod > $TmpDir/pki_user_mod_cfg.out" \
                1 \
                "User modification configuration"
        rlAssertGrep "usage: user-mod <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--email <email>         Email" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--fullName <fullName>   Full name" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--phone <phone>         Phone" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--state <state>         State" "$TmpDir/pki_user_mod_cfg.out"
    rlPhaseEnd


     ##### Tests to modify CA users ####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-001: Modify a user's fullname in CA using CA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1 > $TmpDir/pki-user-mod-ca-001.out" \
		    0 \
		    "Modified $user1 fullname"
        rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-user-mod-ca-001.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-001.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-user-mod-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-002: Modify a user's email,phone,state,password in CA using CA_adminV"
         rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email $user1_mod_email --phone $user1_mod_phone --state $user1_mod_state --password $user1_mod_passwd $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email $user1_mod_email --phone $user1_mod_phone --state $user1_mod_state --password $user1_mod_passwd $user1 > $TmpDir/pki-user-mod-ca-002.out" \
                    0 \
                    "Modified $user1 information"
        rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-user-mod-ca-002.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-002.out"
        rlAssertGrep "Email: $user1_mod_email" "$TmpDir/pki-user-mod-ca-002.out"

	rlAssertGrep "Phone: $user1_mod_phone" "$TmpDir/pki-user-mod-ca-002.out"

	rlAssertGrep "State: $user1_mod_state" "$TmpDir/pki-user-mod-ca-002.out"

	rlAssertGrep "Email: $user1_mod_email" "$TmpDir/pki-user-mod-ca-002.out"

rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-003_1:--email with maximum length "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email abcdefghijklmnopqrstuvwxyx12345678 u1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=abcdefghijklmnopqrstuvwxyx12345678 u1 > $TmpDir/pki-user-mod-ca-003_1.out" \
                    0 \
                    "Modified user using CA_adminV with maximum --email length"
        rlAssertGrep "Modified user \"u1\"" "$TmpDir/pki-user-mod-ca-003_1.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-user-mod-ca-003_1.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-003_1.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-mod-ca-003_1.out"
    rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_mod-CA-003_2:--email with maximum length and symbols "
        randsym=`cat /dev/urandom | tr -dc 'a-zA-Z0-9@#%^&_+=~*-' | fold -w 1024 | head -n 1`

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u2"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=\"$randsym\" u2"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=\"$randsym\" u2 > $TmpDir/pki-user-mod-ca-003_2_2.out" \
                    0 \
                    "Modified user using CA_adminV with maximum --email length and character symbols in it"
        actual_email_string=`cat $TmpDir/pki-user-mod-ca-003_2_2.out | grep "Email: " | xargs echo`
        expected_email_string="Email: $randsym"
        rlAssertGrep "Modified user \"u2\"" "$TmpDir/pki-user-mod-ca-003_2_2.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-user-mod-ca-003_2_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-003_2_2.out"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "$expected_email_string found"
        else
                rlFail "$expected_email_string not found"
        fi
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_mod-CA-003_3:--email with # character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u3"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email # u3"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=#  u3 > $TmpDir/pki-user-mod-ca-003_3.out" \
                    0 \
                    "Modified user using CA_adminV with --email # character"
        rlAssertGrep "Modified user \"u3\"" "$TmpDir/pki-user-mod-ca-003_3.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-user-mod-ca-003_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-003_3.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-mod-ca-003_3.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-003_4:--email with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u4"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email * u4"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=*  u4 > $TmpDir/pki-user-mod-ca-003_4.out" \
                    0 \
                    "Modified user using CA_adminV with --email * character"
        rlAssertGrep "Modified user \"u4\"" "$TmpDir/pki-user-mod-ca-003_4.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-user-mod-ca-003_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-003_4.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-mod-ca-003_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-003_5:--email with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u5"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email $ u5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=$  u5 > $TmpDir/pki-user-mod-ca-003_5.out" \
                    0 \
                    "Modified user using CA_adminV with --email $ character"
        rlAssertGrep "Modified user \"u5\"" "$TmpDir/pki-user-mod-ca-003_5.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-user-mod-ca-003_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-003_5.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-mod-ca-003_5.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-003_6:--email as number 0 "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u6"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email 0 u6"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=0  u6 > $TmpDir/pki-user-mod-ca-003_6.out " \
                    0 \
                    "Modified user using CA_adminV with --email 0"
        rlAssertGrep "Modified user \"u6\"" "$TmpDir/pki-user-mod-ca-003_6.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-user-mod-ca-003_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-003_6.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-mod-ca-003_6.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-004_1:--state with maximum length "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u7"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state abcdefghijklmnopqrstuvwxyx12345678 u7"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=abcdefghijklmnopqrstuvwxyx12345678 u7 > $TmpDir/pki-user-mod-ca-004_1.out" \
                    0 \
                    "Modified user using CA_adminV with maximum --state length"
        rlAssertGrep "Modified user \"u7\"" "$TmpDir/pki-user-mod-ca-004_1.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-user-mod-ca-004_1.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004_1.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-mod-ca-004_1.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-004_2:--state with maximum length and symbols "
	randsym=`cat /dev/urandom | tr -dc 'a-zA-Z0-9@#%^&_+=~*-' | fold -w 1024 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u8"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=\"$randsym\" u8"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=\"$randsym\" u8 > $TmpDir/pki-user-mod-ca-004_2.out" \
                    0 \
                    "Modified user using CA_adminV with maximum --state length and character symbols in it"
	actual_state_string=`cat $TmpDir/pki-user-mod-ca-004_2.out | grep "State: " | xargs echo`
        expected_state_string="State: $randsym"
        rlAssertGrep "Modified user \"u8\"" "$TmpDir/pki-user-mod-ca-004_2.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-user-mod-ca-004_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004_2.out"
	if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "$expected_state_string found"
        else
                rlFail "$expected_state_string not found"
        fi
	rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-004_3:--state with # character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u9"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state # u9"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=#  u9 > $TmpDir/pki-user-mod-ca-004_3.out" \
                    0 \
                    "Modified user using CA_adminV with --state # character"
        rlAssertGrep "Modified user \"u9\"" "$TmpDir/pki-user-mod-ca-004_3.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-user-mod-ca-004_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004_3.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-mod-ca-004_3.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-004_4:--state with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u10"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state * u10"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=*  u10 > $TmpDir/pki-user-mod-ca-004_4.out" \
                    0 \
                    "Modified user using CA_adminV with --state * character"
        rlAssertGrep "Modified user \"u10\"" "$TmpDir/pki-user-mod-ca-004_4.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-mod-ca-004_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004_4.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-mod-ca-004_4.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-004_5:--state with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u11"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state $ u11"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=$  u11 > $TmpDir/pki-user-mod-ca-004_5.out" \
                    0 \
                    "Modified user using CA_adminV with --state $ character"
        rlAssertGrep "Modified user \"u11\"" "$TmpDir/pki-user-mod-ca-004_5.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-user-mod-ca-004_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004_5.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-mod-ca-004_5.out"
    rlPhaseEnd
rlPhaseStartTest "pki_user_cli_user_mod-CA-004_6:--state as number 0 "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u12"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state 0 u12"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=0  u12 > $TmpDir/pki-user-mod-ca-004_6.out " \
                    0 \
                    "Modified user using CA_adminV with --state 0"
        rlAssertGrep "Modified user \"u12\"" "$TmpDir/pki-user-mod-ca-004_6.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-user-mod-ca-004_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004_6.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-mod-ca-004_6.out"
    rlPhaseEnd
        
    rlPhaseStartTest "pki_user_cli_user_mod-CA-005_1:--phone with maximum length"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u13"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone abcdefghijklmnopqrstuvwxyx12345678 u13"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=abcdefghijklmnopqrstuvwxyx12345678 u13 > $TmpDir/pki-user-mod-ca-005_1.out" \
                    0 \
                    "Modified user using CA_adminV with maximum --phone length"
        rlAssertGrep "Modified user \"u13\"" "$TmpDir/pki-user-mod-ca-005_1.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-user-mod-ca-005_1.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-005_1.out"
        rlAssertGrep "Phone: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-mod-ca-005_1.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-005_2:--phone with maximum length and symbols "
	randsym=`cat /dev/urandom | tr -dc 'a-zA-Z0-9@#%^&_+=~*-' | fold -w 1024 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test usr1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=\"$randsym\" usr1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=\"$randsym\"  usr1 > $TmpDir/pki-user-mod-ca-005_2.out  2>&1"\
                    1 \
                    "Cannot modify user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-mod-ca-005_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-005_3:--phone with # character "
	 rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test usr2"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone # usr2"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=# usr2 > $TmpDir/pki-user-mod-ca-005_3.out  2>&1" \
                    1 \
                    "Cannot modify user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-mod-ca-005_3.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-005_4:--phone with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test usr3"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone * usr3"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=*  usr3 > $TmpDir/pki-user-mod-ca-005_4.out 2>&1" \
                    1 \
                    "Cannot modify user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-mod-ca-005_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-005_5:--phone with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test usr4"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone $ usr4"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=$  usr4 > $TmpDir/pki-user-mod-ca-005_5.out 2>&1" \
                    1 \
                    "Cannot modify user using CA_adminV --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-mod-ca-005_5.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-005_6:--phone as negative number -1230 "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u14"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone -1230 u14"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=-1230  u14 > $TmpDir/pki-user-mod-ca-005_6.out " \
                    0 \
                    "Modifying User --phone negative value"
        rlAssertGrep "Modified user \"u14\"" "$TmpDir/pki-user-mod-ca-005_6.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-user-mod-ca-005_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-005_6.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-mod-ca-005_6.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/704"
    rlPhaseEnd
#======https://fedorahosted.org/pki/ticket/704============#

 rlPhaseStartTest "pki_user_cli_user_mod-CA-006: Modify a user to CA with -t option"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u15"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  u15"

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  u15 > $TmpDir/pki-user-mod-ca-006.out" \
                    0 \
                    "Modified user u15 to CA"
        rlAssertGrep "Modified user \"u15\"" "$TmpDir/pki-user-mod-ca-006.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-user-mod-ca-006.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-006.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-007:  Modify a user -- missing required option user id"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\" "

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\" > $TmpDir/pki-user-mod-ca-007.out" \
                     1\
                    "Modify user -- missing required option user id"
        rlAssertGrep "usage: user-mod <User ID> \[OPTIONS...\]" "$TmpDir/pki-user-mod-ca-007.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-008:  Modify a user -- all options provided"
        email="ca_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test u16"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u16"

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u16 >  $TmpDir/pki-user-mod-ca-008.out" \
                    0 \
                    "Modify user u16 to CA -- all options provided"
        rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-008.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-009: Modify user with --password "
        userpw="pass"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
		   -t ca \
                    user-mod --fullName=\"$user1fullname\" --password=$userpw $user1"
        expmsg="PKIException: The password must be at least 8 characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-mod-ca-009.out 2>&1" \
                    1 \
                    "Modify a user --must be at least 8 characters --password"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-mod-ca-009.out"

    rlPhaseEnd

##### Tests to modify users using revoked cert#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-010_1: Should not be able to modify user using a revoked cert CA_adminR"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-010_1.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-mod-ca-010_1.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-010_2: Should not be able to modify user using an agent or a revoked cert CA_agentR"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-010_2.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-mod-ca-010_2.out"
    rlPhaseEnd

##### Tests to modify users using an agent user#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-011_1: Should not be able to modify user using a CA_agentV user"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-011_1.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using a agent cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-mod-ca-011_1.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-011_2: Should not be able to modify user using a CA_agentR user"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-011_2.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using a agent cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-mod-ca-011_2.out"
    rlPhaseEnd

##### Tests to modify users using expired cert#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-012_1: Should not be able to modify user using a CA_adminE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-012_1.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using an expired admin cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-mod-ca-012_1.out"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-012_2: Should not be able to modify user using a CA_agentE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-012_2.out 2>&1" \
                   1 \
                    "https://fedorahosted.org/pki/ticket/821"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-mod-ca-012_2.out"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd
#======https://fedorahosted.org/pki/ticket/821============#
 ##### Tests to modify users using audit users#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-013: Should not be able to modify user using a CA_auditV"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-013.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using an audit cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-mod-ca-013.out"
    rlPhaseEnd

        ##### Tests to modify users using operator user###
    rlPhaseStartTest "pki_user_cli_user_mod-CA-014: Should not be able to modify user using a CA_operatorV"

        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-014.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using a operator cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-mod-ca-014.out"
    rlPhaseEnd

##### Tests to modify users using CA_adminUTCA and CA_agentUTCA  user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-015: Should not be able to modify user using a cert created from a untrusted CA CA_adminUTCA"

        rlLog "Executing: pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-mod --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-mod --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-mod-ca-015.out 2>&1" \
                    1 \
                    "Cannot modify user $user1 using a untrusted cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-mod-ca-015.out"
    rlPhaseEnd


rlPhaseStartTest "pki_user_cli_user_mod-CA-016:  Modify a user -- User ID does not exist"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  u17"

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  u17 > $TmpDir/pki-user-mod-ca-016.out 2>&1" \
                    1 \
                    "Modifying a non existing user"
        rlAssertGrep "ResourceNotFoundException: No such object." "$TmpDir/pki-user-mod-ca-016.out"
    rlPhaseEnd


##### Tests to modify CA users with empty parameters ####

    rlPhaseStartTest "pki_user_cli_user_mod-CA-017_1: Modify a user in CA using CA_adminV - fullname is empty"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"\" $user1 > $TmpDir/pki-user-mod-ca-017_1.out 2>&1" \
                    0 \
                    "Modifying User --fullname is empty"
        rlAssertGrep "Fullname cannot be empty" "$TmpDir/pki-user-mod-ca-017_1.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/833"
    rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_mod-CA-017_2: Modify a user in CA using CA_adminV - email is empty"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u16 > $TmpDir/pki-user-mod-ca-017_2_1.out" 
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-017_2_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-017_2_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-017_2_1.out"
	rlAssertGrep "Email: $email" "$TmpDir/pki-user-mod-ca-017_2_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-017_2_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-017_2_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=\"\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=\"\" u16 > $TmpDir/pki-user-mod-ca-017_2_2.out" \
                    0 \
                    "Modifying $user1 with empty email"
	rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-017_2_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-017_2_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-017_2_2.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-017_2_2.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-017_2_2.out"
    rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_mod-CA-017_3: Modify a user in CA using CA_adminV - phone is empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u16 > $TmpDir/pki-user-mod-ca-017_3_1.out"
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-017_3_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-017_3_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-017_3_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-017_3_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-017_3_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=\"\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --phone=\"\" u16 > $TmpDir/pki-user-mod-ca-017_3_2.out 2>&1" \
                    0 \
                    "Modifying User --phone is empty"
        rlAssertGrep "BadRequestException: Invalid DN syntax." "$TmpDir/pki-user-mod-ca-017_3_2.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/836"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-017_4: Modify a user in CA using CA_adminV - state is empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u16 > $TmpDir/pki-user-mod-ca-017_4_1.out"
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-017_4_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-017_4_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-017_4_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-017_4_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=\"\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --state=\"\" u16 > $TmpDir/pki-user-mod-ca-017_4_2.out 2>&1" \
                    0 \
                    "Modify User --state is empty"
        rlAssertGrep "BadRequestException: Invalid DN syntax." "$TmpDir/pki-user-mod-ca-017_4_2.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/836"
    rlPhaseEnd

##### Tests to modify CA users with the same value ####

    rlPhaseStartTest "pki_user_cli_user_mod-CA-018: Modify a user in CA using CA_adminV - fullname same old value"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user1 > $TmpDir/pki-user-mod-ca-018_1.out"
	rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-mod-ca-018_1.out"
	rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-018_1.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-user-mod-ca-018_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1 > $TmpDir/pki-user-mod-ca-018_2.out" \
                    0 \
                    "Modifying $user1 with same old fullname"
	rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-user-mod-ca-018_2.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-018_2.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-user-mod-ca-018_2.out"
    rlPhaseEnd

##### Tests to modify CA users adding values to params which were previously empty ####

    rlPhaseStartTest "pki_user_cli_user_mod-CA-019: Modify a user in CA using CA_adminV - adding values to params which were previously empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u16 > $TmpDir/pki-user-mod-ca-019_1.out"
        rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-019_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-019_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-019_1.out"
	rlAssertNotGrep "Email:" "$TmpDir/pki-user-mod-ca-019_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=\"$email\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-mod --email=\"$email\" u16 > $TmpDir/pki-user-mod-ca-019_2.out" \
                    0 \
                    "Modifying u16 with new value for phone which was previously empty"
        rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-019_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-019_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-019_2.out"
	rlAssertGrep "Email: $email" "$TmpDir/pki-user-mod-ca-019_2.out"
    rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        i=1
        while [ $i -lt 17 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user-00$i.out" \
                           0 \
                           "Deleted user  u$i"
                rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-00$i.out"
                let i=$i+1
        done
        
        j=1
        while [ $j -lt 2 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done

    rlPhaseEnd


}
