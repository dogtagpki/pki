#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-add    Add users to pki subsystems.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Laxmi Sunkara <lsunkara@redhat.com>
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
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

user1=ca_agent2
user1fullname="Test ca_agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0
export user1 user2 user3 user4 user5 user6 user7
########################################################################

run_pki-user-cli-user-add-ca_tests(){
    rlPhaseStartSetup "pki_user_cli_user_add-ca-startup:Getting the temp directory and nss certificate db "
	 rlLog "nss_db directory = $TmpDir/nssdb"
	 rlLog "temp directory = /tmp/requestdb"
    rlPhaseEnd
	#====Ticket corresponding to pki_user_cli_user_add-configtest : https://fedorahosted.org/pki/ticket/519=====#
    rlPhaseStartTest "pki_user_cli_user_add-configtest: pki user-add configuration test"
        rlRun "pki user-add > $TmpDir/pki_user_add_cfg.out" \
               1 \
               "https://fedorahosted.org/pki/ticket/519"
        rlAssertGrep "usage: user-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--email <email>         Email" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--fullName <fullName>   Full name" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--password <password>   Password" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--phone <phone>         Phone" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--state <state>         State" "$TmpDir/pki_user_add_cfg.out"
        rlAssertGrep "\--type <type>           Type" "$TmpDir/pki_user_add_cfg.out"
    rlPhaseEnd
     ##### Tests to add CA users using a user of admin group with a valid cert####
    rlPhaseStartTest "pki_user_cli_user_add-CA-001: Add a user to CA using CA_adminV"
        rlLog "Executing: pki -d /tmp/requestdb \
		   -n CA_adminV \
		   -c $nss_db_password \
		    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
		   -n CA_adminV \
		   -c $nss_db_password \
		    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-001.out" \
		    0 \
		    "Add user $user1 to CA_adminV"
        rlAssertGrep "Added user \"$user1\"" "$TmpDir/pki-user-add-ca-001.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ca-001.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ca-001.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_1:maximum length of user id "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user2 > $TmpDir/pki-user-add-ca-001_1.out" \
                    0 \
                    "Added user using CA_adminV with maximum user id length"
        rlAssertGrep "Added user \"$user2\"" "$TmpDir/pki-user-add-ca-001_1.out"
        rlAssertGrep "User ID: $user2" "$TmpDir/pki-user-add-ca-001_1.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_1.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_2:User id with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
			    user-add --fullName=test $user3 > $TmpDir/pki-user-add-ca-001_2.out" \
                    0 \
                    "Added user using CA_adminV, user id with # character"
        rlAssertGrep "Added user \"$user3\"" "$TmpDir/pki-user-add-ca-001_2.out"
        rlAssertGrep "User ID: $user3" "$TmpDir/pki-user-add-ca-001_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_2.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_3:User id with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
			    user-add --fullName=test $user4 > $TmpDir/pki-user-add-ca-001_3.out" \
                    0 \
                    "Added user using CA_adminV, user id with $ character"
        rlAssertGrep "Added user \"$user4\"" "$TmpDir/pki-user-add-ca-001_3.out"
        rlAssertGrep "User ID: abc\\$" "$TmpDir/pki-user-add-ca-001_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_3.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_4:User id with @ character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user5 > $TmpDir/pki-user-add-ca-001_4.out " \
                    0 \
                    "Added user using CA_adminV, user id with @ character"
        rlAssertGrep "Added user \"$user5\"" "$TmpDir/pki-user-add-ca-001_4.out"
        rlAssertGrep "User ID: $user5" "$TmpDir/pki-user-add-ca-001_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_4.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_5:User id with ? character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user6 > $TmpDir/pki-user-add-ca-001_5.out " \
                    0 \
                    "Added user using CA_adminV, user id with ? character"
        rlAssertGrep "Added user \"$user6\"" "$TmpDir/pki-user-add-ca-001_5.out"
        rlAssertGrep "User ID: $user6" "$TmpDir/pki-user-add-ca-001_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_5.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_6:User id as 0"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user7 > $TmpDir/pki-user-add-ca-001_6.out " \
                    0 \
                    "Added user using CA_adminV, user id 0"
        rlAssertGrep "Added user \"$user7\"" "$TmpDir/pki-user-add-ca-001_6.out"
        rlAssertGrep "User ID: $user7" "$TmpDir/pki-user-add-ca-001_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_6.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_7:--email with maximum length "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=abcdefghijklmnopqrstuvwxyx12345678 u1 > $TmpDir/pki-user-add-ca-001_7.out" \
                    0 \
                    "Added user using CA_adminV with maximum --email length"
        rlAssertGrep "Added user \"u1\"" "$TmpDir/pki-user-add-ca-001_7.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-user-add-ca-001_7.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_7.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ca-001_7.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_8:--email with maximum length and symbols "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=abcdefghijklmnopqrstuvwxyx12345678#?*@$  u2 > $TmpDir/pki-user-add-ca-001_8.out" \
                    0 \
                    "Added user using CA_adminV with maximum --email length and character symbols in it"
        rlAssertGrep "Added user \"u2\"" "$TmpDir/pki-user-add-ca-001_8.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-user-add-ca-001_8.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_8.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678\\#\\?*$@" "$TmpDir/pki-user-add-ca-001_8.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_9:--email with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=#  u3 > $TmpDir/pki-user-add-ca-001_9.out" \
                    0 \
                    "Added user using CA_adminV with --email # character"
        rlAssertGrep "Added user \"u3\"" "$TmpDir/pki-user-add-ca-001_9.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-user-add-ca-001_9.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_9.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-add-ca-001_9.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_10:--email with * character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=*  u4 > $TmpDir/pki-user-add-ca-001_10.out" \
                    0 \
                    "Added user using CA_adminV with --email * character"
        rlAssertGrep "Added user \"u4\"" "$TmpDir/pki-user-add-ca-001_10.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-user-add-ca-001_10.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_10.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-add-ca-001_10.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_11:--email with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=$  u5 > $TmpDir/pki-user-add-ca-001_11.out" \
                    0 \
                    "Added user using CA_adminV with --email $ character"
        rlAssertGrep "Added user \"u5\"" "$TmpDir/pki-user-add-ca-001_11.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-user-add-ca-001_11.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_11.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-add-ca-001_11.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_12:--email as number 0 "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=0  u6 > $TmpDir/pki-user-add-ca-001_12.out " \
                    0 \
                    "Added user using CA_adminV with --email 0"
        rlAssertGrep "Added user \"u6\"" "$TmpDir/pki-user-add-ca-001_12.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-user-add-ca-001_12.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_12.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-add-ca-001_12.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_13:--state with maximum length "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=abcdefghijklmnopqrstuvwxyx12345678 u7 > $TmpDir/pki-user-add-ca-001_13.out" \
                    0 \
                    "Added user using CA_adminV with maximum --state length"
        rlAssertGrep "Added user \"u7\"" "$TmpDir/pki-user-add-ca-001_13.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-user-add-ca-001_13.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_13.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ca-001_13.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_14:--state with maximum length and symbols "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=abcdefghijklmnopqrstuvwxyx12345678#?*@$  u8 > $TmpDir/pki-user-add-ca-001_14.out" \
                    0 \
                    "Added user using CA_adminV with maximum --state length and character symbols in it"
        rlAssertGrep "Added user \"u8\"" "$TmpDir/pki-user-add-ca-001_14.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-user-add-ca-001_14.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_14.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678\\#\\?*$@" "$TmpDir/pki-user-add-ca-001_14.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_15:--state with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=#  u9 > $TmpDir/pki-user-add-ca-001_15.out" \
                    0 \
                    "Added user using CA_adminV with --state # character"
        rlAssertGrep "Added user \"u9\"" "$TmpDir/pki-user-add-ca-001_15.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-user-add-ca-001_15.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_15.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-add-ca-001_15.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_16:--state with * character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=*  u10 > $TmpDir/pki-user-add-ca-001_16.out" \
                    0 \
                    "Added user using CA_adminV with --state * character"
        rlAssertGrep "Added user \"u10\"" "$TmpDir/pki-user-add-ca-001_16.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-add-ca-001_16.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_16.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-add-ca-001_16.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_17:--state with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=$  u11 > $TmpDir/pki-user-add-ca-001_17.out" \
                    0 \
                    "Added user using CA_adminV with --state $ character"
        rlAssertGrep "Added user \"u11\"" "$TmpDir/pki-user-add-ca-001_17.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-user-add-ca-001_17.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_17.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-add-ca-001_17.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_18:--state as number 0 "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=0  u12 > $TmpDir/pki-user-add-ca-001_18.out " \
                    0 \
                    "Added user using CA_adminV with --state 0"
        rlAssertGrep "Added user \"u12\"" "$TmpDir/pki-user-add-ca-001_18.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-user-add-ca-001_18.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_18.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-add-ca-001_18.out"
    rlPhaseEnd
	#https://www.redhat.com/archives/pki-users/2010-February/msg00015.html
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_19:--phone with maximum length "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=abcdefghijklmnopqrstuvwxyx12345678 u13 > $TmpDir/pki-user-add-ca-001_19.out" \
                    0 \
                    "Added user using CA_adminV with maximum --phone length"
        rlAssertGrep "Added user \"u13\"" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_19.out"
        rlAssertGrep "Phone: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ca-001_19.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_20:--phone with maximum length and symbols "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=abcdefghijklmnopqrstuvwxyx12345678#?*@$  usr1 > $TmpDir/pki-user-add-ca-001_20.out  2>&1"\
                    1 \
                    "Cannot add user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_20.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_21:--phone with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=#  usr2 > $TmpDir/pki-user-add-ca-001_21.out  2>&1" \
                    1 \
                    "Cannot add user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_21.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_22:--phone with * character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=*  usr3 > $TmpDir/pki-user-add-ca-001_22.out 2>&1" \
                    1 \
                    "Cannot add user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_22.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_23:--phone with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=$  usr4 > $TmpDir/pki-user-add-ca-001_23.out 2>&1" \
                    1 \
                    "Cannot add user using CA_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ca-001_23.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_24:--phone as negative number -1230 "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=-1230  u14 > $TmpDir/pki-user-add-ca-001_24.out " \
                    0 \
                    "Added user using CA_adminV with --phone -1230"
        rlAssertGrep "Added user \"u14\"" "$TmpDir/pki-user-add-ca-001_24.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-user-add-ca-001_24.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_24.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-add-ca-001_24.out"
    rlPhaseEnd
#======https://fedorahosted.org/pki/ticket/704============#
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_25:--type as Auditors"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=Auditors u15 > $TmpDir/pki-user-add-ca-001_25.out" \
                    0 \
                    "Added user using CA_adminV with  --type Auditors"
        rlAssertGrep "Added user \"u15\"" "$TmpDir/pki-user-add-ca-001_25.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-user-add-ca-001_25.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_25.out"
        rlAssertGrep "Type: Auditors" "$TmpDir/pki-user-add-ca-001_25.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_26:--type Certificate Manager Agents "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Certificate Manager Agents\" u16 > $TmpDir/pki-user-add-ca-001_26.out" \
                    0 \
                    "Added user using CA_adminV  --type Certificate Manager Agents"
        rlAssertGrep "Added user \"u16\"" "$TmpDir/pki-user-add-ca-001_26.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-add-ca-001_26.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_26.out"
        rlAssertGrep "Type: Certificate Manager Agents" "$TmpDir/pki-user-add-ca-001_26.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_27:--type Registration Manager Agents "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Registration Manager Agents\"  u17 > $TmpDir/pki-user-add-ca-001_27.out" \
                    0 \
                    "Added user using CA_adminV with --type Registration Manager Agents"
        rlAssertGrep "Added user \"u17\"" "$TmpDir/pki-user-add-ca-001_27.out"
        rlAssertGrep "User ID: u17" "$TmpDir/pki-user-add-ca-001_27.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_27.out"
        rlAssertGrep "Type: Registration Manager Agents" "$TmpDir/pki-user-add-ca-001_27.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_28:--type Subsytem Group "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Subsytem Group\"  u18 > $TmpDir/pki-user-add-ca-001_28.out" \
                    0 \
                    "Added user using CA_adminV with --type Subsytem Group"
        rlAssertGrep "Added user \"u18\"" "$TmpDir/pki-user-add-ca-001_28.out"
        rlAssertGrep "User ID: u18" "$TmpDir/pki-user-add-ca-001_28.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_28.out"
        rlAssertGrep "Type: Subsytem Group" "$TmpDir/pki-user-add-ca-001_28.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_29:--type Security Domain Administrators "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Security Domain Administrators\" u19 > $TmpDir/pki-user-add-ca-001_29.out" \
                    0 \
                    "Added user using CA_adminV with --type Security Domain Administrators"
        rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-user-add-ca-001_29.out"
        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-add-ca-001_29.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_29.out"
        rlAssertGrep "Type: Security Domain Administrators" "$TmpDir/pki-user-add-ca-001_29.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_30:--type ClonedSubsystems "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=ClonedSubsystems u20 > $TmpDir/pki-user-add-ca-001_30.out" \
                    0 \
                    "Added user using CA_adminV with --type ClonedSubsystems"
        rlAssertGrep "Added user \"u20\"" "$TmpDir/pki-user-add-ca-001_30.out"
        rlAssertGrep "User ID: u20" "$TmpDir/pki-user-add-ca-001_30.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_30.out"
        rlAssertGrep "Type: ClonedSubsystems" "$TmpDir/pki-user-add-ca-001_30.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-001_31:--type Trusted Managers "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Trusted Managers\" u21 > $TmpDir/pki-user-add-ca-001_31.out" \
                    0 \
                    "Added user using CA_adminV with --type Trusted Managers"
        rlAssertGrep "Added user \"u21\"" "$TmpDir/pki-user-add-ca-001_31.out"
        rlAssertGrep "User ID: u21" "$TmpDir/pki-user-add-ca-001_31.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ca-001_31.out"
        rlAssertGrep "Type: Trusted Managers" "$TmpDir/pki-user-add-ca-001_31.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-002: Add a duplicate user to CA"
         command="pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=\"New user\" $user1 > $TmpDir/pki-user-add-ca-002.out 2>&1 "

         rlLog "Command=$command"
         expmsg="ConflictingOperationException: Entry already exists."
         rlRun "$command" 1 "Add duplicate user"
         rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-003: Add a user to CA with -t option"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  u22"

        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  u22 > $TmpDir/pki-user-add-ca-003.out" \
                    0 \
                    "Add user u22 to CA"
        rlAssertGrep "Added user \"u22\"" "$TmpDir/pki-user-add-ca-003.out"
        rlAssertGrep "User ID: u22" "$TmpDir/pki-user-add-ca-003.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ca-003.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-004:  Add a user -- missing required option user id"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add --fullName=\"$user1fullname\" "

        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add --fullName=\"$user1fullname\" > $TmpDir/pki-user-add-ca-004.out" \
                     1\
                    "Add user -- missing required option user id"
        rlAssertGrep "usage: user-add <User ID> \[OPTIONS...\]" "$TmpDir/pki-user-add-ca-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-005:  Add a user -- missing required option --fullName"
        command="pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add $user1 > $TmpDir/pki-user-add-ca-005.out 2>&1"
        expmsg="Error: Missing required option: fullName"
        rlLog "Executing: $command"
        rlRun "$command" 1 "Add a user -- missing required option --fullName"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ca-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-006:  Add a user -- all options provided"
        email="ca_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                    --type $type \
                     u23"

        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
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

   rlPhaseStartTest "pki_user_cli_user_add-CA-007:  Add user to multiple groups"
       user=u24
       userfullname="Multiple Group User"
       email="multiplegroup@myemail.com"
       user_password="admin2Password"
       phone="1234567890"
       state="NC"
       rlLog "Executing: pki -d /tmp/requestdb \
                  -n CA_adminV \
                  -c $nss_db_password \
                  -t ca \
                   user-add --fullName=\"$userfullname\"  \
                   --email $email \
                   --password $user_password \
                   --phone $phone \
                   --state $state \
                    $user"

       rlRun "pki -d /tmp/requestdb \
                  -n CA_adminV \
                  -c $nss_db_password \
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

       rlRun "pki -d /tmp/requestdb \
                  -n CA_adminV \
                  -c $nss_db_password \
                  -t ca \
                   group-member-add Administrators $user > $TmpDir/pki-user-add-ca-007_1.out"  \
                   0 \
                   "Add user $user to Administrators group"

       rlAssertGrep "Added group member \"$user\"" "$TmpDir/pki-user-add-ca-007_1.out"
       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ca-007_1.out"

       rlRun "pki -d /tmp/requestdb \
                  -n CA_adminV \
                  -c $nss_db_password \
                  -t ca \
                   group-member-find Administrators > $TmpDir/pki-user-add-ca-007.out" \
                   0 \
                   "Show pki group-member-find Administrators"
       rlRun "pki -d /tmp/requestdb \
                  -n CA_adminV \
                  -c $nss_db_password \
                  -t ca \
                   group-member-add \"Certificate Manager Agents\"  $user > $TmpDir/pki-user-add-ca-007_1_1.out"  \
                   0 \
                   "Add user $user to Administrators group"

       rlAssertGrep "Added group member \"$user\"" "$TmpDir/pki-user-add-ca-007_1_1.out"
       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ca-007_1_1.out"

       rlRun "pki -d /tmp/requestdb \
                  -n CA_adminV \
                  -c $nss_db_password \
                  -t ca \
                   group-member-find \"Certificate Manager Agents\"  > $TmpDir/pki-user-add-ca-007_2.out" \
                   0 \
                   "Show pki group-member-find Administrators"

       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ca-007_2.out"
   rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-008: Add user with --password "
        userpw="pass"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-add-ca-008.out 2>&1"
        expmsg="PKIException: The password must be at least 8 characters"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
		   -t ca \
                    user-add --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-add-ca-008.out 2>&1" \
                    1 \
                    "Add a user --must be at least 8 characters --password"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ca-008.out"

    rlPhaseEnd

        ##### Tests to add users using revoked cert#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-009: Cannot add user using a revoked cert CA_adminR"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_adminR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-revoke-adminR-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-revoke-adminR-002.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-CA-009_1: Cannot add user using a agent or a revoked cert CA_agentR"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-revoke-agentR-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-revoke-agentR-002.out"
    rlPhaseEnd


        ##### Tests to add users using an agent user#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-0010: Cannot add user using a CA_agentV user"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_agentV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_agentV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentV-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-agentV-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-0011: Cannot add user using a CA_agentR user"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentR-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ca-agentR-002.out"
    rlPhaseEnd
    ##### Tests to add users using expired cert#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-0012: Cannot add user using a CA_adminE cert"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_adminE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-adminE-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "ResteasyIOException: IOException" "$TmpDir/pki-user-add-ca-adminE-002.out"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-0013: Cannot add user using a CA_agentE cert"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_agentE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_agentE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentE-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "ResteasyIOException: IOException" "$TmpDir/pki-user-add-ca-agentE-002.out"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

	##### Tests to add users using audit users#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-0012: Cannot add user using a CA_auditV"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_auditV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_auditV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-auditV-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a audit cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-auditV-002.out"
    rlPhaseEnd

	##### Tests to add users using operator user###
    rlPhaseStartTest "pki_user_cli_user_add-CA-0013: Cannot add user using a CA_operatorV"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n CA_operatorV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_operatorV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-operatorV-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a operator cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-operatorV-002.out"
    rlPhaseEnd


	 ##### Tests to add users using CA_adminUTCA and CA_agentUTCA  user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_user_cli_user_add-CA-0014: Cannot add user using a CA_adminUTCA"

        rlLog "Executing: pki -d /tmp/dummydb \
                   -n CA_adminUTCA \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/dummydb \
                   -n CA_adminUTCA \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-adminUTCA-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a untrusted cert"
        rlAssertGrep "ResteasyIOException: IOException" "$TmpDir/pki-user-add-ca-adminUTCA-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-CA-0014: Cannot add user using a CA_agentUTCA"

        rlLog "Executing: pki -d /tmp/dummydb \
                   -n CA_agentUTCA \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/dummydb \
                   -n CA_agentUTCA \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ca-agentUTCA-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a untrusted cert"
        rlAssertGrep "ResteasyIOException: IOException" "$TmpDir/pki-user-add-ca-agentUTCA-002.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_cleanup-001_15: Deleting the temp directory and users"
        del_user=($CA_adminV_user $CA_adminR_user $CA_adminE_user $CA_adminUTCA_user $CA_agentV_user $CA_agentR_user $CA_agentE_user $CA_agentUTCA_user $CA_auditV_user $CA_operatorV_user)

        #===Deleting users created using CA_adminV cert===#
        i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d /tmp/requestdb \
                          -n CA_adminV \
                          -c $nss_db_password \
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
               rlRun "pki -d /tmp/requestdb \
                          -n CA_adminV \
                          -c $nss_db_password \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
        i=0
        while [ $i -lt ${#del_user[@]} ] ; do
               userid_del=${del_user[$i]}
               rlRun "pki -d $TmpDir/nssdb \
                          -n \"$admin_cert_nickname\" \
                          -c $nss_db_password \
                           user-del  $userid_del > $TmpDir/pki-user-del-ca-00$i.out"  \
                           0 \
                           "Deleted user  $userid_del"
                rlAssertGrep "Deleted user \"$userid_del\"" "$TmpDir/pki-user-del-ca-00$i.out"
                let i=$i+1
        done


        rlRun "rm -r $TmpDir" 0 "Removing temp directory"
        rlRun "popd"
        rlRun "rm -rf /tmp/requestdb"
        rlRun "rm -rf /tmp/dummydb"

    rlPhaseEnd


}
