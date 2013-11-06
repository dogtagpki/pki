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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-ocsp.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

user1="ocsp_agent2"
user1fullname="Test ocsp_agent"

########################################################################

run_pki-user-cli-user-add-ocsp_tests(){
    rlPhaseStartSetup "pki_user_cli_user_add-ocsp-startup:Getting the temp directory and nss certificate db "
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
     ##### Tests to add OCSP users using a user of admin group with a valid cert####
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001: Add a user to OCSP using OCSP_adminV"
        rlLog "Executing: pki -d /tmp/requestdb \
		   -n OCSP_adminV \
		   -c $nss_db_password \
		    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
		   -n OCSP_adminV \
		   -c $nss_db_password \
		    user-add --fullName=\"$user1fullname\" $user1" \
		    0 \
		    "Add user $user1 to OCSP_adminV"
        rlLog "Executing: pki -d $TmpDir/nssdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show $user1 > $TmpDir/pki-user-add-ocsp-001.out" \
		    0 \
		    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-add-ocsp-001.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ocsp-001.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ocsp-001.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_1:maximum length of user id "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test abcdefghijklmnopqrstuvwxyx12345678 " \
                    0 \
                    "Added user using OCSP_adminV with maximum user id length"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show abcdefghijklmnopqrstuvwxyx12345678 > $TmpDir/pki-user-add-ocsp-001_1.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"abcdefghijklmnopqrstuvwxyx12345678\"" "$TmpDir/pki-user-add-ocsp-001_1.out"
        rlAssertGrep "User ID: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ocsp-001_1.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_1.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del abcdefghijklmnopqrstuvwxyx12345678 " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_2:User id with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test abc# " \
                    0 \
                    "Added user using OCSP_adminV, user id with # character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show abc# > $TmpDir/pki-user-add-ocsp-001_2.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"abc#\"" "$TmpDir/pki-user-add-ocsp-001_2.out"
        rlAssertGrep "User ID: abc#" "$TmpDir/pki-user-add-ocsp-001_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_2.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del abc# " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_3:User id with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test abc$ " \
                    0 \
                    "Added user using OCSP_adminV, user id with $ character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show abc$ > $TmpDir/pki-user-add-ocsp-001_3.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"abc$\"" "$TmpDir/pki-user-add-ocsp-001_3.out"
        rlAssertGrep "User ID: abc\\$" "$TmpDir/pki-user-add-ocsp-001_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_3.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del abc$ " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_4:User id with @ character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test abc@ " \
                    0 \
                    "Added user using OCSP_adminV, user id with @ character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show abc@ > $TmpDir/pki-user-add-ocsp-001_4.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"abc@\"" "$TmpDir/pki-user-add-ocsp-001_4.out"
        rlAssertGrep "User ID: abc@" "$TmpDir/pki-user-add-ocsp-001_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_4.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del abc@ " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_5:User id with ? character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test abc? " \
                    0 \
                    "Added user using OCSP_adminV, user id with ? character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show abc? > $TmpDir/pki-user-add-ocsp-001_5.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"abc?\"" "$TmpDir/pki-user-add-ocsp-001_5.out"
        rlAssertGrep "User ID: abc?" "$TmpDir/pki-user-add-ocsp-001_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_5.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del abc? " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_6:User id as 0"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test 0 " \
                    0 \
                    "Added user using OCSP_adminV, user id 0"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show 0 > $TmpDir/pki-user-add-ocsp-001_6.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"0\"" "$TmpDir/pki-user-add-ocsp-001_6.out"
        rlAssertGrep "User ID: 0" "$TmpDir/pki-user-add-ocsp-001_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_6.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del 0 " \
                    0 \
                    "Delete user from OCSP"

    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_7:--email with maximum length "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=abcdefghijklmnopqrstuvwxyx12345678 a " \
                    0 \
                    "Added user using OCSP_adminV with maximum --email length"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show a > $TmpDir/pki-user-add-ocsp-001_7.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"a\"" "$TmpDir/pki-user-add-ocsp-001_7.out"
        rlAssertGrep "User ID: a" "$TmpDir/pki-user-add-ocsp-001_7.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_7.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ocsp-001_7.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del a" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_8:--email with maximum length and symbols "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=abcdefghijklmnopqrstuvwxyx12345678#?*@$  b " \
                    0 \
                    "Added user using OCSP_adminV with maximum --email length and character symbols in it"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show b > $TmpDir/pki-user-add-ocsp-001_8.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"b\"" "$TmpDir/pki-user-add-ocsp-001_8.out"
        rlAssertGrep "User ID: b" "$TmpDir/pki-user-add-ocsp-001_8.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_8.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678\\#\\?*$@" "$TmpDir/pki-user-add-ocsp-001_8.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del b" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_9:--email with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=#  d " \
                    0 \
                    "Added user using OCSP_adminV with --email # character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show d > $TmpDir/pki-user-add-ocsp-001_9.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"d\"" "$TmpDir/pki-user-add-ocsp-001_9.out"
        rlAssertGrep "User ID: d" "$TmpDir/pki-user-add-ocsp-001_9.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_9.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-add-ocsp-001_9.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del d " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_10:--email with * character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=*  e " \
                    0 \
                    "Added user using OCSP_adminV with --email * character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show e > $TmpDir/pki-user-add-ocsp-001_10.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"e\"" "$TmpDir/pki-user-add-ocsp-001_10.out"
        rlAssertGrep "User ID: e" "$TmpDir/pki-user-add-ocsp-001_10.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_10.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-add-ocsp-001_10.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del e " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_11:--email with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=$  f " \
                    0 \
                    "Added user using OCSP_adminV with --email $ character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show f > $TmpDir/pki-user-add-ocsp-001_11.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"f\"" "$TmpDir/pki-user-add-ocsp-001_11.out"
        rlAssertGrep "User ID: f" "$TmpDir/pki-user-add-ocsp-001_11.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_11.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-add-ocsp-001_11.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del f " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_12:--email as number 0 "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=0  z " \
                    0 \
                    "Added user using OCSP_adminV with --email 0"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show z > $TmpDir/pki-user-add-ocsp-001_12.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"z\"" "$TmpDir/pki-user-add-ocsp-001_12.out"
        rlAssertGrep "User ID: z" "$TmpDir/pki-user-add-ocsp-001_12.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_12.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-add-ocsp-001_12.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del z" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_13:--state with maximum length "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=abcdefghijklmnopqrstuvwxyx12345678 h " \
                    0 \
                    "Added user using OCSP_adminV with maximum --state length"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show h > $TmpDir/pki-user-add-ocsp-001_13.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"h\"" "$TmpDir/pki-user-add-ocsp-001_13.out"
        rlAssertGrep "User ID: h" "$TmpDir/pki-user-add-ocsp-001_13.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_13.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ocsp-001_13.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del h " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_14:--state with maximum length and symbols "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=abcdefghijklmnopqrstuvwxyx12345678#?*@$  i " \
                    0 \
                    "Added user using OCSP_adminV with maximum --state length and character symbols in it"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show i > $TmpDir/pki-user-add-ocsp-001_14.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"i\"" "$TmpDir/pki-user-add-ocsp-001_14.out"
        rlAssertGrep "User ID: i" "$TmpDir/pki-user-add-ocsp-001_14.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_14.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678\\#\\?*$@" "$TmpDir/pki-user-add-ocsp-001_14.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del i " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_15:--state with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=#  j " \
                    0 \
                    "Added user using OCSP_adminV with --state # character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show j > $TmpDir/pki-user-add-ocsp-001_15.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"j\"" "$TmpDir/pki-user-add-ocsp-001_15.out"
        rlAssertGrep "User ID: j" "$TmpDir/pki-user-add-ocsp-001_15.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_15.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-add-ocsp-001_15.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del j" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_16:--state with * character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=*  k " \
                    0 \
                    "Added user using OCSP_adminV with --state * character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show k > $TmpDir/pki-user-add-ocsp-001_16.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"k\"" "$TmpDir/pki-user-add-ocsp-001_16.out"
        rlAssertGrep "User ID: k" "$TmpDir/pki-user-add-ocsp-001_16.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_16.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-add-ocsp-001_16.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del k " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_17:--state with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=$  l " \
                    0 \
                    "Added user using OCSP_adminV with --state $ character"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show l > $TmpDir/pki-user-add-ocsp-001_17.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"l\"" "$TmpDir/pki-user-add-ocsp-001_17.out"
        rlAssertGrep "User ID: l" "$TmpDir/pki-user-add-ocsp-001_17.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_17.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-add-ocsp-001_17.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del l " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_18:--state as number 0 "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=0  m " \
                    0 \
                    "Added user using OCSP_adminV with --state 0"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show m > $TmpDir/pki-user-add-ocsp-001_18.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"m\"" "$TmpDir/pki-user-add-ocsp-001_18.out"
        rlAssertGrep "User ID: m" "$TmpDir/pki-user-add-ocsp-001_18.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_18.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-add-ocsp-001_18.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del m" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_19:--phone with maximum length "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=abcdefghijklmnopqrstuvwxyx12345678 n " \
                    0 \
                    "Added user using OCSP_adminV with maximum --phone length"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show n > $TmpDir/pki-user-add-ocsp-001_19.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"n\"" "$TmpDir/pki-user-add-ocsp-001_19.out"
        rlAssertGrep "User ID: n" "$TmpDir/pki-user-add-ocsp-001_19.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_19.out"
        rlAssertGrep "Phone: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-add-ocsp-001_19.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del n " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_20:--phone with maximum length and symbols "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=abcdefghijklmnopqrstuvwxyx12345678#?*@$  o > $TmpDir/pki-user-add-ocsp-001_20.out  2>&1"\
                    1 \
                    "Cannot add user using OCSP_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ocsp-001_20.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_21:--phone with # character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=#  p > $TmpDir/pki-user-add-ocsp-001_21.out  2>&1" \
                    1 \
                    "Cannot add user using OCSP_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ocsp-001_21.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_22:--phone with * character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=*  q > $TmpDir/pki-user-add-ocsp-001_22.out 2>&1" \
                    1 \
                    "Cannot add user using OCSP_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ocsp-001_22.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_23:--phone with $ character "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=$  r > $TmpDir/pki-user-add-ocsp-001_23.out 2>&1" \
                    1 \
                    "Cannot add user using OCSP_adminV with maximum --phone with character symbols in it"
        rlAssertGrep "PKIException: LDAP error (21): error result" "$TmpDir/pki-user-add-ocsp-001_23.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_24:--phone as negative number -1230 "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=-1230  s " \
                    0 \
                    "Added user using OCSP_adminV with --phone -1230"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show s > $TmpDir/pki-user-add-ocsp-001_24.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"s\"" "$TmpDir/pki-user-add-ocsp-001_24.out"
        rlAssertGrep "User ID: s" "$TmpDir/pki-user-add-ocsp-001_24.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_24.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-add-ocsp-001_24.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del s " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_25:--type as Auditors"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=Auditors t " \
                    0 \
                    "Added user using OCSP_adminV with  --type Auditors"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show t > $TmpDir/pki-user-add-ocsp-001_25.out" \
                    0 \
                    "Show pki OCSP_adminV user"
        rlAssertGrep "User \"t\"" "$TmpDir/pki-user-add-ocsp-001_25.out"
        rlAssertGrep "User ID: t" "$TmpDir/pki-user-add-ocsp-001_25.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_25.out"
        rlAssertGrep "Type: Auditors" "$TmpDir/pki-user-add-ocsp-001_25.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del t " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_26:--type Data Recovery Manager Agents "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Certificate Manager Agents\" t" \
                    0 \
                    "Added user using OCSP_adminV  --type Certificate Manager Agents"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show t > $TmpDir/pki-user-add-ocsp-001_26.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"t\"" "$TmpDir/pki-user-add-ocsp-001_26.out"
        rlAssertGrep "User ID: t" "$TmpDir/pki-user-add-ocsp-001_26.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_26.out"
        rlAssertGrep "Type: Certificate Manager Agents" "$TmpDir/pki-user-add-ocsp-001_26.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del t " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_27:--type Registration Manager Agents "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Registration Manager Agents\"  u " \
                    0 \
                    "Added user using OCSP_adminV with --type Registration Manager Agents"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show u > $TmpDir/pki-user-add-ocsp-001_27.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"u\"" "$TmpDir/pki-user-add-ocsp-001_27.out"
        rlAssertGrep "User ID: u" "$TmpDir/pki-user-add-ocsp-001_27.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_27.out"
        rlAssertGrep "Type: Registration Manager Agents" "$TmpDir/pki-user-add-ocsp-001_27.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del u" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_28:--type Subsytem Group "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Subsytem Group\"  v " \
                    0 \
                    "Added user using OCSP_adminV with --type Subsytem Group"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show v > $TmpDir/pki-user-add-ocsp-001_28.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"v\"" "$TmpDir/pki-user-add-ocsp-001_28.out"
        rlAssertGrep "User ID: v" "$TmpDir/pki-user-add-ocsp-001_28.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_28.out"
        rlAssertGrep "Type: Subsytem Group" "$TmpDir/pki-user-add-ocsp-001_28.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del v" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_29:--type Security Domain Administrators "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Security Domain Administrators\" w " \
                    0 \
                    "Added user using OCSP_adminV with --type Security Domain Administrators"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show w > $TmpDir/pki-user-add-ocsp-001_29.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"w\"" "$TmpDir/pki-user-add-ocsp-001_29.out"
        rlAssertGrep "User ID: w" "$TmpDir/pki-user-add-ocsp-001_29.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_29.out"
        rlAssertGrep "Type: Security Domain Administrators" "$TmpDir/pki-user-add-ocsp-001_29.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del w" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_30:--type ClonedSubsystems "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=ClonedSubsystems x " \
                    0 \
                    "Added user using OCSP_adminV with --type ClonedSubsystems"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show x > $TmpDir/pki-user-add-ocsp-001_30.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"x\"" "$TmpDir/pki-user-add-ocsp-001_30.out"
        rlAssertGrep "User ID: x" "$TmpDir/pki-user-add-ocsp-001_30.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_30.out"
        rlAssertGrep "Type: ClonedSubsystems" "$TmpDir/pki-user-add-ocsp-001_30.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del x " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-001_31:--type Trusted Managers "
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Trusted Managers\" y " \
                    0 \
                    "Added user using OCSP_adminV with --type Trusted Managers"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-show y > $TmpDir/pki-user-add-ocsp-001_31.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"y\"" "$TmpDir/pki-user-add-ocsp-001_31.out"
        rlAssertGrep "User ID: y" "$TmpDir/pki-user-add-ocsp-001_31.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-add-ocsp-001_31.out"
        rlAssertGrep "Type: Trusted Managers" "$TmpDir/pki-user-add-ocsp-001_31.out"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del y " \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-002: Add a duplicate user to CA"
         command="pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=\"New user\" $user1 > $TmpDir/pki-user-add-ocsp-002.out 2>&1 "

         rlLog "Command=$command"
         expmsg="ConflictingOperationException: Entry already exists."
         rlRun "$command" 1 "Add duplicate user"
         rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ocsp-002.out"
         rlLog "Clean-up:"
         rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-del $user1" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-003: Add a user to OCSP with -t option"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add --fullName=\"$user1fullname\"  $user1"

        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add --fullName=\"$user1fullname\"  $user1 > $TmpDir/pki-user-add-ocsp-003.out" \
                    0 \
                    "Add user $user1 to CA"
        rlAssertGrep "Added user \"$user1\"" "$TmpDir/pki-user-add-ocsp-003.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ocsp-003.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ocsp-003.out"

        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-show $user1 > $TmpDir/pki-user-add-ocsp-003_1.out" \
                    0 \
                    "Show pki OCSP user"
        rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-add-ocsp-003_1.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ocsp-003_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ocsp-003_1.out"
        rlLog "Clean-up:"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-del $user1" \
                    0 \
                    "Delete user from OCSP"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_add-OCSP-004:  Add a user -- missing required option user id"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add --fullName=\"$user1fullname\" "

        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add --fullName=\"$user1fullname\" > $TmpDir/pki-user-add-ocsp-004.out" \
                     1\
                    "Add user -- missing required option user id"
        rlAssertGrep "usage: user-add <User ID> \[OPTIONS...\]" "$TmpDir/pki-user-add-ocsp-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-005:  Add a user -- missing required option --fullName"
        command="pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add $user1 > $TmpDir/pki-user-add-ocsp-005.out 2>&1"
        expmsg="Error: Missing required option: fullName"
        rlLog "Executing: $command"
        rlRun "$command" 1 "Add a user -- missing required option --fullName"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ocsp-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-006:  Add a user -- all options provided"
        email="ocsp_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                    --type $type \
                     $user1"

        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-add --fullName=\"$user1fullname\"  \
		    --email $email \
		    --password $user_password \
		    --phone $phone \
		    --state $state \
		    --type $type \
		     $user1 >  $TmpDir/pki-user-add-ocsp-006_1.out" \
                    0 \
                    "Add user $user1 to OCSP -- all options provided"
        rlAssertGrep "Added user \"$user1\"" "$TmpDir/pki-user-add-ocsp-006_1.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ocsp-006_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ocsp-006_1.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-add-ocsp-006_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-add-ocsp-006_1.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-add-ocsp-006_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-add-ocsp-006_1.out"

        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-show $user1 > $TmpDir/pki-user-add-ocsp-006.out" \
                    0 \
                    "Show pki OCSP user"

        rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-add-ocsp-006.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-add-ocsp-006.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-add-ocsp-006.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-add-ocsp-006.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-add-ocsp-006.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-add-ocsp-006.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-add-ocsp-006.out"
        rlLog "Clean-up:"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                   -t ocsp \
                    user-del $user1" \
                    0 \
                    "Delete user from OCSP"

    rlPhaseEnd

   rlPhaseStartTest "pki_user_cli_user_add-OCSP-007:  Add user to multiple groups"
       user=multigroup_user
       userfullname="Multiple Group User"
       email="multiplegroup@myemail.com"
       user_password="admin2Password"
       phone="1234567890"
       state="NC"
       rlLog "Executing: pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
                   user-add --fullName=\"$userfullname\"  \
                   --email $email \
                   --password $user_password \
                   --phone $phone \
                   --state $state \
                    $user"

       rlRun "pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
                   user-add --fullName=\"$userfullname\"  \
                   --email $email \
                   --password $user_password \
                   --phone $phone \
                   --state $state \
                    $user" \
                   0 \
                   "Add user $user using OCSP_adminV"

       rlRun "pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
                   group-add-member Administrators $user > $TmpDir/pki-user-add-ocsp-007_1.out"  \
                   0 \
                   "Add user $user to Administrators group"

       rlAssertGrep "Added group member \"$user\"" "$TmpDir/pki-user-add-ocsp-007_1.out"
       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ocsp-007_1.out"

       rlRun "pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
                   group-find-member Administrators > $TmpDir/pki-user-add-ocsp-007.out" \
                   0 \
                   "Show pki group-find-member Administrators"
       rlRun "pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
                   group-add-member \"Certificate Manager Agents\"  $user > $TmpDir/pki-user-add-ocsp-007_1_1.out"  \
                   0 \
                   "Add user $user to Administrators group"

       rlAssertGrep "Added group member \"$user\"" "$TmpDir/pki-user-add-ocsp-007_1_1.out"
       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ocsp-007_1_1.out"

       rlRun "pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
                   group-find-member \"Certificate Manager Agents\"  > $TmpDir/pki-user-add-ocsp-007_2.out" \
                   0 \
                   "Show pki group-find-member Administrators"

       rlAssertGrep "User: $user" "$TmpDir/pki-user-add-ocsp-007_2.out"

       rlRun "pki -d /tmp/requestdb \
                  -n OCSP_adminV \
                  -c $nss_db_password \
                  -t ocsp \
	    user-del $user" \
                   0 \
                   "Delete user $user "

   rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-008: Add user with --password "
        userpw="pass"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-add-ocsp-008.out 2>&1"
        expmsg="PKIException: The password must be at least 8 characters"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminV \
                   -c $nss_db_password \
		   -t ocsp \
                    user-add --fullName=\"$user1fullname\" --password=$userpw $user1 > $TmpDir/pki-user-add-ocsp-008.out 2>&1" \
                    1 \
                    "Add a user --must be at least 8 characters --password"
        rlAssertGrep "$expmsg" "$TmpDir/pki-user-add-ocsp-008.out"

    rlPhaseEnd

        ##### Tests to add users using revoked cert#####
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-009: Cannot add user using a revoked cert OCSP_adminR"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_adminR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-revoke-adminR-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ocsp-revoke-adminR-002.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-009_1: Cannot add user using a agent or a revoked cert OCSP_agentR"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-revoke-agentR-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a user having revoked cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ocsp-revoke-agentR-002.out"
    rlPhaseEnd


        ##### Tests to add users using an agent user#####
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0010: Cannot add user using a OCSP_agentV user"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_agentV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_agentV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-agentV-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ocsp-agentV-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0011: Cannot add user using a OCSP_agentR user"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_agentR \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-agentR-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ocsp-agentR-002.out"
    rlPhaseEnd
    ##### Tests to add users using expired cert#####
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0012: Cannot add user using a OCSP_adminE cert"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_adminE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_adminE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-adminE-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "RuntimeException: java.io.IOException: SocketException cannot read on socket" "$TmpDir/pki-user-add-ocsp-adminE-002.out"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0013: Cannot add user using a OCSP_agentE cert"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_agentE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_agentE \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-agentE-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a agent cert"
        rlAssertGrep "RuntimeException: java.io.IOException: SocketException cannot read on socket" "$TmpDir/pki-user-add-ocsp-agentE-002.out"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

	##### Tests to add users using audit users#####
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0012: Cannot add user using a OCSP_auditV"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_auditV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_auditV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-auditV-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a audit cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ocsp-auditV-002.out"
    rlPhaseEnd

	##### Tests to add users using operator user###
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0013: Cannot add user using a OCSP_operatorV"

        rlLog "Executing: pki -d /tmp/requestdb \
                   -n OCSP_operatorV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n OCSP_operatorV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-operatorV-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a operator cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ocsp-operatorV-002.out"
    rlPhaseEnd


	 ##### Tests to add users using OCSP_adminUTOCSP and OCSP_agentUTOCSP  user's certificate will be issued by an untrusted OCSP users#####
    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0014: Cannot add user using a OCSP_adminUTOCSP"

        rlLog "Executing: pki -d /tmp/dummydb \
                   -n OCSP_adminUTOCSP \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/dummydb \
                   -n OCSP_adminUTOCSP \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-adminUTOCSP-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a untrusted cert"
        rlAssertGrep "ClientResponseFailure: Error status 401 Unauthorized returned" "$TmpDir/pki-user-add-ocsp-adminUTOCSP-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_add-OCSP-0014: Cannot add user using a OCSP_agentUTOCSP"

        rlLog "Executing: pki -d /tmp/dummydb \
                   -n OCSP_agentUTOCSP \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlRun "pki -d /tmp/dummydb \
                   -n OCSP_agentUTOCSP \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1 > $TmpDir/pki-user-add-ocsp-agentUTOCSP-002.out 2>&1" \
                    1 \
                    "Cannot add  user $user1 using a untrusted cert"
        rlAssertGrep "RuntimeException: java.net.SocketException: Object not found: org.mozilla.jss.crypto.ObjectNotFoundException" "$TmpDir/pki-user-add-ocsp-agentUTOCSP-002.out"
    rlPhaseEnd


}
