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
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
user1=ca_agent2
user1fullname="Test ca_agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0

run_pki-user-cli-user-show-ca_tests(){
    rlPhaseStartSetup "pki_user_cli_user_show-ca-startup:Getting the temp directory and nss certificate db "
	 rlLog "nss_db directory = $TmpDir/nssdb"
	 rlLog "temp directory = /tmp/requestdb"
    rlPhaseEnd
     ##### Tests to show CA users ####
    rlPhaseStartTest "pki_user_cli_user_show-CA-001: Add a user to CA using CA_adminV"
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlLog "Executing: pki -d $TmpDir/nssdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user1 > $TmpDir/pki-user-show-ca-001.out" \
		    0 \
		    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-show-ca-001.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-show-ca-001.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_1:maximum length of user id "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user2"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user2 > $TmpDir/pki-user-show-ca-001_1.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user2\"" "$TmpDir/pki-user-show-ca-001_1.out"
        rlAssertGrep "User ID: $user2" "$TmpDir/pki-user-show-ca-001_1.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_1.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_2:User id with # character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user3"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user3 > $TmpDir/pki-user-show-ca-001_2.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user3\"" "$TmpDir/pki-user-show-ca-001_2.out"
        rlAssertGrep "User ID: $user3" "$TmpDir/pki-user-show-ca-001_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_2.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_3:User id with $ character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                            user-add --fullName=test $user4"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user4 > $TmpDir/pki-user-show-ca-001_3.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user4\"" "$TmpDir/pki-user-show-ca-001_3.out"
        rlAssertGrep "User ID: abc\\$" "$TmpDir/pki-user-show-ca-001_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_3.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_4:User id with @ character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user5"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user5 > $TmpDir/pki-user-show-ca-001_4.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user5\"" "$TmpDir/pki-user-show-ca-001_4.out"
        rlAssertGrep "User ID: $user5" "$TmpDir/pki-user-show-ca-001_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_4.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_5:User id with ? character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user6"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user6 > $TmpDir/pki-user-show-ca-001_5.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user6\"" "$TmpDir/pki-user-show-ca-001_5.out"
        rlAssertGrep "User ID: $user6" "$TmpDir/pki-user-show-ca-001_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_5.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_6:User id as 0"
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test $user7"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show $user7 > $TmpDir/pki-user-show-ca-001_6.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"$user7\"" "$TmpDir/pki-user-show-ca-001_6.out"
        rlAssertGrep "User ID: $user7" "$TmpDir/pki-user-show-ca-001_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_6.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_7:--email with maximum length "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=abcdefghijklmnopqrstuvwxyx12345678 u1"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u1 > $TmpDir/pki-user-show-ca-001_7.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u1\"" "$TmpDir/pki-user-show-ca-001_7.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-user-show-ca-001_7.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_7.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-show-ca-001_7.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_8:--email with maximum length and symbols "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=abcdefghijklmnopqrstuvwxyx12345678#?*@$  u2"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u2 > $TmpDir/pki-user-show-ca-001_8.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u2\"" "$TmpDir/pki-user-show-ca-001_8.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-user-show-ca-001_8.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_8.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678\\#\\?*$@" "$TmpDir/pki-user-show-ca-001_8.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_9:--email with # character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=#  u3"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u3 > $TmpDir/pki-user-show-ca-001_9.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u3\"" "$TmpDir/pki-user-show-ca-001_9.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-user-show-ca-001_9.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_9.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-show-ca-001_9.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_10:--email with * character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=*  u4"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u4 > $TmpDir/pki-user-show-ca-001_10.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u4\"" "$TmpDir/pki-user-show-ca-001_10.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-user-show-ca-001_10.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_10.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-show-ca-001_10.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_11:--email with $ character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=$  u5"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u5 > $TmpDir/pki-user-show-ca-001_11.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u5\"" "$TmpDir/pki-user-show-ca-001_11.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-user-show-ca-001_11.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_11.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-show-ca-001_11.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_12:--email as number 0 "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --email=0  u6"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u6 > $TmpDir/pki-user-show-ca-001_12.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u6\"" "$TmpDir/pki-user-show-ca-001_12.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-user-show-ca-001_12.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_12.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-show-ca-001_12.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_13:--state with maximum length "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=abcdefghijklmnopqrstuvwxyx12345678 u7 "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u7 > $TmpDir/pki-user-show-ca-001_13.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u7\"" "$TmpDir/pki-user-show-ca-001_13.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-user-show-ca-001_13.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_13.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-show-ca-001_13.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_14:--state with maximum length and symbols "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=abcdefghijklmnopqrstuvwxyx12345678#?*@$  u8"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u8 > $TmpDir/pki-user-show-ca-001_14.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u8\"" "$TmpDir/pki-user-show-ca-001_14.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-user-show-ca-001_14.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_14.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678\\#\\?*$@" "$TmpDir/pki-user-show-ca-001_14.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_15:--state with # character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=#  u9"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u9 > $TmpDir/pki-user-show-ca-001_15.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u9\"" "$TmpDir/pki-user-show-ca-001_15.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-user-show-ca-001_15.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_15.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-show-ca-001_15.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_16:--state with * character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=*  u10"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u10 > $TmpDir/pki-user-show-ca-001_16.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u10\"" "$TmpDir/pki-user-show-ca-001_16.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-show-ca-001_16.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_16.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-show-ca-001_16.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_17:--state with $ character "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=$  u11"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u11 > $TmpDir/pki-user-show-ca-001_17.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u11\"" "$TmpDir/pki-user-show-ca-001_17.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-user-show-ca-001_17.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_17.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-show-ca-001_17.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_18:--state as number 0 "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --state=0  u12"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u12 > $TmpDir/pki-user-show-ca-001_18.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u12\"" "$TmpDir/pki-user-show-ca-001_18.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-user-show-ca-001_18.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_18.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-show-ca-001_18.out"
    rlPhaseEnd
	#https://www.redhat.com/archives/pki-users/2010-February/msg00015.html
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_19:--phone with maximum length "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=abcdefghijklmnopqrstuvwxyx12345678 u13"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u13 > $TmpDir/pki-user-show-ca-001_19.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u13\"" "$TmpDir/pki-user-show-ca-001_19.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-user-show-ca-001_19.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_19.out"
        rlAssertGrep "Phone: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-show-ca-001_19.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_24:--phone as negative number -1230 "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --phone=-1230  u14"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u14 > $TmpDir/pki-user-show-ca-001_24.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u14\"" "$TmpDir/pki-user-show-ca-001_24.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-user-show-ca-001_24.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_24.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-show-ca-001_24.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-001_25:--type as Auditors"
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=Auditors u15"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u15 > $TmpDir/pki-user-show-ca-001_25.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u15\"" "$TmpDir/pki-user-show-ca-001_25.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-user-show-ca-001_25.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_25.out"
        rlAssertGrep "Type: Auditors" "$TmpDir/pki-user-show-ca-001_25.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_26:--type Certificate Manager Agents "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Certificate Manager Agents\" u16"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u16 > $TmpDir/pki-user-show-ca-001_26.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-show-ca-001_26.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-show-ca-001_26.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_26.out"
        rlAssertGrep "Type: Certificate Manager Agents" "$TmpDir/pki-user-show-ca-001_26.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_27:--type Registration Manager Agents "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Registration Manager Agents\"  u17"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u17 > $TmpDir/pki-user-show-ca-001_27.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u17\"" "$TmpDir/pki-user-show-ca-001_27.out"
        rlAssertGrep "User ID: u17" "$TmpDir/pki-user-show-ca-001_27.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_27.out"
        rlAssertGrep "Type: Registration Manager Agents" "$TmpDir/pki-user-show-ca-001_27.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_28:--type Subsytem Group "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Subsytem Group\"  u18"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u18 > $TmpDir/pki-user-show-ca-001_28.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u18\"" "$TmpDir/pki-user-show-ca-001_28.out"
        rlAssertGrep "User ID: u18" "$TmpDir/pki-user-show-ca-001_28.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_28.out"
        rlAssertGrep "Type: Subsytem Group" "$TmpDir/pki-user-show-ca-001_28.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_29:--type Security Domain Administrators "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Security Domain Administrators\" u19"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u19 > $TmpDir/pki-user-show-ca-001_29.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u19\"" "$TmpDir/pki-user-show-ca-001_29.out"
        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-show-ca-001_29.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_29.out"
        rlAssertGrep "Type: Security Domain Administrators" "$TmpDir/pki-user-show-ca-001_29.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_30:--type ClonedSubsystems "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=ClonedSubsystems u20"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u20 > $TmpDir/pki-user-show-ca-001_30.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u20\"" "$TmpDir/pki-user-show-ca-001_30.out"
        rlAssertGrep "User ID: u20" "$TmpDir/pki-user-show-ca-001_30.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_30.out"
        rlAssertGrep "Type: ClonedSubsystems" "$TmpDir/pki-user-show-ca-001_30.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_31:--type Trusted Managers "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-add --fullName=test --type=\"Trusted Managers\" u21"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                    user-show u21 > $TmpDir/pki-user-show-ca-001_31.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u21\"" "$TmpDir/pki-user-show-ca-001_31.out"
        rlAssertGrep "User ID: u21" "$TmpDir/pki-user-show-ca-001_31.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_31.out"
        rlAssertGrep "Type: Trusted Managers" "$TmpDir/pki-user-show-ca-001_31.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_32: Add a user to CA with -t option"
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  u22"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-show u22 > $TmpDir/pki-user-show-ca-001_32.out" \
                    0 \
                    "Show pki CA user"
        rlAssertGrep "User \"u22\"" "$TmpDir/pki-user-show-ca-001_32.out"
        rlAssertGrep "User ID: u22" "$TmpDir/pki-user-show-ca-001_32.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001_32.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_33:  Add a user -- all options provided"
	email="ca_agent2@myemail.com"
	user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"
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
                     u23"
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-show u23 > $TmpDir/pki-user-show-ca-001_33.out" \
                    0 \
                    "Show pki CA user"

        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-show-ca-001_33.out"
    rlPhaseEnd
    #Negative Cases
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_34: Missing required option user id "
	rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-show  > $TmpDir/pki-user-show-ca-001_34.out 2>&1" \
                    1 \
                    "Cannot show user without user id"
	rlAssertGrep "usage: user-show <User ID>" "$TmpDir/pki-user-show-ca-001_34.out"
    rlPhaseEnd
    #====#
    rlPhaseStartTest "pki_user_cli_user_show-CA-001_35: Checking if user id case sensitive "
        rlRun "pki -d /tmp/requestdb \
                   -n CA_adminV \
                   -c $nss_db_password \
                   -t ca \
                    user-show U23 > $TmpDir/pki-user-show-ca-001_35.out 2>&1" \
                    0 \
                    "User ID is not case sensitive"
	rlAssertGrep "User \"U23\"" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-show-ca-001_35.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_cleanup-001_36: Deleting the temp directory and users"
	del_user=($CA_adminV_user $CA_adminR_user $CA_adminE_user $CA_adminUTCA_user $CA_agentV_user $CA_agentR_user $CA_agentE_user $CA_agentUTCA_user $CA_auditV_user $CA_operatorV_user)

        #===Deleting users created using CA_adminV cert===#
        i=1
        while [ $i -lt 24 ] ; do
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
