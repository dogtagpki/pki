#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
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
. /opt/rhqa_pki/env.sh

########################################################################
# Test Suite Globals
########################################################################

user1="kra_agent2"
user1fullname="Test kra_agent"


########################################################################

run_pki-user-cli-user-find-kra_tests(){
    rlPhaseStartSetup "pki_user_cli_user_find-startup: Getting nss certificate db"
        rlLog "Certificate directory = $CERTDB_DIR"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-KRA-add: Add users to KRA"
	i=1
	while [ $i -le 5 ] ; do
		rlLog "Adding user user1$i"
		rlRun "pki -d $CERTDB_DIR \
			-n \"$KRA_adminV\" \
				-c $CERTDB_DIR_PASSWORD \
				user-add --fullName=\"fullname1$i\" user1$i > $TmpDir/pki-user-find-kra-a00$i.out 2>&1" \
			 0 \
			"Add user user1$i to KRA"
		rlAssertGrep "Added user \"user1$i\"" "$TmpDir/pki-user-find-kra-a00$i.out"
		rlAssertGrep "User ID: user1$i" "$TmpDir/pki-user-find-kra-a00$i.out"
		rlAssertGrep "Full name: fullname1$i" "$TmpDir/pki-user-find-kra-a00$i.out"
		let i=$i+1
	done
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-001: Find 5 users, --size=5"
	rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=5  > $TmpDir/pki-user-find-kra-001.out 2>&1" \
                         0 \
                        "Found 5 users"
	rlAssertGrep "Number of entries returned 5" "$TmpDir/pki-user-find-kra-001.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_find-kra-002: Find non user, --size=0"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=0  > $TmpDir/pki-user-find-kra-002.out 2>&1" \
                         0 \
                        "Found no users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-kra-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-003: Find all users, maximum possible value as input"
        maximum_check=1000000
	rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$maximum_check  > $TmpDir/pki-user-find-kra-003.out 2>&1" \
                         0 \
                        "All users"
        rlAssertGrep "Number of entries returned " "$TmpDir/pki-user-find-kra-003.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-004: Find users, check for negative input --size=-1"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=-1  > $TmpDir/pki-user-find-kra-004.out 2>&1" \
                         0 \
                        "No  users returned as the size entered is negative value"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-kra-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-005: Find users for size input as noninteger, --size=abc"
        size_noninteger="abc"
	rlLog "Executing: pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-kra-005.out 2>&1"
	rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-kra-005.out 2>&1" \
                         1 \
                        "Found 5 users"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-kra-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-006: Find users, check for no input --size= "
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=  > $TmpDir/pki-user-find-kra-006.out 2>&1" \
                         1 \
                        "No users returned, as --size= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-user-find-kra-006.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_find-kra-007: Find users, --start=10 "
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=10  > $TmpDir/pki-user-find-kra-007.out 2>&1" \
                         0 \
                        "Displays users from the 10th user and the next to the maximum 20 users, if available "
        rlAssertGrep "Number of entries returned " "$TmpDir/pki-user-find-kra-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-008: Find users, --start=10000, maximum possible input "
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=10000  > $TmpDir/pki-user-find-kra-008.out 2>&1" \
                         0 \
                        "No users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-kra-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-009: Find users, --start=0"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=0  > $TmpDir/pki-user-find-kra-009.out 2>&1" \
                         0 \
                        "Displays from the zeroth user, maximum possible are 20 users in a page"
        rlAssertGrep "Number of entries returned" "$TmpDir/pki-user-find-kra-009.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-0010: Find users, --start=-1"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=-1  > $TmpDir/pki-user-find-kra-0010.out 2>&1" \
                         0 \
                        "Maximum possible 20 users are returned, starting from the zeroth user"
        rlAssertGrep "Number of entries returned" "$TmpDir/pki-user-find-kra-0010.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-kra-0011: Find users for size input as noninteger, --start=abc"
        size_noninteger="abc"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=$size_noninteger  > $TmpDir/pki-user-find-kra-0011.out 2>&1" \
                         1 \
                        "Incorrect input to find user"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-kra-0011.out"
    rlPhaseEnd

    rlPhaseStartTest "Cleanup: Delete the KRA users"
	i=1
        while [ $i -le 5 ] ; do
                rlRun "pki -d $CERTDB_DIR \
                        -n \"$KRA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-del user1$i" \
                         0 \
                        "Delete user user1$i"
                let i=$i+1
        done
    rlPhaseEnd

    rlPhaseStartCleanup "pki_user_cli_user_find-cleanup: Delete temp dir"
	rlLog "Deleting users created in the above tests"
    rlPhaseEnd
}
