#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-find  To  list  users in CA.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Laxmi Sunkara <lsunkara@redhat.com>
#            Asha Akkiangady <aakkiang@redhat.com>
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

run_pki-user-cli-user-find-ca_tests(){

    rlPhaseStartSetup "pki_user_cli_user_find-ca-startup-addusers: Create temporary directory and add users"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user u$i"
                let i=$i+1
        done
        j=1
        while [ $j -lt 8 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add  --fullName=test_user $usr"
                let j=$j+1
        done
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-configtest-001: pki user-find --help configuration test"
        rlRun "pki user-find --help > $TmpDir/user_find.out 2>&1" 0 "pki user-find --help"
        rlAssertGrep "usage: user-find [FILTER] [OPTIONS...]" "$TmpDir/user_find.out"
        rlAssertGrep "--size <size>     Page size" "$TmpDir/user_find.out"
        rlAssertGrep "--start <start>   Page start" "$TmpDir/user_find.out"
        rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/user_find.out"
        rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/490"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-configtest-002: pki user-find configuration test"
        rlRun "pki user-find > $TmpDir/user_find_2.out 2>&1" 0 "pki user-find"
        rlAssertNotGrep "ResteasyIOException: IOException" "$TmpDir/user_find_2.out"
        rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/821"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-003: Find 5 users, --size=5"
	rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=5  > $TmpDir/pki-user-find-ca-001.out 2>&1" \
                         0 \
                        "Found 5 users"
	rlAssertGrep "Number of entries returned 5" "$TmpDir/pki-user-find-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-004: Find non user, --size=0"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=0  > $TmpDir/pki-user-find-ca-002.out 2>&1" \
                         0 \
                        "Found no users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-005: Find all users, large value as input"
        large_num=1000000
	rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$large_num  > $TmpDir/pki-user-find-ca-003.out 2>&1" \
                         0 \ 
                        "Find all users, large value as input"
	result=`cat $TmpDir/pki-user-find-ca-003.out | grep "Number of entries returned"`
        number=`echo $result | cut -d " " -f 5`
        if [ $number -gt 25 ] ; then
                rlPass "Number of entries returned is more than 25 as expected"
        else

                rlFail "Number of entries returned is not expected, Got: $number, Expected: > 25"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-006: Find all users, --size with maximum possible value as input"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 9 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$maximum_check  > $TmpDir/pki-user-find-ca-003_2.out 2>&1" \
                         0 \
                        "Find all users, maximum possible value as input"
	result=`cat $TmpDir/pki-user-find-ca-003_2.out | grep "Number of entries returned"`
	number=`echo $result | cut -d " " -f 5`	
	if [ $number -gt 25 ] ; then
        	rlPass "Number of entries returned is more than 25 as expected"
	else
	
        	rlFail "Number of entries returned is not expected, Got: $number, Expected: > 25"
	fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-007: Find all users, --size more than maximum possible value"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 11 | head -n 1`
        rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$maximum_check  > $TmpDir/pki-user-find-ca-003_3.out 2>&1" \
                         1 \
                        "More than maximum possible value as input"
        rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-user-find-ca-003_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-008: Find users, check for negative input --size=-1"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=-1  > $TmpDir/pki-user-find-ca-004.out 2>&1" \
                         0 \
                        "No users returned as the size entered is negative value"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-009: Find users for size input as noninteger, --size=abc"
        size_noninteger="abc"
	rlLog "Executing: pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-ca-005.out 2>&1"
	rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-ca-005.out 2>&1" \
                         1 \
                        "No users returned"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-ca-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-010: Find users, check for no input --size= "
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --size=  > $TmpDir/pki-user-find-ca-006.out 2>&1" \
                         1 \
                        "No users returned, as --size= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-user-find-ca-006.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-011: Find users, --start=10"
	#Find the 10th user
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find  > $TmpDir/pki-user-find-ca-007_1.out 2>&1" \
                         0 \
                        "Get all users in CA"
	user_entry_10=`cat $TmpDir/pki-user-find-ca-007_1.out | grep "User ID" | head -11 | tail -1`
	rlLog "10th entry=$user_entry_10"

	rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=10"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=10  > $TmpDir/pki-user-find-ca-007.out 2>&1" \
                         0 \
                        "Displays users from the 10th user and the next to the maximum 20 users, if available "
	#First user in the response should be the 10th user $user_entry_10
	user_entry_1=`cat $TmpDir/pki-user-find-ca-007.out | grep "User ID" | head -1`
	rlLog "1th entry=$user_entry_1"
	if [ "$user_entry_1" = "$user_entry_10" ]; then
		rlPass "Displays users from the 10th user"
	else
		rlFail "Display did not start from the 10th user"
	fi
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-user-find-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-012: Find users, --start=10000, large possible input"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=10000  > $TmpDir/pki-user-find-ca-008.out 2>&1" \
                         0 \
                        "Find users, --start=10000, large possible input"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-013: Find users, --start with maximum possible input"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 9 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=$maximum_check  > $TmpDir/pki-user-find-ca-008_2.out 2>&1" \
                         0 \
                        "Find users, --start with maximum possible input"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-008_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-014: Find users, --start with more than maximum possible input"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 11 | head -n 1`
        rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=$maximum_check  > $TmpDir/pki-user-find-ca-008_3.out 2>&1" \
                         1 \
                        "Find users, --start with more than maximum possible input"
        rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-user-find-ca-008_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-015: Find users, --start=0"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=0  > $TmpDir/pki-user-find-ca-009.out 2>&1" \
                         0 \
                        "Displays from the zeroth user, maximum possible are 20 users in a page"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-user-find-ca-009.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-016: Find users, --start=-1"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=-1  > $TmpDir/pki-user-find-ca-0010.out 2>&1" \
                         0 \
                        "Maximum possible 20 users are returned, starting from the zeroth user"
        rlAssertGrep "Number of entries returned 19" "$TmpDir/pki-user-find-ca-0010.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-017: Find users for size input as noninteger, --start=abc"
        size_noninteger="abc"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=$size_noninteger  > $TmpDir/pki-user-find-ca-0011.out 2>&1" \
                         1 \
                        "Incorrect input to find user"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-ca-0011.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-018: Find users, check for no input --start= "
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=  > $TmpDir/pki-user-find-ca-0012.out 2>&1" \
                         1 \
                        "No users returned, as --start= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-user-find-ca-0012.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-019: Find users, --size=12 --start=12"
        #Find 12 users starting from 12th user
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find  > $TmpDir/pki-user-find-ca-00_13_1.out 2>&1" \
                         0 \
                        "Get all users in CA"
        user_entry_12=`cat $TmpDir/pki-user-find-ca-00_13_1.out | grep "User ID" | head -13 | tail -1`

        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=12 --size=12  > $TmpDir/pki-user-find-ca-0013.out 2>&1" \
                         0 \
                        "Displays users from the 12th user and the next to the maximum 12 users"
        #First user in the response should be the 12th user $user_entry_12
        user_entry_1=`cat  $TmpDir/pki-user-find-ca-0013.out | grep "User ID" | head -1`
        if [ "$user_entry_1" = "$user_entry_12" ]; then
                rlPass "Displays users from the 12th user"
        else
                rlFail "Display did not start from the 12th user"
        fi
        rlAssertGrep "Number of entries returned 12" "$TmpDir/pki-user-find-ca-0013.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-020: Find users, --size=0 --start=12"
        #Find 12 users starting from 12th user
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find  > $TmpDir/pki-user-find-ca-00_14_1.out 2>&1" \
                         0 \
                        "Get all users in CA"
        user_entry_12=`cat $TmpDir/pki-user-find-ca-00_14_1.out | grep "User ID" | head -13 | tail -1`

        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                user-find --start=12 --size=0  > $TmpDir/pki-user-find-ca-0014.out 2>&1" \
                         0 \
                        "Displays users from the 12th user and 0 users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-0014.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_cleanup-021: Deleting users"
        #===Deleting users created using CA_adminV cert===#
        i=1
        while [ $i -lt 25 ] ; do
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
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
    rlPhaseEnd
}
