#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: pki-ca-user-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-user-cli-ca-user-find  To  list  users in CA.
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
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

########################################################################
# Test Suite Globals
########################################################################

run_pki-ca-user-cli-ca-user-find_tests(){

    rlPhaseStartSetup "pki_ca_user_cli_ca_user_find-startup-addusers: Create temporary directory and add users"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           ca-user-add --fullName=test_user u$i"
                let i=$i+1
        done
        j=1
        while [ $j -lt 8 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           ca-user-add  --fullName=test_user $usr"
                let j=$j+1
        done
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-configtest-001: pki ca-user-find --help configuration test"
        rlRun "pki ca-user-find --help > $TmpDir/ca_user_find.out 2>&1" 0 "pki ca-user-find --help"
        rlAssertGrep "usage: ca-user-find \[FILTER\] \[OPTIONS...\]" "$TmpDir/ca_user_find.out"
        rlAssertGrep "\--size <size>     Page size" "$TmpDir/ca_user_find.out"
        rlAssertGrep "\--start <start>   Page start" "$TmpDir/ca_user_find.out"
        rlAssertGrep "\--help            Show help options" "$TmpDir/ca_user_find.out"
        rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/ca_user_find.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-configtest-002: pki ca-user-find configuration test"
        rlRun "pki ca-user-find > $TmpDir/ca_user_find_2.out 2>&1" 255 "pki ca-user-find"
        rlAssertGrep "Error: Certificate database not initialized." "$TmpDir/ca_user_find_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-003: Find 5 users, --size=5"
	rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --size=5  > $TmpDir/pki-ca-user-find-001.out 2>&1" \
                         0 \
                        "Found 5 users"
	rlAssertGrep "Number of entries returned 5" "$TmpDir/pki-ca-user-find-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-004: Find non user, --size=0"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --size=0  > $TmpDir/pki-ca-user-find-002.out 2>&1" \
                         0 \
                        "Found no users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-ca-user-find-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-005: Find all users, large value as input"
        large_num=1000000
	rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --size=$large_num  > $TmpDir/pki-ca-user-find-003.out 2>&1" \
                         0 \ 
                        "Find all users, large value as input"
	result=`cat $TmpDir/pki-ca-user-find-003.out | grep "Number of entries returned"`
        number=`echo $result | cut -d " " -f 5`
        if [ $number -gt 25 ] ; then
                rlPass "Number of entries returned is more than 25 as expected"
        else

                rlFail "Number of entries returned is not expected, Got: $number, Expected: > 25"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-006: Find all users, --size with maximum possible value as input"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 9 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --size=$maximum_check  > $TmpDir/pki-ca-user-find-003_2.out 2>&1" \
                         0 \
                        "Find all users, maximum possible value as input"
	result=`cat $TmpDir/pki-ca-user-find-003_2.out | grep "Number of entries returned"`
	number=`echo $result | cut -d " " -f 5`	
	if [ $number -gt 25 ] ; then
        	rlPass "Number of entries returned is more than 25 as expected"
	else
	
        	rlFail "Number of entries returned is not expected, Got: $number, Expected: > 25"
	fi
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-007: Find all users, --size more than maximum possible value"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 11 | head -n 1`
        rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                        -c $CERTDB_DIR_PASSWORD \
                         ca-user-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                        -c $CERTDB_DIR_PASSWORD \
                         ca-user-find --size=$maximum_check  > $TmpDir/pki-ca-user-find-003_3.out 2>&1" \
                         255 \
                        "More than maximum possible value as input"
        rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-ca-user-find-003_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-008: Find users, check for negative input --size=-1"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                        -c $CERTDB_DIR_PASSWORD \
                         ca-user-find --size=-1  > $TmpDir/pki-ca-user-find-004.out 2>&1" \
                         0 \
                        "No users returned as the size entered is negative value"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-ca-user-find-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-009: Find users for size input as noninteger, --size=abc"
        size_noninteger="abc"
	rlLog "Executing: pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                        -c $CERTDB_DIR_PASSWORD \
                         ca-user-find --size=$size_noninteger  > $TmpDir/pki-ca-user-find-005.out 2>&1"
	rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                        -c $CERTDB_DIR_PASSWORD \
                         ca-user-find --size=$size_noninteger  > $TmpDir/pki-ca-user-find-005.out 2>&1" \
                         255 \
                        "No users returned"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-ca-user-find-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-010: Find users, check for no input --size="
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                        -c $CERTDB_DIR_PASSWORD \
                         ca-user-find --size=  > $TmpDir/pki-ca-user-find-006.out 2>&1" \
                         255 \
                        "No users returned, as --size= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-ca-user-find-006.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-011: Find users, --start=10"
	#Find the 10th user
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find  > $TmpDir/pki-ca-user-find-007_1.out 2>&1" \
                         0 \
                        "Get all users in CA"
	user_entry_10=`cat $TmpDir/pki-ca-user-find-007_1.out | grep "User ID" | head -11 | tail -1`
	rlLog "10th entry=$user_entry_10"

	rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=10"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=10  > $TmpDir/pki-ca-user-find-007.out 2>&1" \
                         0 \
                        "Displays users from the 10th user and the next to the maximum 20 users, if available "
	#First user in the response should be the 10th user $user_entry_10
	user_entry_1=`cat $TmpDir/pki-ca-user-find-007.out | grep "User ID" | head -1`
	rlLog "1th entry=$user_entry_1"
	if [ "$user_entry_1" = "$user_entry_10" ]; then
		rlPass "Displays users from the 10th user"
	else
		rlFail "Display did not start from the 10th user"
	fi
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-ca-user-find-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-012: Find users, --start=10000, large possible input"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=10000  > $TmpDir/pki-ca-user-find-008.out 2>&1" \
                         0 \
                        "Find users, --start=10000, large possible input"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-ca-user-find-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-013: Find users, --start with maximum possible input"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 9 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=$maximum_check  > $TmpDir/pki-ca-user-find-008_2.out 2>&1" \
                         0 \
                        "Find users, --start with maximum possible input"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-ca-user-find-008_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-014: Find users, --start with more than maximum possible input"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 11 | head -n 1`
        rlLog "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=$maximum_check  > $TmpDir/pki-ca-user-find-008_3.out 2>&1" \
                         255 \
                        "Find users, --start with more than maximum possible input"
        rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-ca-user-find-008_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-015: Find users, --start=0"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=0  > $TmpDir/pki-ca-user-find-009.out 2>&1" \
                         0 \
                        "Displays from the zeroth user, maximum possible are 20 users in a page"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-ca-user-find-009.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-016: Find users, --start=-1"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=-1  > $TmpDir/pki-ca-user-find-0010.out 2>&1" \
                         0 \
                        "Maximum possible 20 users are returned, starting from the zeroth user"
        rlAssertGrep "Number of entries returned 19" "$TmpDir/pki-ca-user-find-0010.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-017: Find users for size input as noninteger, --start=abc"
        size_noninteger="abc"
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=$size_noninteger  > $TmpDir/pki-ca-user-find-0011.out 2>&1" \
                         255 \
                        "Incorrect input to find user"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-ca-user-find-0011.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-018: Find users, check for no input --start= "
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=  > $TmpDir/pki-ca-user-find-0012.out 2>&1" \
                         255 \
                        "No users returned, as --start= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-ca-user-find-0012.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-019: Find users, --size=12 --start=12"
        #Find 12 users starting from 12th user
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find  > $TmpDir/pki-ca-user-find-00_13_1.out 2>&1" \
                         0 \
                        "Get all users in CA"
        user_entry_12=`cat $TmpDir/pki-ca-user-find-00_13_1.out | grep "User ID" | head -13 | tail -1`

        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=12 --size=12  > $TmpDir/pki-ca-user-find-0013.out 2>&1" \
                         0 \
                        "Displays users from the 12th user and the next to the maximum 12 users"
        #First user in the response should be the 12th user $user_entry_12
        user_entry_1=`cat  $TmpDir/pki-ca-user-find-0013.out | grep "User ID" | head -1`
        if [ "$user_entry_1" = "$user_entry_12" ]; then
                rlPass "Displays users from the 12th user"
        else
                rlFail "Display did not start from the 12th user"
        fi
        rlAssertGrep "Number of entries returned 12" "$TmpDir/pki-ca-user-find-0013.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-020: Find users, --size=0 --start=12"
        #Find 12 users starting from 12th user
        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find  > $TmpDir/pki-ca-user-find-00_14_1.out 2>&1" \
                         0 \
                        "Get all users in CA"
        user_entry_12=`cat $TmpDir/pki-ca-user-find-00_14_1.out | grep "User ID" | head -13 | tail -1`

        rlRun "pki -d $CERTDB_DIR \
                        -n \"CA_adminV\" \
                                -c $CERTDB_DIR_PASSWORD \
                                ca-user-find --start=12 --size=0  > $TmpDir/pki-ca-user-find-0014.out 2>&1" \
                         0 \
                        "Displays users from the 12th user and 0 users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-ca-user-find-0014.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-021: Should not be able to find user using a revoked cert CA_adminR"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminR \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-revoke-adminR-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a revoked admin cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-revoke-adminR-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-022: Should not be able to find users using an agent with revoked cert CA_agentR"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-revoke-agentR-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a agent having revoked cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-revoke-agentR-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-023: Should not be able to find users using a valid agent CA_agentV user"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-agentV-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a agent cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-ca-user-find-agentV-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-024: Should not be able to find users using a CA_agentR user"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentR \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-agentR-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a revoked agent cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-agentR-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-025: Should not be able to find users using admin user with expired cert CA_adminE"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminE \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-adminE-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using an expired admin cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-adminE-002.out"
        rlAssertNotGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki-ca-user-find-adminE-002.out"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-026: Should not be able to find users using CA_agentE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_agentE \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-agentE-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using an expired agent cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-agentE-002.out"
        rlAssertNotGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki-ca-user-find-agentE-002.out"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

     rlPhaseStartTest "pki_ca_user_cli_ca_user_find-027: Should not be able to find users using a CA_auditV"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_auditV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-auditV-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a audit cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-ca-user-find-auditV-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-028: Should not be able to find users using a CA_operatorV"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_operatorV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-operatorV-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a operator cert"
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-ca-user-find-operatorV-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-029: Should not be able to find user using a cert created from a untrusted CA CA_adminUTCA"
        rlLog "Executing: pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    ca-user-find --start=1 --size=5"
        rlRun "pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    ca-user-find --start=1 --size=5 > $TmpDir/pki-ca-user-find-adminUTCA-002.out 2>&1" \
                    255 \
                    "Should not be able to find users using a untrusted cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-adminUTCA-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-030: Should not be able to find user using a user cert"
	#Create a user cert
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
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
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $temp_out  -t "u,u,u""
	local expfile="$TmpDir/expfile_pkiuser1.out"
        rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c Password \
                    ca-user-find --start=1 --size=5"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password ca-user-find --start=1 --size=5" > $expfile
	echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        echo "send -- \"\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-ca-user-find-pkiUser1-002.out 2>&1" 255 "Should not be able to find users using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ca-user-find-pkiUser1-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-031: find users when user id has i18n characters"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1`
        rlLog "ca-user-add userid ÖrjanÄke with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-add --fullName='Örjan Äke' 'ÖrjanÄke' > $TmpDir/pki-ca-user-find-001_31.out 2>&1" \
                    0 \
                    "Adding uid ÖrjanÄke with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --size=$maximum_check "
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --size=$maximum_check > $TmpDir/pki-user-show-ca-001_31_2.out" \
                    0 \
                    "Find user with max size"
        rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-user-show-ca-001_31_2.out"
        rlAssertGrep "Full name: Örjan Äke" "$TmpDir/pki-user-show-ca-001_31_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_find-032: find users when userid has i18n characters"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1`
        rlLog "ca-user-add userid ÉricTêko with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-add --fullName='Éric Têko' 'ÉricTêko' > $TmpDir/pki-user-show-ca-001_32.out 2>&1" \
                    0 \
                    "Adding user id ÉricTêko with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    ca-user-find --size=$maximum_check > $TmpDir/pki-user-show-ca-001_32_2.out" \
                    0 \
                    "Find user with max size"
        rlAssertGrep "User ID: ÉricTêko" "$TmpDir/pki-user-show-ca-001_32_2.out"
        rlAssertGrep "Full name: Éric Têko" "$TmpDir/pki-user-show-ca-001_32_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_user_cleanup-021: Deleting users"
        #===Deleting users created using CA_adminV cert===#
        i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           ca-user-del  u$i > $TmpDir/pki-user-del-ca-user-00$i.out" \
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
                           ca-user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done

	#===Deleting i18n users created using CA_adminV cert===#
        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                ca-user-del 'ÖrjanÄke' > $TmpDir/pki-user-del-ca-user-i18n_1.out" \
                0 \
                "Deleted user ÖrjanÄke"
        rlAssertGrep "Deleted user \"ÖrjanÄke\"" "$TmpDir/pki-user-del-ca-user-i18n_1.out"

        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                ca-user-del 'ÉricTêko' > $TmpDir/pki-user-del-ca-user-i18n_2.out" \
                0 \
                "Deleted user ÉricTêko"
        rlAssertGrep "Deleted user \"ÉricTêko\"" "$TmpDir/pki-user-del-ca-user-i18n_2.out"

	#Delete temporary directory
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
