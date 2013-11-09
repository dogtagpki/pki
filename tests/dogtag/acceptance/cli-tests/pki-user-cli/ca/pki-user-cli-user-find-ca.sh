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
. /opt/rhqa_pki/env.sh

########################################################################
# Test Suite Globals
########################################################################

user1="ca_agent2"
user1fullname="Test ca_agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0


########################################################################

run_pki-user-cli-user-find-ca_tests(){
    rlPhaseStartSetup "pki_user_cli_user_find-ca-startup:Getting the temp directory and nss certificate db "
         rlLog "nss_db directory = $TmpDir/nssdb"
         rlLog "temp directory = /tmp/requestdb"
    rlPhaseEnd
    rlPhaseStartSetup "pki_user_cli_user_find-ca-startup-addusers:Add users to test the user-find functionality"
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d /tmp/requestdb \
                          -n CA_adminV \
                          -c $nss_db_password \
                           user-add --fullName=test_user u$i"
                let i=$i+1
        done
        j=1
        while [ $j -lt 8 ] ; do
               eval usr=\$user$j
               rlRun "pki -d /tmp/requestdb \
                          -n CA_adminV \
                          -c $nss_db_password \
                           user-add  --fullName=test_user $usr"
                let j=$j+1
        done


    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_find-ca-001: Find 5 users, --size=5"
	rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=5  > $TmpDir/pki-user-find-ca-001.out 2>&1" \
                         0 \
                        "Found 5 users"
	rlAssertGrep "Number of entries returned 5" "$TmpDir/pki-user-find-ca-001.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_find-ca-002: Find non user, --size=0"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=0  > $TmpDir/pki-user-find-ca-002.out 2>&1" \
                         0 \
                        "Found no users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-003: Find all users, maximum possible value as input"
        maximum_check=1000000
	rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=$maximum_check  > $TmpDir/pki-user-find-ca-003.out 2>&1" \
                         0 \
                        "All users"
        rlAssertGrep "Number of entries returned 47" "$TmpDir/pki-user-find-ca-003.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-004: Find users, check for negative input --size=-1"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=-1  > $TmpDir/pki-user-find-ca-004.out 2>&1" \
                         0 \
                        "No  users returned as the size entered is negative value"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-005: Find users for size input as noninteger, --size=abc"
        size_noninteger="abc"
	rlLog "Executing: pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-ca-005.out 2>&1"
	rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-ca-005.out 2>&1" \
                         1 \
                        "No users returned"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-ca-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-006: Find users, check for no input --size= "
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=  > $TmpDir/pki-user-find-ca-006.out 2>&1" \
                         1 \
                        "No users returned, as --size= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-user-find-ca-006.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_find-ca-007: Find users, --start=10 "
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=10  > $TmpDir/pki-user-find-ca-007.out 2>&1" \
                         0 \
                        "Displays users from the 10th user and the next to the maximum 20 users, if available "
        rlAssertGrep "20 user(s) matched" "$TmpDir/pki-user-find-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-008: Find users, --start=10000, maximum possible input "
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=10000  > $TmpDir/pki-user-find-ca-008.out 2>&1" \
                         0 \
                        "No users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ca-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-009: Find users, --start=0"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=0  > $TmpDir/pki-user-find-ca-009.out 2>&1" \
                         0 \
                        "Displays from the zeroth user, maximum possible are 20 users in a page"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-user-find-ca-009.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-0010: Find users, --start=-1"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=-1  > $TmpDir/pki-user-find-ca-0010.out 2>&1" \
                         0 \
                        "Maximum possible 20 users are returned, starting from the zeroth user"
        rlAssertGrep "19 user(s) matched" "$TmpDir/pki-user-find-ca-0010.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ca-0011: Find users for size input as noninteger, --start=abc"
        size_noninteger="abc"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=$size_noninteger  > $TmpDir/pki-user-find-ca-0011.out 2>&1" \
                         1 \
                        "Incorrect input to find user"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-ca-0011.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_cleanup-001_36: Deleting the temp directory and users"
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
