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
. /opt/rhqa_pki/env.sh

########################################################################
# Test Suite Globals
########################################################################

user1="ocsp_agent2"
user1fullname="Test ocsp_agent"


########################################################################

run_pki-user-cli-user-find-ocsp_tests(){
    rlPhaseStartSetup "pki_user_cli_user_find-startup: Create temp directory and import OCSP agent cert into a nss certificate db and trust OCSP root cert"
        admin_cert_nickname="PKI Administrator for $OCSP_DOMAIN"
        nss_db_password="Password"
        rlLog "Admin Certificate is located at: $OCSP_ADMIN_CERT_LOOCSPTION"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlLog "Temp Directory = $TmpDir"
        rlRun "mkdir $TmpDir/nssdb"
        rlLog "importP12File $OCSP_ADMIN_CERT_LOOCSPTION $OCSP_CLIENT_PKCS12_PASSWORD $TmpDir/nssdb $nss_db_password $admin_cert_nickname"
        rlRun "importP12File $OCSP_ADMIN_CERT_LOOCSPTION $OCSP_CLIENT_PKCS12_PASSWORD $TmpDir/nssdb $nss_db_password $admin_cert_nickname" 0 "Import Admin certificate to $TmpDir/nssdb"
        rlRun "install_and_trust_OCSP_cert $OCSP_SERVER_ROOT $TmpDir/nssdb"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-OCSP-add: Add users to OCSP"
	i=1
	while [ $i -le 5 ] ; do
		rlLog "Adding user user1$i"
		rlRun "pki -d $TmpDir/nssdb \
			-n \"$admin_cert_nickname\" \
				-c $nss_db_password \
				user-add --fullName=\"fullname1$i\" user1$i > $TmpDir/pki-user-find-ocsp-a00$i.out 2>&1" \
			 0 \
			"Add user user1$i to OCSP"
		rlAssertGrep "Added user \"user1$i\"" "$TmpDir/pki-user-find-ocsp-a00$i.out"
		rlAssertGrep "User ID: user1$i" "$TmpDir/pki-user-find-ocsp-a00$i.out"
		rlAssertGrep "Full name: fullname1$i" "$TmpDir/pki-user-find-ocsp-a00$i.out"
		let i=$i+1
	done
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-001: Find 5 users, --size=5"
	rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=5  > $TmpDir/pki-user-find-ocsp-001.out 2>&1" \
                         0 \
                        "Found 5 users"
	rlAssertGrep "Number of entries returned 5" "$TmpDir/pki-user-find-ocsp-001.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_find-ocsp-002: Find non user, --size=0"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=0  > $TmpDir/pki-user-find-ocsp-002.out 2>&1" \
                         0 \
                        "Found no users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ocsp-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-003: Find all users, maximum possible value as input"
        maximum_check=1000000
	rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=$maximum_check  > $TmpDir/pki-user-find-ocsp-003.out 2>&1" \
                         0 \
                        "All users"
        rlAssertGrep "Number of entries returned " "$TmpDir/pki-user-find-ocsp-003.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-004: Find users, check for negative input --size=-1"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=-1  > $TmpDir/pki-user-find-ocsp-004.out 2>&1" \
                         0 \
                        "No  users returned as the size entered is negative value"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ocsp-004.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-005: Find users for size input as noninteger, --size=abc"
        size_noninteger="abc"
	rlLog "Executing: pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-ocsp-005.out 2>&1"
	rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=$size_noninteger  > $TmpDir/pki-user-find-ocsp-005.out 2>&1" \
                         1 \
                        "Found 5 users"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-ocsp-005.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-006: Find users, check for no input --size= "
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --size=  > $TmpDir/pki-user-find-ocsp-006.out 2>&1" \
                         1 \
                        "No users returned, as --size= "
        rlAssertGrep "NumberFormatException: For input string: \"""\"" "$TmpDir/pki-user-find-ocsp-006.out"
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_find-ocsp-007: Find users, --start=10 "
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=10  > $TmpDir/pki-user-find-ocsp-007.out 2>&1" \
                         0 \
                        "Displays users from the 10th user and the next to the maximum 20 users, if available "
        rlAssertGrep "Number of entries returned " "$TmpDir/pki-user-find-ocsp-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-008: Find users, --start=10000, maximum possible input "
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=10000  > $TmpDir/pki-user-find-ocsp-008.out 2>&1" \
                         0 \
                        "No users"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-find-ocsp-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-009: Find users, --start=0"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=0  > $TmpDir/pki-user-find-ocsp-009.out 2>&1" \
                         0 \
                        "Displays from the zeroth user, maximum possible are 20 users in a page"
        rlAssertGrep "Number of entries returned" "$TmpDir/pki-user-find-ocsp-009.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-0010: Find users, --start=-1"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=-1  > $TmpDir/pki-user-find-ocsp-0010.out 2>&1" \
                         0 \
                        "Maximum possible 20 users are returned, starting from the zeroth user"
        rlAssertGrep "Number of entries returned" "$TmpDir/pki-user-find-ocsp-0010.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_find-ocsp-0011: Find users for size input as noninteger, --start=abc"
        size_noninteger="abc"
        rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-find --start=$size_noninteger  > $TmpDir/pki-user-find-ocsp-0011.out 2>&1" \
                         1 \
                        "Incorrect input to find user"
        rlAssertGrep "NumberFormatException: For input string: \"$size_noninteger\"" "$TmpDir/pki-user-find-ocsp-0011.out"
    rlPhaseEnd

    rlPhaseStartTest "Cleanup: Delete the OCSP users"
	i=1
        while [ $i -le 5 ] ; do
                rlRun "pki -d $TmpDir/nssdb \
                        -n \"$admin_cert_nickname\" \
                                -c $nss_db_password \
                                user-del user1$i" \
                         0 \
                        "Delete user user1$i"
                let i=$i+1
        done
    rlPhaseEnd

    rlPhaseStartCleanup "pki_user_cli_user_find-cleanup: Delete temp dir"
#        rlRun "popd"
#        rlRun "rm -r $TmpDir" 0 "Removing temp directory"
    rlPhaseEnd



}
