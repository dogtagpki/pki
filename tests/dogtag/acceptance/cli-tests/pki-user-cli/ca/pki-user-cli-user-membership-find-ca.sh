#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cli-user-membership-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-membership-find    Find user memberships.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Laxmi Sunkara <lsunkara@redhat.com
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-membership-find-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

#Available groups ca-group-find
groupid1="Certificate Manager Agents"
groupid2="Registration Manager Agents"
groupid3="Subsystem Group"
groupid4="Trusted Managers"
groupid5="Administrators"
groupid6="Auditors"
groupid7="ClonedSubsystems"
groupid8="Security Domain Administrators"
groupid9="Enterprise CA Administrators"
groupid10="Enterprise KRA Administrators"
groupid11="Enterprise OCSP Administrators"
groupid12="Enterprise TKS Administrators"
groupid13="Enterprise RA Administrators"
groupid14="Enterprise TPS Administrators"
run_pki-user-cli-user-membership-find-ca_tests(){
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-001: Add a users to CA using CA_adminV and to a group to test user-membership-find functionality"
                i=1
                while [ $i -lt 15 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-user-membership-find-user-find-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-user-membership-find-user-find-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-find-user-find-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-find-user-find-ca-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    user-show u$i > $TmpDir/pki-user-membership-find-user-show-ca-00$i.out" \
                                    0 \
                                    "Show pki CA_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-user-membership-find-user-show-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-find-user-show-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-find-user-show-ca-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add u$i \"$gid\" > $TmpDir/pki-user-membership-find-groupadd-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-find-groupadd-ca-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-ca-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find u$i > $TmpDir/pki-user-membership-find-groupadd-find-ca-00$i.out" \
                                   0 \
                                   "User added to group \"$gid\""
			rlAssertGrep "1 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-00$i.out"
			rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-00$i.out"
                        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki-user-membership-find-groupadd-find-ca-00$i.out"

                        let i=$i+1
                done
        rlPhaseEnd
	rlPhaseStartTest "pki_user_cli_user_membership-find-CA-002: Add a user to all the groups"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-user-membership-find-user-find-ca-userall-001.out" \
                                   0 \
                                   "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-user-membership-find-user-find-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-find-user-find-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-find-user-find-ca-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-show userall > $TmpDir/pki-user-membership-find-user-show-ca-userall-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-user-membership-find-user-show-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-find-user-show-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-find-user-show-ca-userall-001.out"
                rlLog "Adding the user to all the groups"
                i=1
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add userall \"$gid\" > $TmpDir/pki-user-membership-find-groupadd-ca-userall-00$i.out" \
                                   0 \
                                   "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-find-groupadd-ca-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-ca-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall > $TmpDir/pki-user-membership-find-groupadd-find-ca-userall-00$i.out" \
                                   0 \
                                   "User added to group \"$gid\""
			rlAssertGrep "$i entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-userall-00$i.out"
			rlAssertGrep "Number of entries returned $i" "$TmpDir/pki-user-membership-find-groupadd-find-ca-userall-00$i.out"

                        let i=$i+1
                done



        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-003: option --start=5"
			rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --start=5 > $TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out" \
                                   0 \
                                   "Checking user added to group"
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
                        rlAssertGrep "Group: $groupid6" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid7" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid8" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid9" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid10" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid11" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid12" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid13" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
			rlAssertGrep "Group: $groupid14" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"
                        rlAssertGrep "Number of entries returned 9" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-001.out"

	rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-004: option --start=0"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --start=0 > $TmpDir/pki-user-membership-find-groupadd-find-ca-start-002.out" \
                                   0 \
                                   "Checking user added to group "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-002.out"
			while [ $i -lt 15 ] ; do
	                        eval gid=\$groupid$i
		                rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-002.out"
				let i=$i+1
			done
                        rlAssertGrep "Number of entries returned 14" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-002.out"

        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-005: option --start=-1"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --start=-1 > $TmpDir/pki-user-membership-find-groupadd-find-ca-start-003.out" \
                                   0 \
                                   "Checking User added to group "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-003.out"
                        while [ $i -lt 15 ] ; do
                                eval gid=\$groupid$i
                                rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-003.out"
                                let i=$i+1
                        done
                        rlAssertGrep "Number of entries returned 14" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-003.out"
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-006: option --start=15, greater than available number of groups"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --start=15 > $TmpDir/pki-user-membership-find-groupadd-find-ca-start-004.out" \
                                   0 \
                                   "Checking User added to group "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-004.out"
                        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-004.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-007: option --start=a, integer format required"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --start=a > $TmpDir/pki-user-membership-find-groupadd-find-ca-start-005.out 2>&1" 1 \
                                   "String cannot be used as input to start parameter"
                        rlAssertGrep "NumberFormatException: For input string: \"a\"" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-005.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-008: option --size=0 "
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=0 > $TmpDir/pki-user-membership-find-groupadd-find-ca-size-006.out" 0 \
                                   "user_membership-find with size parameter as 0 "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-006.out"
			rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-006.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-009: option --size=1 "
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=1 > $TmpDir/pki-user-membership-find-groupadd-find-ca-size-007.out" 0 \
                                   "user_membership-find with size parameter as 1 "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-007.out"
                        rlAssertGrep "Group: Certificate Manager Agents" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-007.out"
                        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-007.out"

        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-0010: option --size=2 "
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=2 > $TmpDir/pki-user-membership-find-groupadd-find-ca-size-008.out" 0 \
                                   "user_membership-find with size parameter as 2 "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-008.out"
                        rlAssertGrep "Group: Certificate Manager Agents" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-008.out"
			rlAssertGrep "Group: Registration Manager Agents" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-008.out"
                        rlAssertGrep "Number of entries returned 2" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-008.out"
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-0011: option --size=15 "
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=15 > $TmpDir/pki-user-membership-find-groupadd-find-ca-size-009.out" 0 \
                                   "user_membership-find with size parameter as 15 "
			rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-009.out"
                        while [ $i -lt 15 ] ; do
                                eval gid=\$groupid$i
                                rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-009.out"
                                let i=$i+1
                        done
                        rlAssertGrep "Number of entries returned 14" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-009.out"
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-0012: option --size=100 "
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=100 > $TmpDir/pki-user-membership-find-groupadd-find-ca-size-0010.out"  0 \
                                   "user_membership-find with size parameter as 100 "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-0010.out"
                        while [ $i -lt 15 ] ; do
                                eval gid=\$groupid$i
                                rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-0010.out"
                                let i=$i+1
                        done
                        rlAssertGrep "Number of entries returned 14" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-0010.out"
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-0013: option --size=-1"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=-1 > $TmpDir/pki-user-membership-find-groupadd-find-ca-size-0011.out"  0 \
                                   "user_membership-find with size parameter as -1 "
                        rlAssertGrep "14 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-0011.out"
                        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-membership-find-groupadd-find-ca-size-0011.out"
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-find-CA-0015: option --size=a, integer format required"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall --size=a > $TmpDir/pki-user-membership-find-groupadd-find-ca-start-0012.out 2>&1" 1  \
                                   "String cannot be used as input to start parameter "
                        rlAssertGrep "NumberFormatException: For input string: \"a\"" "$TmpDir/pki-user-membership-find-groupadd-find-ca-start-0012.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-ca-cleanup-001: Deleting the temp directory and users"

                #===Deleting users created using CA_adminV cert===#
                i=1
                while [ $i -lt 15 ] ; do
                       rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-del  u$i > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-00$i.out" \
                                   0 \
                                   "Deleted user  u$i"
                        rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-00$i.out"
                        let i=$i+1
                done
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  userall > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-userall.out" \
                           0 \
                           "Deleted user  userall"
               rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-userall.out"

	rlPhaseEnd
}
