#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-membership-del CLI tests
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-membership-add-ca.sh
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
run_pki-user-cli-user-membership-del-ca_tests(){
        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-001: Add a users to CA using CA_adminV and to a group to test user-membership-del functionality"
                i=1
                while [ $i -lt 15 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-user-membership-add-user-add-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-user-membership-add-user-add-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-add-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-add-ca-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    user-show u$i > $TmpDir/pki-user-membership-add-user-show-ca-00$i.out" \
                                    0 \
                                    "Show pki CA_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-user-membership-add-user-show-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-show-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-show-ca-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add u$i \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-ca-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-ca-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find u$i > $TmpDir/pki-user-membership-add-groupadd-find-ca-00$i.out" \
                                   0 \
                                   "User added to group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-ca-00$i.out"
			rlLog "Delete the user from the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-del u$i \"$gid\"  > $TmpDir/pki-user-membership-del-groupdel-del-ca-00$i.out" \
                                   0 \
                                   "User deleted from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-user-membership-del-groupdel-del-ca-00$i.out"


                        let i=$i+1
                done
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-002: Add a user to all the groups"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-user-membership-add-user-add-ca-userall-001.out" \
                                   0 \
                                   "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-user-membership-add-user-add-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-add-user-add-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-add-user-add-ca-userall-001.out"
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
                                   user-membership-add userall \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-ca-userall-00$i.out" \
                                   0 \
                                   "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-ca-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-ca-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find userall > $TmpDir/pki-user-membership-add-groupadd-find-ca-userall-00$i.out" \
                                   0 \
                                   "User added to group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-ca-userall-00$i.out"
                        let i=$i+1
                done
		rlLog "Delete user from all the groups"
                i=1
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-del userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-del userall \"$gid\" > $TmpDir/pki-user-membership-del-groupadd-ca-userall-00$i.out" \
                                   0 \
                                   "Deleted userall from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-user-membership-del-groupadd-ca-userall-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-003: Missing required option <Group id> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-user-membership-add-user-add-ca-user1-001.out" \
                                   0 \
                                   "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add user1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out" \
                                   0 \
                                   "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-del user1 > $TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out 2>&1" \
                                   1 \
                                   "cannot delete user from group, Missing required option <Group id> "
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID>" "$TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out"

        rlPhaseEnd
        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-003: Missing required option <User ID> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-add --fullName=\"fullName_user2\" user2 > $TmpDir/pki-user-membership-add-user-add-ca-user1-001.out" \
                                   0 \
                                   "Adding user user2"
                rlAssertGrep "Added user \"user2\"" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user2" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user2" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-add user2 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out" \
                                   0 \
                                   "Adding user user2 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-del \"Administrators\" > $TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out 2>&1" \
                                   1 \
                                   "cannot delete user from group, Missing required option <user id> "
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID>" "$TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out"

        rlPhaseEnd


        rlPhaseStartTest "pki_user_cli_user_membership-del-ca-cleanup-001: Deleting the temp directory and users"

		#===Deleting users created using CA_adminV cert===#
		i=1
		while [ $i -lt 15 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n CA_adminV \
				  -c $CERTDB_DIR_PASSWORD \
				   user-del  u$i > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-00$i.out" \
				   0 \
				   "Deleted user  u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-00$i.out"
			let i=$i+1
		done
		      rlRun "pki -d $CERTDB_DIR \
				 -n CA_adminV \
				 -c $CERTDB_DIR_PASSWORD \
				  user-del  userall > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
				  0 \
				  "Deleted user  userall"
		       rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
                       rlRun "pki -d $CERTDB_DIR \
                                 -n CA_adminV \
                                 -c $CERTDB_DIR_PASSWORD \
                                  user-del  user1 > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
                                  0 \
                                  "Deleted user  user1"
                       rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
                       rlRun "pki -d $CERTDB_DIR \
                                 -n CA_adminV \
                                 -c $CERTDB_DIR_PASSWORD \
                                  user-del  user2 > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
                                  0 \
                                  "Deleted user  user2"
                       rlAssertGrep "Deleted user \"user2\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out"

        rlPhaseEnd
}
