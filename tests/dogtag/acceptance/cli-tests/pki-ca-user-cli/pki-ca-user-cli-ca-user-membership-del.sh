#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-ca-user-cli
#   Description: pki-ca-user-membership-del CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com>
#            Laxmi Sunkara <lsunkara@redhat.com
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
#pki-ca-user-cli-user-ca.sh should be first executed prior to pki-ca-user-cli-ca-user-membership-add.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################
run_pki-ca-user-cli-ca-user-membership-del_tests(){
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

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-001: Create temporary directory"
                rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
                rlRun "pushd $TmpDir"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-002: pki ca-user-membership-del --help configuration test"
                rlRun "pki ca-user-membership-del --help > $TmpDir/pki_user_membership_del_cfg.out 2>&1" \
                        0 \
                       "pki ca-user-membership-del --help"
                rlAssertGrep "usage: ca-user-membership-del <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_del_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_del_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-003: pki ca-user-membership-del configuration test"
                rlRun "pki ca-user-membership-del > $TmpDir/pki_user_membership_del_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-del"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_user_membership_del_2_cfg.out"
                rlAssertGrep "usage: ca-user-membership-del <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_del_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_del_2_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-004: Delete user-membership when user is added to different groups"
                i=1
                while [ $i -lt 15 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-ca-user-membership-add-ca-user-add-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    user-show u$i > $TmpDir/pki-ca-user-membership-add-user-show-ca-00$i.out" \
                                    0 \
                                    "Show pki CA_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-ca-user-membership-add-user-show-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-ca-user-membership-add-user-show-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-ca-user-membership-add-user-show-ca-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-membership-add u$i \"$gid\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   user-membership-find u$i > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-00$i.out" \
                                   0 \
                                   "Check user is in group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-00$i.out"
			rlLog "Delete the user from the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-del u$i \"$gid\"  > $TmpDir/pki-ca-user-membership-del-groupdel-del-ca-00$i.out" \
                                    0 \
                                    "User deleted from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-ca-user-membership-del-groupdel-del-ca-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-005: Delete user-membership when user is added to many groups"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-ca-user-membership-add-ca-user-add-ca-userall-001.out" \
                            0 \
                            "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-userall-001.out"
                rlLog "Adding the user to all the groups"
                i=1
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-add userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-add userall \"$gid\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-userall-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    user-membership-find userall > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-userall-00$i.out" \
                                    0 \
                                    "Check user membership with group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-userall-00$i.out"
                        let i=$i+1
                done
		rlLog "Delete user from all the groups"
                i=1
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-del userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-del userall \"$gid\" > $TmpDir/pki-ca-user-membership-del-groupadd-ca-userall-00$i.out" \
                                    0 \
                                    "Delete userall from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-userall-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-006: Missing required option <Group id> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out" \
                                   0 \
                                   "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-membership-add user1 \"Administrators\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-user1-001.out" \
                                   0 \
                                   "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-membership-del user1 > $TmpDir/pki-ca-user-membership-del-groupadd-ca-user1-001.out 2>&1" \
                                   255 \
                                   "Cannot delete user from group, Missing required option <Group id>"
                rlAssertGrep "usage: ca-user-membership-del <User ID> <Group ID>" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-user1-001.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-007: Missing required option <User ID> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-add --fullName=\"fullName_user2\" user2 > $TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out" \
                                   0 \
                                   "Adding user user2"
                rlAssertGrep "Added user \"user2\"" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user2" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user2" "$TmpDir/pki-ca-user-membership-add-ca-user-add-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-membership-add user2 \"Administrators\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-user1-001.out" \
                                   0 \
                                   "Adding user user2 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-membership-del \"\" \"Administrators\" > $TmpDir/pki-ca-user-membership-del-groupadd-ca-user1-001.out 2>&1" \
                                   255 \
                                   "cannot delete user from group, Missing required option <user id>"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-user1-001.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-008: Should not be able to ca-user-membership-del using a revoked cert CA_adminR"
                command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
                rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a revoked cert CA_adminR"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-009:  Should not be able to ca-user-membership-del using an agent with revoked cert CA_agentR"
		command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a revoked cert CA_agentR"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-010: Should not be able to ca-user-membership-del using a valid agent CA_agentV user"
		command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a valid agent cert CA_agentV"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-011: Should not be able to ca-user-membership-del using admin user with expired cert CA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-del using admin user with expired cert CA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-012: Should not be able to ca-user-membership-del using CA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-del using CA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-013: Should not be able to ca-user-membership-del using CA_auditV cert"
                command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-del using CA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-014: Should not be able to ca-user-membership-del using CA_operatorV cert"
		command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-del using CA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-015: Should not be able to ca-user-membership-del using CA_adminUTCA cert"
                command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-del using CA_adminUTCA cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-016: Should not be able to ca-user-membership-del using CA_agentUTCA cert"
                command="pki -d /tmp/untrusted_cert_db -n CA_agentUTCA -c Password ca-user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-del using CA_agentUTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-017: Delete user-membership for user id with i18n characters"
                rlLog "ca-user-add userid ÉricTêko with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName='Éric Têko' 'ÉricTêko'"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName='Éric Têko' 'ÉricTêko'" \
                            0 \
                            "Adding uid ÉricTêko with i18n characters"
                rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-ca-user-membership-add-groupadd-ca-017_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-017_1.out"
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-017_1.out"
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-017_1.out"
                rlLog "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add 'ÉricTêko' \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add 'ÉricTêko' \"dadministʁasjɔ̃\" > $TmpDir/pki-ca-user-membership-del-groupadd-ca-017_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-017_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-017_2.out"
		rlLog "Delete user-membership from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-del 'ÉricTêko' 'dadministʁasjɔ̃' > $TmpDir/pki-ca-user-ca-membership-del-017_3.out" \
                            0 \
                            "Delete user-membership from group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted membership in group \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-ca-membership-del-017_3.out"
		rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-membership-find 'ÉricTêko' > $TmpDir/pki-ca-user-membership-find-groupadd-find-ca-017_4.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-ca-user-membership-find-groupadd-find-ca-017_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-018: Delete user-membership for user id with i18n characters"
                rlLog "ca-user-add userid ÖrjanÄke with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=test 'ÖrjanÄke' > $TmpDir/pki-ca-user-add-ca-018.out 2>&1" \
                            0 \
                            "Adding uid ÖrjanÄke with i18n characters"
                rlAssertGrep "Added user \"ÖrjanÄke\"" "$TmpDir/pki-ca-user-add-ca-018.out"
                rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-ca-user-add-ca-018.out"
                rlLog "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add 'ÖrjanÄke' \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add 'ÖrjanÄke' \"dadministʁasjɔ̃\" > $TmpDir/pki-ca-user-membership-del-groupadd-ca-018_2.out" \
                            0 \
                            "Adding user ÖrjanÄke to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-018_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-ca-user-membership-del-groupadd-ca-018_2.out"
		rlLog "Delete user from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-del 'ÖrjanÄke' \"dadministʁasjɔ̃\" > $TmpDir/pki-ca-user-membership-del-groupadd-del-ca-018_3.out" \
                            0 \
                            "Delete user-membership from the group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted membership in group \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-membership-del-groupadd-del-ca-018_3.out"
                rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-membership-find 'ÖrjanÄke' > $TmpDir/pki-ca-user-membership-del-groupadd-del-ca-018_4.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-ca-user-membership-del-groupadd-del-ca-018_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-019: Delete user-membership when uid is not associated with a group"
		rlLog "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullNameuser123\" user123 "
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullNameuser123\" user123 > $TmpDir/pki-ca-user-membership-del-user-del-ca-019.out" \
                            0 \
                            "Adding user user123"
                rlAssertGrep "Added user \"user123\"" "$TmpDir/pki-ca-user-membership-del-user-del-ca-019.out"
                rlAssertGrep "User ID: user123" "$TmpDir/pki-ca-user-membership-del-user-del-ca-019.out"
                rlAssertGrep "Full name: fullNameuser123" "$TmpDir/pki-ca-user-membership-del-user-del-ca-019.out"
                command="pki -d $CERTDB_DIR  -n CA_adminV -c $CERTDB_DIR_PASSWORD ca-user-membership-del user123 \"Administrators\""
                rlLog "Executing $command"
		errmsg="ResourceNotFoundException: No such attribute."
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Delete user-membership when uid is not associated with a group"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-020: Deleting a user that has membership with groups removes the user from the groups"
		rlLog "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullNameu20\" u20 "
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullNameu20\" u20 > $TmpDir/pki-ca-user-membership-del-user-del-ca-020.out" \
                            0 \
                            "Adding user u20"
                rlAssertGrep "Added user \"u20\"" "$TmpDir/pki-ca-user-membership-del-user-del-ca-020.out"
                rlAssertGrep "User ID: u20" "$TmpDir/pki-ca-user-membership-del-user-del-ca-020.out"
                rlAssertGrep "Full name: fullNameu20" "$TmpDir/pki-ca-user-membership-del-user-del-ca-020.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add u20 \"Administrators\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-20_2.out" \
                            0 \
                            "Adding user u20 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-20_2.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add u20 \"Certificate Manager Agents\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-20_3.out" \
                            0 \
                            "Adding user u20 to group \"Certificate Manager Agents\""
                rlAssertGrep "Added membership in \"Certificate Manager Agents\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-20_3.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            group-member-find  Administrators > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_4.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertGrep "User: u20" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_4.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            group-member-find \"Certificate Manager Agents\" > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_5.out" \
                            0 \
                            "List members of Certificate Manager Agents group"
                rlAssertGrep "User: u20" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_5.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-del  u20 > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_6.out" \
                            0 \
                            "Delete user u20"
                rlAssertGrep "Deleted user \"u20\"" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_6.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            group-member-find  Administrators > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_7.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertNotGrep "User: u20" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_7.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            group-member-find \"Certificate Manager Agents\" > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_8.out" \
                            0 \
                            "List members of Certificate Manager Agents group"
                rlAssertNotGrep "User: u20" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-20_8.out"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-021: User deleted from  Administrators group can't create a new user"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-ca-user-membership-del-ca-user-add-ca-0021.out" \
                            0 \
                            "Adding user testuser1"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add testuser1 \"Administrators\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-21_2.out" \
                            0 \
                            "Adding user testuser1 to group \"Administrators\""
        	rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-21_2.out"

		#Create a user cert
                local TEMP_NSS_DB="$TmpDir/nssdb"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
                local temp_out="$TmpDir/usercert-show.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User1\" \"testuser1\" \
                        \"testuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
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
                rlRun "certutil -d $TEMP_NSS_DB -A -n testuser1 -i $temp_out  -t \"u,u,u\""

                #Add certificate to the user
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_021_3.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n \"CA_adminV\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add testuser1 --input $TmpDir/validcert_021_3.pem  > $TmpDir/useraddcert_021_3.out" \
                            0 \
                            "Cert is added to the user testuser1"

		#Add a new user using testuser1
		local expfile="$TmpDir/expfile_testuser1.out"
                echo "spawn -noecho pki -d $TEMP_NSS_DB -n testuser1 -c Password ca-user-add --fullName=test_user u15" > $expfile
                echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
                echo "send -- \"Y\r\"" >> $expfile
                echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
                echo "send -- \"\r\"" >> $expfile
                echo "expect eof" >> $expfile
                echo "catch wait result" >> $expfile
                echo "exit [lindex \$result 3]" >> $expfile
                rlRun "/usr/bin/expect -f $expfile 2>&1 >  $TmpDir/pki-ca-user-add-ca-021_4.out" 0 "Should be able to add users using Administrator user testuser1"
                rlAssertGrep "Added user \"u15\"" "$TmpDir/pki-ca-user-add-ca-021_4.out"
                rlAssertGrep "User ID: u15" "$TmpDir/pki-ca-user-add-ca-021_4.out"
                rlAssertGrep "Full name: test_user" "$TmpDir/pki-ca-user-add-ca-021_4.out"

		#Delete testuser1 from the Administrators group
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-del testuser1 \"Administrators\"  > $TmpDir/pki-ca-user-membership-del-groupdel-del-ca-021_5.out" \
                            0 \
                            "User deleted from group \"Administrators\""
                rlAssertGrep "Deleted membership in group \"Administrators\"" "$TmpDir/pki-ca-user-membership-del-groupdel-del-ca-021_5.out"

		#Trying to add a user using testuser1 should fail since testuser1 is not in Administrators group
		command="pki -d $TEMP_NSS_DB  -n testuser1 -c Password ca-user-add --fullName=test_user u212"
		rlLog "Executing $command"
		errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add users using non Administrator"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-del-022: User deleted from the Certificate Manager Agents group can not approve certificate requests"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add testuser1 \"Certificate Manager Agents\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-22.out" \
                            0 \
                            "Adding user testuser1 to group \"Certificate Manager Agents\""
                rlAssertGrep "Added membership in \"Certificate Manager Agents\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-22.out"

		#Trying to approve a certificate request using testuser1 should succeed
		local TEMP_NSS_DB="$TmpDir/nssdb"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
                local temp_out="$TmpDir/usercert-show_22.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User3\" \"testuser3\" \
                        \"testuser3@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
		rlLog "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out-22_1.out" 0 "Approve Certificate request using testuser1"
                rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out-22_1.out"
                rlLog "pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki cert-request-show $ret_requestid > $TmpDir/usercert-show1_22_2.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1_22_2.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"

		#Delete testuser1 from Certificate Manager Agents group
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-del testuser1 \"Certificate Manager Agents\"  > $TmpDir/pki-ca-user-membership-del-groupdel-del-ca-022_3.out" \
                            0 \
                            "User deleted from group \"Certificate Manager Agents\""
                rlAssertGrep "Deleted membership in group \"Certificate Manager Agents\"" "$TmpDir/pki-ca-user-membership-del-groupdel-del-ca-022_3.out"

		#Trying to approve a certificate request using testuser1 should fail
		local temp_out="$TmpDir/usercert-show_22_4.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User4\" \"testuser4\" \
                        \"testuser4@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve"
                command="pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid --action approve"
                rlLog "Executing: $command"
                errmsg="Authorization failed on resource: certServer.ca.certrequests, operation: execute"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Approve Certificate request using testuser1"	
	rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_ca-membership-del-cleanup-001: Deleting the temp directory and users"

		#===Deleting users created using CA_adminV cert===#
		i=1
		while [ $i -lt 16 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n CA_adminV \
				  -c $CERTDB_DIR_PASSWORD \
				   ca-user-del  u$i > $TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-00$i.out" \
				   0 \
				   "Deleted user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-00$i.out"
			let i=$i+1
		done
		rlRun "pki -d $CERTDB_DIR \
		       	   -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
			    ca-user-del  userall > $TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
			    0 \
			   "Deleted user userall"
	        rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-del  user1 > $TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
                            0 \
                            "Deleted user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-del  user2 > $TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
                            0 \
                            "Deleted user user2"
                rlAssertGrep "Deleted user \"user2\"" "$TmpDir/pki-ca-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-del  user123 > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-user123.out" \
                            0 \
                            "Deleted user user123"
                rlAssertGrep "Deleted user \"user123\"" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-user123.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-del testuser1 > $TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-testuser1.out" \
                            0 \
                            "Deleted user testuser1"
                rlAssertGrep "Deleted user \"testuser1\"" "$TmpDir/pki-ca-user-del-ca-user-membership-find-user-del-ca-testuser1.out"
                #===Deleting i18n users created using CA_adminV cert===#
                rlRun "pki -d $CERTDB_DIR \
                        -n CA_adminV \
                        -c $CERTDB_DIR_PASSWORD \
                        ca-user-del 'ÖrjanÄke' > $TmpDir/pki-ca-user-del-ca-user-i18n_1.out" \
                        0 \
                        "Deleting user ÖrjanÄke"
                rlAssertGrep "Deleted user \"ÖrjanÄke\"" "$TmpDir/pki-ca-user-del-ca-user-i18n_1.out"

                rlRun "pki -d $CERTDB_DIR \
                        -n CA_adminV \
                        -c $CERTDB_DIR_PASSWORD \
                        ca-user-del 'ÉricTêko' > $TmpDir/pki-ca-user-del-ca-user-i18n_2.out" \
                        0 \
                        "Deleting user ÉricTêko"
                rlAssertGrep "Deleted user \"ÉricTêko\"" "$TmpDir/pki-ca-user-del-ca-user-i18n_2.out"

                #===Deleting i18n group created using CA_adminV cert===#
                rlRun "pki -d $CERTDB_DIR \
                        -n CA_adminV \
                        -c $CERTDB_DIR_PASSWORD \
                        group-del 'dadministʁasjɔ̃' > $TmpDir/pki-ca-user-del-ca-group-i18n_1.out" \
                        0 \
                        "Deleting group dadministʁasjɔ̃"
                rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-del-ca-group-i18n_1.out"
		
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
