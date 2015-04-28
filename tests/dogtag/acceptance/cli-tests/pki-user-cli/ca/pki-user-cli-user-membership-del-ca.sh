#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-membership-del CLI tests
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
#create_role_users.sh should be first executed prior to pki-user-cli-user-membership-add-ca.sh
######################################################################################

run_pki-user-cli-user-membership-del-ca_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	prefix=$subsystemId
	ca_instance_created="False"

	if [ "$TOPO9" = "TRUE" ] ; then
        	prefix=$subsystemId
		ca_instance_created=$(eval echo \$${subsystemId}_INSTANCE_CREATED_STATUS)
	elif [ "$MYROLE" = "MASTER" ] ; then
 	       if [[ $subsystemId == SUBCA* ]]; then
                	prefix=$subsystemId
			ca_instance_created=$(eval echo \$${subsystemId}_INSTANCE_CREATED_STATUS)
        	else
	                prefix=ROOTCA
			ca_instance_created=$ROOTCA_INSTANCE_CREATED_STATUS
	        fi
	else
	        prefix=$MYROLE
		ca_instance_created=$(eval echo \$${MYROLE}_INSTANCE_CREATED_STATUS)
	fi

  if [ "$ca_instance_created" = "TRUE" ] ;  then
	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	untrusted_cert_nickname=role_user_UTCA

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

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-001: Create temporary directory"
                rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
                rlRun "pushd $TmpDir"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-002: pki user-membership-del --help configuration test"
                rlRun "pki user-membership-del --help > $TmpDir/pki_user_membership_del_cfg.out 2>&1" \
                        0 \
                       "pki user-membership-del --help"
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_del_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_del_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-003: pki user-membership-del configuration test"
                rlRun "pki user-membership-del > $TmpDir/pki_user_membership_del_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-del"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_user_membership_del_2_cfg.out"
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_del_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_del_2_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-004: Delete user-membership when user is added to different groups"
                i=1
                while [ $i -lt 15 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-user-membership-add-user-add-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-user-membership-add-user-add-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-add-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-add-ca-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-show u$i > $TmpDir/pki-user-membership-add-user-show-ca-00$i.out" \
                                    0 \
                                    "Show pki CA_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-user-membership-add-user-show-ca-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-show-ca-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-show-ca-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-add u$i \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-ca-00$i.out" \
                                   0 \
                                   "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-ca-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-ca-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-find u$i > $TmpDir/pki-user-membership-add-groupadd-find-ca-00$i.out" \
                                   0 \
                                   "Check user is in group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-ca-00$i.out"
			rlLog "Delete the user from the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-del u$i \"$gid\"  > $TmpDir/pki-user-membership-del-groupdel-del-ca-00$i.out" \
                                    0 \
                                    "User deleted from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-user-membership-del-groupdel-del-ca-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-005: Delete user-membership when user is added to many groups"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
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
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-add userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-add userall \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-ca-userall-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-ca-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-ca-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-find userall > $TmpDir/pki-user-membership-add-groupadd-find-ca-userall-00$i.out" \
                                    0 \
                                    "Check user membership with group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-ca-userall-00$i.out"
                        let i=$i+1
                done
		rlLog "Delete user from all the groups"
                i=1
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-del userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-del userall \"$gid\" > $TmpDir/pki-user-membership-del-groupadd-ca-userall-00$i.out" \
                                    0 \
                                    "Delete userall from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-user-membership-del-groupadd-ca-userall-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-006: Missing required option <Group id> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-user-membership-add-user-add-ca-user1-001.out" \
                                   0 \
                                   "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-add user1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out" \
                                   0 \
                                   "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-del user1 > $TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out 2>&1" \
                                   255 \
                                   "Cannot delete user from group, Missing required option <Group id>"
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID>" "$TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-CA-007: Missing required option <User ID> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-add --fullName=\"fullName_user2\" user2 > $TmpDir/pki-user-membership-add-user-add-ca-user1-001.out" \
                                   0 \
                                   "Adding user user2"
                rlAssertGrep "Added user \"user2\"" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user2" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user2" "$TmpDir/pki-user-membership-add-user-add-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-add user2 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out" \
                                   0 \
                                   "Adding user user2 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   user-membership-del \"\" \"Administrators\" > $TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out 2>&1" \
                                   255 \
                                   "cannot delete user from group, Missing required option <user id>"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki-user-membership-del-groupadd-ca-user1-001.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-008: Should not be able to user-membership-del using a revoked cert CA_adminR"
                command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-membership-del user2 \"Administrators\""
                rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a revoked cert CA_adminR"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-009:  Should not be able to user-membership-del using an agent with revoked cert CA_agentR"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a revoked cert CA_agentR"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-010: Should not be able to user-membership-del using a valid agent CA_agentV user"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a valid agent cert CA_agentV"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-011: Should not be able to user-membership-del using admin user with expired cert CA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_adminE -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -c $CERTDB_DIR_PASSWORD user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using admin user with expired cert CA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-012: Should not be able to user-membership-del using CA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using CA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-013: Should not be able to user-membership-del using CA_auditV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using CA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-014: Should not be able to user-membership-del using CA_operatorV cert"
		command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using CA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-015: Should not be able to user-membership-del using CA_adminUTCA cert"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n $untrusted_cert_nickname -c $UNTRUSTED_CERT_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using role_user_UTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-016: Delete user-membership for user fullname with i18n characters"
                rlLog "user-add user fullname Éric Têko with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName='Éric Têko' u16"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName='Éric Têko' u16" \
                            0 \
                            "Adding user fullname  ÉricTêko with i18n characters"
                rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-user-membership-add-groupadd-ca-017_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-ca-017_1.out"
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-ca-017_1.out"
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-user-membership-add-groupadd-ca-017_1.out"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u16 \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u16 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-del-groupadd-ca-017_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-groupadd-ca-017_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-del-groupadd-ca-017_2.out"
		rlLog "Delete user-membership from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-del u16  'dadministʁasjɔ̃' > $TmpDir/pki-user-membership-del-ca-017_3.out" \
                            0 \
                            "Delete user-membership from group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted membership in group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-ca-017_3.out"
		rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-find u16 > $TmpDir/pki-user-membership-find-groupadd-find-ca-017_4.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-017_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-017: Delete user-membership for user fullname with i18n characters"
                rlLog "user-add user fullname ÖrjanÄke with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName='ÖrjanÄke' u17 > $TmpDir/pki-user-add-ca-018.out 2>&1" \
                            0 \
                            "Adding user full name ÖrjanÄke with i18n characters"
                rlAssertGrep "Added user \"u17\"" "$TmpDir/pki-user-add-ca-018.out"
                rlAssertGrep "User ID: u17" "$TmpDir/pki-user-add-ca-018.out"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u17 \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u17 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-del-groupadd-ca-018_2.out" \
                            0 \
                            "Adding user with full name ÖrjanÄke to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-groupadd-ca-018_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-del-groupadd-ca-018_2.out"
		rlLog "Delete user from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-del u17 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-del-groupadd-del-ca-018_3.out" \
                            0 \
                            "Delete user-membership from the group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted membership in group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-groupadd-del-ca-018_3.out"
                rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-find u17 > $TmpDir/pki-user-membership-del-groupadd-del-ca-018_4.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-user-membership-del-groupadd-del-ca-018_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-018: Delete user-membership when uid is not associated with a group"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"fullNameuser123\" user123 "
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"fullNameuser123\" user123 > $TmpDir/pki-user-membership-del-user-del-ca-019.out" \
                            0 \
                            "Adding user user123"
                rlAssertGrep "Added user \"user123\"" "$TmpDir/pki-user-membership-del-user-del-ca-019.out"
                rlAssertGrep "User ID: user123" "$TmpDir/pki-user-membership-del-user-del-ca-019.out"
                rlAssertGrep "Full name: fullNameuser123" "$TmpDir/pki-user-membership-del-user-del-ca-019.out"
                command="pki -d $CERTDB_DIR  -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-del user123 \"Administrators\""
                rlLog "Executing $command"
		errmsg="ResourceNotFoundException: No such attribute."
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Delete user-membership when uid is not associated with a group"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-019: Deleting a user that has membership with groups removes the user from the groups"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"fullNameu20\" u20 "
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"fullNameu20\" u20 > $TmpDir/pki-user-membership-del-user-del-ca-020.out" \
                            0 \
                            "Adding user u20"
                rlAssertGrep "Added user \"u20\"" "$TmpDir/pki-user-membership-del-user-del-ca-020.out"
                rlAssertGrep "User ID: u20" "$TmpDir/pki-user-membership-del-user-del-ca-020.out"
                rlAssertGrep "Full name: fullNameu20" "$TmpDir/pki-user-membership-del-user-del-ca-020.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 		 	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u20 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-20_2.out" \
                            0 \
                            "Adding user u20 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-20_2.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u20 \"Certificate Manager Agents\" > $TmpDir/pki-user-membership-add-groupadd-ca-20_3.out" \
                            0 \
                            "Adding user u20 to group \"Certificate Manager Agents\""
                rlAssertGrep "Added membership in \"Certificate Manager Agents\"" "$TmpDir/pki-user-membership-add-groupadd-ca-20_3.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            group-member-find  Administrators > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_4.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertGrep "User: u20" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_4.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            group-member-find \"Certificate Manager Agents\" > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_5.out" \
                            0 \
                            "List members of Certificate Manager Agents group"
                rlAssertGrep "User: u20" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_5.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del  u20 > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_6.out" \
                            0 \
                            "Delete user u20"
                rlAssertGrep "Deleted user \"u20\"" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_6.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		    	   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            group-member-find  Administrators > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_7.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertNotGrep "User: u20" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_7.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            group-member-find \"Certificate Manager Agents\" > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_8.out" \
                            0 \
                            "List members of Certificate Manager Agents group"
                rlAssertNotGrep "User: u20" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-20_8.out"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-020: User deleted from  Administrators group cannot create a new user"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-user-membership-del-user-add-ca-0021.out" \
                            0 \
                            "Adding user testuser1"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add testuser1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-21_2.out" \
                            0 \
                            "Adding user testuser1 to group \"Administrators\""
        	rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-21_2.out"

		#Create a user cert
                local TEMP_NSS_DB="$TmpDir/nssdb"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
		local requestdn
                local temp_out="$TmpDir/usercert-show.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User1\" \"testuser1\" \
                        \"testuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $SUBSYSTEM_HOST $(eval echo \$${subsystemId}_UNSECURE_PORT) $requestdn $prefix" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${prefix}_agentV\" -h $SUBSYSTEM_HOST  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n \"${prefix}_agentV\" ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
                rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
                rlLog "pki -h $SUBSYSTEM_HOST  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki -h $SUBSYSTEM_HOST  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"

                #Import user certs to $TEMP_NSS_DB
                rlRun "pki -h $SUBSYSTEM_HOST  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
                rlRun "certutil -d $TEMP_NSS_DB -A -n testuser1 -i $temp_out  -t \"u,u,u\""

                #Add certificate to the user
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_021_3.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n \"${prefix}_adminV\" \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t ca \
                            user-cert-add testuser1 --input $TmpDir/validcert_021_3.pem  > $TmpDir/useraddcert_021_3.out" \
                            0 \
                            "Cert is added to the user testuser1"

		#Add a new user using testuser1
		local expfile="$TmpDir/expfile_testuser1.out"
                echo "spawn -noecho pki -d $TEMP_NSS_DB -n testuser1 -c Password -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-add --fullName=test_user u15" > $expfile
                echo "expect \"WARNING: UNTRUSTED ISSUER encountered on '$(eval echo \$${subsystemId}_SSL_SERVER_CERT_SUBJECT_NAME)' indicates a non-trusted CA cert '$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)'
Import CA certificate (Y/n)? \"" >> $expfile
                echo "send -- \"Y\r\"" >> $expfile
                echo "expect \"CA server URI \[http://$HOSTNAME:8080/ca\]: \"" >> $expfile
                echo "send -- \"http://$HOSTNAME:$(eval echo \$${prefix}_UNSECURE_PORT)/ca\r\"" >> $expfile
                echo "expect eof" >> $expfile
                echo "catch wait result" >> $expfile
                echo "exit [lindex \$result 3]" >> $expfile
                rlRun "/usr/bin/expect -f $expfile 2>&1 >  $TmpDir/pki-user-add-ca-021_4.out" 0 "Should be able to add users using Administrator user testuser1"
                rlAssertGrep "Added user \"u15\"" "$TmpDir/pki-user-add-ca-021_4.out"
                rlAssertGrep "User ID: u15" "$TmpDir/pki-user-add-ca-021_4.out"
                rlAssertGrep "Full name: test_user" "$TmpDir/pki-user-add-ca-021_4.out"

		#Delete testuser1 from the Administrators group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-del testuser1 \"Administrators\"  > $TmpDir/pki-user-membership-del-groupdel-del-ca-021_5.out" \
                            0 \
                            "User deleted from group \"Administrators\""
                rlAssertGrep "Deleted membership in group \"Administrators\"" "$TmpDir/pki-user-membership-del-groupdel-del-ca-021_5.out"

		#Trying to add a user using testuser1 should fail since testuser1 is not in Administrators group
		command="pki -d $TEMP_NSS_DB  -n testuser1 -c Password -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-add --fullName=test_user u212"
		rlLog "Executing $command"
		errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add users using non Administrator"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_user_cli_user_membership-del-CA-021: User deleted from the Certificate Manager Agents group can not approve certificate requests"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add testuser1 \"Certificate Manager Agents\" > $TmpDir/pki-user-membership-add-groupadd-ca-22.out" \
                            0 \
                            "Adding user testuser1 to group \"Certificate Manager Agents\""
                rlAssertGrep "Added membership in \"Certificate Manager Agents\"" "$TmpDir/pki-user-membership-add-groupadd-ca-22.out"

		#Trying to approve a certificate request using testuser1 should succeed
		local TEMP_NSS_DB="$TmpDir/nssdb"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
		local requestdn
                local temp_out="$TmpDir/usercert-show_22.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User3\" \"testuser3\" \
                        \"testuser3@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $SUBSYSTEM_HOST $(eval echo \$${subsystemId}_UNSECURE_PORT) $requestdn $prefix" 0 "Generating  pkcs10 Certificate Request"
		rlLog "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out-22_1.out" 0 "Approve Certificate request using testuser1"
                rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out-22_1.out"
                rlLog "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1_22_2.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1_22_2.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"

		#Delete testuser1 from Certificate Manager Agents group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-del testuser1 \"Certificate Manager Agents\"  > $TmpDir/pki-user-membership-del-groupdel-del-ca-022_3.out" \
                            0 \
                            "User deleted from group \"Certificate Manager Agents\""
                rlAssertGrep "Deleted membership in group \"Certificate Manager Agents\"" "$TmpDir/pki-user-membership-del-groupdel-del-ca-022_3.out"

		#Trying to approve a certificate request using testuser1 should fail
		local temp_out="$TmpDir/usercert-show_22_4.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User4\" \"testuser4\" \
                        \"testuser4@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $SUBSYSTEM_HOST $(eval echo \$${subsystemId}_UNSECURE_PORT) $requestdn $prefix" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                        --action approve"
                command="pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid --action approve"
                rlLog "Executing: $command"
                errmsg="Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Approve Certificate request using testuser1"	
	rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-ca-cleanup-001: Deleting the temp directory and users"

		#===Deleting users created using CA_adminV cert===#
		i=1
		while [ $i -lt 18 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
				  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   user-del  u$i > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-00$i.out" \
				   0 \
				   "Deleted user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-00$i.out"
			let i=$i+1
		done
		rlRun "pki -d $CERTDB_DIR \
		       	   -n ${prefix}_adminV \
			   -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    user-del  userall > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
			    0 \
			   "Deleted user userall"
	        rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del  user1 > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
                            0 \
                            "Deleted user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del  user2 > $TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out" \
                            0 \
                            "Deleted user user2"
                rlAssertGrep "Deleted user \"user2\"" "$TmpDir/pki-user-del-ca-user-membership-del-user-del-ca-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del  user123 > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-user123.out" \
                            0 \
                            "Deleted user user123"
                rlAssertGrep "Deleted user \"user123\"" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-user123.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del testuser1 > $TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-testuser1.out" \
                            0 \
                            "Deleted user testuser1"
                rlAssertGrep "Deleted user \"testuser1\"" "$TmpDir/pki-user-del-ca-user-membership-find-user-del-ca-testuser1.out"

                #===Deleting i18n group created using CA_adminV cert===#
                rlRun "pki -d $CERTDB_DIR \
                        -n ${prefix}_adminV \
                        -c $CERTDB_DIR_PASSWORD \
 		-h $SUBSYSTEM_HOST \
 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                        group-del 'dadministʁasjɔ̃' > $TmpDir/pki-user-del-ca-group-i18n_1.out" \
                        0 \
                        "Deleting group dadministʁasjɔ̃"
                rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-del-ca-group-i18n_1.out"
		
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
 else
	rlLog "CA instance not installed"
 fi
}
