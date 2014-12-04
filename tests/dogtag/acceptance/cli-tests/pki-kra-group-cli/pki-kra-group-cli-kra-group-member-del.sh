#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-kra-group-cli
#   Description: PKI kra-group-member-del CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <aakkiang@redhat.com>
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
#create_role_users.sh should be first executed prior to pki-kra-group-cli-kra-group-member-del.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################
run_pki-kra-group-cli-kra-group-member-del_tests(){
	#Available groups kra-group-member-del
	groupid1="Data Recovery Manager Agents"
        groupid2="Subsystem Group"
        groupid3="Trusted Managers"
        groupid4="Administrators"
        groupid5="Auditors"
        groupid6="ClonedSubsystems"
        groupid7="Security Domain Administrators"
        groupid8="Enterprise KRA Administrators"

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-001: Create temporary directory"
                rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
                rlRun "pushd $TmpDir"
        rlPhaseEnd

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
caId=$4
caHost=$5
KRA_HOST=$(eval echo \$${MYROLE})
KRA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
CA_PORT=$(eval echo \$${caId}_UNSECURE_PORT)
CA_HOST=$(eval echo \$${caHost})
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
local cert_info="$TmpDir/cert_info"
ROOTCA_agent_user=${caId}_agentV
        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-002: pki kra-group-member-del --help configuration test"
                rlRun "pki kra-group-member-del --help > $TmpDir/pki_kra_group_member_del_cfg.out 2>&1" \
                        0 \
                       "pki kra-group-member-del --help"
                rlAssertGrep "usage: kra-group-member-del <Group ID> <Member ID> \[OPTIONS...\]" "$TmpDir/pki_kra_group_member_del_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_kra_group_member_del_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-003: pki kra-group-member-del configuration test"
                rlRun "pki kra-group-member-del > $TmpDir/pki_kra_group_member_del_2_cfg.out 2>&1" \
                       255 \
                       "pki kra-group-member-del"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_kra_group_member_del_2_cfg.out"
                rlAssertGrep "usage: kra-group-member-del <Group ID> <Member ID> \[OPTIONS...\]" "$TmpDir/pki_kra_group_member_del_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_kra_group_member_del_2_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-004: Delete kra-group-member when user is added to different groups"
                i=1
                while [ $i -lt 9 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-kra-group-member-del-user-add-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-kra-group-member-del-user-add-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-kra-group-member-del-user-add-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-kra-group-member-del-user-add-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-group-member-add \"$gid\" u$i"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-group-member-add \"$gid\" u$i > $TmpDir/pki-kra-group-member-del-groupadd-00$i.out" \
                                   0 \
                                   "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added group member \"u$i\"" "$TmpDir/pki-kra-group-member-del-groupadd-00$i.out"
                        rlAssertGrep "User: u$i" "$TmpDir/pki-kra-group-member-del-groupadd-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                 kra-group-member-find \"$gid\" > $TmpDir/pki-kra-group-member-del-groupadd-find-00$i.out" \
                                   0 \
                                   "Check user is in group \"$gid\""
                        rlAssertGrep "User: u$i" "$TmpDir/pki-kra-group-member-del-groupadd-find-00$i.out"
			rlLog "Delete the user from the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                    kra-group-member-del \"$gid\" u$i > $TmpDir/pki-kra-group-member-del-groupdel-del-00$i.out" \
                                    0 \
                                    "User deleted from group \"$gid\""
                        rlAssertGrep "Deleted group member \"u$i\"" "$TmpDir/pki-kra-group-member-del-groupdel-del-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-005: Delete kra-group-member from all the groups that user is associated with"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-kra-group-member-del-user-add-userall-001.out" \
                            0 \
                            "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-kra-group-member-del-user-add-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-kra-group-member-del-user-add-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-kra-group-member-del-user-add-userall-001.out"
                rlLog "Adding the user to all the groups"
                i=1
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                    kra-group-member-add \"$gid\" userall"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                    kra-group-member-add \"$gid\" userall > $TmpDir/pki-kra-group-member-del-groupadd-userall-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added group member \"userall\"" "$TmpDir/pki-kra-group-member-del-groupadd-userall-00$i.out"
                        rlAssertGrep "User: userall" "$TmpDir/pki-kra-group-member-del-groupadd-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                    kra-group-member-find \"$gid\" > $TmpDir/pki-kra-group-member-del-groupadd-find-userall-00$i.out" \
                                    0 \
                                    "Check group members with group \"$gid\""
                        rlAssertGrep "User: userall" "$TmpDir/pki-kra-group-member-del-groupadd-find-userall-00$i.out"
                        let i=$i+1
                done
		rlLog "Delete user from all the groups"
                i=1
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                    kra-group-member-del \"$gid\" userall"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                    kra-group-member-del \"$gid\" userall > $TmpDir/pki-kra-group-member-del-groupadd-userall-00$i.out" \
                                    0 \
                                    "Delete userall from group \"$gid\""
                        rlAssertGrep "Deleted group member \"userall\"" "$TmpDir/pki-kra-group-member-del-groupadd-userall-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-006: Missing required option <Group id> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-kra-group-member-del-user-add-user1-001.out" \
                                   0 \
                                   "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-kra-group-member-del-user-add-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-kra-group-member-del-user-add-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-kra-group-member-del-user-add-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-group-member-add \"Administrators\" user1 > $TmpDir/pki-kra-group-member-del-groupadd-user1-001.out" \
                                   0 \
                                   "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added group member \"user1\"" "$TmpDir/pki-kra-group-member-del-groupadd-user1-001.out"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del user1"
		errmsg="Error: Incorrect number of arguments specified."
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete kra-group-member without specifying group ID"	
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-007: Missing required option <Member ID> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                  kra-user-add --fullName=\"fullName_user2\" user2 > $TmpDir/pki-kra-group-member-del-user-add-user1-001.out" \
                                   0 \
                                   "Adding user user2"
                rlAssertGrep "Added user \"user2\"" "$TmpDir/pki-kra-group-member-del-user-add-user1-001.out"
                rlAssertGrep "User ID: user2" "$TmpDir/pki-kra-group-member-del-user-add-user1-001.out"
                rlAssertGrep "Full name: fullName_user2" "$TmpDir/pki-kra-group-member-del-user-add-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                                   kra-group-member-add \"Administrators\" user2 > $TmpDir/pki-kra-group-member-del-groupadd-user1-001.out" \
                                   0 \
                                   "Adding user user2 to group \"Administrators\""
                rlAssertGrep "Added group member \"user2\"" "$TmpDir/pki-kra-group-member-del-groupadd-user1-001.out"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del Administrators"
		errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete kra-group-member without specifying member ID"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-008: Should not be able to kra-group-member-del using a revoked cert KRA_adminR"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete group members using a revoked cert KRA_adminR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-009:  Should not be able to kra-group-member-del using an agent with revoked cert KRA_agentR"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete kra-group-member using a revoked cert KRA_agentR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-010: Should not be able to kra-group-member-del using a valid agent KRA_agentV user"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete group members using a valid agent cert KRA_agentV"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-011: Should not be able to kra-group-member-del using admin user with expired cert KRA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to kra-group-member-del using admin user with expired cert KRA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-012: Should not be able to kra-group-member-del using KRA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to kra-group-member-del using KRA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-013: Should not be able to kra-group-member-del using KRA_auditV cert"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to kra-group-member-del using KRA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-014: Should not be able to kra-group-member-del using KRA_operatorV cert"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to kra-group-member-del using KRA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-015: Should not be able to kra-group-member-del using role_user_UTCA cert"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del 'Administrators' user2"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to kra-group-member-del using KRA_adminUTCA cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-016: Should not be able to kra-group-member-del using role_user_UTCA cert"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user2"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to kra-group-member-del using role_user_UTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-017: Delete kra-group-member for user id with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
			 -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName='u10' u10"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName='u10' 'u10'" \
                            0 \
                            "Adding uid u10"
                rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-kra-group-member-del-groupadd-017_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-kra-group-member-del-groupadd-017_1.out"
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-kra-group-member-del-groupadd-017_1.out"
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-kra-group-member-del-groupadd-017_1.out"
                rlLog "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-add \"dadministʁasjɔ̃\" 'u10'"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                           kra-group-member-add \"dadministʁasjɔ̃\" 'u10' > $TmpDir/pki-kra-group-member-del-groupadd-017_2.out" \
                            0 \
                            "Adding user u10 to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added group member \"u10\"" "$TmpDir/pki-kra-group-member-del-groupadd-017_2.out"
                rlAssertGrep "User: u10" "$TmpDir/pki-kra-group-member-del-groupadd-017_2.out"
		rlLog "Delete group member from the group"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-del 'dadministʁasjɔ̃' 'u10' > $TmpDir/pki-kra-group-member-del-017_3.out" \
                            0 \
                            "Delete group member from group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted group member \"u10\"" "$TmpDir/pki-kra-group-member-del-017_3.out"
		rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-find 'dadministʁasjɔ̃' > $TmpDir/pki-kra-group-member-del-groupadd-find-017_4.out" \
                            0 \
                            "Find group members of group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-kra-group-member-del-groupadd-find-017_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-018: Delete group member when uid is not associated with a group"
		rlLog "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName=\"fullNameuser123\" user123 "
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName=\"fullNameuser123\" user123 > $TmpDir/pki-kra-group-member-del-user-del-019.out" \
                            0 \
                            "Adding user user123"
                rlAssertGrep "Added user \"user123\"" "$TmpDir/pki-kra-group-member-del-user-del-019.out"
                rlAssertGrep "User ID: user123" "$TmpDir/pki-kra-group-member-del-user-del-019.out"
                rlAssertGrep "Full name: fullNameuser123" "$TmpDir/pki-kra-group-member-del-user-del-019.out"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT kra-group-member-del \"Administrators\" user123"
		errmsg="ResourceNotFoundException: No such attribute."
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Delete kra-group-member when uid is not associated with a group"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-019: Deleting a user that has membership with groups removes the user from the groups"
		rlLog "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName=\"fullNameu20\" u20 "
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName=\"fullNameu20\" u20 > $TmpDir/pki-kra-group-member-del-user-del-020.out" \
                            0 \
                            "Adding user u20"
                rlAssertGrep "Added user \"u20\"" "$TmpDir/pki-kra-group-member-del-user-del-020.out"
                rlAssertGrep "User ID: u20" "$TmpDir/pki-kra-group-member-del-user-del-020.out"
                rlAssertGrep "Full name: fullNameu20" "$TmpDir/pki-kra-group-member-del-user-del-020.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-add \"Administrators\" u20 > $TmpDir/pki-kra-group-member-add-groupadd-20_2.out" \
                            0 \
                            "Adding user u20 to group \"Administrators\""
                rlAssertGrep "Added group member \"u20\"" "$TmpDir/pki-kra-group-member-add-groupadd-20_2.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-find  Administrators > $TmpDir/pki-user-del-kra-group-member-find-user-del-20_4.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertGrep "User: u20" "$TmpDir/pki-user-del-kra-group-member-find-user-del-20_4.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-del  u20 > $TmpDir/pki-user-del-kra-group-member-find-user-del-20_6.out" \
                            0 \
                            "Delete user u20"
                rlAssertGrep "Deleted user \"u20\"" "$TmpDir/pki-user-del-kra-group-member-find-user-del-20_6.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-find  Administrators > $TmpDir/pki-user-del-kra-group-member-find-user-del-20_7.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertNotGrep "User: u20" "$TmpDir/pki-user-del-kra-group-member-find-user-del-20_7.out"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-020: User deleted from  Administrators group cannot create a new user"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-kra-group-member-del-user-add-0021.out" \
                            0 \
                            "Adding user testuser1"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-add \"Administrators\" testuser1 > $TmpDir/pki-kra-group-member-add-groupadd-21_2.out" \
                            0 \
                            "Adding user testuser1 to group \"Administrators\""
        	rlAssertGrep "Added group member \"testuser1\"" "$TmpDir/pki-kra-group-member-add-groupadd-21_2.out"

		#Create a user cert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"testuser1\" subject_uid:testuser1 subject_email:testuser1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_kra_group_member_del_encoded_0021pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_kra_group_member_del_encoded_0021pkcs10.out > $TmpDir/pki_kra_group_member_del_encoded_0021pkcs10.pem"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n testuser1 -i $TmpDir/pki_kra_group_member_del_encoded_0021pkcs10.out  -t "u,u,u""

                #Add certificate to the user
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-cert-add testuser1 --input $TmpDir/pki_kra_group_member_del_encoded_0021pkcs10.pem  > $TmpDir/useraddcert_021_3.out" \
                            0 \
                            "Cert is added to the user testuser1"

		#Add a new user using testuser1
		rlLog "pki -d $TEMP_NSS_DB/ \
                           -n testuser1 \
                    -c $TEMP_NSS_DB_PASSWD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName='test_user' u9"
		rlRun "pki -d $TEMP_NSS_DB/ \
                           -n testuser1 \
                    -c $TEMP_NSS_DB_PASSWD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName='test_user' u9 > $TmpDir/pki-user-add-kra-021_4.out"
                rlAssertGrep "Added user \"u9\"" "$TmpDir/pki-user-add-kra-021_4.out"
                rlAssertGrep "User ID: u9" "$TmpDir/pki-user-add-kra-021_4.out"
                rlAssertGrep "Full name: test_user" "$TmpDir/pki-user-add-kra-021_4.out"

		#Delete testuser1 from the Administrators group
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-del \"Administrators\" testuser1 > $TmpDir/pki-kra-group-member-del-groupdel-del-021_5.out" \
                            0 \
                            "User deleted from group \"Administrators\""
                rlAssertGrep "Deleted group member \"testuser1\"" "$TmpDir/pki-kra-group-member-del-groupdel-del-021_5.out"

		#Trying to add a user using testuser1 should fail since testuser1 is not in Administrators group
		command="pki -d $TEMP_NSS_DB  -n testuser1 -c $TEMP_NSS_DB_PASSWD -h $KRA_HOST -p $KRA_PORT kra-user-add --fullName=test_user u212"
		errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add users using non Administrator"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	#Usability tests

	rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-022: Delete group and check for user membership"
                rlLog "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName='Test User2' testuser2"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-add --fullName='Test User2' testuser2 2>&1> /tmp/new_user.out" \
                            0 \
                            "Adding uid testuser2 "
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-add group1 --description=\"New Group\" 2>&1 > $TmpDir/pki-kra-group-member-del-groupadd-022_1.out" \
                            0 \
                            "Adding group group1"
                rlAssertGrep "Added group \"group1\"" "$TmpDir/pki-kra-group-member-del-groupadd-022_1.out"
                rlAssertGrep "Group ID: group1" "$TmpDir/pki-kra-group-member-del-groupadd-022_1.out"
                rlAssertGrep "Description: New Group" "$TmpDir/pki-kra-group-member-del-groupadd-022_1.out"
                rlLog "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-member-add \"group1\" testuser2"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                           kra-group-member-add \"group1\" testuser2 > $TmpDir/pki-kra-group-member-del-groupadd-022_2.out" \
                            0 \
                            "Adding user testuser2 to group \"group1\""
                rlAssertGrep "Added group member \"testuser2\"" "$TmpDir/pki-kra-group-member-del-groupadd-022_2.out"
                rlAssertGrep "User: testuser2" "$TmpDir/pki-kra-group-member-del-groupadd-022_2.out"
                rlLog "Delete group member from the group"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-group-del 'group1'  > $TmpDir/pki-kra-group-member-del-022_3.out" \
                            0 \
                            "Delete group \"group1\""
                rlAssertGrep "Deleted group \"group1\"" "$TmpDir/pki-kra-group-member-del-022_3.out"
                rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-membership-find testuser2 > $TmpDir/pki-kra-group-member-del-groupadd-find-022_4.out" \
                            0 \
                            "Find user-membership of testuser2"
                rlAssertNotGrep "Group: group1" "$TmpDir/pki-kra-group-member-del-groupadd-find-022_4.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_group_cli_kra_group_member-del-cleanup-001: Deleting the temp directory and users"

		#===Deleting users created using KRA_adminV cert===#
		i=1
		while [ $i -lt 11 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
				   kra-user-del  u$i > $TmpDir/pki-user-del-kra-group-member-del-user-del-kra-00$i.out" \
				   0 \
				   "Deleted user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-kra-group-member-del-user-del-kra-00$i.out"
			let i=$i+1
		done
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
			    kra-user-del  userall > $TmpDir/pki-user-del-kra-group-member-del-user-del-kra-userall-001.out" \
			    0 \
			   "Deleted user userall"
	        rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-kra-group-member-del-user-del-kra-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-del  user1 > $TmpDir/pki-user-del-kra-group-member-del-user-del-kra-userall-001.out" \
                            0 \
                            "Deleted user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-kra-group-member-del-user-del-kra-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-del  user2 > $TmpDir/pki-user-del-kra-group-member-del-user-del-kra-userall-001.out" \
                            0 \
                            "Deleted user user2"
                rlAssertGrep "Deleted user \"user2\"" "$TmpDir/pki-user-del-kra-group-member-del-user-del-kra-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-del  user123 > $TmpDir/pki-user-del-kra-group-member-find-user-del-kra-user123.out" \
                            0 \
                            "Deleted user user123"
                rlAssertGrep "Deleted user \"user123\"" "$TmpDir/pki-user-del-kra-group-member-find-user-del-kra-user123.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-del testuser1 > $TmpDir/pki-user-del-kra-group-member-find-user-del-kra-testuser1.out" \
                            0 \
                            "Deleted user testuser1"
                rlAssertGrep "Deleted user \"testuser1\"" "$TmpDir/pki-user-del-kra-group-member-find-user-del-kra-testuser1.out"

		rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                            kra-user-del testuser2 > $TmpDir/pki-user-del-kra-group-member-find-user-del-kra-testuser2.out" \
                            0 \
                            "Deleted user testuser2"
                rlAssertGrep "Deleted user \"testuser2\"" "$TmpDir/pki-user-del-kra-group-member-find-user-del-kra-testuser2.out"


                #===Deleting i18n group created using CA_adminV cert===#
                rlRun "pki -d $CERTDB_DIR \
			-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                        kra-group-del 'dadministʁasjɔ̃' > $TmpDir/pki-user-del-kra-group-i18n_1.out" \
                        0 \
                        "Deleting group dadministʁasjɔ̃"
                rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-del-kra-group-i18n_1.out"
		
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
