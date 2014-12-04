#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-cli-group-membership-add-kra CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-member-add-kra    Add group member.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <rpattath@redhat.com> 
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
#create_role_users.sh should be first executed prior to pki-group-cli-group-member-add-kra.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################
run_pki-group-cli-group-member-add-kra_tests(){
	#Local variables
	groupid1="Data Recovery Manager Agents"
	groupid2="Subsystem Group"
	groupid3="Trusted Managers"
	groupid4="Administrators"
	groupid5="Auditors"
	groupid6="ClonedSubsystems"
	groupid7="Security Domain Administrators"
	groupid8="Enterprise KRA Administrators"

	rlPhaseStartSetup "pki_group_cli_group_membership-add-kra-001: Create temporary directory"
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

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-001: Add users to available groups using valid admin user KRA_adminV"
		i=1
		while [ $i -lt 9 ] ; do
		       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
		    -t kra \
                                  user-add --fullName=\"fullNameu$i\" u$i "
		       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
				   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-kra-group-member-add-group-add-00$i.out" \
				   0 \
				   "Adding user u$i"
			rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-kra-group-member-add-group-add-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-kra-group-member-add-group-add-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-kra-group-member-add-group-add-00$i.out"
			rlLog "Showing the user"
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
				    user-show u$i > $TmpDir/pki-kra-group-member-add-group-show-00$i.out" \
				    0 \
				    "Show pki KRA_adminV user"
			rlAssertGrep "User \"u$i\"" "$TmpDir/pki-kra-group-member-add-group-show-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-kra-group-member-add-group-show-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-kra-group-member-add-group-show-00$i.out"
			rlLog "Adding the user to a group"
			eval gid=\$groupid$i
			rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add \"$gid\" u$i"
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add \"$gid\" u$i > $TmpDir/pki-kra-group-member-add-groupadd-00$i.out" \
                                    0 \
                                    "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added group member \"u$i\"" "$TmpDir/pki-kra-group-member-add-groupadd-00$i.out"
                        rlAssertGrep "User: u$i" "$TmpDir/pki-kra-group-member-add-groupadd-00$i.out"
			rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find \"$gid\" > $TmpDir/pki-kra-group-member-add-groupadd-find-00$i.out" \
                                    0 \
                                    "User added to group \"$gid\""
                        rlAssertGrep "User: u$i" "$TmpDir/pki-kra-group-member-add-groupadd-find-00$i.out"
	                let i=$i+1
		done
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-002: Add a user to all available groups using KRA_adminV"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-kra-group-member-add-user-add-userall-001.out" \
                            0 \
                            "Adding user userall"
		rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-kra-group-member-add-user-add-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-kra-group-member-add-user-add-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-kra-group-member-add-user-add-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-show userall > $TmpDir/pki-kra-group-member-add-user-show-userall-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-kra-group-member-add-user-show-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-kra-group-member-add-user-show-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-kra-group-member-add-user-show-userall-001.out"
                rlLog "Adding the user to all the groups"
		i=1
		while [ $i -lt 9 ] ; do
			eval gid=\$groupid$i
			rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
				    group-member-add \"$gid\" userall"
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
				    group-member-add \"$gid\" userall > $TmpDir/pki-kra-group-member-add-groupadd-userall-00$i.out" \
				    0 \
				    "Adding user userall to group \"$gid\""
			rlAssertGrep "Added group member \"userall\"" "$TmpDir/pki-kra-group-member-add-groupadd-userall-00$i.out"
			rlAssertGrep "User: userall" "$TmpDir/pki-kra-group-member-add-groupadd-userall-00$i.out"
			rlLog "Check if the user is added to the group"
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
				    group-member-find \"$gid\" > $TmpDir/pki-kra-group-member-add-groupadd-find-userall-00$i.out" \
				    0 \
				    "User added to group \"$gid\""
			rlAssertGrep "User: userall" "$TmpDir/pki-kra-group-member-add-groupadd-find-userall-00$i.out"
			let i=$i+1
                done
	rlPhaseEnd

        rlPhaseStartTest "pki_group_cli_group_member-add-kra-003: Add a user to same group multiple times"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-kra-group-member-add-user-add-user1-001.out" \
                            0 \
                            "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-kra-group-member-add-user-add-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-kra-group-member-add-user-add-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-kra-group-member-add-user-add-user1-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-show user1 > $TmpDir/pki-kra-group-member-add-user-show-user1-001.out" \
                            0 \
                            "Show pki KRA_adminV user"
                rlAssertGrep "User \"user1\"" "$TmpDir/pki-kra-group-member-add-user-show-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-kra-group-member-add-user-show-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-kra-group-member-add-user-show-user1-001.out"
                rlLog "Adding the user to the same groups twice"
		rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            group-member-add \"Administrators\" user1 > $TmpDir/pki-kra-group-member-add-groupadd-user1-001.out" \
                            0 \
                            "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added group member \"user1\"" "$TmpDir/pki-kra-group-member-add-groupadd-user1-001.out"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" user1" 
		errmsg="ConflictingOperationException: Attribute or value exists."
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - cannot add user to the same group more than once"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-004: should not be able to add user to a non existing group"
		dummy_group="nonexisting_bogus_group"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                          user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-kra-group-member-add-user-add-user1-008.out" \
                            0 \
                            "Adding user testuser1"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"$dummy_group\" testuser1"
                errmsg="GroupNotFoundException: Group $dummy_group not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - should not be able to add user to a non existing group"
	rlPhaseEnd	

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-005: Should be able to group-member-add groupid with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-add --fullName=u14 u14"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-add --fullName='u14' u14" \
                            0 \
                            "Adding uid u14"
		rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-kra-group-member-add-groupadd-010_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-kra-group-member-add-groupadd-010_1.out"   
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-kra-group-member-add-groupadd-010_1.out"   
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-kra-group-member-add-groupadd-010_1.out"
                rlLog "Adding the user to the dadministʁasjɔ̃ group"
                rlRun "pki -d $CERTDB_DIR \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            group-member-add \"dadministʁasjɔ̃\" u14 > $TmpDir/pki-kra-group-member-add-groupadd-010_2.out" \
                            0 \
                            "Adding user u14 to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added group member \"u14\"" "$TmpDir/pki-kra-group-member-add-groupadd-010_2.out"    
                rlAssertGrep "User: u14" "$TmpDir/pki-kra-group-member-add-groupadd-010_2.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find 'dadministʁasjɔ̃' > $TmpDir/pki-kra-group-member-add-groupadd-find-010_3.out" \
                                    0 \
                                    "Check user u14 added to group dadministʁasjɔ̃"
                        rlAssertGrep "User: u14" "$TmpDir/pki-kra-group-member-add-groupadd-find-010_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-006: Should not be able to group-member-add using a revoked cert KRA_adminR"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"$groupid7\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using a revoked cert KRA_adminR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-kra-007: Should not be able to group-member-add using an agent with revoked cert KRA_agentR"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"$groupid7\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using an agent with revoked cert KRA_agentR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-008: Should not be able to group-member-add using admin user with expired cert KRA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using admin user with expired cert KRA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-009: Should not be able to group-member-add using KRA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using KRA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-010: Should not be able to group-member-add using KRA_auditV cert"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using KRA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-011: Should not be able to group-member-add using KRA_operatorV cert"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using KRA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-012: Should not be able to group-member-add using KRA_adminUTCA cert"
		command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using KRA_adminUTCA cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-013: Should not be able to group-member-add using KRA_agentUTCA cert"
		command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using KRA_agentUTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_group_cli_group_member-add-kra-014: User associated with Administrators group only can create a new user"
		i=2
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
			if [ "$gid" = "Administrators" ] ; then
				rlLog "Not adding testuser1 to $gid group"
			else
	                        rlLog "pki -d $CERTDB_DIR \
				    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add \"$gid\" testuser1"
        	                rlRun "pki -d $CERTDB_DIR \
					-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add \"$gid\" testuser1 > $TmpDir/pki-kra-group-member-add-groupadd-testuser1-00$i.out" \
                                    0 \
                                    "Adding user testuser1 to group \"$gid\""
                	        rlAssertGrep "Added group member \"testuser1\"" "$TmpDir/pki-kra-group-member-add-groupadd-testuser1-00$i.out"
                        	rlAssertGrep "User: testuser1" "$TmpDir/pki-kra-group-member-add-groupadd-testuser1-00$i.out"
			fi
                        let i=$i+1
                done

		#Create a user cert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"testuser1\" subject_uid:testuser1 subject_email:testuser1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_kra_group_member_add_encoded_0019pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_kra_group_member_add_encoded_0019pkcs10.out > $TmpDir/pki_kra_group_member_add_encoded_0019pkcs10.pem"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"testuser1\" -i $TmpDir/pki_kra_group_member_add_encoded_0019pkcs10.pem -t \"u,u,u\""
	rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-cert-add testuser1 --input $TmpDir/pki_kra_group_member_add_encoded_0019pkcs10.pem  > $TmpDir/useraddcert_019_2.out" \
                            0 \
                            "Cert is added to the user testuser1"
		command="pki -d $TEMP_NSS_DB -n testuser1 -c $TEMP_NSS_DB_PASSWD -h $KRA_HOST -p $KRA_PORT -t kra user-add --fullName=test_user u39"
		errmsg="ForbiddenException: Authorization Error"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "user-add operation should fail when authenticating using a user cert"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"

		#Add testuser1 to Administrators group
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            group-member-add \"$groupid4\" testuser1 > $TmpDir/pki-kra-group-member-add-groupadd-usertest1-019_2.out 2>&1" \
                            0 \
                            "Adding user testuser1 to group \"$groupid4\""
                rlAssertGrep "Added group member \"testuser1\"" "$TmpDir/pki-kra-group-member-add-groupadd-usertest1-019_2.out"
                rlAssertGrep "User: testuser1" "$TmpDir/pki-kra-group-member-add-groupadd-usertest1-019_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            group-member-find $groupid4 > $TmpDir/pki-kra-group-member-add-groupadd-find-usertest1-019_3.out" \
                            0 \
                            "Check group-member for user testuser1"
                rlAssertGrep "User: testuser1" "$TmpDir/pki-kra-group-member-add-groupadd-find-usertest1-019_3.out"
	
		#Trying to add a user using testuser1 should succeed now since testuser1 is in Administrators group
		rlRun "pki -d $TEMP_NSS_DB \
                           -n testuser1 \
                           -c $TEMP_NSS_DB_PASSWD \
			   -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
			    user-add --fullName=test_user us19 > $TmpDir/pki-kra-user-add-019_4.out 2>&1" \
                            0 \
                           "Added new user using Admin user testuser1"
      		rlAssertGrep "Added user \"us19\"" "$TmpDir/pki-kra-user-add-019_4.out"
	        rlAssertGrep "User ID: us19" "$TmpDir/pki-kra-user-add-019_4.out"
        	rlAssertGrep "Full name: test_user" "$TmpDir/pki-kra-user-add-019_4.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_group_cli_group_member-add-kra-015: Should not be able to group-member-add using KRA_agentV cert"
                command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using KRA_agentV cert"
        rlPhaseEnd	

	#Usability test

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-016: Should not be able to add a non existing user to a group"	
		user="tuser3"
		command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $KRA_HOST -p $KRA_PORT -t kra group-member-add \"$groupid5\" $user"
                errmsg="UserNotFoundException: User $user not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add group-member to user that does not exist"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1024"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-kra-017: Add a group and add a user to the group using valid admin user KRA_adminV"
		       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g1description\" g1"
		       rlRun "pki -d $CERTDB_DIR \
			 	  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g1description\" g1 > $TmpDir/pki-kra-group-member-add-group-add-022.out" \
				   0 \
				   "Adding group g1"
		       rlAssertGrep "Added group \"g1\"" "$TmpDir/pki-kra-group-member-add-group-add-022.out"
                        rlAssertGrep "Group ID: g1" "$TmpDir/pki-kra-group-member-add-group-add-022.out"
                        rlAssertGrep "Description: g1description" "$TmpDir/pki-kra-group-member-add-group-add-022.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu9\" u9"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu9\" u9 > $TmpDir/pki-kra-group-member-add-user-add-022.out" \
                                   0 \
                                   "Adding user u9"
                        rlAssertGrep "Added user \"u9\"" "$TmpDir/pki-kra-group-member-add-user-add-022.out"
                        rlAssertGrep "User ID: u9" "$TmpDir/pki-kra-group-member-add-user-add-022.out"
                        rlAssertGrep "Full name: fullNameu9" "$TmpDir/pki-kra-group-member-add-user-add-022.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g1 u9"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g1 u9 > $TmpDir/pki-kra-group-member-add-groupadd-022.out" \
                                    0 \
                                    "Adding user u9 to group g1"
                        rlAssertGrep "Added group member \"u9\"" "$TmpDir/pki-kra-group-member-add-groupadd-022.out"
                        rlAssertGrep "User: u9" "$TmpDir/pki-kra-group-member-add-groupadd-022.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find g1 > $TmpDir/pki-kra-group-member-add-groupadd-find-022.out" \
                                    0 \
                                    "User added to group g1"
                        rlAssertGrep "User: u9" "$TmpDir/pki-kra-group-member-add-groupadd-find-022.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-kra-018: Add two group and add a user to the two different group using valid admin user KRA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g2description\" g2"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g2description\" g2 > $TmpDir/pki-kra-group-member-add-group-add-023.out" \
                                   0 \
                                   "Adding group g2"
                       rlAssertGrep "Added group \"g2\"" "$TmpDir/pki-kra-group-member-add-group-add-023.out"
                        rlAssertGrep "Group ID: g2" "$TmpDir/pki-kra-group-member-add-group-add-023.out"
                        rlAssertGrep "Description: g2description" "$TmpDir/pki-kra-group-member-add-group-add-023.out"
			rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g3description\" g3"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g3description\" g3 > $TmpDir/pki-kra-group-member-add-group-add-023_1.out" \
                                   0 \
                                   "Adding group g3"
                       rlAssertGrep "Added group \"g3\"" "$TmpDir/pki-kra-group-member-add-group-add-023_1.out"
                        rlAssertGrep "Group ID: g3" "$TmpDir/pki-kra-group-member-add-group-add-023_1.out"
                        rlAssertGrep "Description: g3description" "$TmpDir/pki-kra-group-member-add-group-add-023_1.out"

                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu10\" u10"
                       rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                      user-add --fullName=\"fullNameu10\" u10 > $TmpDir/pki-kra-group-member-add-user-add-023.out" \
                                   0 \
                                   "Adding user u10"
                        rlAssertGrep "Added user \"u10\"" "$TmpDir/pki-kra-group-member-add-user-add-023.out"
                        rlAssertGrep "User ID: u10" "$TmpDir/pki-kra-group-member-add-user-add-023.out"
                        rlAssertGrep "Full name: fullNameu10" "$TmpDir/pki-kra-group-member-add-user-add-023.out"
                        rlLog "Adding the user u10 to group g2"
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g2 u10"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g2 u10 > $TmpDir/pki-kra-group-member-add-groupadd-023.out" \
                                    0 \
                                    "Adding user u10 to group g2"
                        rlAssertGrep "Added group member \"u10\"" "$TmpDir/pki-kra-group-member-add-groupadd-023.out"
                        rlAssertGrep "User: u10" "$TmpDir/pki-kra-group-member-add-groupadd-023.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find g2 > $TmpDir/pki-kra-group-member-add-groupadd-find-023.out" \
                                    0 \
                                    "User added to group g2"
                        rlAssertGrep "User: u10" "$TmpDir/pki-kra-group-member-add-groupadd-find-023.out"
			rlLog "Adding the user u10 to group g3"
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g3 u10"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g3 u10 > $TmpDir/pki-kra-group-member-add-groupadd-023_1.out" \
                                    0 \
                                    "Adding user u10 to group g3"
                        rlAssertGrep "Added group member \"u10\"" "$TmpDir/pki-kra-group-member-add-groupadd-023_1.out"
                        rlAssertGrep "User: u10" "$TmpDir/pki-kra-group-member-add-groupadd-023_1.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find g3 > $TmpDir/pki-kra-group-member-add-groupadd-find-023_1.out" \
                                    0 \
                                    "User added to group g3"
                        rlAssertGrep "User: u10" "$TmpDir/pki-kra-group-member-add-groupadd-find-023_1.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-kra-019: Add a group, add a user to the group and delete the group using valid admin user KRA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g4description\" gr4"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g4description\" gr4 > $TmpDir/pki-kra-group-member-add-group-add-024.out" \
                                   0 \
                                   "Adding group gr4"
                       rlAssertGrep "Added group \"gr4\"" "$TmpDir/pki-kra-group-member-add-group-add-024.out"
                        rlAssertGrep "Group ID: gr4" "$TmpDir/pki-kra-group-member-add-group-add-024.out"
                        rlAssertGrep "Description: g4description" "$TmpDir/pki-kra-group-member-add-group-add-024.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   -user-add --fullName=\"fullNameu11\" u11"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu11\" u11 > $TmpDir/pki-kra-group-member-add-user-add-024.out" \
                                   0 \
                                   "Adding user u11"
                        rlAssertGrep "Added user \"u11\"" "$TmpDir/pki-kra-group-member-add-user-add-024.out"
                        rlAssertGrep "User ID: u11" "$TmpDir/pki-kra-group-member-add-user-add-024.out"
                        rlAssertGrep "Full name: fullNameu11" "$TmpDir/pki-kra-group-member-add-user-add-024.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add gr4 u11"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add gr4 u11 > $TmpDir/pki-kra-group-member-add-groupadd-024.out" \
                                    0 \
                                    "Adding user u11 to group gr4"
                        rlAssertGrep "Added group member \"u11\"" "$TmpDir/pki-kra-group-member-add-groupadd-024.out"
                        rlAssertGrep "User: u11" "$TmpDir/pki-kra-group-member-add-groupadd-024.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find gr4 > $TmpDir/pki-kra-group-member-add-groupadd-find-024.out" \
                                    0 \
                                    "User added to group gr4"
                        rlAssertGrep "User: u11" "$TmpDir/pki-kra-group-member-add-groupadd-find-024.out"
			#Deleting group gr4
			rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-del gr4"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-del gr4 > $TmpDir/pki-kra-group-member-add-groupdel-024.out" \
                                    0 \
                                    "Deleting group gr4"
			rlAssertGrep "Deleted group \"gr4\"" "$TmpDir/pki-kra-group-member-add-groupdel-024.out"
			#Checking for user-membership
			rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    user-membership-find u11"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    user-membership-find u11 > $TmpDir/pki-kra-group-member-add-usermembership-024.out" \
                                    0 \
                                    "Checking for user membership of u11"
			rlAssertGrep "0 entries matched" "$TmpDir/pki-kra-group-member-add-usermembership-024.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-kra-020: Add a group, add a user to the group and modify the group using valid admin user KRA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g5description\" g4"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g5description\" g4 > $TmpDir/pki-kra-group-member-add-group-add-025.out" \
                                   0 \
                                   "Adding group g4"
                       rlAssertGrep "Added group \"g4\"" "$TmpDir/pki-kra-group-member-add-group-add-025.out"
                        rlAssertGrep "Group ID: g4" "$TmpDir/pki-kra-group-member-add-group-add-025.out"
                        rlAssertGrep "Description: g5description" "$TmpDir/pki-kra-group-member-add-group-add-025.out"
                       rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu12\" u12"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu12\" u12 > $TmpDir/pki-kra-group-member-add-user-add-025.out" \
                                   0 \
                                   "Adding user u12"
                        rlAssertGrep "Added user \"u12\"" "$TmpDir/pki-kra-group-member-add-user-add-025.out"
                        rlAssertGrep "User ID: u12" "$TmpDir/pki-kra-group-member-add-user-add-025.out"
                        rlAssertGrep "Full name: fullNameu12" "$TmpDir/pki-kra-group-member-add-user-add-025.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g4 u12"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g4 u12 > $TmpDir/pki-kra-group-member-add-groupadd-025.out" \
                                    0 \
                                    "Adding user u12 to group g4"
                        rlAssertGrep "Added group member \"u12\"" "$TmpDir/pki-kra-group-member-add-groupadd-025.out"
                        rlAssertGrep "User: u12" "$TmpDir/pki-kra-group-member-add-groupadd-025.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-find g4 > $TmpDir/pki-kra-group-member-add-groupadd-find-025.out" \
                                    0 \
                                    "User added to group g5"
                        rlAssertGrep "User: u12" "$TmpDir/pki-kra-group-member-add-groupadd-find-025.out"
                        #Modifying group g4
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-mod g4 --decription=\"Modified group\""
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-mod g4 --description=\"Modified group\" > $TmpDir/pki-kra-group-member-add-groupmod-025.out" \
                                    0 \
                                    "Modifying group g4"
                        rlAssertGrep "Modified group \"g4\"" "$TmpDir/pki-kra-group-member-add-groupmod-025.out"
			rlAssertGrep "Group ID: g4" "$TmpDir/pki-kra-group-member-add-groupmod-025.out"
        		rlAssertGrep "Description: Modified group" "$TmpDir/pki-kra-group-member-add-groupmod-025.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-kra-021: Add a group, add a user to the group, run user-membership-del on the user and run group-member-find using valid admin user KRA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g5description\" g5"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   group-add --description=\"g6description\" g5 > $TmpDir/pki-kra-group-member-add-group-add-026.out" \
                                   0 \
                                   "Adding group g5"
                       rlAssertGrep "Added group \"g5\"" "$TmpDir/pki-kra-group-member-add-group-add-026.out"
                        rlAssertGrep "Group ID: g5" "$TmpDir/pki-kra-group-member-add-group-add-026.out"
                        rlAssertGrep "Description: g6description" "$TmpDir/pki-kra-group-member-add-group-add-026.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu13\" u13"
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                   user-add --fullName=\"fullNameu13\" u13 > $TmpDir/pki-kra-group-member-add-user-add-026.out" \
                                   0 \
                                   "Adding user u13"
                        rlAssertGrep "Added user \"u13\"" "$TmpDir/pki-kra-group-member-add-user-add-026.out"
                        rlAssertGrep "User ID: u13" "$TmpDir/pki-kra-group-member-add-user-add-026.out"
                        rlAssertGrep "Full name: fullNameu13" "$TmpDir/pki-kra-group-member-add-user-add-026.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                    group-member-add g5 u13"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                              group-member-add g5 u13 > $TmpDir/pki-kra-group-member-add-groupadd-026.out 2>&1" \
                                    0 \
                                    "Adding user u13 to group g5"
                        rlAssertGrep "Added group member \"u13\"" "$TmpDir/pki-kra-group-member-add-groupadd-026.out"
                        rlAssertGrep "User: u13" "$TmpDir/pki-kra-group-member-add-groupadd-026.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                                group-member-find g5 > $TmpDir/pki-kra-group-member-add-groupadd-find-026.out" \
                                    0 \
                                    "User added to group g5"
                        rlAssertGrep "User: u13" "$TmpDir/pki-kra-group-member-add-groupadd-find-026.out"
			#run user-membership-del on u13
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                              user-membership-del u13 g5 > $TmpDir/pki-kra-group-member-add-user-membership-del-026.out" \
				    0 \
				    "user-membership-del on u13"
			rlAssertGrep "Deleted membership in group \"g5\"" "$TmpDir/pki-kra-group-member-add-user-membership-del-026.out"
			#find group members
			rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                              group-member-find g5 > $TmpDir/pki-kra-group-member-add-group-member-find-026.out" \
                                    0 \
                                    "Find member in group g5"
			rlAssertGrep "0 entries matched" "$TmpDir/pki-kra-group-member-add-group-member-find-026.out"
	rlPhaseEnd
	rlPhaseStartTest "pki_group_cli_group_member-add-cleanup-kra-001: Deleting the temp directory and users and groups"
		#===Deleting users created using KRA_adminV cert===#
		i=1
		while [ $i -lt 15 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
			user-del  u$i > $TmpDir/pki-user-del-kra-group-member-add-user-del-kra-00$i.out" \
				   0 \
				   "Deleting user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-kra-group-member-add-user-del-kra-00$i.out"
			let i=$i+1
		done
		i=1
		while [ $i -lt 6 ] ; do
                       rlRun "pki -d $CERTDB_DIR \
				  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                             group-del  g$i > $TmpDir/pki-user-del-kra-group-member-add-group-del-kra-00$i.out" \
                                   0 \
                                   "Deleting group g$i"
                        rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-user-del-kra-group-member-add-group-del-kra-00$i.out"
                        let i=$i+1
                done
	   	rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-del userall > $TmpDir/pki-group-del-kra-group-member-add-user-del-kra-userall-001.out" \
                            0 \
                            "Deleting user userall"
               	rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-group-del-kra-group-member-add-user-del-kra-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-del user1 >  $TmpDir/pki-user-del-kra-group-member-add-user-del-kra-user1-001.out" \
                            0 \
                            "Deleting user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-kra-group-member-add-user-del-kra-user1-001.out"
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
                            user-del us19 >  $TmpDir/pki-user-del-kra-group-member-add-user-del-kra-u13-001.out" \
                            0 \
                            "Deleting user us19"
                rlAssertGrep "Deleted user \"us19\"" "$TmpDir/pki-user-del-kra-group-member-add-user-del-kra-u13-001.out"
		#===Deleting users created using KRA_adminV cert===#
       		i=1
	        while [ $i -lt 2 ] ; do
        		rlRun "pki -d $CERTDB_DIR \
				   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                   -p $KRA_PORT \
                    -t kra \
          	                    user-del  testuser$i > $TmpDir/pki-group-member-add-kra-user-00$i.out" \
                   	            0 \
	                           "Deleting user testuser$i"
	                rlAssertGrep "Deleted user \"testuser$i\"" "$TmpDir/pki-group-member-add-kra-user-00$i.out"
                	let i=$i+1
       		done

		#===Deleting i18n group created using KRA_adminV cert===#
		rlRun "pki -d $CERTDB_DIR \
			-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $KRA_HOST \
                    -p $KRA_PORT \
                    -t kra \
	                group-del 'dadministʁasjɔ̃' > $TmpDir/pki-group-del-kra-group-i18n_1.out" \
        	        0 \
                	"Deleting group dadministʁasjɔ̃"
	        rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-group-del-kra-group-i18n_1.out"

		Delete temporary directory
		rlRun "popd"
		rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
