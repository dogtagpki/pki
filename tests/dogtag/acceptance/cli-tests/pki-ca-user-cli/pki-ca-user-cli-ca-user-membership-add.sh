#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: pki-ca-user-cli-ca-user-membership-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-user-cli-ca-user-membership-add    Add user membership.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com> 
#	     Laxmi Sunkara <lsunkara@redhat.com>
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-ca-user-cli-ca-user-membership-add.sh
######################################################################################

run_pki-ca-user-cli-ca-user-membership-add_tests(){
	#Local variables
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

	rlPhaseStartSetup "pki_ca_user_cli_ca_user_membership-add-001: Create temporary directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	        rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-002: pki user-membership configuration test"
                rlRun "pki user-membership > $TmpDir/pki_ca_user_membership_cfg.out 2>&1" \
                        0 \
                       "pki user-membership"
                rlAssertGrep "Commands:" "$TmpDir/pki_ca_user_membership_cfg.out"
                rlAssertGrep "ca-user-membership-find    Find user memberships" "$TmpDir/pki_ca_user_membership_cfg.out"
                rlAssertGrep "ca-user-membership-add     Add user membership" "$TmpDir/pki_ca_user_membership_cfg.out"
                rlAssertGrep "user-membership-del     Remove user membership" "$TmpDir/pki_ca_user_membership_cfg.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-003: pki ca-user-membership-add --help configuration test"
        	rlRun "pki ca-user-membership-add --help > $TmpDir/pki_ca_user_membership_add_cfg.out 2>&1" \
               		0 \
	               "pki ca-user-membership-add --help"
        	rlAssertGrep "usage: ca-user-membership-add <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_ca_user_membership_add_cfg.out"
	        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_ca_user_membership_add_cfg.out"
   	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-004: pki ca-user-membership-add configuration test"
                rlRun "pki ca-user-membership-add > $TmpDir/pki_ca_user_membership_add_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-add"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_ca_user_membership_add_2_cfg.out"
                rlAssertGrep "usage: ca-user-membership-add <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_ca_user_membership_add_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_ca_user_membership_add_2_cfg.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-005: Add users to available groups using valid admin user CA_adminV"
		i=1
		while [ $i -lt 15 ] ; do
		       rlLog "pki -d $CERTDB_DIR \
                                  -n CA_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
                                   ca-user-add --fullName=\"fullNameu$i\" u$i "
		       rlRun "pki -d $CERTDB_DIR \
				  -n CA_adminV \
				  -c $CERTDB_DIR_PASSWORD \
				   ca-user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-ca-user-membership-add-user-add-ca-00$i.out" \
				   0 \
				   "Adding user u$i"
			rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-ca-user-membership-add-user-add-ca-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-ca-user-membership-add-user-add-ca-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-ca-user-membership-add-user-add-ca-00$i.out"
			rlLog "Showing the user"
			rlRun "pki -d $CERTDB_DIR \
				   -n CA_adminV \
				   -c $CERTDB_DIR_PASSWORD \
				    ca-user-show u$i > $TmpDir/pki-ca-user-membership-ca-add-user-show-00$i.out" \
				    0 \
				    "Show pki CA_adminV user"
			rlAssertGrep "User \"u$i\"" "$TmpDir/pki-ca-user-membership-ca-add-user-show-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-ca-user-membership-ca-add-user-show-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-ca-user-membership-ca-add-user-show-00$i.out"
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
                                    ca-user-membership-find u$i > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-00$i.out" \
                                    0 \
                                    "User added to group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-00$i.out"
	                let i=$i+1
		done
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-006: Add a user to all available groups using CA_adminV"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-ca-user-membership-add-ca-user-add-userall-001.out" \
                            0 \
                            "Adding user userall"
		rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-ca-user-membership-add-ca-user-add-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-ca-user-membership-add-ca-user-add-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-ca-user-membership-add-ca-user-add-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-show userall > $TmpDir/pki-ca-user-membership-ca-add-user-show-userall-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-ca-user-membership-ca-add-user-show-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-ca-user-membership-ca-add-user-show-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-ca-user-membership-ca-add-user-show-userall-001.out"
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
				    ca-user-membership-add userall \"$gid\" > $TmpDir/pki-ca-user-membership-add-groupca-add-userall-00$i.out" \
				    0 \
				    "Adding user userall to group \"$gid\""
			rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-ca-user-membership-add-groupca-add-userall-00$i.out"
			rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupca-add-userall-00$i.out"
			rlLog "Check if the user is added to the group"
			rlRun "pki -d $CERTDB_DIR \
 				   -n CA_adminV \
				   -c $CERTDB_DIR_PASSWORD \
				    ca-user-membership-find userall > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-userall-00$i.out" \
				    0 \
				    "User added to group \"$gid\""
			rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-userall-00$i.out"
			let i=$i+1
                done
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-007: Add a user to same group multiple times"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-ca-user-membership-add-ca-user-add-user1-001.out" \
                            0 \
                            "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-ca-user-membership-add-ca-user-add-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-ca-user-membership-add-ca-user-add-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-ca-user-membership-add-ca-user-add-user1-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-show user1 > $TmpDir/pki-ca-user-membership-ca-add-user-show-user1-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"user1\"" "$TmpDir/pki-ca-user-membership-ca-add-user-show-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-ca-user-membership-ca-add-user-show-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-ca-user-membership-ca-add-user-show-user1-001.out"
                rlLog "Adding the user to the same groups twice"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add user1 \"Administrators\" > $TmpDir/pki-ca-user-membership-add-groupca-add-user1-001.out" \
                            0 \
                            "Adding user userall to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-ca-user-membership-add-groupca-add-user1-001.out"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD ca-user-membership-add user1 \"Administrators\"" 
		rlLog "Executing: $command"
		errmsg="ConflictingOperationException: Attribute or value exists."
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - cannot add user to the same group more than once"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-008: should not be able to add user to a non existing group"
		dummy_group="nonexisting_bogus_group"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-ca-user-membership-add-ca-user-add-user1-008.out" \
                            0 \
                            "Adding user testuser1"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"$dummy_group\""
                rlLog "Executing: $command"
                errmsg="GroupNotFoundException: Group $dummy_group not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - should not be able to add user to a non existing group"
	rlPhaseEnd	

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-009: Should be able to ca-user-membership-add user id with i18n characters"
		rlLog "ca-user-add userid ÖrjanÄke with i18n characters"
	        rlLog "pki -d $CERTDB_DIR \
        	           -n CA_adminV \
                	   -c $CERTDB_DIR_PASSWORD \
	                    ca-user-add --fullName=test 'ÖrjanÄke'"
        	rlRun "pki -d $CERTDB_DIR \
                	   -n CA_adminV \
	                   -c $CERTDB_DIR_PASSWORD \
        	            ca-user-add --fullName=test 'ÖrjanÄke'" \
                	    0 \
	                    "Adding uid ÖrjanÄke with i18n characters"
		rlLog "Adding the user to the Adminstrators group"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD ca-user-membership-add 'ÖrjanÄke' \"Administrators\""
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-ca-user-membership-add-groupadd-ca-009_2.out" \
                            0 \
                            "Adding user ÖrjanÄke to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-009_2.out"	
		rlAssertGrep "Group: Administrators" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-009_2.out"
                rlLog "Check if the user is added to the group"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD ca-user-membership-find 'ÖrjanÄke'"
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-009_3.out" \
                	0 \
                        "Check user ÖrjanÄke added to group Administrators"
                rlAssertGrep "Group: Administrators" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-009_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-010: Should be able to ca-user-membership-add user id with i18n characters"
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
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-ca-user-membership-add-groupadd-ca-010_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-010_1.out"   
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-010_1.out"   
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-010_1.out"
                rlLog "Adding the user to the dadministʁasjɔ̃ group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add 'ÉricTêko' \"dadministʁasjɔ̃\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-010_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-010_2.out"    
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-010_2.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-find 'ÉricTêko' > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-010_3.out" \
                                    0 \
                                    "Check user ÉricTêko added to group dadministʁasjɔ̃"
                        rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-010_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-011: Should not be able to ca-user-membership-add using a revoked cert CA_adminR"
                command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using a revoked cert CA_adminR"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-012: Should not be able to ca-user-membership-add using an agent with revoked cert CA_agentR"
		command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using an agent with revoked cert CA_agentR"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-013: Should not be able to ca-user-membership-add using admin user with expired cert CA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using admin user with expired cert CA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-014: Should not be able to ca-user-membership-add using CA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using CA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-015: Should not be able to ca-user-membership-add using CA_auditV cert"
                command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using CA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-016: Should not be able to ca-user-membership-add using CA_operatorV cert"
                command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using CA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-017: Should not be able to ca-user-membership-add using CA_adminUTCA cert"
		command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using CA_adminUTCA cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-018: Should not be able to ca-user-membership-add using CA_agentUTCA cert"
		command="pki -d /tmp/untrusted_cert_db -n CA_agentUTCA -c Password ca-user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to ca-user-membership-add using CA_agentUTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-019: User associated with Administrators group only can create a new user"
		i=2
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
			if [ "$gid" = "Administrators" ] ; then
				rlLog "Not adding testuser1 to $gid group"
			else
	                        rlLog "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-add testuser1 \"$gid\""
        	                rlRun "pki -d $CERTDB_DIR \
                                   -n CA_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                    ca-user-membership-add testuser1 \"$gid\" > $TmpDir/pki-ca-user-membership-add-groupadd-ca-testuser1-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                	        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-testuser1-00$i.out"
                        	rlAssertGrep "Group: $gid" "$TmpDir/pki-ca-user-membership-add-groupadd-ca-testuser1-00$i.out"
			fi
                        let i=$i+1
                done
		rlLog "Check users group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-find testuser1 > $TmpDir/pki-user-membership-find-groupadd-find-ca-testuser1-019.out" \
                            0 \
                            "Find user-membership to groups of testuser1"
		rlAssertGrep "12 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ca-testuser1-019.out"
                rlAssertGrep "Number of entries returned 12" "$TmpDir/pki-user-membership-find-groupadd-find-ca-testuser1-019.out"
		i=2
                while [ $i -lt 15 ] ; do
			eval gid=\$groupid$i
			if [ "$gid" = "Administrators" ] ; then
				rlLog "testuser1 is not added to $gid"
			else
	                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ca-testuser1-019.out"
			fi
                        let i=$i+1
                done

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
		rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_019_1.pem"
		rlRun "pki -d $CERTDB_DIR/ \
			   -n \"CA_adminV\" \
			   -c $CERTDB_DIR_PASSWORD \
			   -t ca \
			    user-cert-add testuser1 --input $TmpDir/validcert_019_1.pem  > $TmpDir/useraddcert_019_2.out" \
			    0 \
			    "Cert is added to the user testuser1"
		#Trying to add a user using testuser1 should fail since testuser1 is not in Administrators group
	        local expfile="$TmpDir/expfile_testuser1.out"	
		echo "spawn -noecho pki -d $TEMP_NSS_DB -n testuser1 -c Password ca-user-add --fullName=test_user u39" > $expfile
	        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        	echo "send -- \"Y\r\"" >> $expfile
	        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        	echo "send -- \"\r\"" >> $expfile
	        echo "expect eof" >> $expfile
		echo "catch wait result" >> $expfile
	        echo "exit [lindex \$result 3]" >> $expfile
        	rlRun "/usr/bin/expect -f $expfile 2>&1 >  $TmpDir/pki-user-add-ca-testuser1-002.out"  255 "Should not be able to add users using a non Administrator user"
	        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki-user-add-ca-testuser1-002.out"

		#Add testuser1 to Administrators group
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add testuser1 \"$groupid5\" > $TmpDir/pki-ca-user-membership-add-groupca-add-usertest1-019_2.out" \
                            0 \
                            "Adding user testuser1 to group \"$groupid5\""
                rlAssertGrep "Added membership in \"$groupid5\"" "$TmpDir/pki-ca-user-membership-add-groupca-add-usertest1-019_2.out"
                rlAssertGrep "Group: $groupid5" "$TmpDir/pki-ca-user-membership-add-groupca-add-usertest1-019_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-find testuser1 > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-usertest1-019_3.out" \
                            0 \
                            "Check user-membership to group \"$groupid5\""
                rlAssertGrep "Group: $groupid5" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-usertest1-019_3.out"
	
		#Trying to add a user using testuser1 should succeed now since testuser1 is in Administrators group
		rlRun "pki -d $TEMP_NSS_DB \
                           -n testuser1 \
                           -c Password \
			    ca-user-add --fullName=test_user u19 > $TmpDir/pki-user-add-ca-019_4.out" \
                            0 \
                           "Added new user using Admin user testuser1"
      		rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-user-add-ca-019_4.out"
	        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-add-ca-019_4.out"
        	rlAssertGrep "Full name: test_user" "$TmpDir/pki-user-add-ca-019_4.out"
	rlPhaseEnd	

	#Usability test
	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-020: User associated with Certificate Manager Agents group only can approve certificate requests"
		rlLog "Check testuser1 is not in group Certificate Manager Agents"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-find testuser1 > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-usertest1-020_1.out" \
                            0 \
                            "Check user-membership to group \"$groupid1\""
                rlAssertNotGrep "Group: $groupid1" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-usertest1-020_1.out"          

		#Trying to approve a certificate request using testuser1 should fail
		local TEMP_NSS_DB="$TmpDir/nssdb"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
                local temp_out="$TmpDir/usercert-show_20.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User3\" \"testuser3\" \
                        \"testuser3@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve"
		command="pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid --action approve"
		rlLog "Executing: $command"
		errmsg="Authorization failed on resource: certServer.ca.certrequests, operation: execute"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Approve Certificate request using testuser1"
		
		#Add user testuser1 to Certificate Manager Agents group
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-add testuser1 \"$groupid1\" > $TmpDir/pki-ca-user-membership-add-groupca-add-usertest1-020_3.out" \
                            0 \
                            "Adding user testuser1 to group \"$groupid1\""
                rlAssertGrep "Added membership in \"$groupid1\"" "$TmpDir/pki-ca-user-membership-add-groupca-add-usertest1-020_3.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-ca-user-membership-add-groupca-add-usertest1-020_3.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            ca-user-membership-find testuser1 > $TmpDir/pki-ca-user-membership-add-groupadd-find-ca-usertest1-020_4.out" \
                            0 \
                            "Check user-membership to group \"$groupid1\""
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-ca-user-membership-add-groupadd-find-ca-usertest1-020_4.out"          

        	#Trying to approve a certificate request using testuser1 should now succeed
		rlLog "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out-20_5.out" 0 "Approve Certificate request using testuser1"		
		rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out-20_5.out"
                rlLog "pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki cert-request-show $ret_requestid > $TmpDir/usercert-show1_20_6.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1_20_6.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_user_cli_ca_user_membership-add-021: Should not be able to add user-membership to user that does not exist"	
		user="testuser4"
		command="pki -d $CERTDB_DIR -n CA_adminV  -c $CERTDB_DIR_PASSWORD  ca-user-membership-add $user \"$groupid5\""
		rlLog "Executing: $command"
                errmsg="UserNotFoundException: User $user not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add user-membership to user that does not exist"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1024"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-ca-cleanup-001: Deleting the temp directory and users"
		#===Deleting users created using CA_adminV cert===#
		i=1
		while [ $i -lt 15 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n CA_adminV \
				  -c $CERTDB_DIR_PASSWORD \
				   user-del  u$i > $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-00$i.out" \
				   0 \
				   "Deleting user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-00$i.out"
			let i=$i+1
		done
	   	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-del userall > $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-userall-001.out" \
                            0 \
                            "Deleting user userall"
               	rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-del user1 >  $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-user1-001.out" \
                            0 \
                            "Deleting user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-user1-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-del u19 >  $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-u19-001.out" \
                            0 \
                            "Deleting user u19"
                rlAssertGrep "Deleted user \"u19\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-u19-001.out"
		#===Deleting users created using CA_adminV cert===#
       		i=1
	        while [ $i -lt 2 ] ; do
        		rlRun "pki -d $CERTDB_DIR \
                          	   -n CA_adminV \
	                           -c $CERTDB_DIR_PASSWORD \
          	                    user-del  testuser$i > $TmpDir/pki-ca-user-membership-ca-add-user-00$i.out" \
                   	            0 \
	                           "Deleting user testuser$i"
	                rlAssertGrep "Deleted user \"testuser$i\"" "$TmpDir/pki-ca-user-membership-ca-add-user-00$i.out"
                	let i=$i+1
       		done
		#===Deleting i18n users created using CA_adminV cert===#
        	rlRun "pki -d $CERTDB_DIR \
                	-n CA_adminV \
	                -c $CERTDB_DIR_PASSWORD \
        	        user-del 'ÖrjanÄke' > $TmpDir/pki-user-del-ca-user-i18n_1.out" \
                	0 \
	                "Deleting user ÖrjanÄke"
        	rlAssertGrep "Deleted user \"ÖrjanÄke\"" "$TmpDir/pki-user-del-ca-user-i18n_1.out"
        
	        rlRun "pki -d $CERTDB_DIR \
        	        -n CA_adminV \
                	-c $CERTDB_DIR_PASSWORD \
	                user-del 'ÉricTêko' > $TmpDir/pki-user-del-ca-user-i18n_2.out" \
        	        0 \
                	"Deleting user ÉricTêko"
	        rlAssertGrep "Deleted user \"ÉricTêko\"" "$TmpDir/pki-user-del-ca-user-i18n_2.out"

		#===Deleting i18n group created using CA_adminV cert===#
		rlRun "pki -d $CERTDB_DIR \
        	        -n CA_adminV \
                	-c $CERTDB_DIR_PASSWORD \
	                group-del 'dadministʁasjɔ̃' > $TmpDir/pki-user-del-ca-group-i18n_1.out" \
        	        0 \
                	"Deleting group dadministʁasjɔ̃"
	        rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-del-ca-group-i18n_1.out"

		#Delete temporary directory
		rlRun "popd"
		rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
