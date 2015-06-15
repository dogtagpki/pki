#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cli-user-membership-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-membership-add    Add user membership.
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
#create_role_users.sh should be first executed prior to pki-user-cli-user-membership-add-ca.sh
######################################################################################

########################################################################
run_pki-user-cli-user-membership-add-ca_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3

	rlPhaseStartSetup "pki_user_cli_user_membership-add-CA-001: Create temporary directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	        rlRun "pushd $TmpDir"
	rlPhaseEnd

        get_topo_stack $MYROLE $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        ca_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$CA_INST
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                if [[ $CA_INST == SUBCA* ]]; then
                        prefix=$CA_INST
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                else
                        prefix=ROOTCA
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                fi
        else
                prefix=$MYROLE
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	untrusted_cert_nickname=role_user_UTCA

if [ "$ca_instance_created" = "TRUE" ] ;  then
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
	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-002: pki user-membership configuration test"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership > $TmpDir/pki_user_membership_cfg.out 2>&1" \
                        0 \
                       "pki user-membership"
                rlAssertGrep "Commands:" "$TmpDir/pki_user_membership_cfg.out"
                rlAssertGrep "user-membership-find    Find user memberships" "$TmpDir/pki_user_membership_cfg.out"
                rlAssertGrep "user-membership-add     Add user membership" "$TmpDir/pki_user_membership_cfg.out"
                rlAssertGrep "user-membership-del     Remove user membership" "$TmpDir/pki_user_membership_cfg.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-003: pki user-membership-add --help configuration test"
        	rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-add --help > $TmpDir/pki_user_membership_add_cfg.out 2>&1" \
               		0 \
	               "pki user-membership-add --help"
        	rlAssertGrep "usage: user-membership-add <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_add_cfg.out"
	        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_add_cfg.out"
   	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-004: pki user-membership-add configuration test"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-add > $TmpDir/pki_user_membership_add_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-add"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_user_membership_add_2_cfg.out"
                rlAssertGrep "usage: user-membership-add <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_add_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_add_2_cfg.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-005: Add users to available groups using valid admin user CA_adminV"
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
                                    "User added to group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-ca-00$i.out"
	                let i=$i+1
		done
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-006: Add a user to all available groups using CA_adminV"
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
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-show userall > $TmpDir/pki-user-membership-add-user-show-ca-userall-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-user-membership-add-user-show-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-add-user-show-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-add-user-show-ca-userall-001.out"
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
				    "User added to group \"$gid\""
			rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-ca-userall-00$i.out"
			let i=$i+1
                done
	rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-add-CA-007: Add a user to same group multiple times"
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
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-show user1 > $TmpDir/pki-user-membership-add-user-show-ca-user1-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"user1\"" "$TmpDir/pki-user-membership-add-user-show-ca-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-user-membership-add-user-show-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-user-membership-add-user-show-ca-user1-001.out"
                rlLog "Adding the user to the same groups twice"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add user1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out" \
                            0 \
                            "Adding user userall to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-user1-001.out"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-membership-add user1 \"Administrators\"" 
		rlLog "Executing: $command"
		errmsg="ConflictingOperationException: Attribute or value exists."
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - cannot add user to the same group more than once"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-008: should not be able to add user to a non existing group"
		dummy_group="nonexisting_bogus_group"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-user-membership-add-user-add-ca-user1-008.out" \
                            0 \
                            "Adding user testuser1"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-membership-add testuser1 \"$dummy_group\""
                rlLog "Executing: $command"
                errmsg="GroupNotFoundException: Group $dummy_group not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - should not be able to add user to a non existing group"
	rlPhaseEnd	

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-009: Should be able to user-membership-add user name with i18n characters"
		rlLog "user-add user fullname ÖrjanÄke with i18n characters"
	        rlLog "pki -d $CERTDB_DIR \
        	           -n ${prefix}_adminV \
                	   -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
	                    user-add --fullName='ÖrjanÄke' u15"
        	rlRun "pki -d $CERTDB_DIR \
                	   -n ${prefix}_adminV \
	                   -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
        	            user-add --fullName='ÖrjanÄke' u15" \
                	    0 \
	                    "Adding user name ÖrjanÄke with i18n characters"
		rlLog "Adding the user to the Adminstrators group"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-membership-add u15 \"Administrators\""
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-user-membership-add-groupadd-ca-009_2.out" \
                            0 \
                            "Adding user with fullname ÖrjanÄke to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-ca-009_2.out"	
		rlAssertGrep "Group: Administrators" "$TmpDir/pki-user-membership-add-groupadd-ca-009_2.out"
                rlLog "Check if the user is added to the group"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD user-membership-find u15"
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-user-membership-add-groupadd-find-ca-009_3.out" \
                	0 \
                        "Check user with fullname ÖrjanÄke added to group Administrators"
                rlAssertGrep "Group: Administrators" "$TmpDir/pki-user-membership-add-groupadd-find-ca-009_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-010: Should be able to user-membership-add user id with i18n characters"
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
                            "Adding user fullname ÉricTêko with i18n characters"
		rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-user-membership-add-groupadd-ca-010_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-ca-010_1.out"   
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-ca-010_1.out"   
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-user-membership-add-groupadd-ca-010_1.out"
                rlLog "Adding the user to the dadministʁasjɔ̃ group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add u16 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-add-groupadd-ca-010_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-ca-010_2.out"    
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-ca-010_2.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
	 			   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-find u16 > $TmpDir/pki-user-membership-add-groupadd-find-ca-010_3.out" \
                                    0 \
                                    "Check user ÉricTêko added to group dadministʁasjɔ̃"
                        rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-find-ca-010_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-011: Should not be able to user-membership-add using a revoked cert CA_adminR"
                command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using a revoked cert CA_adminR"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-012: Should not be able to user-membership-add using an agent with revoked cert CA_agentR"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -c $CERTDB_DIR_PASSWORD user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using an agent with revoked cert CA_agentR"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-013: Should not be able to user-membership-add using admin user with expired cert CA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using admin user with expired cert CA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-014: Should not be able to user-membership-add using CA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using CA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-015: Should not be able to user-membership-add using CA_auditV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_auditV -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -c $CERTDB_DIR_PASSWORD user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using CA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-016: Should not be able to user-membership-add using CA_operatorV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using CA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-017: Should not be able to user-membership-add using CA_admin_UTCA cert"
		command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n $untrusted_cert_nickname -c $UNTRUSTED_CERT_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using role_user_UTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd


	#Usability tests
	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-018: User associated with Administrators group only can create a new user"
		i=2
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
			if [ "$gid" = "Administrators" ] ; then
				rlLog "Not adding testuser1 to $gid group"
			else
	                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
	 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-add testuser1 \"$gid\""
        	                rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
	 			   -h $SUBSYSTEM_HOST \
	 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    user-membership-add testuser1 \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-ca-testuser1-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                	        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-ca-testuser1-00$i.out"
                        	rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-ca-testuser1-00$i.out"
			fi
                        let i=$i+1
                done
		rlLog "Check users group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-find testuser1 > $TmpDir/pki-user-membership-find-groupadd-find-ca-testuser1-019.out" \
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
		local requestdn
	        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User1\" \"testuser1\" \
        	        \"testuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $SUBSYSTEM_HOST $(eval echo \$${subsystemId}_UNSECURE_PORT) $requestdn $prefix" 0 "Generating  pkcs10 Certificate Request"
	        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n \"${prefix}_agentV\" ca-cert-request-review $ret_requestid \
        	        --action approve 1"
	        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${prefix}_agentV\" -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
        	        --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
	        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        	rlLog "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
	        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        	valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
	        rlLog "valid_serialNumber=$valid_serialNumber"

        	#Import user certs to $TEMP_NSS_DB
	        rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
        	rlRun "certutil -d $TEMP_NSS_DB -A -n testuser1 -i $temp_out  -t \"u,u,u\""

		#Add certificate to the user
		rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_019_1.pem"
		rlRun "pki -d $CERTDB_DIR/ \
			   -n \"${prefix}_adminV\" \
			   -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t ca \
			    user-cert-add testuser1 --input $TmpDir/validcert_019_1.pem  > $TmpDir/useraddcert_019_2.out" \
			    0 \
			    "Cert is added to the user testuser1"
		#Trying to add a user using testuser1 should fail since testuser1 is not in Administrators group
	        local expfile="$TmpDir/expfile_testuser1.out"	
		echo "spawn -noecho pki -d $TEMP_NSS_DB -n testuser1 -c Password -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-add --fullName=test_user u39" > $expfile
	        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on '$(eval echo \$${subsystemId}_SSL_SERVER_CERT_SUBJECT_NAME)' indicates a non-trusted CA cert '$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)'
Import CA certificate (Y/n)? \"" >> $expfile
        	echo "send -- \"Y\r\"" >> $expfile
	        echo "expect \"CA server URI \[http://$HOSTNAME:8080/ca\]: \"" >> $expfile
        	echo "send -- \"http://$HOSTNAME:$(eval echo \$${prefix}_UNSECURE_PORT)/ca\r\"" >> $expfile
	        echo "expect eof" >> $expfile
		echo "catch wait result" >> $expfile
	        echo "exit [lindex \$result 3]" >> $expfile
        	rlRun "/usr/bin/expect -f $expfile 2>&1 >  $TmpDir/pki-user-add-ca-testuser1-002.out"  255 "Should not be able to add users using a non Administrator user"
	        rlAssertGrep "ForbiddenException: Authorization Error" "$TmpDir/pki-user-add-ca-testuser1-002.out"

		#Add testuser1 to Administrators group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add testuser1 \"$groupid5\" > $TmpDir/pki-user-membership-add-groupadd-ca-usertest1-019_2.out" \
                            0 \
                            "Adding user testuser1 to group \"$groupid5\""
                rlAssertGrep "Added membership in \"$groupid5\"" "$TmpDir/pki-user-membership-add-groupadd-ca-usertest1-019_2.out"
                rlAssertGrep "Group: $groupid5" "$TmpDir/pki-user-membership-add-groupadd-ca-usertest1-019_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-find testuser1 > $TmpDir/pki-user-membership-add-groupadd-find-ca-usertest1-019_3.out" \
                            0 \
                            "Check user-membership to group \"$groupid5\""
                rlAssertGrep "Group: $groupid5" "$TmpDir/pki-user-membership-add-groupadd-find-ca-usertest1-019_3.out"
	
		#Trying to add a user using testuser1 should succeed now since testuser1 is in Administrators group
		rlRun "pki -d $TEMP_NSS_DB \
                           -n testuser1 \
                           -c Password \
	 		   -h $SUBSYSTEM_HOST \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    user-add --fullName=test_user u19 > $TmpDir/pki-user-add-ca-019_4.out" \
                            0 \
                           "Added new user using Admin user testuser1"
      		rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-user-add-ca-019_4.out"
	        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-add-ca-019_4.out"
        	rlAssertGrep "Full name: test_user" "$TmpDir/pki-user-add-ca-019_4.out"
	rlPhaseEnd	

	#Usability test
	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-019: User associated with Certificate Manager Agents group only can approve certificate requests"
		rlLog "Check testuser1 is not in group Certificate Manager Agents"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-find testuser1 > $TmpDir/pki-user-membership-add-groupadd-find-ca-usertest1-020_1.out" \
                            0 \
                            "Check user-membership to group \"$groupid1\""
                rlAssertNotGrep "Group: $groupid1" "$TmpDir/pki-user-membership-add-groupadd-find-ca-usertest1-020_1.out"          

		#Trying to approve a certificate request using testuser1 should fail
		local TEMP_NSS_DB="$TmpDir/nssdb"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
		local requestdn
                local temp_out="$TmpDir/usercert-show_20.out"
                rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"test User3\" \"testuser3\" \
                        \"testuser3@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $SUBSYSTEM_HOST $(eval echo \$${subsystemId}_UNSECURE_PORT) $requestdn $prefix" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid \
                        --action approve"
		command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $TEMP_NSS_DB -c Password -n \"testuser1\" ca-cert-request-review $ret_requestid --action approve"
		rlLog "Executing: $command"
		errmsg="Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Approve Certificate request using testuser1"
		
		#Add user testuser1 to Certificate Manager Agents group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-add testuser1 \"$groupid1\" > $TmpDir/pki-user-membership-add-groupadd-ca-usertest1-020_3.out" \
                            0 \
                            "Adding user testuser1 to group \"$groupid1\""
                rlAssertGrep "Added membership in \"$groupid1\"" "$TmpDir/pki-user-membership-add-groupadd-ca-usertest1-020_3.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-user-membership-add-groupadd-ca-usertest1-020_3.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-membership-find testuser1 > $TmpDir/pki-user-membership-add-groupadd-find-ca-usertest1-020_4.out" \
                            0 \
                            "Check user-membership to group \"$groupid1\""
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-user-membership-add-groupadd-find-ca-usertest1-020_4.out"          

        	#Trying to approve a certificate request using testuser1 should now succeed
		rlLog "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -d $TEMP_NSS_DB -c Password -n \"testuser1\" -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out-20_5.out" 0 "Approve Certificate request using testuser1"		
		rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out-20_5.out"
                rlLog "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1_20_6.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1_20_6.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-CA-020: Should not be able to add user-membership to user that does not exist"	
		user="testuser4"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV  -c $CERTDB_DIR_PASSWORD  -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-membership-add $user \"$groupid5\""
		rlLog "Executing: $command"
                errmsg="UserNotFoundException: User $user not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add user-membership to user that does not exist"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1024"
	rlPhaseEnd

	rlPhaseStartCleanup "pki_user_cli_user_membership-add-ca-cleanup-001: Deleting the temp directory and users"
		#===Deleting users created using CA_adminV cert===#
		i=1
		while [ $i -lt 17 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
				  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   user-del  u$i > $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-00$i.out" \
				   0 \
				   "Deleting user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-00$i.out"
			let i=$i+1
		done
	   	rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del userall > $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-userall-001.out" \
                            0 \
                            "Deleting user userall"
               	rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del user1 >  $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-user1-001.out" \
                            0 \
                            "Deleting user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-user1-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-del u19 >  $TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-u19-001.out" \
                            0 \
                            "Deleting user u19"
                rlAssertGrep "Deleted user \"u19\"" "$TmpDir/pki-user-del-ca-user-membership-add-user-del-ca-u19-001.out"
		#===Deleting users created using CA_adminV cert===#
       		i=1
	        while [ $i -lt 2 ] ; do
        		rlRun "pki -d $CERTDB_DIR \
                          	   -n ${prefix}_adminV \
	                           -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
          	                    user-del  testuser$i > $TmpDir/pki-user-membership-add-ca-user-00$i.out" \
                   	            0 \
	                           "Deleting user testuser$i"
	                rlAssertGrep "Deleted user \"testuser$i\"" "$TmpDir/pki-user-membership-add-ca-user-00$i.out"
                	let i=$i+1
       		done

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
