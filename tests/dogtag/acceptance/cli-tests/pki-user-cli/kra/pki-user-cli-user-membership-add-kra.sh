#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cli-user-membership-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-membership-add    Add  KRA user membership.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com> 
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2015 Red Hat, Inc. All rights reserved.
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
. /opt/rhqa_pki/pki-key-cli-lib.sh
. /opt/rhqa_pki/env.sh
######################################################################################
#create_role_users.sh should be first executed prior to pki-user-cli-user-membership-add-kra.sh
######################################################################################

########################################################################
run_pki-user-cli-user-membership-add-kra_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	caId=$4
	CA_HOST=$5
	# Creating Temporary Directory for pki user-kra
        rlPhaseStartSetup "pki user-kra Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $MYROLE $TmpDir/topo_file
        local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
        kra_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$KRA_INST
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                prefix=KRA3
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	untrusted_cert_nickname=role_user_UTCA

if [ "$kra_instance_created" = "TRUE" ] ;  then
	#Local variables
	groupid1="Data Recovery Manager Agents"
        groupid2="Subsystem Group"
        groupid3="Trusted Managers"
        groupid4="Administrators"
        groupid5="Auditors"
        groupid6="ClonedSubsystems"
        groupid7="Security Domain Administrators"
        groupid8="Enterprise KRA Administrators"

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-002: pki user-membership configuration test"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-membership > $TmpDir/pki_user_membership_cfg.out 2>&1" \
                        0 \
                       "pki user-membership"
                rlAssertGrep "Commands:" "$TmpDir/pki_user_membership_cfg.out"
                rlAssertGrep "user-membership-find    Find user memberships" "$TmpDir/pki_user_membership_cfg.out"
                rlAssertGrep "user-membership-add     Add user membership" "$TmpDir/pki_user_membership_cfg.out"
                rlAssertGrep "user-membership-del     Remove user membership" "$TmpDir/pki_user_membership_cfg.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-003: pki user-membership-add --help configuration test"
        	rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-membership-add --help > $TmpDir/pki_user_membership_add_cfg.out 2>&1" \
               		0 \
	               "pki user-membership-add --help"
        	rlAssertGrep "usage: user-membership-add <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_add_cfg.out"
	        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_add_cfg.out"
   	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-004: pki user-membership-add configuration test"
                rlRun "pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-membership-add > $TmpDir/pki_user_membership_add_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-add"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_user_membership_add_2_cfg.out"
                rlAssertGrep "usage: user-membership-add <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_add_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_add_2_cfg.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-005: Add users to available groups using valid admin user KRA_adminV"
		i=1
		while [ $i -lt 9 ] ; do
		       rlLog "pki -d $CERTDB_DIR \
                                  -n ${KRA_INST}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
	    	 		  -h $SUBSYSTEM_HOST \
	 	  		  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t kra \
                                   user-add --fullName=\"fullNameu$i\" u$i "
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${KRA_INST}_adminV \
				  -c $CERTDB_DIR_PASSWORD \
		 		  -h $SUBSYSTEM_HOST \
				  -t kra \
		 		  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-user-membership-add-user-add-kra-00$i.out" \
				   0 \
				   "Adding user u$i"
			rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-user-membership-add-user-add-kra-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-add-kra-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-add-kra-00$i.out"
			rlLog "Showing the user"
			rlRun "pki -d $CERTDB_DIR \
				   -n ${KRA_INST}_adminV \
				   -c $CERTDB_DIR_PASSWORD \
		    		   -h $SUBSYSTEM_HOST \
		 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
				    user-show u$i > $TmpDir/pki-user-membership-add-user-show-kra-00$i.out" \
				    0 \
				    "Show pki KRA_adminV user"
			rlAssertGrep "User \"u$i\"" "$TmpDir/pki-user-membership-add-user-show-kra-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-show-kra-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-show-kra-00$i.out"
			rlLog "Adding the user to a group"
			eval gid=\$groupid$i
			rlLog "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
		 		   -h $SUBSYSTEM_HOST \
		 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
                                    user-membership-add u$i \"$gid\""
			rlRun "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
		 		   -h $SUBSYSTEM_HOST \
		 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
                                    user-membership-add u$i \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-kra-00$i.out" \
                                    0 \
                                    "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-kra-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-kra-00$i.out"
			rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
		 		   -h $SUBSYSTEM_HOST \
		 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
                                    user-membership-find u$i > $TmpDir/pki-user-membership-add-groupadd-find-kra-00$i.out" \
                                    0 \
                                    "User added to group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-kra-00$i.out"
	                let i=$i+1
		done
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-006: Add a user to all available groups using KRA_adminV"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
	 	  	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-user-membership-add-user-add-kra-userall-001.out" \
                            0 \
                            "Adding user userall"
		rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-user-membership-add-user-add-kra-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-add-user-add-kra-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-add-user-add-kra-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-show userall > $TmpDir/pki-user-membership-add-user-show-kra-userall-001.out" \
                            0 \
                            "Show pki KRA_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-user-membership-add-user-show-kra-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-add-user-show-kra-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-add-user-show-kra-userall-001.out"
                rlLog "Adding the user to all the groups"
		i=1
		while [ $i -lt 9 ] ; do
			eval gid=\$groupid$i
			rlLog "pki -d $CERTDB_DIR \
				   -n ${KRA_INST}_adminV \
				   -c $CERTDB_DIR_PASSWORD \
	 			   -h $SUBSYSTEM_HOST \
		 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
				    user-membership-add userall \"$gid\""
			rlRun "pki -d $CERTDB_DIR \
				   -n ${KRA_INST}_adminV \
				   -c $CERTDB_DIR_PASSWORD \
	 		  	   -h $SUBSYSTEM_HOST \
	 		     	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
				    user-membership-add userall \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-kra-userall-00$i.out" \
				    0 \
				    "Adding user userall to group \"$gid\""
			rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-kra-userall-00$i.out"
			rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-kra-userall-00$i.out"
			rlLog "Check if the user is added to the group"
			rlRun "pki -d $CERTDB_DIR \
 				   -n ${KRA_INST}_adminV \
				   -c $CERTDB_DIR_PASSWORD \
		 		   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t kra \
				    user-membership-find userall > $TmpDir/pki-user-membership-add-groupadd-find-kra-userall-00$i.out" \
				    0 \
				    "User added to group \"$gid\""
			rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-kra-userall-00$i.out"
			let i=$i+1
                done
	rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-007: Add a user to same group multiple times"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-user-membership-add-user-add-kra-user1-001.out" \
                            0 \
                            "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-user-membership-add-user-add-kra-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-user-membership-add-user-add-kra-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-user-membership-add-user-add-kra-user1-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-show user1 > $TmpDir/pki-user-membership-add-user-show-kra-user1-001.out" \
                            0 \
                            "Show pki KRA_adminV user"
                rlAssertGrep "User \"user1\"" "$TmpDir/pki-user-membership-add-user-show-kra-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-user-membership-add-user-show-kra-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-user-membership-add-user-show-kra-user1-001.out"
                rlLog "Adding the user to the same groups twice"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-add user1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-kra-user1-001.out" \
                            0 \
                            "Adding user userall to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-kra-user1-001.out"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${KRA_INST}_adminV -c $CERTDB_DIR_PASSWORD -t kra user-membership-add user1 \"Administrators\"" 
		rlLog "Executing: $command"
		errmsg="ConflictingOperationException: Attribute or value exists."
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - cannot add user to the same group more than once"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-008: should not be able to add user to a non existing group"
		dummy_group="nonexisting_bogus_group"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-user-membership-add-user-add-kra-user1-008.out" \
                            0 \
                            "Adding user testuser1"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${KRA_INST}_adminV -c $CERTDB_DIR_PASSWORD  -t kra user-membership-add testuser1 \"$dummy_group\""
                rlLog "Executing: $command"
                errmsg="GroupNotFoundException: Group $dummy_group not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - should not be able to add user to a non existing group"
	rlPhaseEnd	

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-009: Should be able to user-membership-add user name with i18n characters"
		rlLog "user-add user fullname ÖrjanÄke with i18n characters"
	        rlLog "pki -d $CERTDB_DIR \
        	           -n ${KRA_INST}_adminV \
                	   -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
	                    user-add --fullName='ÖrjanÄke' u9"
        	rlRun "pki -d $CERTDB_DIR \
                	   -n ${KRA_INST}_adminV \
	                   -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
			   -t kra \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
        	            user-add --fullName='ÖrjanÄke' u9" \
                	    0 \
	                    "Adding user name ÖrjanÄke with i18n characters"
		rlLog "Adding the user to the Adminstrators group"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${KRA_INST}_adminV -c $CERTDB_DIR_PASSWORD -t kra  user-membership-add u9 \"Administrators\""
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-user-membership-add-groupadd-kra-009_2.out" \
                            0 \
                            "Adding user with fullname ÖrjanÄke to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-kra-009_2.out"	
		rlAssertGrep "Group: Administrators" "$TmpDir/pki-user-membership-add-groupadd-kra-009_2.out"
                rlLog "Check if the user is added to the group"
		command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${KRA_INST}_adminV -c $CERTDB_DIR_PASSWORD -t kra user-membership-find u9"
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-user-membership-add-groupadd-find-kra-009_3.out" \
                	0 \
                        "Check user with fullname ÖrjanÄke added to group Administrators"
                rlAssertGrep "Group: Administrators" "$TmpDir/pki-user-membership-add-groupadd-find-kra-009_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-010: Should be able to user-membership-add user to group id with i18n characters"
                rlLog "user-add user fullname Éric Têko with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-add --fullName='Éric Têko' u10"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
			   -t kra \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            user-add --fullName='Éric Têko' u10" \
                            0 \
                            "Adding user fullname ÉricTêko with i18n characters"
		rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
	 		   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-user-membership-add-groupadd-kra-010_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-kra-010_1.out"   
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-kra-010_1.out"   
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-user-membership-add-groupadd-kra-010_1.out"
                rlLog "Adding the user to the dadministʁasjɔ̃ group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-add u10 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-add-groupadd-kra-010_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-kra-010_2.out"    
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-kra-010_2.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
	 			   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   	   -t kra \
                                    user-membership-find u10 > $TmpDir/pki-user-membership-add-groupadd-find-kra-010_3.out" \
                                    0 \
                                    "Check user ÉricTêko added to group dadministʁasjɔ̃"
                        rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-find-kra-010_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-011: Should not be able to user-membership-add using a revoked cert KRA_adminR"
                command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${KRA_INST}_adminR -c $CERTDB_DIR_PASSWORD -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using a revoked cert KRA_adminR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
        	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-012: Should not be able to user-membership-add using an agent with revoked cert KRA_agentR"
		command="pki -d $CERTDB_DIR -n ${KRA_INST}_agentR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -c $CERTDB_DIR_PASSWORD -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using an agent with revoked cert KRA_agentR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-013: Should not be able to user-membership-add using admin user with expired cert KRA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${KRA_INST}_adminE -c $CERTDB_DIR_PASSWORD -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using admin user with expired cert KRA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-014: Should not be able to user-membership-add using KRA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${KRA_INST}_agentE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using KRA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-015: Should not be able to user-membership-add using KRA_auditV cert"
                command="pki -d $CERTDB_DIR -n ${KRA_INST}_auditV -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -c $CERTDB_DIR_PASSWORD -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using KRA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-016: Should not be able to user-membership-add using KRA_operatorV cert"
                command="pki -d $CERTDB_DIR -n ${KRA_INST}_operatorV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using KRA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-017: Should not be able to user-membership-add using KRA_admin_UTCA cert"
		command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n $untrusted_cert_nickname -c $UNTRUSTED_CERT_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-membership-add testuser1 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-add using role_user_UTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd


	#Usability tests
	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-018: User associated with Administrators group only can create a new user"
		local user2="testuser2"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $SUBSYSTEM_HOST \
                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t kra \
                            user-add --fullName=\"fullName_user2\" $user2 > $TmpDir/pki-user-membership-add-user-add-kra-user2-018.out" \
                            0 \
                            "Adding user $user2"
		i=1
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
			rlLog "$gid"
			if [ "$gid" = "Administrators" ] ; then
				rlLog "Not adding $user2 to $gid group"
			else
	                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
	 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   	   -t kra \
                                    user-membership-add $user2 \"$gid\""
        	                rlRun "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
	 			   -h $SUBSYSTEM_HOST \
	 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   	   -t kra \
                                    user-membership-add $user2 \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-kra-$user2-00$i.out" \
                                    0 \
                                    "Adding user to all groups except administrators group \"$gid\""
                	        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-kra-$user2-00$i.out"
                        	rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-kra-$user2-00$i.out"
			fi
                        let i=$i+1
                done
		rlLog "Check users group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-find $user2 > $TmpDir/pki-user-membership-find-groupadd-find-kra-$user2-019.out" \
                            0 \
                            "Find user-membership to groups of $user2"
		rlAssertGrep "7 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-kra-$user2-019.out"
                rlAssertGrep "Number of entries returned 7" "$TmpDir/pki-user-membership-find-groupadd-find-kra-$user2-019.out"
		i=1
                while [ $i -lt 9 ] ; do
			eval gid=\$groupid$i
			if [ "$gid" = "Administrators" ] ; then
				rlAssertNotGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-kra-$user2-019.out"
				rlLog "$user2 is not added to $gid"
			else
	                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-kra-$user2-019.out"
			fi
                        let i=$i+1
                done

		#Create a user cert
 	        local TEMP_NSS_DB="$TmpDir/nssdb"
 	        local TEMP_NSS_DB_PASSWORD="Password"
	        local ret_reqstatus
        	local ret_requestid
	        local valid_serialNumber
        	local temp_out="$TmpDir/usercert-show.out"
		local requestdn
	        rlRun "create_cert_request $TEMP_NSS_DB $TEMP_NSS_DB_PASSWORD pkcs10 rsa 2048 \"test User2\" \"$user2\" \
        	        \"$user2@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $CA_HOST $(eval echo \$${caId}_UNSECURE_PORT) $requestdn $KRA_INST" 0 "Generating  pkcs10 Certificate Request"
	        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) -n \"${caId}_agentV\" ca-cert-request-review $ret_requestid \
        	        --action approve 1"
	        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
        	        --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
	        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        	rlLog "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
	        rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        	valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
	        rlLog "valid_serialNumber=$valid_serialNumber"

        	#Import user certs to $TEMP_NSS_DB
	        rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
        	rlRun "certutil -d $TEMP_NSS_DB -A -n $user2 -i $temp_out  -t \"u,u,u\""

		#Add certificate to the user
		rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_019_1.pem"
		rlRun "pki -d $CERTDB_DIR/ \
			   -n \"${KRA_INST}_adminV\" \
			   -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
			    user-cert-add $user2 --input $TmpDir/validcert_019_1.pem  > $TmpDir/useraddcert_019_2.out" \
			    0 \
			    "Cert is added to the user $user2"
		#Trying to add a user using $user2 should fail since $user2 is not in Administrators group
	        local expfile="$TmpDir/expfile_$user2.out"	
		echo "spawn -noecho pki -d $TEMP_NSS_DB -n $user2 -c $TEMP_NSS_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t kra user-add --fullName=test_user u39" > $expfile
	        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on '$(eval echo \$${subsystemId}_SSL_SERVER_CERT_SUBJECT_NAME)' indicates a non-trusted CA cert '$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)'
Import CA certificate (Y/n)? \"" >> $expfile
        	echo "send -- \"Y\r\"" >> $expfile
	        echo "expect \"CA server URI \[http://$HOSTNAME:8080/ca\]: \"" >> $expfile
        	echo "send -- \"http://$HOSTNAME:$(eval echo \$${caId}_UNSECURE_PORT)/ca\r\"" >> $expfile
	        echo "expect eof" >> $expfile
		echo "catch wait result" >> $expfile
	        echo "exit [lindex \$result 3]" >> $expfile
        	rlRun "/usr/bin/expect -f $expfile 2>&1 >  $TmpDir/pki-user-add-kra-$user2-002.out"  255 "Should not be able to add users using a non Administrator user"
	        rlAssertGrep "ForbiddenException: Authorization Error" "$TmpDir/pki-user-add-kra-$user2-002.out"

		#Add $user2 to Administrators group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-add $user2 \"$groupid4\" > $TmpDir/pki-user-membership-add-groupadd-kra-usertest2-019_2.out" \
                            0 \
                            "Adding user $user2 to group \"$groupid4\""
                rlAssertGrep "Added membership in \"$groupid4\"" "$TmpDir/pki-user-membership-add-groupadd-kra-usertest2-019_2.out"
                rlAssertGrep "Group: $groupid4" "$TmpDir/pki-user-membership-add-groupadd-kra-usertest2-019_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-find $user2 > $TmpDir/pki-user-membership-add-groupadd-find-kra-usertest1-019_3.out" \
                            0 \
                            "Check user-membership to group \"$groupid4\""
                rlAssertGrep "Group: $groupid4" "$TmpDir/pki-user-membership-add-groupadd-find-kra-usertest1-019_3.out"
	
		#Trying to add a user using $user2 should succeed now since $user2 is in Administrators group
		rlRun "pki -d $TEMP_NSS_DB \
                           -n $user2 \
                           -c $TEMP_NSS_DB_PASSWORD \
	 		   -h $SUBSYSTEM_HOST \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
			    user-add --fullName=test_user u19 > $TmpDir/pki-user-add-kra-019_4.out" \
                            0 \
                           "Added new user using Admin user $user2"
      		rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-user-add-kra-019_4.out"
	        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-add-kra-019_4.out"
        	rlAssertGrep "Full name: test_user" "$TmpDir/pki-user-add-kra-019_4.out"
	rlPhaseEnd	

	#Usability test
	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-019: User associated with Certificate Manager Agents group only perform asymmetric key recovery"
		local user3="testuser3"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $SUBSYSTEM_HOST \
                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t kra \
                            user-add --fullName=\"fullName_user3\" $user3 > $TmpDir/pki-user-membership-add-user-add-kra-user3-019.out" \
                            0 \
                            "Adding user $user3"
		i=2
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                   -h $SUBSYSTEM_HOST \
                                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   -t kra \
                                    user-membership-add $user3 \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${KRA_INST}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
                                   -h $SUBSYSTEM_HOST \
                                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   -t kra \
                                    user-membership-add $user3 \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-kra-$user3-00$i.out" \
                                    0 \
                                    "Adding user to all groups except Data Recovery Manager Agents group - now adding to \"$gid\""
                                rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-kra-$user3-00$i.out"
                                rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-kra-$user3-00$i.out"
                        let i=$i+1
                done	

		#Create a user cert
                local TEMP_NSS_DB="$TmpDir/nssdb"
                local TEMP_NSS_DB_PASSWORD="Password"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
                local temp_out="$TmpDir/usercert-show.out"
                local requestdn
                rlRun "create_cert_request $TEMP_NSS_DB $TEMP_NSS_DB_PASSWORD pkcs10 rsa 2048 \"test User3\" \"$user3\" \
                        \"$user3@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $CA_HOST $(eval echo \$${caId}_UNSECURE_PORT) $requestdn $KRA_INST" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) -n \"${caId}_agentV\" ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
                rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
                rlLog "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"

                #Import user certs to $TEMP_NSS_DB
                rlRun "pki -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
                rlRun "certutil -d $TEMP_NSS_DB -A -n $user3 -i $temp_out  -t \"u,u,u\""

                #Add certificate to the user
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_020_1.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n \"${KRA_INST}_adminV\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $SUBSYSTEM_HOST \
                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t kra \
                            user-cert-add $user3 --input $TmpDir/validcert_020_1.pem  > $TmpDir/useraddcert_020_2.out" \
                            0 \
                            "Cert is added to the user $user3"
	
		rlLog "Check $user3 is not in group Certificate Manager Agents"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-find $user3 > $TmpDir/pki-user-membership-add-groupadd-find-kra-usertest3-020_1.out" \
                            0 \
                            "Check user-membership to group \"$groupid1\""
                rlAssertNotGrep "Group: $groupid1" "$TmpDir/pki-user-membership-add-groupadd-find-kra-usertest3-020_1.out"          

        	#Trying to perform Asymmetric key recovery using $user3's cert should fail
		local rand=$RANDOM
		local client_id=temp$rand
		local algo=AES
		local action=NULL
		local key_size=128
		local usages=wrap
		local key_generate_output=$TmpDir/key-generate.out
		local key_recover_output=$TmpDir/key-recover.out
		local key_recover_output_2=$TmpDir/key-recover-2.out
		rlRun "generate_key $client_id $algo $key_size $usages $action $SUBSYSTEM_HOST $(eval echo \$${subsystemId}_UNSECURE_PORT) ${KRA_INST}_agentV $key_generate_output" \
		0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
		local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')

		rlLog "Executing pki -d $TEMP_NSS_DB \
	                -c $TEMP_NSS_DB_PASSWORD \
        	        -h $SUBSYSTEM_HOST \
                	-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
	                -n \"$user3\" \
			-t kra \
        	         kra-key-recover --keyID $key_id > $key_recover_output"
		command="pki -d $TEMP_NSS_DB -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n $user3 -c $TEMP_NSS_DB_PASSWORD -t kra kra-key-recover --keyID $key_id "

                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Asymmetric key recovery using $user3's cert should fail"
		#Add user $user3 to Certificate Manager Agents group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-add $user3 \"$groupid1\" > $TmpDir/pki-user-membership-add-groupadd-kra-usertest3-020_3.out" \
                            0 \
                            "Adding user $user3 to group \"$groupid1\""
                rlAssertGrep "Added membership in \"$groupid1\"" "$TmpDir/pki-user-membership-add-groupadd-kra-usertest3-020_3.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-user-membership-add-groupadd-kra-usertest3-020_3.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-membership-find $user3 > $TmpDir/pki-user-membership-add-groupadd-find-kra-usertest3-020_4.out" \
                            0 \
                            "Check user-membership to group \"$groupid1\""
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-user-membership-add-groupadd-find-kra-usertest3-020_4.out"          

        	#Trying to perform Asymmetric key recovery using $user3's cert should succeed
		 rlLog "Executing pki -d $TEMP_NSS_DB \
                        -c $TEMP_NSS_DB_PASSWORD \
                        -h $SUBSYSTEM_HOST \
                        -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                        -n \"$user3\" \
			-t kra \
                        kra-key-recover --keyID $key_id > $key_recover_output"
                rlRun "pki -d $TEMP_NSS_DB \
                        -c $TEMP_NSS_DB_PASSWORD \
                        -h $SUBSYSTEM_HOST  \
                        -p $(eval echo \$${subsystemId}_UNSECURE_PORT)  \
			-t kra \
                        -n \"$user3\" \
                        kra-key-recover --keyID $key_id > $key_recover_output_2" 0 "Recover key $key_id as $user3 cert"
                local recover_request_id=$(cat $key_recover_output_2 | grep "Request ID" | awk -F ": " '{print $2}')
                rlAssertGrep "Key ID: $key_id" "$key_recover_output_2"
                rlAssertGrep "Type: securityDataRecovery" "$key_recover_output_2"
                rlAssertGrep "Status: svc_pending" "$key_recover_output_2"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-add-KRA-020: Should not be able to add user-membership to user that does not exist"	
		user="testuser4"
		command="pki -d $CERTDB_DIR -n ${caId}_adminV  -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $(eval echo \$${caId}_UNSECURE_PORT) -t kra user-membership-add $user \"$groupid5\""
		rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add user-membership to user that does not exist"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1024"
	rlPhaseEnd

	rlPhaseStartCleanup "pki_user_cli_user_membership-add-kra-cleanup-001: Deleting the temp directory and users"
		#===Deleting users created using KRA_adminV cert===#
		i=1
		while [ $i -lt 11 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${KRA_INST}_adminV \
				  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   	  -t kra \
				   user-del  u$i > $TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-00$i.out" \
				   0 \
				   "Deleting user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-00$i.out"
			let i=$i+1
		done
	   	rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-del userall > $TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-userall-001.out" \
                            0 \
                            "Deleting user userall"
               	rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-del user1 >  $TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-user1-001.out" \
                            0 \
                            "Deleting user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-user1-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${KRA_INST}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t kra \
                            user-del u19 >  $TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-u19-001.out" \
                            0 \
                            "Deleting user u19"
                rlAssertGrep "Deleted user \"u19\"" "$TmpDir/pki-user-del-kra-user-membership-add-user-del-kra-u19-001.out"
		#===Deleting users created using KRA_adminV cert===#
       		i=1
	        while [ $i -lt 4 ] ; do
        		rlRun "pki -d $CERTDB_DIR \
                          	   -n ${KRA_INST}_adminV \
	                           -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   	   -t kra \
          	                    user-del  testuser$i > $TmpDir/pki-user-membership-add-kra-user-00$i.out" \
                   	            0 \
	                           "Deleting user testuser$i"
	                rlAssertGrep "Deleted user \"testuser$i\"" "$TmpDir/pki-user-membership-add-kra-user-00$i.out"
                	let i=$i+1
       		done

		#===Deleting i18n group created using KRA_adminV cert===#
		rlRun "pki -d $CERTDB_DIR \
        	        -n ${KRA_INST}_adminV \
                	-c $CERTDB_DIR_PASSWORD \
 			-h $SUBSYSTEM_HOST \
	 		-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			-t kra \
	                group-del 'dadministʁasjɔ̃' > $TmpDir/pki-user-del-kra-group-i18n_1.out" \
        	        0 \
                	"Deleting group dadministʁasjɔ̃"
	        rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-del-kra-group-i18n_1.out"

		#Delete temporary directory
		rlRun "popd"
		rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
 else
	rlLog "KRA instance not installed"
 fi
}
