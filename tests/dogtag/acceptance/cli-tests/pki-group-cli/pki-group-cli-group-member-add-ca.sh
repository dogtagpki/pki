#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-cli-group-membership-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-member-add    Add group member.
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-group-cli-group-member-add-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################
run_pki-group-cli-group-member-add-ca_tests(){
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

	rlPhaseStartSetup "pki_group_cli_group_membership-add-CA-001: Create temporary directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	        rlRun "pushd $TmpDir"
	rlPhaseEnd

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3

if [ "$TOPO9" = "TRUE" ] ; then
        ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
        prefix=$subsystemId
        CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
elif [ "$MYROLE" = "MASTER" ] ; then
        if [[ $subsystemId == SUBCA* ]]; then
                ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
                prefix=$subsystemId
                CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
        else
                ADMIN_CERT_LOCATION=$ROOTCA_ADMIN_CERT_LOCATION
                prefix=ROOTCA
                CLIENT_PKCS12_PASSWORD=$ROOTCA_CLIENT_PKCS12_PASSWORD
        fi
else
        ADMIN_CERT_LOCATION=$(eval echo \$${MYROLE}_ADMIN_CERT_LOCATION)
        prefix=$MYROLE
        CLIENT_PKCS12_PASSWORD=$(eval echo \$${MYROLE}_CLIENT_PKCS12_PASSWORD)
fi

CA_HOST=$(eval echo \$${MYROLE})
CA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
local cert_info="$TmpDir/cert_info"

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-002: pki group-member configuration test"
                rlRun "pki group-member > $TmpDir/pki_group_member_cfg.out 2>&1" \
                        0 \
                       "pki group-member"
                rlAssertGrep "Commands:" "$TmpDir/pki_group_member_cfg.out"
                rlAssertGrep "group-member-find       Find group members" "$TmpDir/pki_group_member_cfg.out"
                rlAssertGrep "group-member-add        Add group member" "$TmpDir/pki_group_member_cfg.out"
                rlAssertGrep "group-member-del        Remove group member" "$TmpDir/pki_group_member_cfg.out"
		rlAssertGrep "group-member-show       Show group member" "$TmpDir/pki_group_member_cfg.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-003: pki group-member-add --help configuration test"
        	rlRun "pki group-member-add --help > $TmpDir/pki_group_member_add_cfg.out 2>&1" \
               		0 \
	               "pki group-member-add --help"
        	rlAssertGrep "usage: group-member-add <Group ID> <Member ID> \[OPTIONS...\]" "$TmpDir/pki_group_member_add_cfg.out"
	        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_group_member_add_cfg.out"
   	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-004: pki group-member-add configuration test"
                rlRun "pki group-member-add > $TmpDir/pki_group_member_add_2_cfg.out 2>&1" \
                       255 \
                       "pki group-member-add"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_group_member_add_2_cfg.out"
                rlAssertGrep "usage: group-member-add <Group ID> <Member ID> \[OPTIONS...\]" "$TmpDir/pki_group_member_add_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_group_member_add_2_cfg.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-005: Add users to available groups using valid admin user CA_adminV"
		i=1
		while [ $i -lt 15 ] ; do
		       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu$i\" u$i "
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
				   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-group-member-add-group-add-ca-00$i.out" \
				   0 \
				   "Adding user u$i"
			rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-group-member-add-group-add-ca-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-group-member-add-group-add-ca-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-group-member-add-group-add-ca-00$i.out"
			rlLog "Showing the user"
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
				    user-show u$i > $TmpDir/pki-group-member-add-group-show-ca-00$i.out" \
				    0 \
				    "Show pki CA_adminV user"
			rlAssertGrep "User \"u$i\"" "$TmpDir/pki-group-member-add-group-show-ca-00$i.out"
			rlAssertGrep "User ID: u$i" "$TmpDir/pki-group-member-add-group-show-ca-00$i.out"
			rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-group-member-add-group-show-ca-00$i.out"
			rlLog "Adding the user to a group"
			eval gid=\$groupid$i
			rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add \"$gid\" u$i"
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add \"$gid\" u$i > $TmpDir/pki-group-member-add-groupadd-ca-00$i.out" \
                                    0 \
                                    "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added group member \"u$i\"" "$TmpDir/pki-group-member-add-groupadd-ca-00$i.out"
                        rlAssertGrep "User: u$i" "$TmpDir/pki-group-member-add-groupadd-ca-00$i.out"
			rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find \"$gid\" > $TmpDir/pki-group-member-add-groupadd-find-ca-00$i.out" \
                                    0 \
                                    "User added to group \"$gid\""
                        rlAssertGrep "User: u$i" "$TmpDir/pki-group-member-add-groupadd-find-ca-00$i.out"
	                let i=$i+1
		done
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-006: Add a user to all available groups using CA_adminV"
		rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-group-member-add-user-add-ca-userall-001.out" \
                            0 \
                            "Adding user userall"
		rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-group-member-add-user-add-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-group-member-add-user-add-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-group-member-add-user-add-ca-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-show userall > $TmpDir/pki-group-member-add-user-show-ca-userall-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-group-member-add-user-show-ca-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-group-member-add-user-show-ca-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-group-member-add-user-show-ca-userall-001.out"
                rlLog "Adding the user to all the groups"
		i=1
		while [ $i -lt 15 ] ; do
			eval gid=\$groupid$i
			rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
				    group-member-add \"$gid\" userall"
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
				    group-member-add \"$gid\" userall > $TmpDir/pki-group-member-add-groupadd-ca-userall-00$i.out" \
				    0 \
				    "Adding user userall to group \"$gid\""
			rlAssertGrep "Added group member \"userall\"" "$TmpDir/pki-group-member-add-groupadd-ca-userall-00$i.out"
			rlAssertGrep "User: userall" "$TmpDir/pki-group-member-add-groupadd-ca-userall-00$i.out"
			rlLog "Check if the user is added to the group"
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
				    group-member-find \"$gid\" > $TmpDir/pki-group-member-add-groupadd-find-ca-userall-00$i.out" \
				    0 \
				    "User added to group \"$gid\""
			rlAssertGrep "User: userall" "$TmpDir/pki-group-member-add-groupadd-find-ca-userall-00$i.out"
			let i=$i+1
                done
	rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_group_member-add-CA-007: Add a user to same group multiple times"
                rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-group-member-add-user-add-ca-user1-001.out" \
                            0 \
                            "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-group-member-add-user-add-ca-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-group-member-add-user-add-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-group-member-add-user-add-ca-user1-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-show user1 > $TmpDir/pki-group-member-add-user-show-ca-user1-001.out" \
                            0 \
                            "Show pki CA_adminV user"
                rlAssertGrep "User \"user1\"" "$TmpDir/pki-group-member-add-user-show-ca-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-group-member-add-user-show-ca-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-group-member-add-user-show-ca-user1-001.out"
                rlLog "Adding the user to the same groups twice"
		rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-add \"Administrators\" user1 > $TmpDir/pki-group-member-add-groupadd-ca-user1-001.out" \
                            0 \
                            "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added group member \"user1\"" "$TmpDir/pki-group-member-add-groupadd-ca-user1-001.out"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" user1" 
		errmsg="ConflictingOperationException: Attribute or value exists."
		errorcode=255
        	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - cannot add user to the same group more than once"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-008: should not be able to add user to a non existing group"
		dummy_group="nonexisting_bogus_group"
		rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-group-member-add-user-add-ca-user1-008.out" \
                            0 \
                            "Adding user testuser1"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"$dummy_group\" testuser1"
                errmsg="GroupNotFoundException: Group $dummy_group not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - should not be able to add user to a non existing group"
	rlPhaseEnd	

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-009: Should be able to group-member-add user to Administrator group"
	        rlLog "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
	                    user-add --fullName=test u20"
        	rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
        	            user-add --fullName=test u20" \
                	    0 \
	                    "Adding uid u20"
		rlLog "Adding the user to the Adminstrators group"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" u20"
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-group-member-add-groupadd-ca-009_2.out" \
                            0 \
                            "Adding user u20 to group \"Administrators\""
                rlAssertGrep "Added group member \"u20\"" "$TmpDir/pki-group-member-add-groupadd-ca-009_2.out"	
		rlAssertGrep "User: u20" "$TmpDir/pki-group-member-add-groupadd-ca-009_2.out"
                rlLog "Check if the user is added to the group"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-find 'Administrators'"
		rlLog "Executing: $command"
                rlRun "$command > $TmpDir/pki-group-member-add-groupadd-find-ca-009_3.out" \
                	0 \
                        "Check user u20 added to group Administrators"
                rlAssertGrep "User: u20" "$TmpDir/pki-group-member-add-groupadd-find-ca-009_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-010: Should be able to group-member-add groupid with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName='u21' u21"
                rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName='u21' u21" \
                            0 \
                            "Adding uid u21"
		rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
		rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-group-member-add-groupadd-ca-010_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-group-member-add-groupadd-ca-010_1.out"   
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-group-member-add-groupadd-ca-010_1.out"   
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-group-member-add-groupadd-ca-010_1.out"
                rlLog "Adding the user to the dadministʁasjɔ̃ group"
                rlRun "pki -d $CERTDB_DIR \
			   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-add \"dadministʁasjɔ̃\" u21 > $TmpDir/pki-group-member-add-groupadd-ca-010_2.out" \
                            0 \
                            "Adding user u21 to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added group member \"u21\"" "$TmpDir/pki-group-member-add-groupadd-ca-010_2.out"    
                rlAssertGrep "User: u21" "$TmpDir/pki-group-member-add-groupadd-ca-010_2.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find 'dadministʁasjɔ̃' > $TmpDir/pki-group-member-add-groupadd-find-ca-010_3.out" \
                                    0 \
                                    "Check user u21 added to group dadministʁasjɔ̃"
                        rlAssertGrep "User: u21" "$TmpDir/pki-group-member-add-groupadd-find-ca-010_3.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-011: Should not be able to group-member-add using a revoked cert CA_adminR"
                command="pki -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using a revoked cert CA_adminR"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-012: Should not be able to group-member-add using an agent with revoked cert CA_agentR"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using an agent with revoked cert CA_agentR"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-013: Should not be able to group-member-add using admin user with expired cert CA_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using admin user with expired cert CA_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-014: Should not be able to group-member-add using CA_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using CA_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-015: Should not be able to group-member-add using CA_auditV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using CA_auditV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-016: Should not be able to group-member-add using CA_operatorV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using CA_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-017: Should not be able to group-member-add using role_user_UTCA cert"
		command="pki -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using CA_adminUTCA cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-018: Should not be able to group-member-add using role_user_UTCA cert"
		command="pki -d /tmp/untrusted_cert_db -n role_user_UTCA -c Password -h $CA_HOST -p $CA_PORT group-member-add \"Administrators\" testuser1"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to group-member-add using CA_agentUTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-019: User associated with Administrators group only can create a new user"
		i=2
                while [ $i -lt 15 ] ; do
                        eval gid=\$groupid$i
			if [ "$gid" = "Administrators" ] ; then
				rlLog "Not adding testuser1 to $gid group"
			else
	                        rlLog "pki -d $CERTDB_DIR \
				    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add \"$gid\" testuser1"
        	                rlRun "pki -d $CERTDB_DIR \
				    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add \"$gid\" testuser1 > $TmpDir/pki-group-member-add-groupadd-ca-testuser1-00$i.out" \
                                    0 \
                                    "Adding user testuser1 to group \"$gid\""
                	        rlAssertGrep "Added group member \"testuser1\"" "$TmpDir/pki-group-member-add-groupadd-ca-testuser1-00$i.out"
                        	rlAssertGrep "User: testuser1" "$TmpDir/pki-group-member-add-groupadd-ca-testuser1-00$i.out"
			fi
                        let i=$i+1
                done
		
		#Create a user cert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Test User1\" subject_uid:testuser1 subject_email:testuser1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_group_member_add_encoded_0019pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_group_member_add_encoded_0019pkcs10.out > $TmpDir/pki_ca_group_member_add_encoded_0019pkcs10.pem"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n testuser1 -i $TmpDir/pki_ca_group_member_add_encoded_0019pkcs10.pem -t "u,u,u""
        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-cert-add testuser1 --input $TmpDir/pki_ca_group_member_add_encoded_0019pkcs10.pem  > $TmpDir/useraddcert_019_2.out" \
                            0 \
                            "Cert is added to the user testuser1"
                command="pki -d $TEMP_NSS_DB -n testuser1 -c $TEMP_NSS_DB_PASSWD -h $CA_HOST -p $CA_PORT ca-user-add --fullName=test_user u39"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "ca-user-add operation should fail when authenticating using a user cert"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"

                #Add testuser1 to Administrators group
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-add \"$groupid5\" testuser1 > $TmpDir/pki-ca-group-member-add-groupadd-usertest1-019_2.out" \
                            0 \
                            "Adding user testuser1 to group \"$groupid5\""
                rlAssertGrep "Added group member \"testuser1\"" "$TmpDir/pki-ca-group-member-add-groupadd-usertest1-019_2.out"
                rlAssertGrep "User: testuser1" "$TmpDir/pki-ca-group-member-add-groupadd-usertest1-019_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-find $groupid5 > $TmpDir/pki-ca-group-member-add-groupadd-find-usertest1-019_3.out" \
                            0 \
                            "Check group-member for user testuser1"
                rlAssertGrep "User: testuser1" "$TmpDir/pki-ca-group-member-add-groupadd-find-usertest1-019_3.out"

                #Trying to add a user using testuser1 should succeed now since testuser1 is in Administrators group
                rlRun "pki -d $TEMP_NSS_DB \
                           -n testuser1 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName=test_user us19 > $TmpDir/pki-ca-user-add-019_4.out" \
                            0 \
                           "Added new user using Admin user testuser1"
                rlAssertGrep "Added user \"us19\"" "$TmpDir/pki-ca-user-add-019_4.out"
                rlAssertGrep "User ID: us19" "$TmpDir/pki-ca-user-add-019_4.out"
                rlAssertGrep "Full name: test_user" "$TmpDir/pki-ca-user-add-019_4.out"
        rlPhaseEnd

	#Usability test
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-020: User associated with Certificate Manager Agents group only can approve certificate requests"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-add --fullName=\"fullName_user2\" testuser2"
                 #Create a user cert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Test User2\" subject_uid:testuser2 subject_email:testuser2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"${prefix}_agentV\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_group_member_add_encoded_0020pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_group_member_add_encoded_0020pkcs10.out > $TmpDir/pki_ca_group_member_add_encoded_0020pkcs10.pem"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n testuser2 -i $TmpDir/pki_ca_group_member_add_encoded_0020pkcs10.pem -t "u,u,u""
        rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                           user-cert-add testuser2 --input $TmpDir/pki_ca_group_member_add_encoded_0020pkcs10.pem"
                rlLog "Check testuser2 is not in group Certificate Manager Agents"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-find \"$groupid1\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-find \"$groupid1\" > $TmpDir/pki-ca-group-member-add-groupadd-find-usertest1-020_1.out" \
                            0 \
                            "Check ca-group-member for testuser2"
                rlAssertNotGrep "User: testuser2" "$TmpDir/pki-ca-group-member-add-groupadd-find-usertest1-020_1.out"

                #Trying to approve a certificate request using testuser2 should fail
                rlRun "run_req_action_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"testuser2\" cert_info:$cert_info" 0 "Cert approval by testuser2 should fail"

        rlAssertGrep "Authorization Error" "$cert_info"

                #Add user testuser2 to Certificate Manager Agents group
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-add \"$groupid1\" testuser2 > $TmpDir/pki-ca-group-member-add-groupadd-usertest1-020_3.out" \
                            0 \
                            "Adding user testuser2 to group \"$groupid1\""
                rlAssertGrep "Added group member \"testuser2\"" "$TmpDir/pki-ca-group-member-add-groupadd-usertest1-020_3.out"
                rlAssertGrep "User: testuser2" "$TmpDir/pki-ca-group-member-add-groupadd-usertest1-020_3.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            group-member-find \"$groupid1\" > $TmpDir/pki-ca-group-member-add-groupadd-find-usertest1-020_4.out" \
                            0 \
                            "Check group-memberfor testuser2"
                rlAssertGrep "User: testuser2" "$TmpDir/pki-ca-group-member-add-groupadd-find-usertest1-020_4.out"

                #Trying to approve a certificate request using testuser2 should now succeed
                rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"testuser2\" cert_info:$cert_info" 0 "Successfully approved a cert by testuser2"

	rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-021: Should not be able to add a non existing user to a group"	
		user="testuser4"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT group-member-add \"$groupid5\" $user"
                errmsg="UserNotFoundException: User $user not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add group-member to user that does not exist"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1024"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-022: Add a group and add a user to the group using valid admin user CA_adminV"
		       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g1description\" g1"
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g1description\" g1 > $TmpDir/pki-group-member-add-group-add-ca-022.out" \
				   0 \
				   "Adding group g1"
		       rlAssertGrep "Added group \"g1\"" "$TmpDir/pki-group-member-add-group-add-ca-022.out"
                        rlAssertGrep "Group ID: g1" "$TmpDir/pki-group-member-add-group-add-ca-022.out"
                        rlAssertGrep "Description: g1description" "$TmpDir/pki-group-member-add-group-add-ca-022.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu15\" u15"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu15\" u15 > $TmpDir/pki-group-member-add-user-add-ca-022.out" \
                                   0 \
                                   "Adding user u15"
                        rlAssertGrep "Added user \"u15\"" "$TmpDir/pki-group-member-add-user-add-ca-022.out"
                        rlAssertGrep "User ID: u15" "$TmpDir/pki-group-member-add-user-add-ca-022.out"
                        rlAssertGrep "Full name: fullNameu15" "$TmpDir/pki-group-member-add-user-add-ca-022.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g1 u15"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g1 u15 > $TmpDir/pki-group-member-add-groupadd-ca-022.out" \
                                    0 \
                                    "Adding user u15 to group g1"
                        rlAssertGrep "Added group member \"u15\"" "$TmpDir/pki-group-member-add-groupadd-ca-022.out"
                        rlAssertGrep "User: u15" "$TmpDir/pki-group-member-add-groupadd-ca-022.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find g1 > $TmpDir/pki-group-member-add-groupadd-find-ca-022.out" \
                                    0 \
                                    "User added to group g1"
                        rlAssertGrep "User: u15" "$TmpDir/pki-group-member-add-groupadd-find-ca-022.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-023: Add two group and add a user to the two different group using valid admin user CA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g2description\" g2"
                       rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g2description\" g2 > $TmpDir/pki-group-member-add-group-add-ca-023.out" \
                                   0 \
                                   "Adding group g2"
                       rlAssertGrep "Added group \"g2\"" "$TmpDir/pki-group-member-add-group-add-ca-023.out"
                        rlAssertGrep "Group ID: g2" "$TmpDir/pki-group-member-add-group-add-ca-023.out"
                        rlAssertGrep "Description: g2description" "$TmpDir/pki-group-member-add-group-add-ca-023.out"
			rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g3description\" g3"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g3description\" g3 > $TmpDir/pki-group-member-add-group-add-ca-023_1.out" \
                                   0 \
                                   "Adding group g3"
                       rlAssertGrep "Added group \"g3\"" "$TmpDir/pki-group-member-add-group-add-ca-023_1.out"
                        rlAssertGrep "Group ID: g3" "$TmpDir/pki-group-member-add-group-add-ca-023_1.out"
                        rlAssertGrep "Description: g3description" "$TmpDir/pki-group-member-add-group-add-ca-023_1.out"

                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu16\" u16"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu16\" u16 > $TmpDir/pki-group-member-add-user-add-ca-023.out" \
                                   0 \
                                   "Adding user u16"
                        rlAssertGrep "Added user \"u16\"" "$TmpDir/pki-group-member-add-user-add-ca-023.out"
                        rlAssertGrep "User ID: u16" "$TmpDir/pki-group-member-add-user-add-ca-023.out"
                        rlAssertGrep "Full name: fullNameu16" "$TmpDir/pki-group-member-add-user-add-ca-023.out"
                        rlLog "Adding the user u16 to group g2"
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g2 u16"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g2 u16 > $TmpDir/pki-group-member-add-groupadd-ca-023.out" \
                                    0 \
                                    "Adding user u16 to group g2"
                        rlAssertGrep "Added group member \"u16\"" "$TmpDir/pki-group-member-add-groupadd-ca-023.out"
                        rlAssertGrep "User: u16" "$TmpDir/pki-group-member-add-groupadd-ca-023.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find g2 > $TmpDir/pki-group-member-add-groupadd-find-ca-023.out" \
                                    0 \
                                    "User added to group g2"
                        rlAssertGrep "User: u16" "$TmpDir/pki-group-member-add-groupadd-find-ca-023.out"
			rlLog "Adding the user u16 to group g3"
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g3 u16"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g3 u16 > $TmpDir/pki-group-member-add-groupadd-ca-023_1.out" \
                                    0 \
                                    "Adding user u16 to group g3"
                        rlAssertGrep "Added group member \"u16\"" "$TmpDir/pki-group-member-add-groupadd-ca-023_1.out"
                        rlAssertGrep "User: u16" "$TmpDir/pki-group-member-add-groupadd-ca-023_1.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find g3 > $TmpDir/pki-group-member-add-groupadd-find-ca-023_1.out" \
                                    0 \
                                    "User added to group g3"
                        rlAssertGrep "User: u16" "$TmpDir/pki-group-member-add-groupadd-find-ca-023_1.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_member-add-CA-024: Add a group, add a user to the group and delete the group using valid admin user CA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g4description\" gr4"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g4description\" gr4 > $TmpDir/pki-group-member-add-group-add-ca-024.out" \
                                   0 \
                                   "Adding group gr4"
                       rlAssertGrep "Added group \"gr4\"" "$TmpDir/pki-group-member-add-group-add-ca-024.out"
                        rlAssertGrep "Group ID: gr4" "$TmpDir/pki-group-member-add-group-add-ca-024.out"
                        rlAssertGrep "Description: g4description" "$TmpDir/pki-group-member-add-group-add-ca-024.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu17\" u17"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu17\" u17 > $TmpDir/pki-group-member-add-user-add-ca-024.out" \
                                   0 \
                                   "Adding user u17"
                        rlAssertGrep "Added user \"u17\"" "$TmpDir/pki-group-member-add-user-add-ca-024.out"
                        rlAssertGrep "User ID: u17" "$TmpDir/pki-group-member-add-user-add-ca-024.out"
                        rlAssertGrep "Full name: fullNameu17" "$TmpDir/pki-group-member-add-user-add-ca-024.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add gr4 u17"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add gr4 u17 > $TmpDir/pki-group-member-add-groupadd-ca-024.out" \
                                    0 \
                                    "Adding user u17 to group gr4"
                        rlAssertGrep "Added group member \"u17\"" "$TmpDir/pki-group-member-add-groupadd-ca-024.out"
                        rlAssertGrep "User: u17" "$TmpDir/pki-group-member-add-groupadd-ca-024.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find gr4 > $TmpDir/pki-group-member-add-groupadd-find-ca-024.out" \
                                    0 \
                                    "User added to group gr4"
                        rlAssertGrep "User: u17" "$TmpDir/pki-group-member-add-groupadd-find-ca-024.out"
			#Deleting group gr4
			rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-del gr4"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-del gr4 > $TmpDir/pki-group-member-add-groupdel-ca-024.out" \
                                    0 \
                                    "Deleting group gr4"
			rlAssertGrep "Deleted group \"gr4\"" "$TmpDir/pki-group-member-add-groupdel-ca-024.out"
			#Checking for user-membership
			rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    user-membership-find u17"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    user-membership-find u17 > $TmpDir/pki-group-member-add-usermembership-ca-024.out" \
                                    0 \
                                    "Checking for user membership of u17"
			rlAssertGrep "0 entries matched" "$TmpDir/pki-group-member-add-usermembership-ca-024.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-025: Add a group, add a user to the group and modify the group using valid admin user CA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g5description\" g4"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g5description\" g4 > $TmpDir/pki-group-member-add-group-add-ca-025.out" \
                                   0 \
                                   "Adding group g4"
                       rlAssertGrep "Added group \"g4\"" "$TmpDir/pki-group-member-add-group-add-ca-025.out"
                        rlAssertGrep "Group ID: g4" "$TmpDir/pki-group-member-add-group-add-ca-025.out"
                        rlAssertGrep "Description: g5description" "$TmpDir/pki-group-member-add-group-add-ca-025.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu18\" u18"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu18\" u18 > $TmpDir/pki-group-member-add-user-add-ca-025.out" \
                                   0 \
                                   "Adding user u18"
                        rlAssertGrep "Added user \"u18\"" "$TmpDir/pki-group-member-add-user-add-ca-025.out"
                        rlAssertGrep "User ID: u18" "$TmpDir/pki-group-member-add-user-add-ca-025.out"
                        rlAssertGrep "Full name: fullNameu18" "$TmpDir/pki-group-member-add-user-add-ca-025.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g4 u18"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g4 u18 > $TmpDir/pki-group-member-add-groupadd-ca-025.out" \
                                    0 \
                                    "Adding user u18 to group g4"
                        rlAssertGrep "Added group member \"u18\"" "$TmpDir/pki-group-member-add-groupadd-ca-025.out"
                        rlAssertGrep "User: u18" "$TmpDir/pki-group-member-add-groupadd-ca-025.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find g4 > $TmpDir/pki-group-member-add-groupadd-find-ca-025.out" \
                                    0 \
                                    "User added to group g5"
                        rlAssertGrep "User: u18" "$TmpDir/pki-group-member-add-groupadd-find-ca-025.out"
                        #Modifying group g4
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-mod g4 --decription=\"Modified group\""
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-mod g4 --description=\"Modified group\" > $TmpDir/pki-group-member-add-groupmod-ca-025.out" \
                                    0 \
                                    "Modifying group g4"
                        rlAssertGrep "Modified group \"g4\"" "$TmpDir/pki-group-member-add-groupmod-ca-025.out"
			rlAssertGrep "Group ID: g4" "$TmpDir/pki-group-member-add-groupmod-ca-025.out"
        		rlAssertGrep "Description: Modified group" "$TmpDir/pki-group-member-add-groupmod-ca-025.out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_group_cli_group_member-add-CA-026: Add a group, add a user to the group, run user-membership-del on the user and run group-member-find using valid admin user CA_adminV"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g5description\" g5"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-add --description=\"g6description\" g5 > $TmpDir/pki-group-member-add-group-add-ca-026.out" \
                                   0 \
                                   "Adding group g5"
                       rlAssertGrep "Added group \"g5\"" "$TmpDir/pki-group-member-add-group-add-ca-026.out"
                        rlAssertGrep "Group ID: g5" "$TmpDir/pki-group-member-add-group-add-ca-026.out"
                        rlAssertGrep "Description: g6description" "$TmpDir/pki-group-member-add-group-add-ca-026.out"
                       rlLog "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu19\" u19"
                       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   user-add --fullName=\"fullNameu19\" u19 > $TmpDir/pki-group-member-add-user-add-ca-026.out" \
                                   0 \
                                   "Adding user u19"
                        rlAssertGrep "Added user \"u19\"" "$TmpDir/pki-group-member-add-user-add-ca-026.out"
                        rlAssertGrep "User ID: u19" "$TmpDir/pki-group-member-add-user-add-ca-026.out"
                        rlAssertGrep "Full name: fullNameu19" "$TmpDir/pki-group-member-add-user-add-ca-026.out"
                        rlLog "Adding the user to a group"
                        rlLog "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g5 u19"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-add g5 u19 > $TmpDir/pki-group-member-add-groupadd-ca-026.out" \
                                    0 \
                                    "Adding user u19 to group g5"
                        rlAssertGrep "Added group member \"u19\"" "$TmpDir/pki-group-member-add-groupadd-ca-026.out"
                        rlAssertGrep "User: u19" "$TmpDir/pki-group-member-add-groupadd-ca-026.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find g5 > $TmpDir/pki-group-member-add-groupadd-find-ca-026.out" \
                                    0 \
                                    "User added to group g5"
                        rlAssertGrep "User: u19" "$TmpDir/pki-group-member-add-groupadd-find-ca-026.out"
			#run user-membership-del on u19
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    user-membership-del u19 g5 > $TmpDir/pki-group-member-add-user-membership-del-ca-026.out" \
				    0 \
				    "user-membership-del on u19"
			rlAssertGrep "Deleted membership in group \"g5\"" "$TmpDir/pki-group-member-add-user-membership-del-ca-026.out"
			#find group members
			rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                    group-member-find g5 > $TmpDir/pki-group-member-add-group-member-find-ca-026.out" \
                                    0 \
                                    "Find member in group g5"
			rlAssertGrep "0 entries matched" "$TmpDir/pki-group-member-add-group-member-find-ca-026.out"
	rlPhaseEnd
	rlPhaseStartTest "pki_group_cli_group_member-add-ca-cleanup-001: Deleting the temp directory and users and groups"
		#===Deleting users created using CA_adminV cert===#
		i=1
		while [ $i -lt 22 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
				   user-del  u$i > $TmpDir/pki-user-del-ca-group-member-add-user-del-ca-00$i.out" \
				   0 \
				   "Deleting user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-group-member-add-user-del-ca-00$i.out"
			let i=$i+1
		done
		i=1
		while [ $i -lt 6 ] ; do
                       rlRun "pki -d $CERTDB_DIR \
				   -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                                   group-del  g$i > $TmpDir/pki-user-del-ca-group-member-add-group-del-ca-00$i.out" \
                                   0 \
                                   "Deleting group g$i"
                        rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-user-del-ca-group-member-add-group-del-ca-00$i.out"
                        let i=$i+1
                done
	   	rlRun "pki -d $CERTDB_DIR \
			    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-del userall > $TmpDir/pki-group-del-ca-group-member-add-user-del-ca-userall-001.out" \
                            0 \
                            "Deleting user userall"
               	rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-group-del-ca-group-member-add-user-del-ca-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
			    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-del user1 >  $TmpDir/pki-user-del-ca-group-member-add-user-del-ca-user1-001.out" \
                            0 \
                            "Deleting user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-ca-group-member-add-user-del-ca-user1-001.out"
		rlRun "pki -d $CERTDB_DIR \
			    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
                            user-del us19 >  $TmpDir/pki-user-del-ca-group-member-add-user-del-ca-u19-001.out" \
                            0 \
                            "Deleting user us19"
                rlAssertGrep "Deleted user \"us19\"" "$TmpDir/pki-user-del-ca-group-member-add-user-del-ca-u19-001.out"
		#===Deleting users created using CA_adminV cert===#
       		i=1
	        while [ $i -lt 3 ] ; do
        		rlRun "pki -d $CERTDB_DIR \
				    -n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
          	                    user-del  testuser$i > $TmpDir/pki-group-member-add-ca-user-00$i.out" \
                   	            0 \
	                           "Deleting user testuser$i"
	                rlAssertGrep "Deleted user \"testuser$i\"" "$TmpDir/pki-group-member-add-ca-user-00$i.out"
                	let i=$i+1
       		done

		#===Deleting i18n group created using CA_adminV cert===#
		rlRun "pki -d $CERTDB_DIR \
			-n ${prefix}_adminV \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $CA_HOST \
                    -p $CA_PORT \
	                group-del 'dadministʁasjɔ̃' > $TmpDir/pki-group-del-ca-group-i18n_1.out" \
        	        0 \
                	"Deleting group dadministʁasjɔ̃"
	        rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-group-del-ca-group-i18n_1.out"

		#Delete temporary directory
		#rlRun "popd"
		#rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
