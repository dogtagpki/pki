#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cli-user-membership-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-membership-find    Find OCSP user memberships.
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
. /opt/rhqa_pki/env.sh
######################################################################################
#create_role_users.sh should be first executed prior to pki-user-cli-user-membership-find-ocsp.sh
######################################################################################

run_pki-user-cli-user-membership-find-ocsp_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	prefix=$subsystemId
	# Creating Temporary Directory for pki user-ocsp
        rlPhaseStartSetup "pki user-ocsp Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $MYROLE $TmpDir/topo_file
        local OCSP_INST=$(cat $TmpDir/topo_file | grep MY_OCSP | cut -d= -f2)
        ocsp_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$OCSP_INST
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                prefix=OCSP3
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        fi

 if [ "$ocsp_instance_created" = "TRUE" ] ;  then
	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	untrusted_cert_nickname=role_user_UTCA

	#Local variables
	#Available groups ocsp-group-find
	groupid1="Online Certificate Status Manager Agents"
        groupid2="Subsystem Group"
        groupid3="Trusted Managers"
        groupid4="Administrators"
        groupid5="Auditors"
        groupid6="ClonedSubsystems"
        groupid7="Security Domain Administrators"
        groupid8="Enterprise OCSP Administrators"

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-002: pki user-membership-find --help configuration test"
                rlRun "pki user-membership-find --help > $TmpDir/pki_user_membership_find_cfg.out 2>&1" \
                        0 \
                       "pki user-membership-find --help"
                rlAssertGrep "usage: user-membership-find <User ID> \[FILTER\] \[OPTIONS...\]" "$TmpDir/pki_user_membership_find_cfg.out"
                rlAssertGrep "\--help            Show help options" "$TmpDir/pki_user_membership_find_cfg.out"
                rlAssertGrep "\--size <size>     Page size" "$TmpDir/pki_user_membership_find_cfg.out"
                rlAssertGrep "\--start <start>   Page start" "$TmpDir/pki_user_membership_find_cfg.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-003: pki user-membership-find configuration test"
                rlRun "pki user-membership-find > $TmpDir/pki_user_membership_find_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-find"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_user_membership_find_2_cfg.out"
                rlAssertGrep "usage: user-membership-find <User ID> \[FILTER\] \[OPTIONS...\]" "$TmpDir/pki_user_membership_find_2_cfg.out"
                rlAssertGrep "\--help            Show help options" "$TmpDir/pki_user_membership_find_2_cfg.out"
                rlAssertGrep "\--size <size>     Page size" "$TmpDir/pki_user_membership_find_2_cfg.out"
                rlAssertGrep "\--start <start>   Page start" "$TmpDir/pki_user_membership_find_2_cfg.out"
        rlPhaseEnd
 
        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-004: Find user-membership when user is added to different groups"
                i=1
                while [ $i -lt 9 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 				  -t ocsp \
                                   user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 				  -t ocsp \
                                   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-user-membership-find-user-find-ocsp-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-user-membership-find-user-find-ocsp-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-find-user-find-ocsp-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-find-user-find-ocsp-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
 				   -t ocsp \
                                    user-show u$i > $TmpDir/pki-user-membership-find-user-show-ocsp-00$i.out" \
                                    0 \
                                    "Show pki OCSP_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-user-membership-find-user-show-ocsp-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-find-user-show-ocsp-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-find-user-show-ocsp-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t ocsp \
                                    user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
				   -t ocsp \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                     user-membership-add u$i \"$gid\" > $TmpDir/pki-user-membership-find-groupadd-ocsp-00$i.out" \
                                     0 \
                                     "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-find-groupadd-ocsp-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-ocsp-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t ocsp \
                                    user-membership-find u$i > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-00$i.out" \
                                    0 \
                                    "Find user-membership with group \"$gid\""
			rlAssertGrep "1 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-00$i.out"
			rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-00$i.out"
                        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-00$i.out"

                        let i=$i+1
                done
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-005: Find user-membership when user is added to many groups"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t ocsp \
                            user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-user-membership-find-user-find-ocsp-userall-001.out" \
                            0 \
                            "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-user-membership-find-user-find-ocsp-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-find-user-find-ocsp-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-find-user-find-ocsp-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t ocsp \
                            user-show userall > $TmpDir/pki-user-membership-find-user-show-ocsp-userall-001.out" \
                            0 \
                            "Show pki OCSP_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-user-membership-find-user-show-ocsp-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-find-user-show-ocsp-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-find-user-show-ocsp-userall-001.out"
                rlLog "Adding the user to all the groups"
                i=1
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t ocsp \
                                    user-membership-add userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t ocsp \
                                    user-membership-add userall \"$gid\" > $TmpDir/pki-user-membership-find-groupadd-ocsp-userall-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-find-groupadd-ocsp-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-ocsp-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t ocsp \
                                    user-membership-find userall > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-userall-00$i.out" \
                                    0 \
                                    "Find user-membership to group \"$gid\""
			rlAssertGrep "$i entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-userall-00$i.out"
			rlAssertGrep "Number of entries returned $i" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-userall-00$i.out"

                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-006: Find user-membership of a user from the 6th position (start=5)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=5 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-001.out" \
                            0 \
                            "Checking user added to group"
		rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-001.out"
                rlAssertGrep "Group: $groupid6" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-001.out"
		rlAssertGrep "Group: $groupid7" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-001.out"
		rlAssertGrep "Group: $groupid8" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-001.out"
                rlAssertGrep "Number of entries returned 3" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-001.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-007: Find all user-memberships of a user (start=0)"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=0 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-002.out" \
                            0 \
                            "Checking user-mambership to group "
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-002.out"
		i=1
		while [ $i -lt 9 ] ; do
	       		eval gid=\$groupid$i
			rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-002.out"
			let i=$i+1
		done
                rlAssertGrep "Number of entries returned 8" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-002.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-008: Find user-memberships when page start is negative (start=-1)"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=-1 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-003.out" \
                            0 \
                            "Checking user-membership to group"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-003.out"
		i=1
                while [ $i -lt 9 ] ; do
	                eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-003.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 8" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-003.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-009: Find user-memberships when page start greater than available number of groups (start=9)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=9 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-004.out" \
                            0 \
                            "Checking user-membership to group"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-004.out"
                rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-start-004.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-010: Should not be able to find user-membership when page start is non integer"
		command="pki -d $CERTDB_DIR  -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminV  -c $CERTDB_DIR_PASSWORD  -t ocsp user-membership-find userall --start=a"
		errmsg="NumberFormatException: For input string: \"a\""
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership when page start is non integer"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-011: Find user-memberships when page size is 0 (size=0)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=0 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-006.out" 0 \
                            "user_membership-find with size parameter as 0"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-006.out"
		rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-006.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-012: Find user-memberships when page size is 1 (size=1)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=1 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-007.out" 0 \
                            "user_membership-find with size parameter as 1"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-007.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-007.out"
                rlAssertGrep "Number of entries returned 1" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-007.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-013: Find user-memberships when page size is 2 (size=2)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=2 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-008.out" 0 \
                            "user_membership-find with size parameter as 2"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-008.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-008.out"
		rlAssertGrep "Group: $groupid2" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-008.out"
                rlAssertGrep "Number of entries returned 2" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-008.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-014: Find user-memberships when page size is 9 (size=9)"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=9 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-009.out" 0 \
                            "user_membership-find with size parameter as 9"
		rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-009.out"
		i=1
                while [ $i -lt 9 ] ; do
                	eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-009.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 8" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-009.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-015: Find user-memberships when page size greater than available number of groups (size=100)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=100 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0010.out"  0 \
                            "user_membership-find with size parameter as 100"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0010.out"
		i=1
                while [ $i -lt 9 ] ; do
               		eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0010.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 8" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0010.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-016: Find user-memberships when page size is negative (size=-1)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=-1 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0011.out"  0 \
                            "user_membership-find with size parameter as -1"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0011.out"
                rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-size-0011.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-017: Should not be able to find user-membership when page size is non integer"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --size=a"
		errmsg="NumberFormatException: For input string: \"a\""
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "String cannot be used as input to start parameter "
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-018: Find user-membership with page start and page size option"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=6 --size=5"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=6 --size=5 > $TmpDir/pki-user-membership-find-ocsp-019.out" \
                            0 \
                            "Find user-membership with page start and page size option"
                rlAssertGrep "8 entries matched" "$TmpDir/pki-user-membership-find-ocsp-019.out"
		i=7
                while [ $i -lt 9 ] ; do
                        eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-find-ocsp-019.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 2" "$TmpDir/pki-user-membership-find-ocsp-019.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-019: Find user-membership with --size more than maximum possible value"
	maximum_check=$(echo $RANDOM$RANDOM$RANDOM$RANDOM)
	maximum_check=${maximum_check:1:12}
	rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=$maximum_check"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --size=$maximum_check > $TmpDir/pki-user-membership-find-ocsp-020.out 2>&1" \
                            255 \
                            "Find user-membership with --size more than maximum possible value"
		rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-user-membership-find-ocsp-020.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-020: Find user-membership with --start more than maximum possible value"
	maximum_check=$(echo $RANDOM$RANDOM$RANDOM$RANDOM)
	maximum_check=${maximum_check:1:12}
        rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=$maximum_check"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find userall --start=$maximum_check > $TmpDir/pki-user-membership-find-ocsp-021.out 2>&1" \
                            255 \
                            "Find user-membership with --start more than maximum possible value"
                rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-user-membership-find-ocsp-021.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-021: Should not be able to user-membership-find using a revoked cert OCSP_adminR"
                command="pki -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t ocsp user-membership-find userall --start=0 --size=5"
		rlLog "Executing $command"
		errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a revoked cert OCSP_adminR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
        	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-022: Should not be able to user-membership-find using an agent with revoked cert OCSP_agentR"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --start=0 --size=5"
		rlLog "Executing $command"
		errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using an agent with revoked cert OCSP_agentR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-023: Should not be able to user-membership-find using a valid agent OCSP_agentV user"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a valid agent OCSP_agentV user cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-024: Should not be able to user-membership-find using admin user with expired cert OCSP_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
       		rlRun "date"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a expired admin OCSP_adminE user cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-025: Should not be able to user-membership-find using OCSP_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a expired agent OCSP_agentE user cert"
                rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-026: Should not be able to user-membership-find using OCSP_auditV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a valid auditor OCSP_auditV user cert"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-027: Should not be able to user-membership-find using OCSP_operatorV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a valid operator OCSP_operatorV user cert"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-028: Should not be able to user-membership-find using OCSP_adminUTCA cert"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n $untrusted_cert_nickname -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -c $UNTRUSTED_CERT_DB_PASSWORD -t ocsp user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find user-membership using a untrusted role_user_UTCA user cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-029:Find user-membership for user fullname with i18n characters"
		rlLog "user-add user fullname Éric Têko with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-add --fullName='Éric Têko' u9"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-add --fullName='Éric Têko' u9" \
                            0 \
                            "Adding uid ÉricTêko with i18n characters"	
		rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-user-membership-add-groupadd-ocsp-031_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-ocsp-031_1.out"
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-ocsp-031_1.out"
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-user-membership-add-groupadd-ocsp-031_1.out"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-add u9 \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-add u9 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-find-groupadd-ocsp-031_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-find-groupadd-ocsp-031_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-find-groupadd-ocsp-031_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find u9 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-031_3.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "1 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-031_3.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-031_3.out"	
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-030: Find user-membership for user fullname with i18n characters"
		rlLog "user-add user fullname ÖrjanÄke with i18n characters"
        	rlRun "pki -d $CERTDB_DIR \
                	   -n ${prefix}_adminV \
	                   -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
        	            user-add --fullName='ÖrjanÄke' u10 > $TmpDir/pki-user-add-ocsp-032.out 2>&1" \
                	    0 \
	                    "Adding user fullname ÖrjanÄke with i18n characters"
        	rlAssertGrep "Added user \"u10\"" "$TmpDir/pki-user-add-ocsp-032.out"
	        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-add-ocsp-032.out"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-add u10 \"dadministʁasjɔ̃\""
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-add u10 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-find-groupadd-ocsp-032_2.out" \
                            0 \
                            "Adding user ÖrjanÄke to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-find-groupadd-ocsp-032_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-find-groupadd-ocsp-032_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-membership-find u10 > $TmpDir/pki-user-membership-find-groupadd-find-ocsp-032_3.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "1 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-032_3.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-find-groupadd-find-ocsp-032_3.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-find-OCSP-031: Find user-membership when uid is not associated with a group"
		rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   	  -t ocsp \
                                   user-add --fullName=\"fullNameuser123\" user123 "
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-add --fullName=\"fullNameuser123\" user123 > $TmpDir/pki-user-membership-find-user-find-ocsp-033.out" \
                            0 \
                            "Adding user user123"
                rlAssertGrep "Added user \"user123\"" "$TmpDir/pki-user-membership-find-user-find-ocsp-033.out"
                rlAssertGrep "User ID: user123" "$TmpDir/pki-user-membership-find-user-find-ocsp-033.out"
                rlAssertGrep "Full name: fullNameuser123" "$TmpDir/pki-user-membership-find-user-find-ocsp-033.out"
                command="pki -d $CERTDB_DIR  -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -t ocsp user-membership-find user123 --start=6 --size=5"
		rlLog "Executing $command"
		rlRun "$command > $TmpDir/pki-user-membership-find-user-find-ocsp-033_2.out" 0 "Find user-membership when uid is not associated with a group"
                rlAssertGrep "0 entries matched" "$TmpDir/pki-user-membership-find-user-find-ocsp-033_2.out"
        rlPhaseEnd

        rlPhaseStartCleanup "pki_user_cli_user_membership-find-ocsp-cleanup-001: Deleting the temp directory and users"
		
                #===Deleting users created using OCSP_adminV cert===#
                i=1
                while [ $i -lt 11 ] ; do
                       rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   	  -t ocsp \
                                   user-del  u$i > $TmpDir/pki-user-del-ocsp-user-membership-find-user-del-ocsp-00$i.out" \
                                   0 \
                                   "Deleted user u$i"
                        rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ocsp-user-membership-find-user-del-ocsp-00$i.out"
                        let i=$i+1
                done
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-del  userall > $TmpDir/pki-user-del-ocsp-user-membership-find-user-del-ocsp-userall.out" \
                            0 \
                            "Deleted user userall"
                rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-ocsp-user-membership-find-user-del-ocsp-userall.out"
	
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	   -t ocsp \
                            user-del  user123 > $TmpDir/pki-user-del-ocsp-user-membership-find-user-del-ocsp-user123.out" \
                            0 \
                            "Deleted user user123"
                rlAssertGrep "Deleted user \"user123\"" "$TmpDir/pki-user-del-ocsp-user-membership-find-user-del-ocsp-user123.out"	

	        #===Deleting i18n group created using OCSP_adminV cert===#
        	rlRun "pki -d $CERTDB_DIR \
                	-n ${prefix}_adminV \
	                -c $CERTDB_DIR_PASSWORD \
 			-h $SUBSYSTEM_HOST \
 			-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		  	-t ocsp \
        	        group-del 'dadministʁasjɔ̃' > $TmpDir/pki-user-del-ocsp-group-i18n_1.out" \
                	0 \
	                "Deleting group dadministʁasjɔ̃"
        	rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-del-ocsp-group-i18n_1.out"

		#Delete temporary directory
		rlRun "popd"
		rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
 else
	rlLog "OCSP instance not installed"
 fi
}
