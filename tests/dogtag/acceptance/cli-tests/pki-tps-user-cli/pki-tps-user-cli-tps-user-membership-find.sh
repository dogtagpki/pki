#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-tps-user-cli
#   Description: PKI user-cli-tps-user-membership-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-tps-user-cli-tps-user-membership-find    Find TPS user memberships.
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
#create_role_users.sh should be first executed prior to pki-tps-user-cli-tps-user-membership-find.sh
######################################################################################

run_pki-tps-user-cli-tps-user-membership-find_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	prefix=$subsystemId

	rlPhaseStartSetup "pki_tps_user_cli_tps_user_membership-find-001: Create temporary directory"
                rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
                rlRun "pushd $TmpDir"
        rlPhaseEnd
        get_topo_stack $MYROLE $TmpDir/topo_file
        local TPS_INST=$(cat $TmpDir/topo_file | grep MY_TPS | cut -d= -f2)
        tps_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$TPS_INST
                tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                        prefix=TPS1
                        tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        fi

 if [ "$tps_instance_created" = "TRUE" ] ;  then
	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	untrusted_cert_nickname=role_user_UTCA

	#Local variables
	#Available groups tps-group-find
	groupid1="TPS Agents"
        groupid2="TPS Officers"
        groupid3="Administrators"
        groupid4="TPS Operators"

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-002: pki tps-user-membership-find --help configuration test"
                rlRun "pki tps-user-membership-find --help > $TmpDir/pki_tps_user_membership_find_cfg.out 2>&1" \
                        0 \
                       "pki tps-user-membership-find --help"
                rlAssertGrep "usage: tps-user-membership-find <User ID> \[FILTER\] \[OPTIONS...\]" "$TmpDir/pki_tps_user_membership_find_cfg.out"
                rlAssertGrep "\--help            Show help options" "$TmpDir/pki_tps_user_membership_find_cfg.out"
                rlAssertGrep "\--size <size>     Page size" "$TmpDir/pki_tps_user_membership_find_cfg.out"
                rlAssertGrep "\--start <start>   Page start" "$TmpDir/pki_tps_user_membership_find_cfg.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-003: pki tps-user-membership-find configuration test"
                rlRun "pki tps-user-membership-find > $TmpDir/pki_tps_user_membership_find_2_cfg.out 2>&1" \
                       255 \
                       "pki tps-user-membership-find"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_tps_user_membership_find_2_cfg.out"
                rlAssertGrep "usage: tps-user-membership-find <User ID> \[FILTER\] \[OPTIONS...\]" "$TmpDir/pki_tps_user_membership_find_2_cfg.out"
                rlAssertGrep "\--help            Show help options" "$TmpDir/pki_tps_user_membership_find_2_cfg.out"
                rlAssertGrep "\--size <size>     Page size" "$TmpDir/pki_tps_user_membership_find_2_cfg.out"
                rlAssertGrep "\--start <start>   Page start" "$TmpDir/pki_tps_user_membership_find_2_cfg.out"
        rlPhaseEnd
 
        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-004: Find tps-user-membership when user is added to different groups"
                i=1
                while [ $i -lt 5 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   tps-user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   tps-user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-tps-user-membership-find-user-find-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-tps-user-membership-find-user-find-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-tps-user-membership-find-user-find-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-tps-user-membership-find-user-find-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    tps-user-show u$i > $TmpDir/pki-tps-user-membership-find-tps-user-show-00$i.out" \
                                    0 \
                                    "Show pki TPS_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-tps-user-membership-find-tps-user-show-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-tps-user-membership-find-tps-user-show-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-tps-user-membership-find-tps-user-show-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    tps-user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                     tps-user-membership-add u$i \"$gid\" > $TmpDir/pki-tps-user-membership-find-groupadd-tps-00$i.out" \
                                     0 \
                                     "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    tps-user-membership-find u$i > $TmpDir/pki-tps-user-membership-find-groupadd-find-00$i.out" \
                                    0 \
                                    "Find tps-user-membership with group \"$gid\""
			rlAssertGrep "1 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-00$i.out"
			rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-find-00$i.out"
                        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki-tps-user-membership-find-groupadd-find-00$i.out"

                        let i=$i+1
                done
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-005: Find tps-user-membership when user is added to many groups"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-tps-user-membership-find-user-find-userall-001.out" \
                            0 \
                            "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-tps-user-membership-find-user-find-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-tps-user-membership-find-user-find-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-tps-user-membership-find-user-find-userall-001.out"
                rlLog "Showing the user"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-show userall > $TmpDir/pki-tps-user-membership-find-tps-user-show-userall-001.out" \
                            0 \
                            "Show pki TPS_adminV user"
                rlAssertGrep "User \"userall\"" "$TmpDir/pki-tps-user-membership-find-tps-user-show-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-tps-user-membership-find-tps-user-show-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-tps-user-membership-find-tps-user-show-userall-001.out"
                rlLog "Adding the user to all the groups"
                i=1
                while [ $i -lt 5 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    tps-user-membership-add userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    tps-user-membership-add userall \"$gid\" > $TmpDir/pki-tps-user-membership-find-groupadd-tps-userall-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    tps-user-membership-find userall > $TmpDir/pki-tps-user-membership-find-groupadd-find-userall-00$i.out" \
                                    0 \
                                    "Find tps-user-membership to group \"$gid\""
			rlAssertGrep "$i entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-find-userall-00$i.out"
			rlAssertGrep "Number of entries returned $i" "$TmpDir/pki-tps-user-membership-find-groupadd-find-userall-00$i.out"

                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-006: Find tps-user-membership of a user from the 3rd position (start=2)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=2 > $TmpDir/pki-tps-user-membership-find-groupadd-find-start-001.out" \
                            0 \
                            "Checking user added to group"
		rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-001.out"
                rlAssertGrep "Group: $groupid3" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-001.out"
		rlAssertGrep "Group: $groupid4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-001.out"
                rlAssertGrep "Number of entries returned 2" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-001.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-007: Find all tps-user-memberships of a user (start=0)"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=0 > $TmpDir/pki-tps-user-membership-find-groupadd-find-start-002.out" \
                            0 \
                            "Checking user-mambership to group "
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-002.out"
		i=1
		while [ $i -lt 5 ] ; do
	       		eval gid=\$groupid$i
			rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-002.out"
			let i=$i+1
		done
                rlAssertGrep "Number of entries returned 4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-002.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-008: Find tps-user-memberships when page start is negative (start=-1)"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=-1 > $TmpDir/pki-tps-user-membership-find-groupadd-find-start-003.out" \
                            0 \
                            "Checking tps-user-membership to group"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-003.out"
		i=1
                while [ $i -lt 5 ] ; do
	                eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-003.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-003.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-009: Find tps-user-memberships when page start greater than available number of groups (start=5)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=5 > $TmpDir/pki-tps-user-membership-find-groupadd-find-start-004.out" \
                            0 \
                            "Checking tps-user-membership to group"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-004.out"
                rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-tps-user-membership-find-groupadd-find-start-004.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-010: Should not be able to find tps-user-membership when page start is non integer"
		command="pki -d $CERTDB_DIR  -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -n ${prefix}_adminV  -c $CERTDB_DIR_PASSWORD  tps-user-membership-find userall --start=a"
		errmsg="NumberFormatException: For input string: \"a\""
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership when page start is non integer"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-011: Find tps-user-memberships when page size is 0 (size=0)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=0 > $TmpDir/pki-tps-user-membership-find-groupadd-find-size-006.out" 0 \
                            "user_membership-find with size parameter as 0"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-006.out"
		rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-006.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-012: Find tps-user-memberships when page size is 1 (size=1)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=1 > $TmpDir/pki-tps-user-membership-find-groupadd-find-size-007.out" 0 \
                            "user_membership-find with size parameter as 1"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-007.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-007.out"
                rlAssertGrep "Number of entries returned 1" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-007.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-013: Find tps-user-memberships when page size is max 4 (size=4)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=4 > $TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out" 0 \
                            "user_membership-find with size paramete is max"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out"
                rlAssertGrep "Group: $groupid1" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out"
		rlAssertGrep "Group: $groupid2" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out"
		rlAssertGrep "Group: $groupid3" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out"
		rlAssertGrep "Group: $groupid4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out"
                rlAssertGrep "Number of entries returned 4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-008.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-014: Find tps-user-memberships when page size is 5 (size=5)"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=5 > $TmpDir/pki-tps-user-membership-find-groupadd-find-size-009.out" 0 \
                            "user_membership-find with size parameter as 5"
		rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-009.out"
		i=1
                while [ $i -lt 5 ] ; do
                	eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-009.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-009.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-015: Find tps-user-memberships when page size greater than available number of groups (size=100)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=100 > $TmpDir/pki-tps-user-membership-find-groupadd-find-size-0010.out"  0 \
                            "user_membership-find with size parameter as 100"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-0010.out"
		i=1
                while [ $i -lt 5 ] ; do
               		eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-0010.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 4" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-0010.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-016: Find tps-user-memberships when page size is negative (size=-1)"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=-1 > $TmpDir/pki-tps-user-membership-find-groupadd-find-size-0011.out"  0 \
                            "user_membership-find with size parameter as -1"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-0011.out"
                rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-tps-user-membership-find-groupadd-find-size-0011.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-017: Should not be able to find tps-user-membership when page size is non integer"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --size=a"
		errmsg="NumberFormatException: For input string: \"a\""
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "String cannot be used as input to start parameter "
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-018: Find tps-user-membership with page start and page size option"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=2 --size=5"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=2 --size=5 > $TmpDir/pki-tps-user-membership-find-019.out" \
                            0 \
                            "Find tps-user-membership with page start and page size option"
                rlAssertGrep "4 entries matched" "$TmpDir/pki-tps-user-membership-find-019.out"
		i=3
                while [ $i -lt 5 ] ; do
                        eval gid=\$groupid$i
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-tps-user-membership-find-019.out"
                        let i=$i+1
                done
                rlAssertGrep "Number of entries returned 2" "$TmpDir/pki-tps-user-membership-find-019.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-019: Find tps-user-membership with --size more than maximum possible value"
	maximum_check=$(echo $RANDOM$RANDOM$RANDOM$RANDOM)
	maximum_check=${maximum_check:1:12}
	rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=$maximum_check"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --size=$maximum_check > $TmpDir/pki-tps-user-membership-find-020.out 2>&1" \
                            255 \
                            "Find tps-user-membership with --size more than maximum possible value"
		rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-tps-user-membership-find-020.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-020: Find tps-user-membership with --start more than maximum possible value"
	maximum_check=$(echo $RANDOM$RANDOM$RANDOM$RANDOM)
	maximum_check=${maximum_check:1:12}
        rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=$maximum_check"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find userall --start=$maximum_check > $TmpDir/pki-tps-user-membership-find-021.out 2>&1" \
                            255 \
                            "Find tps-user-membership with --start more than maximum possible value"
                rlAssertGrep "NumberFormatException: For input string: \"$maximum_check\"" "$TmpDir/pki-tps-user-membership-find-021.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-021: Should not be able to tps-user-membership-find using a revoked cert TPS_adminR"
                command="pki -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) tps-user-membership-find userall --start=0 --size=5"
		rlLog "Executing $command"
		errmsg="PKIException: Unauthorized"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a revoked cert TPS_adminR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
        	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
	        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-022: Should not be able to tps-user-membership-find using an agent with revoked cert TPS_agentR"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --start=0 --size=5"
		rlLog "Executing $command"
		errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using an agent with revoked cert TPS_agentR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-023: Should not be able to tps-user-membership-find using a valid agent TPS_agentV user"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a valid agent TPS_agentV user cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-024: Should not be able to tps-user-membership-find using admin user with expired cert TPS_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
       		rlRun "date"
		command="pki -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a expired admin TPS_adminE user cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-025: Should not be able to tps-user-membership-find using TPS_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a expired agent TPS_agentE user cert"
                rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-026: Should not be able to tps-user-membership-find using TPS_officerV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_officerV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a valid officer TPS_officerV user cert"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-027: Should not be able to tps-user-membership-find using TPS_operatorV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a valid operator TPS_operatorV user cert"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-028: Should not be able to tps-user-membership-find using TPS_adminUTCA cert"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n $untrusted_cert_nickname -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST -c $UNTRUSTED_CERT_DB_PASSWORD tps-user-membership-find userall --start=0 --size=5"
                rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to find tps-user-membership using a untrusted role_user_UTCA user cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-029:Find tps-user-membership for user fullname with i18n characters"
		user9="u9"
		rlLog "tps-user-add user fullname Éric Têko with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-add --fullName='Éric Têko' $user9"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-add --fullName='Éric Têko' $user9" \
                            0 \
                            "Adding uid ÉricTêko with i18n characters"	
		rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-tps-user-membership-add-groupadd-tps-031_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-tps-user-membership-add-groupadd-tps-031_1.out"
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-tps-user-membership-add-groupadd-tps-031_1.out"
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-tps-user-membership-add-groupadd-tps-031_1.out"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-add $user9 \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-add $user9 \"dadministʁasjɔ̃\" > $TmpDir/pki-tps-user-membership-find-groupadd-tps-031_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-031_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-031_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find $user9 > $TmpDir/pki-tps-user-membership-find-groupadd-find-031_3.out" \
                            0 \
                            "Find tps-user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "1 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-031_3.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-tps-user-membership-find-groupadd-find-031_3.out"	
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-030: Find tps-user-membership for user fullname with i18n characters"
		user6="u5"
		rlLog "tps-user-add user fullname ÖrjanÄke with i18n characters"
        	rlRun "pki -d $CERTDB_DIR \
                	   -n ${prefix}_adminV \
	                   -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
        	            tps-user-add --fullName='ÖrjanÄke' $user6 > $TmpDir/pki-tps-user-add-tps-032.out 2>&1" \
                	    0 \
	                    "Adding user fullname ÖrjanÄke with i18n characters"
        	rlAssertGrep "Added user \"$user6\"" "$TmpDir/pki-tps-user-add-tps-032.out"
	        rlAssertGrep "User ID: $user6" "$TmpDir/pki-tps-user-add-tps-032.out"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-add $user6 \"dadministʁasjɔ̃\""
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-add $user6 \"dadministʁasjɔ̃\" > $TmpDir/pki-tps-user-membership-find-groupadd-tps-032_2.out" \
                            0 \
                            "Adding user ÖrjanÄke to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-032_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-tps-user-membership-find-groupadd-tps-032_2.out"
                rlLog "Check if the user is added to the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-membership-find $user6 > $TmpDir/pki-tps-user-membership-find-groupadd-find-032_3.out" \
                            0 \
                            "Find tps-user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "1 entries matched" "$TmpDir/pki-tps-user-membership-find-groupadd-find-032_3.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-tps-user-membership-find-groupadd-find-032_3.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_user_cli_tps_user_membership-find-031: Find tps-user-membership when uid is not associated with a group"
		rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   tps-user-add --fullName=\"fullNameuser123\" user123 "
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-add --fullName=\"fullNameuser123\" user123 > $TmpDir/pki-tps-user-membership-find-user-find-033.out" \
                            0 \
                            "Adding user user123"
                rlAssertGrep "Added user \"user123\"" "$TmpDir/pki-tps-user-membership-find-user-find-033.out"
                rlAssertGrep "User ID: user123" "$TmpDir/pki-tps-user-membership-find-user-find-033.out"
                rlAssertGrep "Full name: fullNameuser123" "$TmpDir/pki-tps-user-membership-find-user-find-033.out"
                command="pki -d $CERTDB_DIR  -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -h $SUBSYSTEM_HOST tps-user-membership-find user123 --start=6 --size=5"
		rlLog "Executing $command"
		rlRun "$command > $TmpDir/pki-tps-user-membership-find-user-find-033_2.out" 0 "Find tps-user-membership when uid is not associated with a group"
                rlAssertGrep "0 entries matched" "$TmpDir/pki-tps-user-membership-find-user-find-033_2.out"
        rlPhaseEnd

        rlPhaseStartCleanup "pki_tps_user_cli_tps_user_membership-find-cleanup-001: Deleting the temp directory and users"
		
                #===Deleting users created using TPS_adminV cert===#
                i=1
                while [ $i -lt 6 ] ; do
                       rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                   tps-user-del  u$i > $TmpDir/pki-tps-user-del-user-membership-find-tps-user-del-00$i.out" \
                                   0 \
                                   "Deleted user u$i"
                        rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-tps-user-del-user-membership-find-tps-user-del-00$i.out"
                        let i=$i+1
                done
		
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-del  userall > $TmpDir/pki-tps-user-del-user-membership-find-tps-user-del-userall.out" \
                            0 \
                            "Deleted user userall"
                rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-tps-user-del-user-membership-find-tps-user-del-userall.out"
	
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                            tps-user-del  user123 > $TmpDir/pki-tps-user-del-user-membership-find-tps-user-del-user123.out" \
                            0 \
                            "Deleted user user123"
                rlAssertGrep "Deleted user \"user123\"" "$TmpDir/pki-tps-user-del-user-membership-find-tps-user-del-user123.out"	

	        #===Deleting i18n group created using TPS_adminV cert===#
        	rlRun "pki -d $CERTDB_DIR \
                	-n ${prefix}_adminV \
	                -c $CERTDB_DIR_PASSWORD \
 			-h $SUBSYSTEM_HOST \
 			-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
        	        tps-group-del 'dadministʁasjɔ̃' > $TmpDir/pki-tps-user-del-group-i18n_1.out" \
                	0 \
	                "Deleting group dadministʁasjɔ̃"
        	rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-tps-user-del-group-i18n_1.out"

		#Delete temporary directory
		rlRun "popd"
		rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
 else
	rlLog "TPS instance not installed"
 fi
}
