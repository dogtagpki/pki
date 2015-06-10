#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-ocsp-group-cli
#   Description: PKI ocsp-group-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ocsp-group-cli-ocsp-group-show   Show groups 
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
#create-role-users.sh should be first executed prior to pki-ocsp-group-cli-ocsp-group-show.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-ocsp-group-cli-ocsp-group-show_tests(){

rlPhaseStartSetup "pki_ocsp_group_cli_ocsp_group_show-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
caId=$4
CA_HOST=$5
	get_topo_stack $MYROLE $TmpDir/topo_file
        local OCSP_INST=$(cat $TmpDir/topo_file | grep MY_OCSP | cut -d= -f2)
        ocsp_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$OCSP_INST
                ocsp_instance_created=$(eval echo \$${prefix}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                prefix=OCSP3
                ocsp_instance_created=$(eval echo \$${prefix}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                ocsp_instance_created=$(eval echo \$${prefix}_INSTANCE_CREATED_STATUS)
        fi
if [ "$ocsp_instance_created" = "TRUE" ];  then
OCSP_HOST=$(eval echo \$${MYROLE})
OCSP_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
CA_PORT=$(eval echo \$${caId}_UNSECURE_PORT)
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
ROOTCA_agent_user=${caId}_agentV
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
local cert_info="$TmpDir/cert_info"
    #local variables
    group1=test_group
    group1desc="Test Group"
    group2=abcdefghijklmnopqrstuvwxyx12345678
    group3=abc#
    group4=abc$
    group5=abc@
    group6=abc?
    group7=0

    rlPhaseStartTest "pki_ocsp_group_show-configtest: pki ocsp-group-show configuration test"
        rlRun "pki ocsp-group-show --help > $TmpDir/pki_ocsp_group_show_cfg.out 2>&1" \
               0 \
               "pki ocsp-group-show"
        rlAssertGrep "usage: ocsp-group-show <Group ID> \[OPTIONS...\]" "$TmpDir/pki_ocsp_group_show_cfg.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_ocsp_group_show_cfg.out"
    rlPhaseEnd

     ##### Tests to show OCSP groups ####
    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-001: Add group to OCSP using OCSP_adminV and show group"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=\"$group1desc\" $group1" \
		    0 \
                    "Add group $group1 using OCSP_adminV"
        rlLog "Executing: pki -d $CERTDB_DIR \
		    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group1"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group1 > $TmpDir/pki-ocsp-group-show-001.out" \
		    0 \
		    "Show group $group1"
        rlAssertGrep "Group \"$group1\"" "$TmpDir/pki-ocsp-group-show-001.out"
        rlAssertGrep "Group ID: $group1" "$TmpDir/pki-ocsp-group-show-001.out"
        rlAssertGrep "Description: $group1desc" "$TmpDir/pki-ocsp-group-show-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-002: maximum length of group id"
	group2=$(openssl rand -hex 2048 |  perl -p -e 's/\n//')
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test $group2" \
		    0 \
                    "Add group $group2"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group2 > $TmpDir/pki-ocsp-group-show-001_1.out" \
                    0 \
                    "Show $group2 group"
        rlAssertGrep "Group \"$group2\"" "$TmpDir/pki-ocsp-group-show-001_1.out"
	actual_groupid_string=`cat $TmpDir/pki-ocsp-group-show-001_1.out | grep 'Group ID:' | xargs echo`
        expected_groupid_string="Group ID: $group2"
        if [[ $actual_groupid_string = $expected_groupid_string ]] ; then
                rlPass "Group ID: $group2 found"
        else
                rlFail "Group ID: $group2 not found"
        fi
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_1.out"
	
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-003: Group id with # character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test $group3" \
		    0 \
                    "Add group $group3 using OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group3 > $TmpDir/pki-ocsp-group-show-001_2.out" \
                    0 \
                    "Show $group3 group"
        rlAssertGrep "Group \"$group3\"" "$TmpDir/pki-ocsp-group-show-001_2.out"
        rlAssertGrep "Group ID: $group3" "$TmpDir/pki-ocsp-group-show-001_2.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-004: Group id with $ character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test $group4" \
		    0 \
                    "Add group $group4 using OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group4 > $TmpDir/pki-ocsp-group-show-001_3.out" \
                    0 \
                    "Show $group4 group"
        rlAssertGrep "Group \"$group4\"" "$TmpDir/pki-ocsp-group-show-001_3.out"
        rlAssertGrep "Group ID: abc\\$" "$TmpDir/pki-ocsp-group-show-001_3.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-005: Group id with @ character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test $group5" \
                    0 \
                    "Add $group5 using OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group5 > $TmpDir/pki-ocsp-group-show-001_4.out" \
                    0 \
                    "Show $group5 group"
        rlAssertGrep "Group \"$group5\"" "$TmpDir/pki-ocsp-group-show-001_4.out"
        rlAssertGrep "Group ID: $group5" "$TmpDir/pki-ocsp-group-show-001_4.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-006: Group id with ? character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test $group6" \
                    0 \
                    "Add $group6 using OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group6 > $TmpDir/pki-ocsp-group-show-001_5.out" \
                    0 \
                    "Show $group6 group"
        rlAssertGrep "Group \"$group6\"" "$TmpDir/pki-ocsp-group-show-001_5.out"
        rlAssertGrep "Group ID: $group6" "$TmpDir/pki-ocsp-group-show-001_5.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_5.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-007: Group id as 0"
	rlRun "pki -d $CERTDB_DIR \
		    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test $group7" \
                    0 \
                    "Add group $group7 using OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show $group7 > $TmpDir/pki-ocsp-group-show-001_6.out" \
                    0 \
                    "Show group $group7"
        rlAssertGrep "Group \"$group7\"" "$TmpDir/pki-ocsp-group-show-001_6.out"
        rlAssertGrep "Group ID: $group7" "$TmpDir/pki-ocsp-group-show-001_6.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_6.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-008: --description with maximum length"
	desc=$(openssl rand -hex 2048 |  perl -p -e 's/\n//')
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description='$desc' g1" \
		    0 \
		    "Added group using OCSP_adminV with maximum --description length"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show g1 > $TmpDir/pki-ocsp-group-show-001_7.out" \
                    0 \
                    "Show group g1"
        rlAssertGrep "Group \"g1\"" "$TmpDir/pki-ocsp-group-show-001_7.out"
        rlAssertGrep "Group ID: g1" "$TmpDir/pki-ocsp-group-show-001_7.out"
	actual_desc_string=`cat $TmpDir/pki-ocsp-group-show-001_7.out | grep Description: | xargs echo`
        expected_desc_string="Description: $desc"
        if [[ $actual_desc_string = $expected_desc_string ]] ; then
                rlPass "Description: $desc found"
        else
                rlFail "Description: $desc not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-009: --description with maximum length and symbols"
	desc_b64=$(openssl rand -base64 2048 |  perl -p -e 's/\n//')
        desc=$(echo $desc_b64 | sed 's/\///g')	
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description='$desc' g2" \
		    0 \
		    "Added group with maximum --description length and character symbols in it"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show g2 > $TmpDir/pki-ocsp-group-show-001_8.out" \
                    0 \
                    "Show group g2"
        rlAssertGrep "Group \"g2\"" "$TmpDir/pki-ocsp-group-show-001_8.out"
        rlAssertGrep "Group ID: g2" "$TmpDir/pki-ocsp-group-show-001_8.out"
	actual_desc_string=`cat $TmpDir/pki-ocsp-group-show-001_8.out | grep Description: | xargs echo`
        expected_desc_string="Description: $desc"
        if [[ $actual_desc_string = $expected_desc_string ]] ; then
                rlPass "Description: $desc found"
        else
                rlFail "Description: $desc not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-010: --description with # character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=# g3" \
                    0 \
                    "Add group g3 using pki OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show g3 > $TmpDir/pki-ocsp-group-show-001_9.out" \
		     0 \
                    "Add group g3"
        rlAssertGrep "Group \"g3\"" "$TmpDir/pki-ocsp-group-show-001_9.out"
        rlAssertGrep "Group ID: g3" "$TmpDir/pki-ocsp-group-show-001_9.out"
        rlAssertGrep "Description: #" "$TmpDir/pki-ocsp-group-show-001_9.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-011: --description with * character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=*  g4" \
		    0 \
                    "Add group g4"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show g4 > $TmpDir/pki-ocsp-group-show-001_10.out" \
                    0 \
                    "Show group g4 using OCSP_adminV"
        rlAssertGrep "Group \"g4\"" "$TmpDir/pki-ocsp-group-show-001_10.out"
        rlAssertGrep "Group ID: g4" "$TmpDir/pki-ocsp-group-show-001_10.out"
        rlAssertGrep "Description: *" "$TmpDir/pki-ocsp-group-show-001_10.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-012: --description with $ character"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=$  g5" \
		    0 \
                    "Add group g5 using pki OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show g5 > $TmpDir/pki-ocsp-group-show-001_11.out" \
                    0 \
                    "Show group g5 using OCSP_adminV"
        rlAssertGrep "Group \"g5\"" "$TmpDir/pki-ocsp-group-show-001_11.out"
        rlAssertGrep "Group ID: g5" "$TmpDir/pki-ocsp-group-show-001_11.out"
        rlAssertGrep "Description: \\$" "$TmpDir/pki-ocsp-group-show-001_11.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-013: --description as number 0"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=0 g6" \
		    0 \
                    "Add group g6 using pki OCSP_adminV"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show g6 > $TmpDir/pki-ocsp-group-show-001_12.out" \
                    0 \
                    "Show group g6 using OCSP_adminV"
        rlAssertGrep "Group \"g6\"" "$TmpDir/pki-ocsp-group-show-001_12.out"
        rlAssertGrep "Group ID: g6" "$TmpDir/pki-ocsp-group-show-001_12.out"
        rlAssertGrep "Description: 0" "$TmpDir/pki-ocsp-group-show-001_12.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-014: Show group with -t ocsp option"
	rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                   -t ocsp \
                    ocsp-group-add --description=test g7" \
		    0 \
                    "Adding group g7"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                   -t ocsp \
                    ocsp-group-show g7 > $TmpDir/pki-ocsp-group-show-001_32.out" \
                    0 \
                    "Show group g7 using OCSP_adminV"
        rlAssertGrep "Group \"g7\"" "$TmpDir/pki-ocsp-group-show-001_32.out"
        rlAssertGrep "Group ID: g7" "$TmpDir/pki-ocsp-group-show-001_32.out"
        rlAssertGrep "Description: $test" "$TmpDir/pki-ocsp-group-show-001_32.out"
    rlPhaseEnd


    #Negative Cases
    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-015: Missing required option group id"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show"
        errmsg="Error: No Group ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show group without group id"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-016: Checking if group id case sensitive "
        rlRun "pki -d $CERTDB_DIR \
		    -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show G7 > $TmpDir/pki-ocsp-group-show-001_35.out 2>&1" \
                    0 \
                    "Group ID is not case sensitive"
	rlAssertGrep "Group \"G7\"" "$TmpDir/pki-ocsp-group-show-001_35.out"
        rlAssertGrep "Group ID: g7" "$TmpDir/pki-ocsp-group-show-001_35.out"
        rlAssertGrep "Description: test" "$TmpDir/pki-ocsp-group-show-001_35.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-017: Should not be able to show group using a revoked cert OCSP_adminR"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a admin having revoked cert"
	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-018: Should not be able to show group using an agent with revoked cert OCSP_agentR"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a agent having revoked cert"
	rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
        rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-019: Should not be able to show group using a valid agent OCSP_agentV user"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-020: Should not be able to show group using admin user with expired cert OCSP_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using an expired admin cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-021: Should not be able to show group using OCSP_agentE cert"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a agent cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://engineering.redhat.com/trac/pki-tests/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-022: Should not be able to show group using a OCSP_auditV"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a audit cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-023: Should not be able to show group using a OCSP_operatorV"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
        errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using a operator cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-024: Should not be able to show group using a cert created from a untrusted OCSP OCSP_adminUTCA"
	command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show g7"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show group g7 using OCSP_adminUTCA"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-025: Should not be able to show group using a user cert"
        #Create a user cert
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"pki User2\" subject_uid:pkiUser2 subject_email:pkiuser2@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$OCSP_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$ROOTCA_agent_user\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $OCSP_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ocsp_group_show_encoded_0025pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ocsp_group_show_encoded_0025pkcs10.out > $TmpDir/pki_ocsp_group_show_encoded_0025pkcs10.pem"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser2 -i $TmpDir/pki_ocsp_group_show_encoded_0025pkcs10.pem  -t "u,u,u""
	rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser2 \
                   -c $TEMP_NSS_DB_PASSWD \
                   -h $OCSP_HOST \
                   -p $OCSP_PORT \
                    ocsp-group-show g7"
        rlRun "pki -d $TEMP_NSS_DB \
                   -n pkiUser2 \
                   -c $TEMP_NSS_DB_PASSWD \
                   -h $OCSP_HOST \
                   -p $OCSP_PORT \
                    ocsp-group-show g7 >  $TmpDir/pki-ocsp-group-show-pkiUser1-0025.out 2>&1" 255 "Should not be able to find groups using a user cert"

        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-ocsp-group-show-pkiUser1-0025.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-026: group id length exceeds maximum limit defined in the schema"
	group_length_exceed_max=$(openssl rand -hex 10000 |  perl -p -e 's/\n//')
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $OCSP_HOST -p $OCSP_PORT ocsp-group-show  '$group_length_exceed_max'"
	errmsg="ClientResponseFailure: ldap can't save, exceeds max length"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Show group using OCSP_adminV with group id length exceed maximum defined in ldap schema should fail"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/842"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-027: group id with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test 'ÖrjanÄke' > $TmpDir/pki-ocsp-group-show-001_56.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
	rlLog "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show 'ÖrjanÄke' > $TmpDir/pki-ocsp-group-show-001_56_2.out" \
                    0 \
                    "Show group 'ÖrjanÄke'"
        rlAssertGrep "Group \"ÖrjanÄke\"" "$TmpDir/pki-ocsp-group-show-001_56_2.out"
        rlAssertGrep "Group ID: ÖrjanÄke" "$TmpDir/pki-ocsp-group-show-001_56_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_show-028: groupid with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-add --description=test 'ÉricTêko' > $TmpDir/pki-ocsp-group-show-001_57.out 2>&1" \
                    0 \
                    "Adding group id ÉricTêko with i18n characters"
	rlLog "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show 'ÉricTêko'"
        rlRun "pki -d $CERTDB_DIR \
		   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                    ocsp-group-show 'ÉricTêko' > $TmpDir/pki-ocsp-group-show-001_57_2.out" \
                    0 \
                    "Show group 'ÉricTêko'"
        rlAssertGrep "Group \"ÉricTêko\"" "$TmpDir/pki-ocsp-group-show-001_57_2.out"
        rlAssertGrep "Group ID: ÉricTêko" "$TmpDir/pki-ocsp-group-show-001_57_2.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_ocsp_group_cli_ocsp_group_cleanup: Deleting the temp directory and groups"

        #===Deleting groups created using OCSP_adminV cert===#
        i=1
        while [ $i -lt 8 ] ; do
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                           ocsp-group-del  g$i > $TmpDir/pki-ocsp-group-del-group-00$i.out" \
                           0 \
                           "Deleted group g$i"
                rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-ocsp-group-del-group-00$i.out"
                let i=$i+1
        done
        #===Deleting groups(symbols) created using OCSP_adminV cert===#
        j=1
        while [ $j -lt 8 ] ; do
               eval grp=\$group$j
               rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                           ocsp-group-del  $grp > $TmpDir/pki-group-del-ocsp-group-symbol-00$j.out" \
                           0 \
                           "Deleted group $grp"
                rlAssertGrep "Deleted group \"$grp\"" "$TmpDir/pki-group-del-ocsp-group-symbol-00$j.out"
                let j=$j+1
        done

	#===Deleting i18n groups created using OCSP_adminV cert===#
        rlRun "pki -d $CERTDB_DIR \
		-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
                ocsp-group-del 'ÖrjanÄke' > $TmpDir/pki-group-del-ocsp-group-i18n_1.out" \
                0 \
                "Deleted group ÖrjanÄke"
        rlAssertGrep "Deleted group \"ÖrjanÄke\"" "$TmpDir/pki-group-del-ocsp-group-i18n_1.out"

        rlRun "pki -d $CERTDB_DIR \
		-n $(eval echo \$${subsystemId}_adminV_user) \
                    -c $CERTDB_DIR_PASSWORD \
                    -h $OCSP_HOST \
                    -p $OCSP_PORT \
               ocsp-group-del 'ÉricTêko' > $TmpDir/pki-group-del-ocsp-group-i18n_2.out" \
                0 \
                "Deleted group ÉricTêko"
        rlAssertGrep "Deleted group \"ÉricTêko\"" "$TmpDir/pki-group-del-ocsp-group-i18n_2.out"

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
else
        rlPhaseStartCleanup "pki ocsp-group-show cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlLog "OCSP subsystem is not installed"
        rlPhaseEnd
fi
}
