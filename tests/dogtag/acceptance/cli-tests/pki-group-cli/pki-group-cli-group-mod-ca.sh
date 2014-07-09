#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-mod CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-mod    Modify existing groups in the pki ca subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-group-cli-group-mod-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-group-cli-group-mod-ca_tests(){

    #####Create temporary dir to save the output files #####
    rlPhaseStartSetup "pki_group_cli_group_mod-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

group1=ca_group
group1desc="Test ca group"
group2=abcdefghijklmnopqrstuvwxyx12345678
group3=abc#
group4=abc$
group5=abc@
group6=abc?
group7=0
group1_mod_description="Test ca agent Modified"
randsym=""
i18ngroup=i18ngroup
i18ngroupdescription="Örjan Äke"
i18ngroup_mod_description="kakskümmend"

	##### pki_group_cli_group_mod-configtest ####
     rlPhaseStartTest "pki_group_cli_group_mod-configtest-001: pki group-mod configuration test"
        rlRun "pki group-mod --help > $TmpDir/pki_group_mod_cfg.out 2>&1" \
               0 \
                "Group modification configuration"
        rlAssertGrep "usage: group-mod <Group ID> \[OPTIONS...\]" "$TmpDir/pki_group_mod_cfg.out"
        rlAssertGrep "\--description <description>   Description" "$TmpDir/pki_group_mod_cfg.out"
	rlAssertGrep "\--help                        Show help options" "$TmpDir/pki_group_mod_cfg.out"
    rlPhaseEnd


     ##### Tests to modify CA groups ####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-002: Modify a group's description in CA using CA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"$group1desc\" $group1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$group1_mod_description\" $group1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$group1_mod_description\" $group1 > $TmpDir/pki-group-mod-ca-002.out" \
		    0 \
		    "Modified $group1 description"
        rlAssertGrep "Modified group \"$group1\"" "$TmpDir/pki-group-mod-ca-002.out"
        rlAssertGrep "Group ID: $group1" "$TmpDir/pki-group-mod-ca-002.out"
        rlAssertGrep "Description: $group1_mod_description" "$TmpDir/pki-group-mod-ca-002.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd


rlPhaseStartTest "pki_group_cli_group_mod-CA-003:--description with characters and numbers"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test g1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description abcdefghijklmnopqrstuvwxyx12345678 g1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=abcdefghijklmnopqrstuvwxyx12345678 g1 > $TmpDir/pki-group-mod-ca-004.out" \
                    0 \
                    "Modified group using CA_adminV with --description with characters and numbers"
        rlAssertGrep "Modified group \"g1\"" "$TmpDir/pki-group-mod-ca-004.out"
        rlAssertGrep "Group ID: g1" "$TmpDir/pki-group-mod-ca-004.out"
        rlAssertGrep "Description: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-group-mod-ca-004.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_mod-CA-004:--description with maximum length and symbols "
        randsym=`cat /dev/urandom | tr -dc 'a-zA-Z0-9@#%^&_+=~*-' | fold -w 1024 | head -n 1`

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test g2"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$randsym\" g2"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$randsym\" g2 > $TmpDir/pki-group-mod-ca-005.out" \
                    0 \
                    "Modified group using CA_adminV with maximum --description length and character symbols in it"
        actual_group_string=`cat $TmpDir/pki-group-mod-ca-005.out | grep "Description: " | xargs echo`
        expected_group_string="Description: $randsym"
        rlAssertGrep "Modified group \"g2\"" "$TmpDir/pki-group-mod-ca-005.out"
        rlAssertGrep "Group ID: u2" "$TmpDir/pki-group-mod-ca-005.out"
        if [[ $actual_group_string = $expected_group_string ]] ; then
                rlPass "$expected_group_string found"
        else
                rlFail "$expected_group_string not found"
        fi
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd



    rlPhaseStartTest "pki_group_cli_group_mod-CA-005:--description with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test g3"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=$ g3"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=$ g3 > $TmpDir/pki-group-mod-ca-008.out" \
                    0 \
                    "Modified group using CA_adminV with --description $ character"
        rlAssertGrep "Modified group \"g3\"" "$TmpDir/pki-group-mod-ca-008.out"
        rlAssertGrep "Group ID: g3" "$TmpDir/pki-group-mod-ca-008.out"
        rlAssertGrep "Description: \\$" "$TmpDir/pki-group-mod-ca-008.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd


 rlPhaseStartTest "pki_group_cli_group_mod-CA-006: Modify a group to CA with -t option"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=test g4"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-mod --description=\"$group1desc\"  g4"

        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-mod --description=\"$group1desc\" g4 > $TmpDir/pki-group-mod-ca-007.out" \
                    0 \
                    "Modified group g4 to CA"
        rlAssertGrep "Modified group \"g4\"" "$TmpDir/pki-group-mod-ca-007.out"
        rlAssertGrep "Group ID: g4" "$TmpDir/pki-group-mod-ca-007.out"
        rlAssertGrep "Description: $group1desc" "$TmpDir/pki-group-mod-ca-007.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd
    rlPhaseStartTest "pki_group_cli_group_mod-CA-007:  Modify a group -- missing required option group id"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca group-mod --description='$group1desc'"
	errmsg="Error: No Group ID specified."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modify group -- missing required option group id"
    rlPhaseEnd



##### Tests to modify groups using revoked cert#####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-008: Should not be able to modify groups using a revoked cert CA_adminR"
	command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using a user having revoked cert"
    rlPhaseEnd
    rlPhaseStartTest "pki_group_cli_group_mod-CA-009: Should not be able to modify group using an agent or a revoked cert CA_agentR"
	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using a user having revoked cert"
    rlPhaseEnd

##### Tests to modify groups using an agent user#####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-010: Should not be able to modify groups using a CA_agentV user"
	command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_mod-CA-011: Should not be able to modify group using a CA_agentR user"
	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using a agent cert"
    rlPhaseEnd

##### Tests to modify groups using expired cert#####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-012: Should not be able to modify group using a CA_adminE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using an expired admin cert"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/934"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_mod-CA-013: Should not be able to modify group using a CA_agentE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using an expired agent cert"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/934"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

 ##### Tests to modify groups using audit users#####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-014: Should not be able to modify group using a CA_auditV"
	command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 using an audit cert"
    rlPhaseEnd

        ##### Tests to modify groups using operator user###
    rlPhaseStartTest "pki_group_cli_group_mod-CA-015: Should not be able to modify group using a CA_operatorV"
	command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD group-mod --description='$group1desc' $group1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 as CA_operatorV"
    rlPhaseEnd

##### Tests to modify groups using CA_adminUTCA and CA_agentUTCA  user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-016: Should not be able to modify groups using a cert created from a untrusted CA CA_adminUTCA"
	command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password group-mod --description='$group1desc' $group1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify group $group1 as adminUTCA"
    rlPhaseEnd

rlPhaseStartTest "pki_group_cli_group_mod-CA-017:  Modify a group -- Group ID does not exist"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca group-mod --description='$group1desc' g5"
        errmsg="ResourceNotFoundException: Group g5  not found."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying a non existing group"
    rlPhaseEnd

##### Tests to modify CA groups with empty parameters ####

    rlPhaseStartTest "pki_group_cli_group_mod-CA-018: Modify a user created group in CA using CA_adminV - description is empty"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    group-add --description=\"$group1desc\" g5"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-mod --description=\"\" g5"
	errmsg="BadRequestException: Invalid DN syntax."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying Group --description is empty"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd


##### Tests to modify CA groups with the same value ####

    rlPhaseStartTest "pki_group_cli_group_mod-CA-019: Modify a group in CA using CA_adminV - description same old value"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show $group1 > $TmpDir/pki-group-mod-ca-041_1.out"
	rlAssertGrep "Group \"$group1\"" "$TmpDir/pki-group-mod-ca-041_1.out"
	rlAssertGrep "Group ID: $group1" "$TmpDir/pki-group-mod-ca-041_1.out"
        rlAssertGrep "Description: $group1desc" "$TmpDir/pki-group-mod-ca-041_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$group1desc\" $group1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$group1desc\" $group1 > $TmpDir/pki-group-mod-ca-041_2.out" \
                    0 \
                    "Modifying $group1 with same old description"
	rlAssertGrep "Modified group \"$group1\"" "$TmpDir/pki-group-mod-ca-041_2.out"
        rlAssertGrep "Group ID: $group1" "$TmpDir/pki-group-mod-ca-041_2.out"
        rlAssertGrep "Description: $group1desc" "$TmpDir/pki-group-mod-ca-041_2.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd

##### Tests to modify CA groups having i18n chars in the description ####

rlPhaseStartTest "pki_group_cli_group_mod-CA-020: Modify a groups's description having i18n chars in CA using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description=\"$i18ngroupdescription\" $i18ngroup"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$i18ngroup_mod_description\" $i18ngroup"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$i18ngroup_mod_description\" $i18ngroup > $TmpDir/pki-group-mod-ca-043.out" \
                   0 \
                    "Modified $i18ngroup description"
        rlAssertGrep "Modified group \"$i18ngroup\"" "$TmpDir/pki-group-mod-ca-043.out"
        rlAssertGrep "Group ID: $i18ngroup" "$TmpDir/pki-group-mod-ca-043.out"
        rlAssertGrep "Description: $i18ngroup_mod_description" "$TmpDir/pki-group-mod-ca-043.out"
	rlLog "PKI TICKET: https://fedorahosted.org/pki/ticket/818"
    rlPhaseEnd

##### Tests to modify system generated CA groups ####
    rlPhaseStartTest "pki_group_cli_group_mod-CA-021: Modify Administrator group's description in CA using CA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-show Administrators > $TmpDir/pki-group-mod-ca-group-show-022.out"
	admin_group_desc=$(cat $TmpDir/pki-group-mod-ca-group-show-022.out| grep Description | cut -d- -f2)
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$group1_mod_description\" Administrators"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$group1_mod_description\" Administrators > $TmpDir/pki-group-mod-ca-022.out" \
                    0 \
                    "Modified Administrators group description"
        rlAssertGrep "Modified group \"Administrators\"" "$TmpDir/pki-group-mod-ca-022.out"
        rlAssertGrep "Group ID: Administrators" "$TmpDir/pki-group-mod-ca-022.out"
        rlAssertGrep "Description: $group1_mod_description" "$TmpDir/pki-group-mod-ca-022.out"
	#Restoring the original description of Administrators group
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-mod --description=\"$admin_group_desc\" Administrators"
    rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_mod-CA-022: Modify Administrators group in CA using CA_adminV - description is empty"
        command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-mod --description=\"\" Administrators"
        errmsg="BadRequestException: Invalid DN syntax."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying Group --description is empty"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/833"
    rlPhaseEnd


#===Deleting groups===#
rlPhaseStartTest "pki_group_cli_group_cleanup: Deleting role groups"

        i=1
        while [ $i -lt 6 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  g$i > $TmpDir/pki-group-del-ca-group-00$i.out" \
                           0 \
                           "Deleted group  g$i"
                rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-group-del-ca-group-00$i.out"
                let i=$i+1
        done
        
        j=1
        while [ $j -lt 2 ] ; do
               eval grp=\$group$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  $grp > $TmpDir/pki-group-del-ca-group-symbol-00$j.out" \
                           0 \
                           "Deleted group $grp"
                rlAssertGrep "Deleted group \"$grp\"" "$TmpDir/pki-group-del-ca-group-symbol-00$j.out"
                let j=$j+1
        done
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del $i18ngroup > $TmpDir/pki-group-del-ca-i18ngroup-001.out" \
                           0 \
                           "Deleted group $i18ngroup"
                rlAssertGrep "Deleted group \"$i18ngroup\"" "$TmpDir/pki-group-del-ca-i18ngroup-001.out"

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"

    rlPhaseEnd
}
