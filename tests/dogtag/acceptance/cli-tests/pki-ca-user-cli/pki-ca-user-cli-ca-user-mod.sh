#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-mod CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-user-cli-ca-user-mod    Modify existing users in the pki ca subsystem.
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
#create_role_users.sh should be first executed prior to pki-ca-user-cli-ca-user-mod.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-ca-user-cli-ca-user-mod_tests(){
	subsystemId=$1
        SUBSYSTEM_TYPE=$2
        MYROLE=$3

        #####Create temporary dir to save the output files #####
        rlPhaseStartSetup "pki_ca_user_cli_ca_user_mod-startup: Create temporary directory"
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
  if [ "$ca_instance_created" = "TRUE" ] ;  then
	CA_HOST=$(eval echo \$${MYROLE})
	CA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)

user1=ca_agent2
user1fullname="Test ca agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0
user1_mod_fullname="Test ca agent Modified"
user1_mod_email="testcaagent@myemail.com"
user1_mod_passwd="Secret1234"
user1_mod_state="NC"
user1_mod_phone="1234567890"
randsym=""
i18nuser=i18nuser
i18nuserfullname="Örjan Äke"
i18nuser_mod_fullname="kakskümmend"
i18nuser_mod_email="kakskümmend@example.com"
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
	##### pki_ca_user_cli_ca_user_mod-configtest ####
     rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-configtest-001: pki ca-user-mod configuration test"
        rlRun "pki ca-user-mod --help > $TmpDir/pki_ca_user_mod_cfg.out 2>&1" \
               0 \
                "User modification configuration"
        rlAssertGrep "usage: ca-user-mod <User ID> \[OPTIONS...\]" "$TmpDir/pki_ca_user_mod_cfg.out"
        rlAssertGrep "\--email <email>         Email" "$TmpDir/pki_ca_user_mod_cfg.out"
        rlAssertGrep "\--fullName <fullName>   Full name" "$TmpDir/pki_ca_user_mod_cfg.out"
        rlAssertGrep "\--phone <phone>         Phone" "$TmpDir/pki_ca_user_mod_cfg.out"
        rlAssertGrep "\--state <state>         State" "$TmpDir/pki_ca_user_mod_cfg.out"
	rlAssertGrep "\--help                  Show help options" "$TmpDir/pki_ca_user_mod_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_ca_user_mod_cfg.out"
    rlPhaseEnd

	#### Modify a user's full name ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-002: Modify a user's fullname in CA using CA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
		   -h $CA_HOST \
		   -p $CA_PORT \
                    ca-user-add --fullName=\"$user1fullname\" $user1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$user1_mod_fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$user1_mod_fullname\" $user1 > $TmpDir/pki-ca-user-mod-002.out" \
		    0 \
		    "Modified $user1 fullname"
        rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-ca-user-mod-002.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-ca-user-mod-002.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-ca-user-mod-002.out"
    rlPhaseEnd

	#### Modify a user's email, phone, state, password ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-003: Modify a user's email,phone,state,password in CA using CA_adminV"
         rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email $user1_mod_email --phone $user1_mod_phone --state $user1_mod_state --password $user1_mod_passwd $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email $user1_mod_email --phone $user1_mod_phone --state $user1_mod_state --password $user1_mod_passwd $user1 > $TmpDir/pki-ca-user-mod-003.out" \
                    0 \
                    "Modified $user1 information"
        rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-ca-user-mod-003.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-ca-user-mod-003.out"
        rlAssertGrep "Email: $user1_mod_email" "$TmpDir/pki-ca-user-mod-003.out"

	rlAssertGrep "Phone: $user1_mod_phone" "$TmpDir/pki-ca-user-mod-003.out"

	rlAssertGrep "State: $user1_mod_state" "$TmpDir/pki-ca-user-mod-003.out"

	rlAssertGrep "Email: $user1_mod_email" "$TmpDir/pki-ca-user-mod-003.out"
rlPhaseEnd

	#### Modify a user's email with characters and numbers ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-004:--email with characters and numbers"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email abcdefghijklmnopqrstuvwxyx12345678 u1"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=abcdefghijklmnopqrstuvwxyx12345678 u1 > $TmpDir/pki-ca-user-mod-004.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with maximum --email length"
        rlAssertGrep "Modified user \"u1\"" "$TmpDir/pki-ca-user-mod-004.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-ca-user-mod-004.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-004.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-ca-user-mod-004.out"
    rlPhaseEnd

	#### Modify a user's email with maximum length and symbols ####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-005:--email with maximum length and symbols "
	randsym_b64=$(openssl rand -base64 1024 |  perl -p -e 's/\n//')
        randsym=$(echo $randsym_b64 | tr -d /)
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u2"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=\"$randsym\" u2"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=\"$randsym\" u2 > $TmpDir/pki-ca-user-mod-005.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with maximum --email length and character symbols in it"
        actual_email_string=`cat $TmpDir/pki-ca-user-mod-005.out | grep "Email: " | xargs echo`
        expected_email_string="Email: $randsym"
        rlAssertGrep "Modified user \"u2\"" "$TmpDir/pki-ca-user-mod-005.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-ca-user-mod-005.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-005.out"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "$expected_email_string found"
        else
                rlFail "$expected_email_string not found"
        fi
    rlPhaseEnd

	#### Modify a user's email with # character ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-006:--email with # character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u3"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email # u3"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=#  u3 > $TmpDir/pki-ca-user-mod-006.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --email # character"
        rlAssertGrep "Modified user \"u3\"" "$TmpDir/pki-ca-user-mod-006.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-ca-user-mod-006.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-006.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-ca-user-mod-006.out"
    rlPhaseEnd

	#### Modify a user's email with * character ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-007:--email with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u4"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email * u4"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=*  u4 > $TmpDir/pki-ca-user-mod-007.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --email * character"
        rlAssertGrep "Modified user \"u4\"" "$TmpDir/pki-ca-user-mod-007.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-ca-user-mod-007.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-007.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-ca-user-mod-007.out"
    rlPhaseEnd

	#### Modify a user's email with $ character ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-008:--email with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u5"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email $ u5"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=$  u5 > $TmpDir/pki-ca-user-mod-008.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --email $ character"
        rlAssertGrep "Modified user \"u5\"" "$TmpDir/pki-ca-user-mod-008.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-ca-user-mod-008.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-008.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-ca-user-mod-008.out"
    rlPhaseEnd

	#### Modify a user's email with value 0 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-009:--email as number 0 "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u6"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email 0 u6"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=0  u6 > $TmpDir/pki-ca-user-mod-009.out " \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --email 0"
        rlAssertGrep "Modified user \"u6\"" "$TmpDir/pki-ca-user-mod-009.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-ca-user-mod-009.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-009.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-ca-user-mod-009.out"
    rlPhaseEnd

	#### Modify a user's state with characters and numbers ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-010:--state with characters and numbers "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u7"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state abcdefghijklmnopqrstuvwxyx12345678 u7"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=abcdefghijklmnopqrstuvwxyx12345678 u7 > $TmpDir/pki-ca-user-mod-010.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with maximum --state length"
        rlAssertGrep "Modified user \"u7\"" "$TmpDir/pki-ca-user-mod-010.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-ca-user-mod-010.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-010.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-ca-user-mod-010.out"
    rlPhaseEnd

	#### Modify a user's state with maximum length and symbols ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-011:--state with maximum length and symbols "
	randsym_b64=$(openssl rand -base64 1024 |  perl -p -e 's/\n//')
        randsym=$(echo $randsym_b64 | tr -d /)
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u8"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=\"$randsym\" u8"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=\"$randsym\" u8 > $TmpDir/pki-ca-user-mod-011.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with maximum --state length and character symbols in it"
	actual_state_string=`cat $TmpDir/pki-ca-user-mod-011.out | grep "State: " | xargs echo`
        expected_state_string="State: $randsym"
        rlAssertGrep "Modified user \"u8\"" "$TmpDir/pki-ca-user-mod-011.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-ca-user-mod-011.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-011.out"
	if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "$expected_state_string found"
        else
                rlFail "$expected_state_string not found"
        fi
	rlPhaseEnd

	#### Modify a user's state with # character ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-012:--state with # character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u9"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state # u9"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=#  u9 > $TmpDir/pki-ca-user-mod-012.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --state # character"
        rlAssertGrep "Modified user \"u9\"" "$TmpDir/pki-ca-user-mod-012.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-ca-user-mod-012.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-012.out"
        rlAssertGrep "State: #" "$TmpDir/pki-ca-user-mod-012.out"
    rlPhaseEnd

	#### Modify a user's state with * character ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-013:--state with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u10"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state * u10"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=*  u10 > $TmpDir/pki-ca-user-mod-013.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --state * character"
        rlAssertGrep "Modified user \"u10\"" "$TmpDir/pki-ca-user-mod-013.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-ca-user-mod-013.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-013.out"
        rlAssertGrep "State: *" "$TmpDir/pki-ca-user-mod-013.out"
    rlPhaseEnd

	#### Modify a user's state with $ character ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-014:--state with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u11"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state $ u11"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=$  u11 > $TmpDir/pki-ca-user-mod-014.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --state $ character"
        rlAssertGrep "Modified user \"u11\"" "$TmpDir/pki-ca-user-mod-014.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-ca-user-mod-014.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-014.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-ca-user-mod-014.out"
    rlPhaseEnd

	#### Modify a user's state with number 0 ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-015:--state as number 0 "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u12"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state 0 u12"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --state=0  u12 > $TmpDir/pki-ca-user-mod-015.out " \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with --state 0"
        rlAssertGrep "Modified user \"u12\"" "$TmpDir/pki-ca-user-mod-015.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-ca-user-mod-015.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-015.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-ca-user-mod-015.out"
    rlPhaseEnd
        
	#### Modify a user's phone with characters and numbers ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-016:--phone with characters and numbers"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u13"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --phone abcdefghijklmnopqrstuvwxyx12345678 u13"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --phone=abcdefghijklmnopqrstuvwxyx12345678 u13 > $TmpDir/pki-ca-user-mod-016.out" \
                    0 \
                    "Modified user using $(eval echo \$${subsystemId}_adminV_user) with maximum --phone length"
        rlAssertGrep "Modified user \"u13\"" "$TmpDir/pki-ca-user-mod-016.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-ca-user-mod-016.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-016.out"
        rlAssertGrep "Phone: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-ca-user-mod-016.out"
    rlPhaseEnd

	#### Modify a user's phone with maximum length and symbols ####
	
rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-017:--phone with maximum length and symbols "
	randsym_b64=$(openssl rand -base64 1024 |  perl -p -e 's/\n//')
        randsym=$(echo $randsym_b64 | tr -d /)
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test usr1"
	special_symbols="*$#"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-mod --phone='$randsym$special_symbols' usr1"
	errmsg="PKIException: LDAP error (21): error result"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using CA_adminV with maximum length --phone with character symbols in it"
    rlPhaseEnd

	#### Modify a user's phone with maximum length and numbers only ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-018:--phone with maximum length and numbers only "
	randhex=$(openssl rand -hex 1024 |  perl -p -e 's/\n//')
        randhex_covup=${randhex^^}
        randsym=$(echo "ibase=16;$randhex_covup" | BC_LINE_LENGTH=0 bc)
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --phone=\"$randsym\" usr1"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --phone=\"$randsym\"  usr1 > $TmpDir/pki-ca-user-mod-018.out"\
                    0 \
                    "Modify user with maximum length and numbers only"
	rlAssertGrep "Modified user \"usr1\"" "$TmpDir/pki-ca-user-mod-018.out"
        rlAssertGrep "User ID: usr1" "$TmpDir/pki-ca-user-mod-018.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-018.out"
        rlAssertGrep "Phone: $randsym" "$TmpDir/pki-ca-user-mod-018.out"	
    rlPhaseEnd

	#### Modify a user's phone with # character ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-019:--phone with \# character"
	 rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test usr2 > /tmp/useraddres 2>&1"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-mod --phone=\"#\" usr2"
	errmsg="PKIException: LDAP error (21): error result"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using CA_adminV --phone with character symbols in it"
    rlPhaseEnd

	#### Modify a user's phone with * character ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-020:--phone with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test usr3"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --phone=\"*\" usr3"
	errmsg="PKIException: LDAP error (21): error result"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using CA_adminV --phone with character symbols in it"
    rlPhaseEnd

	#### Modify a user's phone with $ character ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-021:--phone with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test usr4"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --phone $ usr4"
	errmsg="PKIException: LDAP error (21): error result"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using CA_adminV --phone with character symbols in it"
    rlPhaseEnd

	#### Modify a user's phone with negative number ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-022:--phone as negative number -1230 "
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u14"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                  ca-user-mod --phone -1230 u14"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --phone=-1230  u14 > $TmpDir/pki-ca-user-mod-022.out " \
                    0 \
                    "Modifying User --phone negative value"
        rlAssertGrep "Modified user \"u14\"" "$TmpDir/pki-ca-user-mod-022.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-ca-user-mod-022.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-ca-user-mod-022.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-ca-user-mod-022.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/704"
    rlPhaseEnd

	#### Modify a user - missing required option user id ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-023-tier1:  Modify a user -- missing required option user id"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname'"
	errmsg="Error: No User ID specified."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modify user -- missing required option user id"
    rlPhaseEnd

	#### Modify a user - all options provided ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-024-tier1:  Modify a user -- all options provided"
        email="ca_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=test u15"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u15"

        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u15 >  $TmpDir/pki-ca-user-mod-025.out" \
                    0 \
                    "Modify user u15 to CA -- all options provided"
        rlAssertGrep "Modified user \"u15\"" "$TmpDir/pki-ca-user-mod-025.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-ca-user-mod-025.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-025.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-ca-user-mod-025.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-ca-user-mod-025.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-ca-user-mod-025.out"
    rlPhaseEnd

	#### Modify a user - password less than 8 characters ####

rlPhaseStartTest "pki_user_cli_user_mod-CA-025: Modify user with --password "
        userpw="pass"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-mod $user1 --fullName='$user1fullname' --password=$userpw"
        errmsg="PKIException: The password must be at least 8 characters"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modify a user --must be at least 8 characters --password"
    rlPhaseEnd

##### Tests to modify users using revoked cert#####
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-026: Should not be able to modify user using a revoked cert CA_adminR"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a user having revoked cert"
    rlPhaseEnd
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-027: Should not be able to modify user using an agent or a revoked cert CA_agentR"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a user having revoked cert"
    rlPhaseEnd

##### Tests to modify users using an agent user#####
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-028: Should not be able to modify user using a CA_agentV user"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-029: Should not be able to modify user using a CA_agentR user"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a agent cert"
    rlPhaseEnd

##### Tests to modify users using expired cert#####
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-030: Should not be able to modify user using a CA_adminE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using an expired admin cert"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/934"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-031: Should not be able to modify user using a CA_agentE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using an expired agent cert"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/934"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

 ##### Tests to modify users using audit users#####
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-032: Should not be able to modify user using a CA_auditV"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using an audit cert"
    rlPhaseEnd

        ##### Tests to modify users using operator user###
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-033: Should not be able to modify user using a CA_operatorV"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 as CA_operatorV"
    rlPhaseEnd

##### Tests to modify users using role_user_UTCA  user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-034: Should not be able to modify user using a cert created from a untrusted CA role_user_UTCA"
	command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 as role_user_UTCA"
    rlPhaseEnd

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-035:  Modify a user -- User ID does not exist"
        command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName='$user1fullname'  u17"
        errmsg="ResourceNotFoundException: No such object."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying a non existing user"
    rlPhaseEnd

	#### Modify a user - fullName option is empty ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-036: Modify a user in CA using CA_adminV - fullname is empty"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u16"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --fullName=\"\" u16"
	errmsg="BadRequestException: Invalid DN syntax."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying User --fullname is empty"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/833"
    rlPhaseEnd

	#### Modify a user - email is empty ####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-037: Modify a user in CA using CA_adminV - email is empty"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-show u16 > $TmpDir/pki-ca-user-mod-038_1.out" 
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-ca-user-mod-038_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-ca-user-mod-038_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-038_1.out"
	rlAssertGrep "Email: $email" "$TmpDir/pki-ca-user-mod-038_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-ca-user-mod-038_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-ca-user-mod-038_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=\"\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=\"\" u16 > $TmpDir/pki-ca-user-mod-038_2.out" \
                    0 \
                    "Modifying $user1 with empty email"
	rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-ca-user-mod-038_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-ca-user-mod-038_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-038_2.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-ca-user-mod-038_2.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-ca-user-mod-038_2.out"
    rlPhaseEnd

	#### Modify a user - phone is empty ####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-038: Modify a user in CA using CA_adminV - phone is empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-show u16 > $TmpDir/pki-ca-user-mod-039_1.out"
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-ca-user-mod-039_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-ca-user-mod-039_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-039_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-ca-user-mod-039_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-ca-user-mod-039_1.out"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --phone=\"\" u16"
	rlRun "$command" 0 "Successfully updated phone to empty value"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/836"
    rlPhaseEnd

	#### Modify a user - state option is empty ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-039: Modify a user in CA using CA_adminV - state is empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-show u16 > $TmpDir/pki-ca-user-mod-040_1.out"
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-ca-user-mod-040_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-ca-user-mod-040_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-040_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-ca-user-mod-040_1.out"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --state=\"\" u16"
	rlRun "$command" 0 "Successfully updated phone to empty value"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/836"
    rlPhaseEnd


##### Tests to modify CA users with the same value ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-040: Modify a user in CA using CA_adminV - fullname same old value"
	rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-show $user1 > $TmpDir/pki-ca-user-mod-041_1.out"
	rlAssertGrep "User \"$user1\"" "$TmpDir/pki-ca-user-mod-041_1.out"
	rlAssertGrep "User ID: $user1" "$TmpDir/pki-ca-user-mod-041_1.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-ca-user-mod-041_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$user1_mod_fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$user1_mod_fullname\" $user1 > $TmpDir/pki-ca-user-mod-041_2.out" \
                    0 \
                    "Modifying $user1 with same old fullname"
	rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-ca-user-mod-041_2.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-ca-user-mod-041_2.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-ca-user-mod-041_2.out"
    rlPhaseEnd

##### Tests to modify CA users adding values to params which were previously empty ####

    rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-041: Modify a user in CA using CA_adminV - adding values to params which were previously empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-show u16 > $TmpDir/pki-ca-user-mod-042_1.out"
        rlAssertGrep "User \"u16\"" "$TmpDir/pki-ca-user-mod-042_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-ca-user-mod-042_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-042_1.out"
	rlAssertNotGrep "Email:" "$TmpDir/pki-ca-user-mod-042_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=\"$email\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --email=\"$email\" u16 > $TmpDir/pki-ca-user-mod-042_2.out" \
                    0 \
                    "Modifying u16 with new value for phone which was previously empty"
        rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-ca-user-mod-042_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-ca-user-mod-042_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-ca-user-mod-042_2.out"
	rlAssertGrep "Email: $email" "$TmpDir/pki-ca-user-mod-042_2.out"
    rlPhaseEnd

##### Tests to modify CA users having i18n chars in the fullname ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-042: Modify a user's fullname having i18n chars in CA using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-add --fullName=\"$i18nuserfullname\" $i18nuser"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$i18nuser_mod_fullname\" $i18nuser"
        rlRun "pki -d $CERTDB_DIR \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                    ca-user-mod --fullName=\"$i18nuser_mod_fullname\" $i18nuser > $TmpDir/pki-ca-user-mod-043.out" \
                   0 \
                    "Modified $i18nuser fullname"
        rlAssertGrep "Modified user \"$i18nuser\"" "$TmpDir/pki-ca-user-mod-043.out"
        rlAssertGrep "User ID: $i18nuser" "$TmpDir/pki-ca-user-mod-043.out"
        rlAssertGrep "Full name: $i18nuser_mod_fullname" "$TmpDir/pki-ca-user-mod-043.out"
    rlPhaseEnd

##### Tests to modify CA users having i18n chars in email ####

rlPhaseStartTest "pki_ca_user_cli_ca_user_mod-043: Modify a user's email having i18n chars in CA using CA_adminV"
	command="pki -d $CERTDB_DIR -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD  -h $CA_HOST -p $CA_PORT ca-user-mod --email=$i18nuser_mod_email $i18nuser"
	errmsg="PKIException: LDAP error (21): error result"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modified $i18nuser email should fail"
	rlLog "FAIL:https://fedorahosted.org/pki/ticket/860"
    rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        i=1
        while [ $i -lt 17 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n $(eval echo \$${subsystemId}_adminV_user) \
                          -c $CERTDB_DIR_PASSWORD \
			  -h $CA_HOST \
                   	  -p $CA_PORT \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user-00$i.out" \
                           0 \
                           "Deleted user  u$i"
                rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-00$i.out"
                let i=$i+1
        done
	j=1
        while [ $j -lt 5 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                   -h $SUBSYSTEM_HOST \
                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  usr$j > $TmpDir/pki-user-del-ca-usr-00$j.out" \
                           0 \
                           "Deleted user usr$j"
                rlAssertGrep "Deleted user \"usr$j\"" "$TmpDir/pki-user-del-ca-usr-00$j.out"
                let j=$j+1
        done
        
        j=1
        while [ $j -lt 2 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n $(eval echo \$${subsystemId}_adminV_user) \
                          -c $CERTDB_DIR_PASSWORD \
			  -h $CA_HOST \
                   	  -p $CA_PORT \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
	rlRun "pki -d $CERTDB_DIR \
                          -n $(eval echo \$${subsystemId}_adminV_user) \
                          -c $CERTDB_DIR_PASSWORD \
			  -h $CA_HOST \
                   	  -p $CA_PORT \
                           user-del $i18nuser > $TmpDir/pki-user-del-ca-i18nuser-001.out" \
                           0 \
                           "Deleted user $i18nuser"
                rlAssertGrep "Deleted user \"$i18nuser\"" "$TmpDir/pki-user-del-ca-i18nuser-001.out"
$i18nuser
	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"

    rlPhaseEnd
  else
	rlLog "CA instance not installed"
  fi
}
