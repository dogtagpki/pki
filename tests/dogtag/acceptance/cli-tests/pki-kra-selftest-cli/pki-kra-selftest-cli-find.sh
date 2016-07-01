#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-selftest-cli
#
#   Description: PKI KRA SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki ca-selftest cli commands needs to be tested:
#  pki kra-selftest-find
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mrniranjan@redhat.com>
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
. /opt/rhqa_pki/env.sh

run_pki-kra-selftest-find_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki kra-selftest-find
        rlPhaseStartSetup "pki kra-selftest-find Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
        kra_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$KRA_INST
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                prefix=KRA3
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$cs_Role
                kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$kra_instance_created" = "TRUE" ] ;  then
 
        local target_secure_port=$(eval echo \$${KRA_INST}_SECURE_PORT)
        local tmp_ca_agent=$KRA_INST\_agentV
        local tmp_ca_admin=$KRA_INST\_adminV
        local tmp_kra_port=$(eval echo \$${KRA_INST}_UNSECURE_PORT)
        local tmp_kra_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$KRA_INST\_agentV
        local valid_audit_cert=$KRA_INST\_auditV
        local valid_operator_cert=$KRA_INST\_operatorV
        local valid_admin_cert=$KRA_INST\_adminV
        local revoked_agent_cert=$KRA_INST\_agentR
        local revoked_admin_cert=$KRA_INST\_adminR
        local expired_admin_cert=$KRA_INST\_adminE
        local expired_agent_cert=$KRA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local kra_selftest_find_output=$TmpDir/kra-selftest-find.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki kra-selftest-find
	rlPhaseStartTest "pki_kra_selftest_find-configtest: pki kra-selftest-find --help configuration test"
	rlRun "pki kra-selftest-find --help > $kra_selftest_find_output" 0 "pki kra-selftest-find --help"
	rlAssertGrep "usage: kra-selftest-find \[FILTER\] \[OPTIONS...\]" "$kra_selftest_find_output"
	rlAssertGrep "    --help            Show help options" "$kra_selftest_find_output"
	rlAssertGrep "    --size <size>     Page size" "$kra_selftest_find_output"
	rlAssertGrep "    --start <start>   Page start" "$kra_selftest_find_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_kra_selftest_find-001: find all the existing selftests for CA using admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_admin_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_admin_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $valid_admin_cert"
	rlAssertGrep "1 entries matched" "$kra_selftest_find_output"
	rlAssertGrep "  SelfTest ID: KRAPresence" "$kra_selftest_find_output"
	rlAssertGrep "  Enabled at startup: false" "$kra_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$kra_selftest_find_output"
	rlAssertGrep "  Critical on demand: true" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-002: verifying all kra selftests cannot be found by agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_agent_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_agent_cert\" \
		kra-selftest-find 2> $kra_selftest_find_output" 1,255 "Find all the KRA Selftest using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-003: verifying all kra selftests cannot be found by operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_operator_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_operator_cert\" \
		kra-selftest-find 2> $kra_selftest_find_output" 1,255 "Find all the KRA Selftest using $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-004: verifying all kra selftests cannot be found by audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_operator_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$valid_operator_cert\" \
		kra-selftest-find 2> $kra_selftest_find_output" 1,255 "Find all the KRA Selftest using $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$kra_selftest_find_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_kra_selftest_find-005: verifying all kra selftests cannot be found by Revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$revoked_admin_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$revoked_admin_cert\" \
		kra-selftest-find > $kra_selftest_find_output 2>&1" 1,255 "Find all the KRA Selftest using $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-006: verifying all kra selftests cannot be found by Revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$revoked_agent_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$revoked_agent_cert\" \
		kra-selftest-find > $kra_selftest_find_output 2>&1" 1,255 "Find all the KRA Selftest using $revoked_agent_cert"
	rlAssertGrep "PKIException: Unauthorized" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-007: verifying all kra selftests cannot be found by Expired agent cert"
	local cur_date=$(date +%a\ %b\ %d\ %H:%M:%S)
	local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_agent_cert | grep "Not After" | awk -F ": " '{print $2}')
	rlLog "Current Date/Time: $(date)"
	rlLog "Current Date/Time: before modifying using chrony $(date)"
	rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Move system to $end_date + 1 day ahead"
	rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after modifying using chrony: $(date)"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$expired_agent_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$expired_agent_cert\" \
		kra-selftest-find > $kra_selftest_find_output 2>&1" 1,255 "Find all the KRA Selftest using $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$kra_selftest_find_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-008: verifying all kra selftests cannot be found by Expired admin cert"
	local cur_date=$(date +%a\ %b\ %d\ %H:%M:%S)
	local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_admin_cert | grep "Not After" | awk -F ": " '{print $2}')
	rlLog "Current Date/Time: $(date)"
	rlLog "Current Date/Time: before modifying using chrony $(date)"
	rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Move system to $end_date + 1 day ahead"
	rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after modifying using chrony: $(date)"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$expired_admin_cert\" \
		kra-selftest-find > $kra_selftest_find_output" 0 "Find all the KRA Selftest using $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $tmp_kra_port \
		-n \"$expired_admin_cert\" \
		kra-selftest-find > $kra_selftest_find_output 2>&1" 1,255 "Find all the KRA Selftest using $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$kra_selftest_find_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-009: verify when --size 1 is specified only 1 KRA selftest is displayed"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size 1 > $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size 1"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size 1 1> $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size 1"
        rlAssertGrep "1 entries matched" "$kra_selftest_find_output"
        rlAssertGrep "  SelfTest ID: KRAPresence" "$kra_selftest_find_output"
        rlAssertGrep "  Enabled at startup: false" "$kra_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$kra_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$kra_selftest_find_output"
	rlPhaseEnd


	rlPhaseStart "pki_kra_selftest_find-0010: verify when value given in --size is more than 3 display all the selftests"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size 100 > $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size 100"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size 100 > $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size 100"
	rlAssertGrep "1 entries matched" "$kra_selftest_find_output"
        rlAssertGrep "  SelfTest ID: KRAPresence" "$kra_selftest_find_output"
        rlAssertGrep "  Enabled at startup: false" "$kra_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$kra_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-0011: verify when value given in --size is junk no results are returned"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size adafdafds > $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size adafdafds"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size adafdafds > $kra_selftest_find_output 2>&1" 1,255 "Run pki kra-selftest-find --size adafdafds"
	rlAssertGrep "NumberFormatException: For input string: \"adafdafds\"" "$kra_selftest_find_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-0012: verify when no value with --size command fails with help message"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size > $kra_selftest_find_output 2>&1" 1,255 "No value is passed to pki kra-selftest-find --size"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size > $kra_selftest_find_output 2>&1" 1,255 "No value is passed to pki kra-selftest-find --size"
	rlAssertGrep "Error: Missing argument for option: size" "$kra_selftest_find_output"
	rlAssertGrep "usage: kra-selftest-find \[FILTER\] \[OPTIONS...\]" "$kra_selftest_find_output"
        rlAssertGrep "    --help            Show help options" "$kra_selftest_find_output"
        rlAssertGrep "    --size <size>     Page size" "$kra_selftest_find_output"
        rlAssertGrep "    --start <start>   Page start" "$kra_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_selftest_find-0013: verify when --size 1 and --start 1 is specified only 1 KRA selftest is displayed"
	 rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size 1 --start 1 > $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size 1 --start 1"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --size 1 --start 0 > $kra_selftest_find_output" 0 "Run pki kra-selftest-find --size 1 --start 1"
	rlAssertGrep "1 entries matched" "$kra_selftest_find_output"
        rlAssertGrep "  SelfTest ID: KRAPresence" "$kra_selftest_find_output"
        rlAssertGrep "  Enabled at startup: false" "$kra_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$kra_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$kra_selftest_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_selftest_find-0014: verify when no value with --start command fails with help message"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --start > $kra_selftest_find_output 2>&1" 1,255 "No value is passed to pki kra-selftest-find --size"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $tmp_kra_port \
                -n \"$valid_admin_cert\" \
                kra-selftest-find --start > $kra_selftest_find_output 2>&1" 1,255 "No value is passed to pki kra-selftest-find --size"
        rlAssertGrep "Error: Missing argument for option: start" "$kra_selftest_find_output"
        rlAssertGrep "usage: kra-selftest-find \[FILTER\] \[OPTIONS...\]" "$kra_selftest_find_output"
        rlAssertGrep "    --help            Show help options" "$kra_selftest_find_output"
        rlAssertGrep "    --size <size>     Page size" "$kra_selftest_find_output"
        rlAssertGrep "    --start <start>   Page start" "$kra_selftest_find_output"
        rlPhaseEnd
else
	rlPhaseStartCleanup "pki kra-selftest-find cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "KRA subsystem is not installed"
        rlPhaseEnd
fi
}
