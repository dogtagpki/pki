#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-tps-selftest-cli
#
#   Description: PKI TPS SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki tps-selftest cli commands needs to be tested:
#  pki tps-selftest-find
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
. /opt/rhqa_pki/pki-key-cli-lib.sh
. /opt/rhqa_pki/env.sh

run_pki-tps-selftest-find_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki tps-selftest-find
        rlPhaseStartSetup "pki tps-selftest-find Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local TPS_INST=$(cat $TmpDir/topo_file | grep MY_TPS | cut -d= -f2)
        tps_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$TPS_INST
                tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                        prefix=TPS1
                        tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$cs_Role
                tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$tps_instance_created" = "TRUE" ] ;  then
 
        local target_secure_port=$(eval echo \$${TPS_INST}_SECURE_PORT)
        local tmp_tps_agent=$TPS_INST\_agentV
        local tmp_tps_admin=$TPS_INST\_adminV
        local tmp_tps_port=$(eval echo \$${TPS_INST}_UNSECURE_PORT)
        local tmp_tps_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$TPS_INST\_agentV
        local valid_audit_cert=$TPS_INST\_auditV
        local valid_operator_cert=$TPS_INST\_operatorV
        local valid_admin_cert=$TPS_INST\_adminV
        local revoked_agent_cert=$TPS_INST\_agentR
        local revoked_admin_cert=$TPS_INST\_adminR
        local expired_admin_cert=$TPS_INST\_adminE
        local expired_agent_cert=$TPS_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local ca_selftest_find_output=$TmpDir/tps-selftest-find.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki tps-selftest-find
	rlPhaseStartTest "pki_tps_selftest-configtest: pki tps-selftest-find --help configuration test"
	rlRun "pki tps-selftest-find --help > $ca_selftest_find_output" 0 "pki tps-selftest-find --help"
	rlAssertGrep "usage: tps-selftest-find \[FILTER\] \[OPTIONS...\]" "$ca_selftest_find_output"
	rlAssertGrep "    --help            Show help options" "$ca_selftest_find_output"
	rlAssertGrep "    --size <size>     Page size" "$ca_selftest_find_output"
	rlAssertGrep "    --start <start>   Page start" "$ca_selftest_find_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pk_tps_selftest-001: find all the existing selftests for CA using admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $valid_admin_cert"
	rlAssertGrep "3 entries matched" "$ca_selftest_find_output"
	rlAssertGrep "  SelfTest ID: TPSPresence" "$ca_selftest_find_output"
	rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
	rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
	rlAssertGrep "  Critical on demand: true" "$ca_selftest_find_output"
	rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ca_selftest_find_output"
	rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
	rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
	rlAssertGrep "  Critical on demand: true" "$ca_selftest_find_output"
	rlAssertGrep "  SelfTest ID: TPSValidity" "$ca_selftest_find_output"
	rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
	rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-002: verifying all ca selftests cannot be found by agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_agent_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_agent_cert\" \
		tps-selftest-find 2> $ca_selftest_find_output" 1,255 "Find all the TPS Selftest using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-003: verifying all ca selftests cannot be found by operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-find 2> $ca_selftest_find_output" 1,255 "Find all the TPS Selftest using $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-004: verifying all ca selftests cannot be found by audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-find 2> $ca_selftest_find_output" 1,255 "Find all the TPS Selftest using $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_find_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tps_selftest-005: verifying all ca selftests cannot be found by Revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_admin_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_admin_cert\" \
		tps-selftest-find 2> $ca_selftest_find_output" 1,255 "Find all the TPS Selftest using $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-006: verifying all ca selftests cannot be found by Revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_agent_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_agent_cert\" \
		tps-selftest-find 2> $ca_selftest_find_output" 1,255 "Find all the TPS Selftest using $revoked_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-007: verifying all ca selftests cannot be found by Expired agent cert"
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
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_agent_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_agent_cert\" \
		tps-selftest-find > $ca_selftest_find_output 2>&1" 1,255 "Find all the TPS Selftest using $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ca_selftest_find_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-008: verifying all ca selftests cannot be found by Expired admin cert"
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
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_admin_cert\" \
		tps-selftest-find > $ca_selftest_find_output" 0 "Find all the TPS Selftest using $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_admin_cert\" \
		tps-selftest-find > $ca_selftest_find_output 2>&1" 1,255 "Find all the TPS Selftest using $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ca_selftest_find_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-009: verify when --size 1 is specified only 1 TPS selftest is displayed"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size 1 > $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size 1"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size 1 1> $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size 1"
        rlAssertGrep "3 entries matched" "$ca_selftest_find_output"
        rlAssertGrep "  SelfTest ID: TPSPresence" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_find_output"
	rlPhaseEnd


	rlPhaseStart "pki_tps_selftest-0010: verify when value given in --size is more than 3 display all the selftests"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size 100 > $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size 100"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size 100 > $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size 100"
        rlAssertGrep "3 entries matched" "$ca_selftest_find_output"
        rlAssertGrep "  SelfTest ID: TPSPresence" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  SelfTest ID: TPSValidity" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-0011: verify when value given in --size is junk no results are returned"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size adafdafds > $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size adafdafds"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size adafdafds > $ca_selftest_find_output 2>&1" 1,255 "Run pki tps-selftest-find --size adafdafds"
	rlAssertGrep "NumberFormatException: For input string: \"adafdafds\"" "$ca_selftest_find_output"
	rlAssertGroup
        PhaseEnd

	rlPhaseStartTest "pki_tps_selftest-0012: verify when no value with --size command fails with help message"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size > $ca_selftest_find_output 2>&1" 1,255 "No value is passed to pki tps-selftest-find --size"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size > $ca_selftest_find_output 2>&1" 1,255 "No value is passed to pki tps-selftest-find --size"
	rlAssertGrep "Error: Missing argument for option: size" "$ca_selftest_find_output"
	rlAssertGrep "usage: tps-selftest-find \[FILTER\] \[OPTIONS...\]" "$ca_selftest_find_output"
        rlAssertGrep "    --help            Show help options" "$ca_selftest_find_output"
        rlAssertGrep "    --size <size>     Page size" "$ca_selftest_find_output"
        rlAssertGrep "    --start <start>   Page start" "$ca_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest-0013: verify when --size 1 and --start 1 is specified only 1 TPS selftest is displayed"
	 rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size 1 --start 1 > $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size 1 --start 1"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --size 1 --start 1 > $ca_selftest_find_output" 0 "Run pki tps-selftest-find --size 1 --start 1"
        rlAssertGrep "3 entries matched" "$ca_selftest_find_output"
        rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_find_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_tps_selftest-0014: verify when no value with --start command fails with help message"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --start > $ca_selftest_find_output 2>&1" 1,255 "No value is passed to pki tps-selftest-find --size"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-find --start > $ca_selftest_find_output 2>&1" 1,255 "No value is passed to pki tps-selftest-find --size"
        rlAssertGrep "Error: Missing argument for option: start" "$ca_selftest_find_output"
        rlAssertGrep "usage: tps-selftest-find \[FILTER\] \[OPTIONS...\]" "$ca_selftest_find_output"
        rlAssertGrep "    --help            Show help options" "$ca_selftest_find_output"
        rlAssertGrep "    --size <size>     Page size" "$ca_selftest_find_output"
        rlAssertGrep "    --start <start>   Page start" "$ca_selftest_find_output"
        rlPhaseEnd
else
	rlPhaseStartCleanup "pki tps-selftest-find cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "TPS subsystem is not installed"
        rlPhaseEnd
fi
}
