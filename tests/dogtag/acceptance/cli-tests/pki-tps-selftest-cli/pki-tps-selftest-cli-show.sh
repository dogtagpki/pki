#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-tps-selftest-cli
#
#   Description: PKI CA SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki tps-selftest cli commands needs to be tested:
#  pki tps-selftest-show
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

run_pki-tps-selftest-show_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki tps-selftest-show
        rlPhaseStartSetup "pki tps-selftest-show Temporary Directory"
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
        local tps_selftest_show_output=$TmpDir/tps-selftest-show.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki tps-selftest-show
	rlPhaseStartTest "pki_tps_selftest_show-configtest: pki tps-selftest-show --help configuration test"
	rlRun "pki tps-selftest-show --help > $tps_selftest_show_output" 0 "pki tps-selftest-show --help"
	rlAssertGrep "usage: tps-selftest-show <SelfTest ID> \[OPTIONS...\]" "$tps_selftest_show_output"
	rlAssertGrep "    --help            Show help options" "$tps_selftest_show_output"
	rlAssertGrep "    --output <file>   Output file to store selfTest properties." "$tps_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-001: Show TPSPresence selftest properties"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence Selftest"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence Selftest"
	rlAssertGrep "SelfTest \"TPSPresence\""  "$tps_selftest_show_output"
	rlAssertGrep "  SelfTest ID: TPSPresence" "$tps_selftest_show_output"
        rlAssertGrep "  Enabled at startup: true" "$tps_selftest_show_output"
        rlAssertGrep "  Critical at startup: true" "$tps_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$tps_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$tps_selftest_show_output"
	rlPhaseEnd

	
	rlPhaseStartTest "pki_tps_selftest_show-002: Copy  TPSPresence selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show TPSPresence --output $TmpDir/TPSPresence > $tps_selftest_show_output" 0 "Save TPSPresence Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show TPSPresence --output $TmpDir/TPSPresence > $tps_selftest_show_output" 0 "Save TPSPresence Selftest to a file"
	rlAssertGrep "Stored selfTest \"TPSPresence\" into $TmpDir/TPSPresence" "$tps_selftest_show_output"
        rlPhaseEnd	

	rlPhaseStartTest "pki_tps_selftest_show-003: Show SystemCertsVerification selftest properties"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show SystemCertsVerification > $tps_selftest_show_output" 0 "Show SystemCertsVerification Selftest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show SystemCertsVerification > $tps_selftest_show_output" 0 "Show SystemCertsVerification Selftest"
        rlAssertGrep "SelfTest \"SystemCertsVerification\""  "$tps_selftest_show_output"
	rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$tps_selftest_show_output"
        rlAssertGrep "  Enabled at startup: true" "$tps_selftest_show_output"
        rlAssertGrep "  Critical at startup: true" "$tps_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$tps_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$tps_selftest_show_output"
        rlPhaseEnd


        rlPhaseStartTest "pki_tps_selftest_show-004: Copy SystemCertsVerification selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show SystemCertsVerification --output $TmpDir/SystemCertsVerification > $tps_selftest_show_output" 0 "Save SystemCertsVerification Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show SystemCertsVerification --output $TmpDir/SystemCertsVerification > $tps_selftest_show_output" 0 "Save SystemCertsVerification Selftest to a file"
        rlAssertGrep "Stored selfTest \"SystemCertsVerification\" into $TmpDir/SystemCertsVerification" "$tps_selftest_show_output"
        rlPhaseEnd


	rlPhaseStartTest "pki_tps_selftest_show-005: Show TPSValidity selftest properties"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show TPSValidity > $tps_selftest_show_output" 0 "Show TPSValidity Selftest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show TPSValidity > $tps_selftest_show_output" 0 "Show TPSValidity Selftest"
        rlAssertGrep "SelfTest \"TPSValidity\""  "$tps_selftest_show_output"
	rlAssertGrep "  SelfTest ID: TPSValidity" "$tps_selftest_show_output"
        rlAssertGrep "  Enabled at startup: false" "$tps_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$tps_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$tps_selftest_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_selftest_show-006: Copy TPSValidity selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show TPSValidity --output $TmpDir/TPSValidity > $tps_selftest_show_output" 0 "Save TPSValidity Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show TPSValidity --output $TmpDir/TPSValidity > $tps_selftest_show_output" 0 "Save TPSValidity Selftest to a file"
        rlAssertGrep "Stored selfTest \"TPSValidity\" into $TmpDir/TPSValidity" "$tps_selftest_show_output"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_tps_selftest_show-007: Verify TPSPresence selftest properties are shown using admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-selftest-show  TPSPresence > $tps_selftest_show_output" 0 "show TPSPresence selftest using $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "show TPSPresence Selftest using $valid_admin_cert"
	rlAssertGrep "SelfTest ID: TPSPresence" "$tps_selftest_show_output"
	rlAssertGrep "  Enabled at startup: true" "$tps_selftest_show_output"
	rlAssertGrep "  Critical at startup: true" "$tps_selftest_show_output"
	rlAssertGrep "  Enabled on demand: true" "$tps_selftest_show_output"
	rlAssertGrep "  Critical on demand: true" "$tps_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-008: verify TPSPresence selftest properties cannot be shown using agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_agent_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_agent_cert\" \
		tps-selftest-show TPSPresence 2> $tps_selftest_show_output" 1,255 "Show TPSPresence selftest property using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-009: verify TPSPresence selftest properties cannot be shown using operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-show  TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-show TPSPresence 2> $tps_selftest_show_output" 1,255 "Show TPSPresence selftest property using $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-0010: verify TPSPresence selftest properties cannot be shown using audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-show TPSPresence 2> $tps_selftest_show_output" 1,255 "Show TPSPresence selftest property using $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_show_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tps_selftest_show-0011: verify TPSPresence selftest properties cannot be shown using revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_admin_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_admin_cert\" \
		tps-selftest-show TPSPresence 2> $tps_selftest_show_output" 1,255 "Show TPSPresence selftest property using $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$tps_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-0012: verify TPSPresence selftest properties cannot be shown using revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_agent_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_agent_cert\" \
		tps-selftest-show TPSPresence 2> $tps_selftest_show_output" 1,255 "Show TPSPresence selftest property using $revoked_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-0013: verify TPSPresence selftest properties cannot be shown using Expired agent cert"
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
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_agent_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output 2>&1" 1,255 "Show TPSPresence selftest property using $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$tps_selftest_show_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-0014: verify TPSPresence selftest properties cannot be shown using Expired admin cert"
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
		tps-selftest-show TPSPresence > $tps_selftest_show_output" 0 "Show TPSPresence selftest property using $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_admin_cert\" \
		tps-selftest-show TPSPresence > $tps_selftest_show_output 2>&1" 1,255 "Show TPSPresence selftest property using $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$tps_selftest_show_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_show-0015: verify when no valid selftestID is provided pki tps-selftest-show show show proper help message"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show > $tps_selftest_show_output" 0 "Do not pass any selftestId"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show > $tps_selftest_show_output 2>&1" 255,1 "Do not pass any selftestId"	
	rlAssertGrep "Error: No SelfTest ID specified." "$tps_selftest_show_output"
	rlAssertGrep "usage: tps-selftest-show <SelfTest ID> \[OPTIONS...\]" "$tps_selftest_show_output"
        rlAssertGrep "    --help            Show help options" "$tps_selftest_show_output"
        rlAssertGrep "    --output <file>   Output file to store selfTest properties." "$tps_selftest_show_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tps_selftest_show-0016: verify when junk/invalid selftestid is provided, "
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show \"asdfasdf\" > $tps_selftest_show_output" 0 "pass junk \"asdfasdf\" to pki tps-selftest-show"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tps_host \
                -p $tmp_tps_port \
                -n \"$valid_admin_cert\" \
                tps-selftest-show \"asdfasdf\" > $tps_selftest_show_output" 0 "pass junk \"asdfasdf\" to pki tps-selftest-show"
	rlAssertGrep "SelfTest \"asdfasdf\"" "$tps_selftest_show_output"
	rlAssertGrep "  SelfTest ID: asdfasdf" "$tps_selftest_show_output"
	rlAssertGrep "  Enabled at startup: false"  "$tps_selftest_show_output"
	rlAssertGrep "  Enabled on demand: false"  "$tps_selftest_show_output"
	rlAssertNotGrep " SelfTest \"TPSPresence\""  "$tps_selftest_show_output"
        rlAssertNotGrep "  SelfTest ID: TPSPresence" "$tps_selftest_show_output"
        rlAssertNotGrep "  Enabled at startup: true" "$tps_selftest_show_output"
        rlAssertNotGrep "  Critical at startup: true" "$tps_selftest_show_output"
        rlAssertNotGrep "  Enabled on demand: true" "$tps_selftest_show_output"
        rlAssertNotGrep "  Critical on demand: true" "$tps_selftest_show_output"
        rlPhaseEnd
else
	rlPhaseStartCleanup "pki tps-selftest-show cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "TPS subsystem is not installed"
        rlPhaseEnd
fi
}
