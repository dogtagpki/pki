#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-tks-selftest-cli
#
#   Description: PKI TKS SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki ca-selftest cli commands needs to be tested:
#  pki tks-selftest-show
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

run_pki-tks-selftest-show_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki tks-selftest-show
        rlPhaseStartSetup "pki tks-selftest-show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local TKS_INST=$(cat $TmpDir/topo_file | grep MY_TKS | cut -d= -f2)
        tks_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$TKS_INST
                tks_instance_created=$(eval echo \$${TKS_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                        prefix=TKS1
                        tks_instance_created=$(eval echo \$${TKS_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$cs_Role
                tks_instance_created=$(eval echo \$${TKS_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$tks_instance_created" = "TRUE" ] ;  then
        local target_secure_port=$(eval echo \$${TKS_INST}_SECURE_PORT)
        local tmp_tks_agent=$TKS_INST\_agentV
        local tmp_tks_admin=$TKS_INST\_adminV
        local tmp_tks_port=$(eval echo \$${TKS_INST}_UNSECURE_PORT)
        local tmp_tks_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$TKS_INST\_agentV
        local valid_audit_cert=$TKS_INST\_auditV
        local valid_operator_cert=$TKS_INST\_operatorV
        local valid_admin_cert=$TKS_INST\_adminV
        local revoked_agent_cert=$TKS_INST\_agentR
        local revoked_admin_cert=$TKS_INST\_adminR
        local expired_admin_cert=$TKS_INST\_adminE
        local expired_agent_cert=$TKS_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local tks_selftest_show_output=$TmpDir/tks-selftest-show.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki tks-selftest-show
	rlPhaseStartTest "pki_tks_selftest_show-configtest: pki tks-selftest-show --help configuration test"
	rlRun "pki tks-selftest-show --help > $tks_selftest_show_output" 0 "pki tks-selftest-show --help"
	rlAssertGrep "usage: tks-selftest-show <SelfTest ID> \[OPTIONS...\]" "$tks_selftest_show_output"
	rlAssertGrep "    --help            Show help options" "$tks_selftest_show_output"
	rlAssertGrep "    --output <file>   Output file to store selfTest properties." "$tks_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-001: Show TKSKnownSessionKey selftest properties"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey Selftest"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey Selftest"
	rlAssertGrep "SelfTest \"TKSKnownSessionKey\""  "$tks_selftest_show_output"
	rlAssertGrep "  SelfTest ID: TKSKnownSessionKey" "$tks_selftest_show_output"
        rlAssertGrep "  Enabled at startup: true" "$tks_selftest_show_output"
        rlAssertGrep "  Critical at startup: true" "$tks_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$tks_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$tks_selftest_show_output"
	rlPhaseEnd

	
	rlPhaseStartTest "pki_tks_selftest_show-002: Copy  TKSKnownSessionKey selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show TKSKnownSessionKey --output $TmpDir/TKSKnownSessionKey > $tks_selftest_show_output" 0 "Save TKSKnownSessionKey Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show TKSKnownSessionKey --output $TmpDir/TKSKnownSessionKey > $tks_selftest_show_output" 0 "Save TKSKnownSessionKey Selftest to a file"
	rlAssertGrep "Stored selfTest \"TKSKnownSessionKey\" into $TmpDir/TKSKnownSessionKey" "$tks_selftest_show_output"
        rlPhaseEnd	

	rlPhaseStartTest "pki_tks_selftest_show-003: Show SystemCertsVerification selftest properties"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show SystemCertsVerification > $tks_selftest_show_output" 0 "Show SystemCertsVerification Selftest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show SystemCertsVerification > $tks_selftest_show_output" 0 "Show SystemCertsVerification Selftest"
        rlAssertGrep "SelfTest \"SystemCertsVerification\""  "$tks_selftest_show_output"
	rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$tks_selftest_show_output"
        rlAssertGrep "  Enabled at startup: true" "$tks_selftest_show_output"
        rlAssertGrep "  Critical at startup: true" "$tks_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$tks_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$tks_selftest_show_output"
        rlPhaseEnd


        rlPhaseStartTest "pki_tks_selftest_show-004: Copy SystemCertsVerification selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show SystemCertsVerification --output $TmpDir/SystemCertsVerification > $tks_selftest_show_output" 0 "Save SystemCertsVerification Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show SystemCertsVerification --output $TmpDir/SystemCertsVerification > $tks_selftest_show_output" 0 "Save SystemCertsVerification Selftest to a file"
        rlAssertGrep "Stored selfTest \"SystemCertsVerification\" into $TmpDir/SystemCertsVerification" "$tks_selftest_show_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-005: Verify TKSKnownSessionKey selftest properties are shown using admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_admin_cert\" \
		tks-selftest-show  TKSKnownSessionKey > $tks_selftest_show_output" 0 "show TKSKnownSessionKey selftest using $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "show TKSKnownSessionKey Selftest using $valid_admin_cert"
	rlAssertGrep "SelfTest ID: TKSKnownSessionKey" "$tks_selftest_show_output"
	rlAssertGrep "  Enabled at startup: true" "$tks_selftest_show_output"
	rlAssertGrep "  Critical at startup: true" "$tks_selftest_show_output"
	rlAssertGrep "  Enabled on demand: true" "$tks_selftest_show_output"
	rlAssertGrep "  Critical on demand: true" "$tks_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-006: verify TKSKnownSessionKey selftest properties cannot be shown using agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_agent_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_agent_cert\" \
		tks-selftest-show TKSKnownSessionKey 2> $tks_selftest_show_output" 1,255 "Show TKSKnownSessionKey selftest property using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tks_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-007: verify TKSKnownSessionKey selftest properties cannot be shown using operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_operator_cert\" \
		tks-selftest-show  TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_operator_cert\" \
		tks-selftest-show TKSKnownSessionKey 2> $tks_selftest_show_output" 1,255 "Show TKSKnownSessionKey selftest property using $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tks_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-008: verify TKSKnownSessionKey selftest properties cannot be shown using audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_operator_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$valid_operator_cert\" \
		tks-selftest-show TKSKnownSessionKey 2> $tks_selftest_show_output" 1,255 "Show TKSKnownSessionKey selftest property using $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tks_selftest_show_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tks_selftest_show-009: verify TKSKnownSessionKey selftest properties cannot be shown using revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$revoked_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$revoked_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey 2> $tks_selftest_show_output" 1,255 "Show TKSKnownSessionKey selftest property using $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$tks_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-0010: verify TKSKnownSessionKey selftest properties cannot be shown using revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$revoked_agent_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$revoked_agent_cert\" \
		tks-selftest-show TKSKnownSessionKey 2> $tks_selftest_show_output" 1,255 "Show TKSKnownSessionKey selftest property using $revoked_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tks_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-0011: verify TKSKnownSessionKey selftest properties cannot be shown using Expired agent cert"
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
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$expired_agent_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$expired_agent_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output 2>&1" 1,255 "Show TKSKnownSessionKey selftest property using $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$tks_selftest_show_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-0012: verify TKSKnownSessionKey selftest properties cannot be shown using Expired admin cert"
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
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$expired_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output" 0 "Show TKSKnownSessionKey selftest property using $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tks_host \
		-p $tmp_tks_port \
		-n \"$expired_admin_cert\" \
		tks-selftest-show TKSKnownSessionKey > $tks_selftest_show_output 2>&1" 1,255 "Show TKSKnownSessionKey selftest property using $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$tks_selftest_show_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tks_selftest_show-0013: verify when no valid selftestID is provided pki tks-selftest-show show show proper help message"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show > $tks_selftest_show_output" 0 "Do not pass any selftestId"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show > $tks_selftest_show_output 2>&1" 255,1 "Do not pass any selftestId"	
	rlAssertGrep "Error: No SelfTest ID specified." "$tks_selftest_show_output"
	rlAssertGrep "usage: tks-selftest-show <SelfTest ID> \[OPTIONS...\]" "$tks_selftest_show_output"
        rlAssertGrep "    --help            Show help options" "$tks_selftest_show_output"
        rlAssertGrep "    --output <file>   Output file to store selfTest properties." "$tks_selftest_show_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tks_selftest_show-0014: verify when junk/invalid selftestid is provided, "
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show \"asdfasdf\" > $tks_selftest_show_output" 0 "pass junk \"asdfasdf\" to pki tks-selftest-show"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_tks_host \
                -p $tmp_tks_port \
                -n \"$valid_admin_cert\" \
                tks-selftest-show \"asdfasdf\" > $tks_selftest_show_output" 0 "pass junk \"asdfasdf\" to pki tks-selftest-show"
	rlAssertGrep "SelfTest \"asdfasdf\"" "$tks_selftest_show_output"
	rlAssertGrep "  SelfTest ID: asdfasdf" "$tks_selftest_show_output"
	rlAssertGrep "  Enabled at startup: false"  "$tks_selftest_show_output"
	rlAssertGrep "  Enabled on demand: false"  "$tks_selftest_show_output"
	rlAssertNotGrep " SelfTest \"TKSKnownSessionKey\""  "$tks_selftest_show_output"
        rlAssertNotGrep "  SelfTest ID: TKSKnownSessionKey" "$tks_selftest_show_output"
        rlAssertNotGrep "  Enabled at startup: true" "$tks_selftest_show_output"
        rlAssertNotGrep "  Critical at startup: true" "$tks_selftest_show_output"
        rlAssertNotGrep "  Enabled on demand: true" "$tks_selftest_show_output"
        rlAssertNotGrep "  Critical on demand: true" "$tks_selftest_show_output"
        rlPhaseEnd
else
	rlPhaseStartCleanup "pki tks-selftest-show cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "TKS subsystem is not installed"
        rlPhaseEnd
fi
}
