#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-selftest-cli
#
#   Description: PKI CA SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki ca-selftest cli commands needs to be tested:
#  pki ca-selftest-show
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

run_pki-ca-selftest-show_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki ca-selftest-show
        rlPhaseStartSetup "pki ca-selftest-show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        ca_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$CA_INST
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                if [[ $CA_INST == SUBCA* ]]; then
                        prefix=$CA_INST
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                else
                        prefix=ROOTCA
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                fi
        else
                prefix=$cs_Role
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$ca_instance_created" = "TRUE" ] ;  then
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$CA_INST\_agentV
        local valid_audit_cert=$CA_INST\_auditV
        local valid_operator_cert=$CA_INST\_operatorV
        local valid_admin_cert=$CA_INST\_adminV
        local revoked_agent_cert=$CA_INST\_agentR
        local revoked_admin_cert=$CA_INST\_adminR
        local expired_admin_cert=$CA_INST\_adminE
        local expired_agent_cert=$CA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local ca_selftest_show_output=$TmpDir/ca-selftest-show.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki ca-selftest-show
	rlPhaseStartTest "pki_ca_selftest_show-configtest: pki ca-selftest-show --help configuration test"
	rlRun "pki ca-selftest-show --help > $ca_selftest_show_output" 0 "pki ca-selftest-show --help"
	rlAssertGrep "usage: ca-selftest-show <SelfTest ID> \[OPTIONS...\]" "$ca_selftest_show_output"
	rlAssertGrep "    --help            Show help options" "$ca_selftest_show_output"
	rlAssertGrep "    --output <file>   Output file to store selfTest properties." "$ca_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-001: Show CAPresence selftest properties"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence Selftest"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence Selftest"
	rlAssertGrep "SelfTest \"CAPresence\""  "$ca_selftest_show_output"
	rlAssertGrep "  SelfTest ID: CAPresence" "$ca_selftest_show_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_show_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_show_output"
	rlPhaseEnd

	
	rlPhaseStartTest "pki_ca_selftest_show-002: Copy  CAPresence selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show CAPresence --output $TmpDir/CAPresence > $ca_selftest_show_output" 0 "Save CAPresence Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show CAPresence --output $TmpDir/CAPresence > $ca_selftest_show_output" 0 "Save CAPresence Selftest to a file"
	rlAssertGrep "Stored selfTest \"CAPresence\" into $TmpDir/CAPresence" "$ca_selftest_show_output"
        rlPhaseEnd	

	rlPhaseStartTest "pki_ca_selftest_show-003: Show SystemCertsVerification selftest properties"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show SystemCertsVerification > $ca_selftest_show_output" 0 "Show SystemCertsVerification Selftest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show SystemCertsVerification > $ca_selftest_show_output" 0 "Show SystemCertsVerification Selftest"
        rlAssertGrep "SelfTest \"SystemCertsVerification\""  "$ca_selftest_show_output"
	rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ca_selftest_show_output"
        rlAssertGrep "  Enabled at startup: true" "$ca_selftest_show_output"
        rlAssertGrep "  Critical at startup: true" "$ca_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_show_output"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_selftest_show-004: Copy SystemCertsVerification selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show SystemCertsVerification --output $TmpDir/SystemCertsVerification > $ca_selftest_show_output" 0 "Save SystemCertsVerification Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show SystemCertsVerification --output $TmpDir/SystemCertsVerification > $ca_selftest_show_output" 0 "Save SystemCertsVerification Selftest to a file"
        rlAssertGrep "Stored selfTest \"SystemCertsVerification\" into $TmpDir/SystemCertsVerification" "$ca_selftest_show_output"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_selftest_show-005: Show CAValidity selftest properties"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show CAValidity > $ca_selftest_show_output" 0 "Show CAValidity Selftest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show CAValidity > $ca_selftest_show_output" 0 "Show CAValidity Selftest"
        rlAssertGrep "SelfTest \"CAValidity\""  "$ca_selftest_show_output"
	rlAssertGrep "  SelfTest ID: CAValidity" "$ca_selftest_show_output"
        rlAssertGrep "  Enabled at startup: false" "$ca_selftest_show_output"
        rlAssertGrep "  Enabled on demand: true" "$ca_selftest_show_output"
        rlAssertGrep "  Critical on demand: true" "$ca_selftest_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_selftest_show-006: Copy CAValidity selftest Properties to a file"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show CAValidity --output $TmpDir/CAValidity > $ca_selftest_show_output" 0 "Save CAValidity Selftest to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show CAValidity --output $TmpDir/CAValidity > $ca_selftest_show_output" 0 "Save CAValidity Selftest to a file"
        rlAssertGrep "Stored selfTest \"CAValidity\" into $TmpDir/CAValidity" "$ca_selftest_show_output"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_selftest_show-007: Verify CAPresence selftest properties are shown using admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_admin_cert\" \
		ca-selftest-show  CAPresence > $ca_selftest_show_output" 0 "show CAPresence selftest using $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_admin_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "show CAPresence Selftest using $valid_admin_cert"
	rlAssertGrep "SelfTest ID: CAPresence" "$ca_selftest_show_output"
	rlAssertGrep "  Enabled at startup: true" "$ca_selftest_show_output"
	rlAssertGrep "  Critical at startup: true" "$ca_selftest_show_output"
	rlAssertGrep "  Enabled on demand: true" "$ca_selftest_show_output"
	rlAssertGrep "  Critical on demand: true" "$ca_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-008: verify CAPresence selftest properties cannot be shown using agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_agent_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_agent_cert\" \
		ca-selftest-show CAPresence 2> $ca_selftest_show_output" 1,255 "Show CAPresence selftest property using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-009: verify CAPresence selftest properties cannot be shown using operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_operator_cert\" \
		ca-selftest-show  CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_operator_cert\" \
		ca-selftest-show CAPresence 2> $ca_selftest_show_output" 1,255 "Show CAPresence selftest property using $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-0010: verify CAPresence selftest properties cannot be shown using audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_operator_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$valid_operator_cert\" \
		ca-selftest-show CAPresence 2> $ca_selftest_show_output" 1,255 "Show CAPresence selftest property using $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ca_selftest_show_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_selftest_show-0011: verify CAPresence selftest properties cannot be shown using revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$revoked_admin_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$revoked_admin_cert\" \
		ca-selftest-show CAPresence 2> $ca_selftest_show_output" 1,255 "Show CAPresence selftest property using $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$ca_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-0012: verify CAPresence selftest properties cannot be shown using revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$revoked_agent_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$revoked_agent_cert\" \
		ca-selftest-show CAPresence 2> $ca_selftest_show_output" 1,255 "Show CAPresence selftest property using $revoked_agent_cert"
	rlAssertGrep "PKIException: Unauthorized" "$ca_selftest_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-0013: verify CAPresence selftest properties cannot be shown using Expired agent cert"
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
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$expired_agent_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$expired_agent_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output 2>&1" 1,255 "Show CAPresence selftest property using $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ca_selftest_show_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-0014: verify CAPresence selftest properties cannot be shown using Expired admin cert"
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
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$expired_admin_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output" 0 "Show CAPresence selftest property using $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ca_host \
		-p $tmp_ca_port \
		-n \"$expired_admin_cert\" \
		ca-selftest-show CAPresence > $ca_selftest_show_output 2>&1" 1,255 "Show CAPresence selftest property using $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ca_selftest_show_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_selftest_show-0015: verify when no valid selftestID is provided pki ca-selftest-show show show proper help message"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show > $ca_selftest_show_output" 0 "Do not pass any selftestId"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show > $ca_selftest_show_output 2>&1" 255,1 "Do not pass any selftestId"	
	rlAssertGrep "Error: No SelfTest ID specified." "$ca_selftest_show_output"
	rlAssertGrep "usage: ca-selftest-show <SelfTest ID> \[OPTIONS...\]" "$ca_selftest_show_output"
        rlAssertGrep "    --help            Show help options" "$ca_selftest_show_output"
        rlAssertGrep "    --output <file>   Output file to store selfTest properties." "$ca_selftest_show_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_selftest_show-0016: verify when junk/invalid selftestid is provided, "
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show \"asdfasdf\" > $ca_selftest_show_output" 0 "pass junk \"asdfasdf\" to pki ca-selftest-show"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n \"$valid_admin_cert\" \
                ca-selftest-show \"asdfasdf\" > $ca_selftest_show_output" 0 "pass junk \"asdfasdf\" to pki ca-selftest-show"
	rlAssertGrep "SelfTest \"asdfasdf\"" "$ca_selftest_show_output"
	rlAssertGrep "  SelfTest ID: asdfasdf" "$ca_selftest_show_output"
	rlAssertGrep "  Enabled at startup: false"  "$ca_selftest_show_output"
	rlAssertGrep "  Enabled on demand: false"  "$ca_selftest_show_output"
	rlAssertNotGrep " SelfTest \"CAPresence\""  "$ca_selftest_show_output"
        rlAssertNotGrep "  SelfTest ID: CAPresence" "$ca_selftest_show_output"
        rlAssertNotGrep "  Enabled at startup: true" "$ca_selftest_show_output"
        rlAssertNotGrep "  Critical at startup: true" "$ca_selftest_show_output"
        rlAssertNotGrep "  Enabled on demand: true" "$ca_selftest_show_output"
        rlAssertNotGrep "  Critical on demand: true" "$ca_selftest_show_output"
        rlPhaseEnd
else
	rlPhaseStartCleanup "pki ca-selftest-show cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "CA subsystem is not installed"
        rlPhaseEnd
fi
}
