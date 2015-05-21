#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-tps-selftest-cli
#
#   Description: PKI TPS SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki tps-selftest cli commands needs to be tested:
#  pki tps-selftest-run
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

run_pki-tps-selftest-run_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki tps-selftest-run
        rlPhaseStartSetup "pki tps-selftest-run Temporary Directory"
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
        local tps_selftest_run_output=$TmpDir/tps-selftest-run.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki tps-selftest-run
	rlPhaseStartTest "pki_tps_selftest_run-configtest: pki tps-selftest-run --help configuration test"
	rlRun "pki tps-selftest-run --help > $tps_selftest_run_output" 0 "pki tps-selftest-run --help"
	rlAssertGrep "usage: tps-selftest-run \[OPTIONS...\]" "$tps_selftest_run_output"
	rlAssertGrep "    --help   Show help options" "$tps_selftest_run_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tps_selftest_run-001: Run TPS Selftest using admin cert and verify ca subsystem is up"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $valid_admin_cert"
	rlAssertGrep "Selftests completed" "$tps_selftest_run_output"
	rlLog "Verify tps instance is running"
	rlRun "systemctl status pki-tomcatd@$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME) 1> $TmpDir/systemctl.out"
	rlAssertGrep "Active: active (running)" "$TmpDir/systemctl.out"
	rlLog "Ascertain by running pki tps-user-find command if tps instance is responding"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_admin_cert\" \
		tps-user-find --size 1 > $Tmpdir/tps-user-find.out" 0 "Execute pki tps-user-find to verify if tps user instance is responding"
	rlAssertGrep "Number of entries returned 1" "$Tmpdir/tps-user-find.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_run-002: Verify ca selftests cannot be run by agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_agent_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_agent_cert\" \
		tps-selftest-run 2> $tps_selftest_run_output" 1,255 "Execute pki tps-selftest-run as $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_run-003: Verify ca selftests cannot be run operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-run 2> $tps_selftest_run_output" 1,255 "Execute pki tps-selftest-run as $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_run-004: Verify ca selftests cannot be run audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$valid_operator_cert\" \
		tps-selftest-run 2> $tps_selftest_run_output" 1,255 "Execute pki tps-selftest-run as $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_run_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_tps_selftest_run-005: Verify ca selftests cannot be run Revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_admin_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_admin_cert\" \
		tps-selftest-run 2> $tps_selftest_run_output" 1,255 "Execute pki tps-selftest-run as $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$tps_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_run-006: Verify ca selftests cannot be run Revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_agent_cert\" \
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$revoked_agent_cert\" \
		tps-selftest-run 2> $tps_selftest_run_output" 1,255 "Execute pki tps-selftest-run as $revoked_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$tps_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_run-007: Verify ca selftests cannot be run Expired agent cert"
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
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_agent_cert\" \
		tps-selftest-run > $tps_selftest_run_output 2>&1" 1,255 "Execute pki tps-selftest-run as $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$tps_selftest_run_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_selftest_run-008: Verify ca selftests cannot be run Expired admin cert"
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
		tps-selftest-run > $tps_selftest_run_output" 0 "Execute pki tps-selftest-run as $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_tps_host \
		-p $tmp_tps_port \
		-n \"$expired_admin_cert\" \
		tps-selftest-run > $tps_selftest_run_output 2>&1" 1,255 "Execute pki tps-selftest-run as $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$tps_selftest_run_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd
else
	rlPhaseStartCleanup "pki tps-selftest-run cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "TPS subsystem is not installed"
        rlPhaseEnd
fi
}
