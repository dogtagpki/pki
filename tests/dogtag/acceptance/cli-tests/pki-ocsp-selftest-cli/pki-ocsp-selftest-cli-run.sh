#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ocsp-selftest-cli
#
#   Description: PKI OCSP SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki ocsp-selftest cli commands needs to be tested:
#  pki ocsp-selftest-run
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

run_pki-ocsp-selftest-run_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki ocsp-selftest-run
        rlPhaseStartSetup "pki ocsp-selftest-run Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Loocspl Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local OCSP_INST=$(cat $TmpDir/topo_file | grep MY_OCSP | cut -d= -f2)
        ocsp_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$OCSP_INST
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                prefix=OCSP3
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$cs_Role
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$ocsp_instance_created" = "TRUE" ] ;  then
        local target_secure_port=$(eval echo \$${OCSP_INST}_SECURE_PORT)
        local tmp_ocsp_agent=$OCSP_INST\_agentV
        local tmp_ocsp_admin=$OCSP_INST\_adminV
        local tmp_ocsp_port=$(eval echo \$${OCSP_INST}_UNSECURE_PORT)
        local tmp_ocsp_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$OCSP_INST\_agentV
        local valid_audit_cert=$OCSP_INST\_auditV
        local valid_operator_cert=$OCSP_INST\_operatorV
        local valid_admin_cert=$OCSP_INST\_adminV
        local revoked_agent_cert=$OCSP_INST\_agentR
        local revoked_admin_cert=$OCSP_INST\_adminR
        local expired_admin_cert=$OCSP_INST\_adminE
        local expired_agent_cert=$OCSP_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local ocsp_selftest_run_output=$TmpDir/ocsp-selftest-run.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki ocsp-selftest-run
	rlPhaseStartTest "pki_ocsp_selftest_run-configtest: pki ocsp-selftest-run --help configuration test"
	rlRun "pki ocsp-selftest-run --help > $ocsp_selftest_run_output" 0 "pki ocsp-selftest-run --help"
	rlAssertGrep "usage: ocsp-selftest-run \[OPTIONS...\]" "$ocsp_selftest_run_output"
	rlAssertGrep "    --help   Show help options" "$ocsp_selftest_run_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ocsp_selftest_run-001: Run OCSP Selftest using admin cert and verify ocsp subsystem is up"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_admin_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_admin_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $valid_admin_cert"
	rlAssertGrep "Selftests completed" "$ocsp_selftest_run_output"
	rlLog "Verify ocsp instance is running"
	rlRun "systemctl status pki-tomcatd@$(eval echo \$${OCSP_INST}_TOMCAT_INSTANCE_NAME) 1> $TmpDir/systemctl.out"
	rlAssertGrep "Active: active (running)" "$TmpDir/systemctl.out"
	rlLog "Ascertain by running pki ocsp-user-find command if ocsp instance is responding"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_admin_cert\" \
		ocsp-user-find --size 1 > $Tmpdir/ocsp-user-find.out" 0 "Execute pki ocsp-user-find to verify if ocsp instance is responding"
	rlAssertGrep "Number of entries returned 1" "$Tmpdir/ocsp-user-find.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_run-002: Verify ocsp selftests cannot be run by agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_agent_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_agent_cert\" \
		ocsp-selftest-run 2> $ocsp_selftest_run_output" 1,255 "Execute pki ocsp-selftest-run as $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_run-003: Verify ocsp selftests cannot be run operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-run 2> $ocsp_selftest_run_output" 1,255 "Execute pki ocsp-selftest-run as $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_run-004: Verify ocsp selftests cannot be run audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-run 2> $ocsp_selftest_run_output" 1,255 "Execute pki ocsp-selftest-run as $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_run_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ocsp_selftest_run-005: Verify ocsp selftests cannot be run Revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_admin_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_admin_cert\" \
		ocsp-selftest-run 2> $ocsp_selftest_run_output" 1,255 "Execute pki ocsp-selftest-run as $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$ocsp_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_run-006: Verify ocsp selftests cannot be run Revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_agent_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_agent_cert\" \
		ocsp-selftest-run 2> $ocsp_selftest_run_output" 1,255 "Execute pki ocsp-selftest-run as $revoked_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_run_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_run-007: Verify ocsp selftests cannot be run Expired agent cert"
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
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_agent_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_agent_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output 2>&1" 1,255 "Execute pki ocsp-selftest-run as $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ocsp_selftest_run_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_run-008: Verify ocsp selftests cannot be run Expired admin cert"
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
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_admin_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output" 0 "Execute pki ocsp-selftest-run as $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_admin_cert\" \
		ocsp-selftest-run > $ocsp_selftest_run_output 2>&1" 1,255 "Execute pki ocsp-selftest-run as $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ocsp_selftest_run_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd
else
	rlPhaseStartCleanup "pki ocsp-selftest-run cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "OCSP subsystem is not installed"
        rlPhaseEnd
fi
}
