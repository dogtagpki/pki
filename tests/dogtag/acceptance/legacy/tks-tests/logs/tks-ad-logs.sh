#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/tks-tests/tks-ad-logs.sh
#   Description: TKS Admin logs tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki key cli commands needs to be tested:
#   TKS Admin logs test
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mniranja@redhat.com>
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

run_admin-tks-log_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for legacy test
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local TKS_INST=$(cat $TmpDir/topo_file | grep MY_TKS | cut -d= -f2)
	local tomcat_name=$(eval echo \$${TKS_INST}_TOMCAT_INSTANCE_NAME)
	local target_unsecure_port=$(eval echo \$${TKS_INST}_UNSECURE_PORT)
	local target_secure_port=$(eval echo \$${TKS_INST}_SECURE_PORT)
	local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_tks_host=$(eval echo \$${cs_Role})
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_ca_agent_cert=$CA_INST\_agentV
        local valid_agent=$TKS_INST\_agentV
        local valid_agent_pwd=$TKS_INST\_agentV_password
        local valid_audit=$TKS_INST\_auditV
        local valid_audit_pwd=$TKS_INST\_auditV_password
        local valid_operator=$TKS_INST\_operatorV
        local valid_operator_pwd=$TKS_INST\_operatorV_password
        local valid_admin=$TKS_INST\_adminV
        local valid_admin_pwd=$TKS_INST\_adminV_password
        local revoked_agent=$TKS_INST\_agentR
        local revoked_admin=$TKS_INST\_adminR
        local expired_admin=$TKS_INST\_adminE
        local expired_agent=$TKS_INST\_agentE
        local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"


	rlPhaseStartTest "pki_console_log-001: TKS Admin Interface - Add a new log file"
	rlLog "Create a new log of type system"
	local logfile=log$RANDOM
	local level=0
	local rolloverinterval=1
	local logtype="system"
	local flushinterval=5
	local filename=/tmp/$logfile
	local logenable="True"
	local signedAuditCertNickname="kraauditsigningcert"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=logRule&RS_ID=$logfile&unselected.events=&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&mandatory.events=&bufferSize=512&maxFileSize=2000&fileName=$filename&enable=$logenable&signedAuditCertNickname=$signedAuditCertNickname&implName=file&type=$logtype&logSigning=true&events=&RULENAME=$logfile\" -k https://$tmp_tks_host:$target_secure_port/tks/log >> $admin_out" 0 "Create $logfile file of type $logtype"
	rlLog "List all logs"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=OP_SEARCH&OP_SCOPE=logRule\" -k https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "List all logs configured"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "$logfile=file:visible" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-002: TKS Admin Interface - List all logs"
	rlLog "List all logs"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
		 -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=logRule\" -k https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "List all logs configured"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "Transactions=file:visible" "$admin_out"
	rlAssertGrep "SignedAudit=file:visible" "$admin_out"
	rlAssertGrep "System=file:visible" "$admin_out"
	rlAssertGrep "$logfile=file:visible" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-003: TKS Admin Interface - Edit log file configuration"
        local level=0
        local rolloverinterval=1
        local logtype="system"
        local flushinterval=5
        local filename=/tmp/$logfile
        local logenable="false"
	local maxfilesize=3000
	local buffersize=512
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=logRule&RS_ID=$logfile&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&bufferSize=$buffersize&maxFileSize=$maxfilesize&fileName=$filename&enable=$logenable&implName=file&type=$logtype&RULENAME=$logfile\" -k https://$tmp_tks_host:$target_secure_port/tks/log >> $admin_out" 0 "Modify $logfile file"
	rlLog "Changes require restart of CA instance"
	rlRun "rhcs_stop_instance $tomcat_name"
	rlRun "rhcs_start_instance $tomcat_name"
	rlLog "Read $logfile and verify values are updated"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=logRule&RS_ID=$logfile\" -k  https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "Read $logfile file"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "maxFileSize=$maxfilesize" "$admin_out"
	rlAssertGrep "enable=$logenable" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-004: TKS Admin Interface - View log file"
	rlLog "Read $logfile"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=logRule&RS_ID=$logfile\" -k  https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "Read $logfile file"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "implName=file" "$admin_out"
	rlAssertGrep "type=$logtype" "$admin_out"
	rlAssertGrep "enable=$logenable" "$admin_out"
	rlAssertGrep "level=Debug" "$admin_out"
	rlAssertGrep "bufferSize=$buffersize" "$admin_out"
	rlAssertGrep "maxFileSize=$maxfilesize" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-005: TKS Admin Interface - Delete log file"
	rlLog "Delete log $logfile file"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=logRule&RS_ID=$logfile\" -k  https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "Delete $logfile file"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlLog "List all logs"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_admin:$valid_admin_pwd" \
                 -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=logRule\" -k https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "List all logs configured"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "Transactions=file:visible" "$admin_out"
        rlAssertGrep "SignedAudit=file:visible" "$admin_out"
        rlAssertGrep "System=file:visible" "$admin_out"
        rlAssertNotGrep "$logfile=file:visible" "$admin_out"	
	rlPhaseEnd

        rlPhaseStartTest "pki_console_log-006: TKS Admin Interface - Adding a log file with agent privileges should fail"
        local logfile=log$RANDOM
        local level=0
        local rolloverinterval=1
        local logtype="system"
        local flushinterval=5
        local filename=/tmp/$logfile
        local logenable="True"
        local signedAuditCertNickname="caauditsigningcert"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_agent:$valid_agent_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=logRule&RS_ID=$logfile&unselected.events=&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&mandatory.events=&bufferSize=512&maxFileSize=2000&fileName=$filename&enable=$logenable&signedAuditCertNickname=$signedAuditCertNickname&implName=file&type=$logtype&logSigning=true&events=&RULENAME=$logfile\" -k https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "Create $logfile file of type $logtype"   
        rlAssertGrep "You are not authorized to perform this operation" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_log-007: TKS Admin Interface - Adding a log file with audit privileges should fail"
        local logfile=log$RANDOM
        local level=0
        local rolloverinterval=1
        local logtype="system"
        local flushinterval=5
        local filename=/tmp/$logfile
        local logenable="True"
        local signedAuditCertNickname="caauditsigningcert"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$valid_audit:$valid_audit_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=logRule&RS_ID=$logfile&unselected.events=&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&mandatory.events=&bufferSize=512&maxFileSize=2000&fileName=$filename&enable=$logenable&signedAuditCertNickname=$signedAuditCertNickname&implName=file&type=$logtype&logSigning=true&events=&RULENAME=$logfile\" -k https://$tmp_tks_host:$target_secure_port/tks/log > $admin_out" 0 "Create $logfile file of type $logtype"
        rlAssertGrep "You are not authorized to perform this operation" "$admin_out"
        rlPhaseEnd

	rlPhaseStartCleanup "Delete temporary dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
