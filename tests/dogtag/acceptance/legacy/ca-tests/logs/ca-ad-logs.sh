#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-profile-cli
#   Description: PKI CA PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki ca-profile-add
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

run_admin-ca-log_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for pki ca-profile-add
        rlPhaseStartSetup "pki key-show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$CA_INST\_agentV
        local valid_audit_cert=$CA_INST\_auditV
        local valid_operator_cert=$CA_INST\_operatorV
        local valid_admin_cert=$CA_INST\_adminV
	local test_admin_user=$CA_INST\_adminV
	local test_admin_pwd=$CA_INST\_adminV_password
	local test_agent_user=$CA_INST\_agentV
	local test_agent_pwd=$CA_INST\_agentV_password
	local test_audit_user=$CA_INST\_auditV
	local test_audit_pwd=$CA_INST\_auditV_password
	local test_operator_user=$CA_INST\_operatorV
	local test_operator_pwd=$CA_INST\_operatorV_password
	local cert_find_info="$TmpDir/cert_find_info"
        local revoked_agent_cert=$CA_INST\_agentR
        local revoked_admin_cert=$CA_INST\_adminR
        local expired_admin_cert=$CA_INST\_adminE
        local expired_agent_cert=$CA_INST\_agentE
	local PKIDAEMON_STATUS="$TmpDir/pkidaemon-status"
	local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')        
	local SSL_DIR=$CERTDB_DIR


	rlPhaseStartTest "pki_console_log-001:CA Admin Interface - Add a new log file"
	rlLog "Create a new log of type system"
	local logfile=log$RANDOM
	local level=0
	local rolloverinterval=1
	local logtype="system"
	local flushinterval=5
	local filename=/tmp/$logfile
	local logenable="True"
	local signedAuditCertNickname="caauditsigningcert"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=logRule&RS_ID=$logfile&unselected.events=&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&mandatory.events=&bufferSize=512&maxFileSize=2000&fileName=$filename&enable=$logenable&signedAuditCertNickname=$signedAuditCertNickname&implName=file&type=$logtype&logSigning=true&events=&RULENAME=$logfile\" -k https://$tmp_ca_host:$target_secure_port/ca/log >> $admin_out" 0 "Create $logfile file of type $logtype"
	rlLog "List all logs"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_SEARCH&OP_SCOPE=logRule\" -k https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "List all logs configured"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "$logfile=file:visible" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-002:CA Admin Interface - List all logs"
	rlLog "List all logs"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		 -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=logRule\" -k https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "List all logs configured"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "Transactions=file:visible" "$admin_out"
	rlAssertGrep "SignedAudit=file:visible" "$admin_out"
	rlAssertGrep "System=file:visible" "$admin_out"
	rlAssertGrep "$logfile=file:visible" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-003:CA Admin Interface - Edit log file configuration"
        local level=0
        local rolloverinterval=1
        local logtype="system"
        local flushinterval=5
        local filename=/tmp/$logfile
        local logenable="false"
	local maxfilesize=3000
	local buffersize=512
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=logRule&RS_ID=$logfile&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&bufferSize=$buffersize&maxFileSize=$maxfilesize&fileName=$filename&enable=$logenable&implName=file&type=$logtype&RULENAME=$logfile\" -k https://$tmp_ca_host:$target_secure_port/ca/log >> $admin_out" 0 "Modify $logfile file"
	rlLog "Changes require restart of CA instance"
	rlRun "rhcs_stop_instance $tomcat_name"
	rlRun "rhcs_start_instance $tomcat_name"
	rlLog "Read $logfile and verify values are updated"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=logRule&RS_ID=$logfile\" -k  https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "Read $logfile file"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "maxFileSize=$maxfilesize" "$admin_out"
	rlAssertGrep "enable=$logenable" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-004:CA Admin Interface - View log file"
	rlLog "Read $logfile"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
		-d \"OP_TYPE=OP_READ&OP_SCOPE=logRule&RS_ID=$logfile\" -k  https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "Read $logfile file"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "implName=file" "$admin_out"
	rlAssertGrep "type=$logtype" "$admin_out"
	rlAssertGrep "enable=$logenable" "$admin_out"
	rlAssertGrep "level=Debug" "$admin_out"
	rlAssertGrep "bufferSize=$buffersize" "$admin_out"
	rlAssertGrep "maxFileSize=$maxfilesize" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_log-005:CA Admin Interface - Delete log file"
	rlLog "Delete log $logfile file"
	rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=logRule&RS_ID=$logfile\" -k  https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "Read $logfile file"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlLog "List all logs"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_admin_user:$test_admin_pwd" \
                 -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=logRule\" -k https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "List all logs configured"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
        rlAssertGrep "Transactions=file:visible" "$admin_out"
        rlAssertGrep "SignedAudit=file:visible" "$admin_out"
        rlAssertGrep "System=file:visible" "$admin_out"
        rlAssertNotGrep "$logfile=file:visible" "$admin_out"	
	rlPhaseEnd

        rlPhaseStartTest "pki_console_log-006: CA Admin Interface - Adding a log file with agent privileges should fail"
        local logfile=log$RANDOM
        local level=0
        local rolloverinterval=1
        local logtype="system"
        local flushinterval=5
        local filename=/tmp/$logfile
        local logenable="True"
        local signedAuditCertNickname="caauditsigningcert"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_agent_user:$test_agent_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=logRule&RS_ID=$logfile&unselected.events=&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&mandatory.events=&bufferSize=512&maxFileSize=2000&fileName=$filename&enable=$logenable&signedAuditCertNickname=$signedAuditCertNickname&implName=file&type=$logtype&logSigning=true&events=&RULENAME=$logfile\" -k https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "Create $logfile file of type $logtype"   
        rlAssertGrep "You are not authorized to perform this operation" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_log-007: CA Admin Interface - Adding a log file with audit privileges should fail"
        local logfile=log$RANDOM
        local level=0
        local rolloverinterval=1
        local logtype="system"
        local flushinterval=5
        local filename=/tmp/$logfile
        local logenable="True"
        local signedAuditCertNickname="caauditsigningcert"
        rlRun "curl --capath "$CERTDB_DIR" --basic --user "$test_audit_user:$test_audit_pwd" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=logRule&RS_ID=$logfile&unselected.events=&level=$level&rolloverInterval=$rolloverinterval&flushInterval=$flushinterval&mandatory.events=&bufferSize=512&maxFileSize=2000&fileName=$filename&enable=$logenable&signedAuditCertNickname=$signedAuditCertNickname&implName=file&type=$logtype&logSigning=true&events=&RULENAME=$logfile\" -k https://$tmp_ca_host:$target_secure_port/ca/log > $admin_out" 0 "Create $logfile file of type $logtype"
        rlAssertGrep "You are not authorized to perform this operation" "$admin_out"
        rlPhaseEnd


}
