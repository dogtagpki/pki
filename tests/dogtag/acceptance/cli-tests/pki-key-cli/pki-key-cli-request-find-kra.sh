#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-key-cli
#   Description: PKI KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki key-request-find
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
run_pki-key-request-find-kra_tests()
{
	local cs_Id=$1
        local cs_Role=$2
	
	# Creating Temporary Directory for pki key-request-find
        rlPhaseStartSetup "pki key-request-find Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd
	
	# Local Variables
	get_topo_stack $cs_Role $TmpDir/topo_file
	local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
	local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local tmp_kra_host=$(eval echo \$${cs_Role})
        local target_unsecure_port=$(eval echo \$${KRA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${KRA_INST}_SECURE_PORT)
        local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$tmp_kra_host
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
	local key_request_find_output=$TmpDir/key-request-find.out
	local key_generate_output=$TmpDir/key-generate.out
	local key_archive_output=$TmpDir/key-archive.out
	local rand=$RANDOM
	local cert_request_submit="$TEMP_NSS_DB/pki-cert-request-submit.out"
	local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')

	# Config test of pki key-request-find
	rlPhaseStartTest "pki_key_cli-configtest: pki key-request-find --help configuration test"
	rlRun "pki key-request-find --help > $key_request_find_output" 0 "pki key-request-find --help"
	rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
	rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
	rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
	rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
	rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
	rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
	rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
	rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
	rlAssertGrep "    --type <type>                Request type" "$key_request_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-001: Search key requests with Valid clientId using Agent Cert"
	local rand=$RANDOM
	local client_id=temp$rand
	local algo=AES
	local action=NULL
	local key_size=128
	local usages=wrap
	rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
		0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
	local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	local tmp_request_id=$(cat $key_generate_output | grep "Request ID" | awk -F ": " '{print $2}')
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --client $client_id > $key_request_find_output"
	rlAssertGrep "Request ID: $tmp_request_id" "$key_request_find_output"
	rlAssertGrep "Key ID: $tmp_key_id" "$key_request_find_output"
	rlAssertGrep "Type: symkeyGenRequest " "$key_request_find_output"
	rlAssertGrep "Status: complete" "$key_request_find_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1123"
	rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-002: Search key requests with Non Existent ClientID should give no results"
	local client_id=invalidtemp$rand
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --client $client_id > $key_request_find_output" 0 "Search key with client Id $client_id using $valid_agent_cert"
	rlAssertGrep "0 entries matched" "$key_request_find_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-003: Searching key requests with junkdata passed to ClientID should give no results"
        local client_id=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --client $client_id > $key_request_find_output" 0 "Search key request with Junk data using $valid_agent_cert"
        rlAssertGrep "0 entries matched" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-004: Searching key requests when no data passed to ClientID should fail with command help"
        local client_id=' '
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --client $client_id > $key_request_find_output 2>&1" 255,1 "Search key with client Id invalidtemp$rand using $valid_agent_cert"
        rlAssertGrep "Error: Missing argument for option: client" "$key_request_find_output"
        rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
        rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
        rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
        rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
        rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
        rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
        rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
        rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
        rlAssertGrep "    --type <type>                Request type" "$key_request_find_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-005: Search key requests with --maxResults 5 and verify 5 results are returned"
        local rand=$RANDOM
        local client_id=temp$rand
	local maxResults=5
        local algo=AES
        local key_size=128
        local usages=wrap
	local action=NULL
	for i in $(seq 1 6); do 
        rlRun "generate_key $client_id-$i $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id-$i, algo $algo, key_size $key_size, usages $usages"
	done
	local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	local tmp_request_id=$(cat $key_generate_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --maxResults $maxResults  > $key_request_find_output" 0 "Search key requests with --maxResults 5"
	rlAssertGrep "Number of entries returned 5" "$key_request_find_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1124"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-006: Search key requests with junkvalue passed --maxResults and verify no results are returned"
        local maxResults=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                 key-request-find --maxResults $maxResults  > $key_request_find_output 2>&1" 255, 1 "Search keys with junk data passed to --maxResults"
        rlAssertGrep "NumberFormatException: For input string: \"$maxResults\"" "$key_request_find_output"
        rlPhaseEnd

       rlPhaseStartTest "pki_key_request_find-007: Search key requests with Negative value passed --maxResults and verify no results are returned"
        local maxResults=-128
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --maxResults $maxResults  > $key_request_find_output 2>&1" 255,1 "Search keys with negative value -128 passed to maxResults"
        rlAssertGrep "NumberFormatException: For input string: \"$maxResults\" " "$key_request_find_output"
        rlPhaseEnd

       rlPhaseStartTest "pki_key_request_find-008: Search key requests with Maximum integer value(10 digits) passed to --maxResults and verify no results are returned"
        local maxResults=1234567890123
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --maxResults $maxResults  > $key_request_find_output 2>&1" 255,1 "Search keys with 10 digit integer passed to --maxResults"
        rlAssertGrep "NumberFormatException: For input string: \"$maxResults\"" "$key_request_find_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-009: Search key requests with no value passed to --maxResults and verify command help is returned"
        local maxResults=' '
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --maxResults $maxResults  > $key_request_find_output 2>&1" 255,1
        rlAssertGrep "Error: Missing argument for option: maxResults" "$key_request_find_output"
        rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
        rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
        rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
        rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
        rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
        rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
        rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
        rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
        rlAssertGrep "    --type <type>                Request type" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0010: Search key requests with --pageSize 5 and verify 5 results are returned"
        local size=5
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --pageSize $size  > $key_request_find_output" 0 "Search keys with --pageSize $size"
        rlAssertGrep "Number of entries returned 5" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0011: Search key requests with junkvalue passed --pageSize and verify no results are returned"
        local size=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                 key-request-find --pageSize $size  > $key_request_find_output 2>&1" 255, 1 "Search keys with junk data passed to --pageSize"
        rlAssertGrep "NumberFormatException: For input string: \"$size\"" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0012: Search key requests with Negative value passed to --pageSize and verify no results are returned"
        local size=-128
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --pageSize $size  > $key_request_find_output 2>&1" 255,1,0
        rlAssertGrep "NumberFormatException: For input string: \"$size\" " "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0013: Search key requests with Maximum integer value(10 digits) passed to --pageSize and verify no results are returned"
        local size=1234567890123
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --pageSize $size  > $key_request_find_output 2>&1" 255,1 "Searching keys with 10digit integer value passed to --size"
        rlAssertGrep "NumberFormatException: For input string: \"$size\"" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0014: Search key requests with no value passed to --pageSize and verify command help is returned"
        local size=' '
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                 key-request-find --pageSize $size  > $key_request_find_output 2>&1" 255,1 "Searching keys with no value passed to --size"
        rlAssertGrep "Error: Missing argument for option: pageSize" "$key_request_find_output"
        rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
        rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
        rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
        rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
        rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
        rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
        rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
        rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
        rlAssertGrep "    --type <type>                Request type" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0015: Search key requests with key status complete using Agent Cert"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=NULL
        local key_size=128
        local usages=wrap
	local status=complete
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                 key-request-find --status $status --pageSize 500 > $key_request_find_output" 0 "Search keys with $status status"
	local check_result=$(cat $key_request_find_output | grep Status | grep -v complete | wc -l)
	if [ $check_result -ne 0 ]; then
		rlFail "results contain key requests other than complete"
	else
		rlPass "Results contain key requests with status complete"
	fi
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0016: Search key requests with Invalid key status using Agent Cert"
        local status=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --status $status --pageSize 100 > $key_request_find_output" 0 "Search keys with junk status"
	rlAssertGrep "0 entries matched" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0017: Searching keys witn no status passed should fail with command help"
        local status=' '
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --status $status  > $key_request_find_output 2>&1" 255,1 "Search keys with no status passed to --status"
        rlAssertGrep "Error: Missing argument for option: status" "$key_request_find_output"
        rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
        rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
        rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
        rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
        rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
        rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
        rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
        rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
        rlAssertGrep "    --type <type>                Request type" "$key_request_find_output";
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0018: Search key requests starting from 0x5 using --start"
        local startsize=5
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --start $startsize > $key_request_find_output" 0 "Search key requests with --pageSize 5"
	local checkkeyID=$(cat $key_request_find_output | grep "Request ID" | head -n 1 | awk -F ": " '{print $2}')
	if [ "$checkkeyID" == "0x5" ]; then
		rlPass "Search results start with Request ID 0x5"
	else
		rlFail "Search results do not start with Request ID 0x5"
	fi
        rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-0019: Search key requests  starting from 0x5 with only 10 results returned using --pageSize"
        local startsize=5
	local size=10
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --start $startsize --pageSize $size > $key_request_find_output" 0 "Search keys with --size 5"
	rlAssertGrep "Number of entries returned 10" "$key_request_find_output"
        local checkkeyID=$(cat $key_request_find_output | grep "Key ID" | head -n 1| awk -F ": " '{print $2}')
        if [ "$checkkeyID" == "0x5" ]; then
                rlPass "Search results start with key ID 0x5"
        else
                rlFail "Search results do not start with key ID 0x5"
        fi
	rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0020: Search key requests with negative values passed to  --start should not return any results"
        local startsize=-128
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --start $startsize > $key_request_find_output" 0 "Search keys with --pageSize $startsize"
	rlAssertGrep "Number of entries returned 0" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0021: Search key requests with no value passed to --start should fail with command help"
        local startsize=' '
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --start $startsize > $key_request_find_output" 255,1 "Search keys with --pageSize $startsize"
        rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
        rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
        rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
        rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
        rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
        rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
        rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
        rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
        rlAssertGrep "    --type <type>                Request type" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0022: Generate more than 100 key requests and verify --pageSize 105 returns 105 key results"
        local rand=$RANDOM
        local client_id=temp$rand
        local size=105
        local algo=AES
        local key_size=128
        local usages=wrap
        local action=NULL
        for i in $(seq 1 110); do 
        rlRun "generate_key $client_id-$i $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id-$i, algo $algo, key_size $key_size, usages $usages"
        done
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --pageSize $size  > $key_request_find_output" 0 "Search key requests with --pageSize $size"
        rlAssertGrep "Number of entries returned $size" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0023: Generate more than 100 key requests of type symkeyGenRequest and verify --maxResults 105 returns 105 key results"
        local size=105
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --type symkeyGenRequest --maxResults $size  > $key_request_find_output" 0 "Search key requests with --maxResults $size"
        rlAssertGrep "Number of entries returned $size" "$key_request_find_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1124"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_key_request_find-0024: Search key requests with --maxTime <positive value> and verify search results are returned"
        local maxTime=5
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --maxTime $maxTime --pageSize 10  > $key_request_find_output" 0 "Search key requests with --maxTime $maxTime"
        rlAssertGrep "Number of entries returned 10" "$key_request_find_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0025: Searching key requests with junk value passed to --MaxTime should fail"
        local maxTime=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --maxTime $maxTime --pageSize 50 > $key_request_find_output 2>&1" 255,1 "Search key requests with junk value passed to --maxTime"
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0026: Searching key requests using valid admin cert should fail"	
	rlLog "Executing pki key-request-find as $valid_admin_cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $valid_admin_cert"
	rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
	rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0027: Searching symmetric key requests using revoked Agent cert should fail"
        rlLog "Executing pki key-request-find as $revoked Agent Cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $revoked_agent_cert"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0028: Searching key requests using Expired admin(not a member of agents Group) cert should fail"
        rlLog "Executing pki key-request-find as $expired_admin_cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_admin_cert | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$expired_admin_cert\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $expired_admin_cert"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd


        rlPhaseStartTest "pki_key_request_find-0029: Searching key requests using Expired agent cert should fail"
        rlLog "Executing pki key-request-find as $expired_agent_cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_agent_cert | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$expired_agent_cert\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $expired_agent_cert"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0030: Searching symmetric key requests using valid Audit cert should fail"
        rlLog "Executing pki key-request-find as $valid_audit_cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $valid_audit_cert"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0031: Searching symmetric key requests using valid Operator cert should fail"
        rlLog "Executing pki key-request-find as $valid_operator_cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_operator_cert\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $valid_operator_cert"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0032: Searching key requests using normal user cert(without any privileges) should fail"
	local rand=$RANDOM
        local pki_user="idm1_user_$rand"
        local pki_user_fullName="Idm1 User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -n \"$valid_admin_cert\" \
                -c $CERTDB_DIR_PASSWORD -h $tmp_ca_host -p $tmp_ca_port \
                kra-user-add $pki_user \
                --fullName \"$pki_user_fullName\" \
                --password $pki_pwd" 0 "Create $pki_user User"
        rlLog "Generate cert for user $pki_user"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa key_size:2048 \
                subject_cn:\"$pki_user_fullName\" \
                subject_uid:$pki_user \
                subject_email:$pki_user@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$target_unsecure_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"caadmincert\" \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $tmp_ca_agent \
                -h $tmp_ca_host \
                -p $target_unsecure_port cert-show $cert_serialNumber \
                --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $tmp_ca_agent \
                -h $tmp_ca_host \
                -p $target_unsecure_port cert-show 0x1 \
                --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD -h $tmp_kra_host -p $target_unsecure_port \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"CA Signing Certificate - $CA_DOMAIN Security Domain\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate \"CA Signing Certificate - $CA_DOMAIN Security Domain\"" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
                -n $valid_admin_cert \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -t kra user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
	rlLog "Executing pki key-request-find as $pki_user_fullName"
        rlRun "pki -d $TEMP_NSS_DB\
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$pki_user\" \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $pki_user_fullName"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_find_output"
        rlPhaseEnd	

        rlPhaseStartTest "pki_key_request_find-0033: Search key requests using host URI parameter(https)"
        rlLog "Executing pki key-request-find using http host URI parameter(https)"
	rlLog "tmp_kra_host=$tmp_kra_host"
	rlLog "tmp_secure_port=$target_secure_port"
        rlRun "pki -d $CERTDB_DIR \
		-U https://$tmp_kra_host:$target_secure_port \
		-c $CERTDB_DIR_PASSWORD \
		-n $valid_agent_cert \
                key-request-find  > $key_request_find_output" 0 "Search key requests as $valid_agent_cert"
        rlAssertGrep "Number of entries returned 20" "$key_request_find_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0034: Search symmetric keys using valid user(Not a member of any group) should fail"
        rlRun "pki -d $CERTDB_DIR\
                -h $tmp_kra_host \
                -p $target_unsecure_port \
		-u $pki_user \
		-w $pki_pwd \
                key-request-find  > $key_request_find_output 2>&1" 255,1 "Search key requests as $pki_user_fullName"
        rlAssertNotGrep "Number of entries returned 20" "$key_request_find_output"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_find_output"
        
	rlPhaseStartTest "pki_key_request_find-0035: Searching symmetric keys using in-valid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki key-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -h $tmp_kra_host -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd  \
                key-request-find > $key_request_find_output 2>&1" 255,1 "Search key requests as $invalid_pki_user"
	rlAssertGrep "PKIException: Unauthorized" "$key_request_find_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-0036: Searching key request of type symkeyGenRequest using agent cert"
	local rand=$RANDOM
	local req_type=symkeyGenRequest
	local client_id=temp$rand
        local algo=AES
	local action=NULL
	local key_size=128
	local usages=wrap
	rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        local tmp_request_id=$(cat $key_generate_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" key-request-find --type $req_type --maxResults 100 > $key_request_find_output" 0 "Search key requests of type symkeyGenRequest"
	local verify_output=$(cat $key_request_find_output | grep Type | grep -v $req_type)
	if [ "$verify_ouput" == "0" ]; then 
		rlFail "Search output has results other than $req_type"
	else
		rlPass "Search output has results of type $req_type"
	fi
	rlPhaseEnd

      	rlPhaseStartTest "pki_key_request_find-0037: Searching key request of type securityDataEnrollment using agent cert"
        local rand=$RANDOM
	local client_id=temp$rand
	local passphrase=Secret123
	local req_type=securityDataEnrollment
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		key-archive --clientKeyID $client_id \
		 --passphrase $passphrase > $key_archive_output" 0 "Archive $passphrase in DRM"
	rlAssertGrep "Status: complete" "$key_archive_output"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        local tmp_request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --type $req_type --maxResults 100 > $key_request_find_output" 0 "Search key requests of type $req_type"
        local verify_output=$(cat $key_request_find_output | grep Type | grep -v $req_type)
        if [ "$verify_ouput" == "0" ]; then
                rlFail "Search output has results other than $req_type"
        else
                rlPass "Search output has results of type $req_type"
        fi
        rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-0038: Search key requests of type enrollment using agent cert"
	rlLog "Generate Cert using profile caDualCert"
	profile=caDualCert
	req_type=enrollment
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:crmf \
                algo:rsa key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:true \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$target_unsecure_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"caadmincert\" \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --type $req_type --maxResults 100 > $key_request_find_output" 0 "Search key requests of type $req_type"
        local verify_output = $(cat $key_request_find_output | grep Type | grep -v $req_type)
        if [ $verify_ouput -ne 0 ]; then
                rlFail "Search output has results other than $req_type"
        else
                rlPass "Search output has results of type $req_type"
        fi
        rlPhaseEnd

	rlPhaseStartTest "pki_key_request_find-0039: Searching key requests should fail when junk data is passed to --type"
	req_type=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --type $req_type > $key_request_find_output" 0 "Search key requests of type someJunkData"
	rlAssertGrep "0 entries matched" "$key_request_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_key_request_Find-0040: Searching key request should fail and command help should be returned when no data is passed to --type"
        req_type=" "
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-find --type $req_type > $key_request_find_output" 255,1 "Search key requests with no data passed --type"
        rlAssertGrep "usage: key-request-find \[OPTIONS...\]" "$key_request_find_output"
        rlAssertGrep "    --client <client ID>         Client ID" "$key_request_find_output"
        rlAssertGrep "    --help                       Show help options" "$key_request_find_output"
        rlAssertGrep "    --maxResults <max results>   Maximum results" "$key_request_find_output"
        rlAssertGrep "    --maxTime <max time>         Maximum time" "$key_request_find_output"
        rlAssertGrep "    --pageSize <page size>       Page size" "$key_request_find_output"
        rlAssertGrep "    --start <starting page>      Page to start" "$key_request_find_output"
        rlAssertGrep "    --status <status>            Request status" "$key_request_find_output"
        rlAssertGrep "    --type <type>                Request type" "$key_request_find_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_request_find-0041: Searching key requests with special characters passed to ClientID should give no results"
        local client_id="!?@~#*^_+$"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -p $target_unsecure_port \
                -h $tmp_kra_host \
                -n \"$valid_agent_cert\" \
                key-request-find --client \"$client_id\" > $key_request_find_output" 0 "Search key request with Junk data using $valid_agent_cert"
        rlAssertGrep "0 entries matched" "$key_request_find_output"
        rlPhaseEnd

	rlPhaseStartCleanup "pki key-request-find cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd

}
