#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki kra key cli commands needs to be tested:
#  pki kra-key-generate
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
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

run_pki-kra-key-generate-kra_tests()
{
	local cs_Id=$1
        local cs_Role=$2
	
	# Creating Temporary Directory for pki key-generate
        rlPhaseStartSetup "pki key-generate Temporary Directory"
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
        local expired_admin_cert=$kRA_INST\_adminE
        local expired_agent_cert=$KRA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
	local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
	local cert_info="$TmpDir/cert_info"
	local key_generate_output=$TmpDir/key-generate.out
	local rand=$RANDOM
	local cert_request_submit="$TEMP_NSS_DB/pki-cert-request-submit.out"
	local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	local profile=caUserCert

	# Config test of pki key-generate
	rlPhaseStartTest "pki_kra_key_cli-configtest: pki kra-key-generate --help configuration test"
	rlRun "pki kra-key-generate --help > $key_generate_output" 0 "pki kra-key-generate --help"
	rlAssertGrep "usage: key-generate <Client Key ID> --key-algorithm <algorithm>" "$key_generate_output"
	rlAssertGrep "                    \[OPTIONS...\]" "$key_generate_output"
	rlAssertGrep "    --help                        Show help option" "$key_generate_output"
	rlAssertGrep "    --key-algorithm <algorithm>   Algorithm to be used to create a key." "$key_generate_output"
	rlAssertGrep "                                  Valid values: AES, DES, DES3, RC2, RC4," "$key_generate_output"
	rlAssertGrep "                                  DESede." "$key_generate_output"
	rlAssertGrep "    --key-size <size>             Size of the key to be generated." "$key_generate_output"
	rlAssertGrep "                                  This is required for AES, RC2 and RC4." "$key_generate_output"
	rlAssertGrep "                                  Valid values for AES: 128, 192. 256." "$key_generate_output"
	rlAssertGrep "                                  Valid values for RC2: 8-128." "$key_generate_output"
	rlAssertGrep "                                  Valid values for RC4: Any positive" "$key_generate_output"
	rlAssertGrep "                                  integer." "$key_generate_output"
	rlAssertGrep "    --usages <list of usages>     Comma separated list of usages." "$key_generate_output"
	rlAssertGrep "                                  Valid values: wrap, unwrap, sign," "$key_generate_output"
	rlAssertGrep "                                  verify, encrypt, decrypt." "$key_generate_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_generate-001: Generate symmetric keys with AES algo of size 128 with --usages wrap"
	local client_id=temp$rand
	local algo=AES
	local key_size=128
	local usages=wrap
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		kra-key-generate $client_id \
		--key-algorithm $algo \
		--key-size $key_size \
		--usages $usages > $key_generate_output" 
	rlAssertGrep "Key generation request info" "$key_generate_output"
	rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
	rlAssertGrep "Status: complete" "$key_generate_output"
	rlLog "Verify by approving the request"
	local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlRun "pki -d $CERTDB_DIR \
		 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
		 -n \"$valid_agent_cert\" \
		 key-request-review $key_request_id \
		 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
	rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
	rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
	rlAssertGrep "Status: complete" "$key_generate_output-approve.out"	
	rlPhaseEnd
	
        rlPhaseStartTest "pki_kra_key_generate-002: Generate symmetric keys with AES algo of size 192 with --usages unwrap"
	local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=192
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-003: Generate symmetric keys with AES algo of size 256 with --usages sign"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=256
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-004: Generate symmetric keys with AES algo of size 128 with --usages verify"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=verify
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1114"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-005: Generate symmetric keys with AES algo of size 128 with --usages encrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-006: Generate symmetric keys with AES algo of size 128 with --usages decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-007: Generate symmetric keys with AES algo of size 128 with --usages wrap,unwrap,sign,encrypt,decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd


	rlPhaseStartTest "pki_kra_key_generate-008: Generate symmetric keys with AES algo of size 128 with --usages <no-data-passed>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1 "No data passed to --usages"
	rlAssertGrep "Error: Missing argument for option: usages" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-009: Generate symmetric keys with AES algo of size 128 with --usages <junk data>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0010: Generating symmetric keys with AES algo and invalid key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=1283323
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
	rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0011: Generating symmetric keys with AES algo and negative key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=-128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "$key_generate_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1115"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0012: Generating symmetric keys with AES algo with no key size provided should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing argument for option: key-size" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0013: Generating symmetric keys with AES algo with --usages wrap,unwrap,sign,encrypt,decrypt,junk-data should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt,$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
	rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_generate-0014: Generating symmetric keys should fail when no client id is provided"
        local rand=$RANDOM
        local client_id=
        local algo=AES
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing Client Key Id." "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0015: Generate symmetric keys with AES algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
	rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0016: Generate symmetric keys with DES algo with --usages wrap"
	local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd


        rlPhaseStartTest "pki_kra_key_generate-0017: Generate symmetric keys with DES algo with --usages unwrap"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0018: Generate symmetric keys with DES algo with --usages sign"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=sign
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0019: Generate symmetric keys with DES algo with --usages verify"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=verify
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1114"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0020: Generate symmetric keys with DES algo --usages encrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0021: Generate symmetric keys with DES algo with --usages decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0022: Generate symmetric keys with DES algo with --usages wrap,unwrap,sign,encrypt,decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0023: Generate symmetric keys with DES algo with --usages <no-data-passed>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1 "No data passed to --usages"
        rlAssertGrep "Error: Missing argument for option: usages" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0024: Generate symmetric keys with DES algo with --usages <junk data>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0025: Generating symmetric keys with DES algo with --usages wrap,unwrap,sign,encrypt,decrypt,junk-data should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=wrap,unwrap,sign,encrypt,decrypt,$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0026: Generating symmetric keys with DES algo should fail when no client id is provided"
        local rand=$RANDOM
        local client_id=
        local algo=DES
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing Client Key Id." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0027: Generate symmetric keys with DES algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0028: Generate symmetric keys with DES3 algo with --usages wrap"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd


        rlPhaseStartTest "pki_kra_key_generate-0029: Generate symmetric keys with DES3 algo with --usages unwrap"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0030: Generate symmetric keys with DES3 algo with --usages sign"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0031: Generate symmetric keys with DES3 algo with --usages verify"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=verify
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1114"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0032: Generate symmetric keys with DES3 algo --usages encrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0033: Generate symmetric keys with DES3 algo with --usages decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0034: Generate symmetric keys with DES3 algo with --usages wrap,unwrap,sign,encrypt,decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0035: Generate symmetric keys with DES3 algo with --usages <no-data-passed>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1 "No data passed to --usages"
        rlAssertGrep "Error: Missing argument for option: usages" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0036: Generate symmetric keys with DES3 algo with --usages <junk data>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0037: Generating symmetric keys with DES3 algo with --usages wrap,unwrap,sign,encrypt,decrypt,junk-data should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=wrap,unwrap,sign,encrypt,decrypt,$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0038: Generating symmetric keys with DES3 algo should fail when no client id is provided"
        local rand=$RANDOM
        local client_id=
        local algo=DES3
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing Client Key Id." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0039: Generate symmetric keys with DES3 algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DES3
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_generate-0040: Generate symmetric keys with RC2 algo of size 128 with --usages wrap"
	local rand=$RANDOM
	local client_id=temp$rand
	local algo=RC2
	local key_size=128
	local usages=wrap
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		kra-key-generate $client_id \
		--key-algorithm $algo \
		--key-size $key_size \
		--usages $usages > $key_generate_output" 
	rlAssertGrep "Key generation request info" "$key_generate_output"
	rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
	rlAssertGrep "Status: complete" "$key_generate_output"
	rlLog "Verify by approving the request"
	local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlRun "pki -d $CERTDB_DIR \
		 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
		 -n \"$valid_agent_cert\" \
		 key-request-review $key_request_id \
		 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
	rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
	rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
	rlAssertGrep "Status: complete" "$key_generate_output-approve.out"	
	rlPhaseEnd
	
        rlPhaseStartTest "pki_kra_key_generate-0041: Generate symmetric keys with RC2 algo of size 192 with --usages unwrap"
	local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=192
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0042: Generate symmetric keys with RC2 algo of size 256 with --usages sign"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=256
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0043: Generate symmetric keys with RC2 algo of size 128 with --usages verify"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=verify
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1114"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0044: Generate symmetric keys with RC2 algo of size 128 with --usages encrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0045: Generate symmetric keys with RC2 algo of size 128 with --usages decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0046: Generate symmetric keys with RC2 algo of size 128 with --usages wrap,unwrap,sign,encrypt,decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd


	rlPhaseStartTest "pki_kra_key_generate-0047: Generate symmetric keys with RC2 algo of size 128 with --usages <no-data-passed>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1 "No data passed to --usages"
	rlAssertGrep "Error: Missing argument for option: usages" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0048: Generate symmetric keys with RC2 algo of size 128 with --usages <junk data>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0049: Generating symmetric keys with RC2 algo and invalid key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=1283323
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
	rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0050: Generating symmetric keys with RC2 algo using negative key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=-128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "$key_generate_output"
	rlLog "PKI Ticket:: https://fedorahosted.org/pki/ticket/1115"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0051: Generating symmetric keys with RC2 algo with no key size provided should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing argument for option: key-size" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0052: Generating symmetric keys with RC2 algo with --usages wrap,unwrap,sign,encrypt,decrypt,junk-data should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt,$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
	rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_generate-0053: Generating symmetric keys using RC2 should fail when no client id is provided"
        local rand=$RANDOM
        local client_id=
        local algo=RC2
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing Client Key Id." "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0054: Generate symmetric keys with RC2 algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
	rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0055: Generate symmetric keys with RC2 algo with existing ClientID but with different key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
	local key_size=256
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_generate-0056: Generate symmetric keys with RC4 algo of size 128 with --usages wrap"
	local rand=$RANDOM
	local client_id=temp$rand
	local algo=RC4
	local key_size=128
	local usages=wrap
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		kra-key-generate $client_id \
		--key-algorithm $algo \
		--key-size $key_size \
		--usages $usages > $key_generate_output" 
	rlAssertGrep "Key generation request info" "$key_generate_output"
	rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
	rlAssertGrep "Status: complete" "$key_generate_output"
	rlLog "Verify by approving the request"
	local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlRun "pki -d $CERTDB_DIR \
		 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
		 -n \"$valid_agent_cert\" \
		 key-request-review $key_request_id \
		 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
	rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
	rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
	rlAssertGrep "Status: complete" "$key_generate_output-approve.out"	
	rlPhaseEnd
	
        rlPhaseStartTest "pki_kra_key_generate-0057: Generate symmetric keys with RC4 algo of size 192 with --usages unwrap"
	local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=192
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0058: Generate symmetric keys with RC4 algo of size 256 with --usages sign"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=256
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0059: Generate symmetric keys with RC4 algo of size 128 with --usages verify"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=verify
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1114"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0060: Generate symmetric keys with RC4 algo of size 128 with --usages encrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0061: Generate symmetric keys with RC4 algo of size 128 with --usages decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0062: Generate symmetric keys with RC4 algo of size 128 with --usages wrap,unwrap,sign,encrypt,decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd


	rlPhaseStartTest "pki_kra_key_generate-0063: Generate symmetric keys with RC4 algo of size 128 with --usages <no-data-passed>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1 "No data passed to --usages"
	rlAssertGrep "Error: Missing argument for option: usages" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0064: Generate symmetric keys with RC4 algo of size 128 with --usages <junk data>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0065: Generating symmetric keys with RC4 algo and invalid key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC2
        local key_size=1283abced
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
	rlAssertGrep "NumberFormatException: For input string: \"$key_size\"" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0066: Generating symmetric keys with RC4 algo and negative key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=-128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "$key_generate_output"
	rlLog "PKI Ticket:: https://fedorahosted.org/pki/ticket/1116"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0067: Generating symmetric keys with RC4 algo with no key size provided should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing argument for option: key-size" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0068: Generating symmetric keys with RC4 algo with --usages wrap,unwrap,sign,encrypt,decrypt,junk-data should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt,$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
	rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_generate-0069: Generating symmetric keys using RC4 should fail when no client id is provided"
        local rand=$RANDOM
        local client_id=
        local algo=RC4
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing Client Key Id." "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0070: Generate symmetric keys with RC4 algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
	rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0071: Generate symmetric keys with RC4 algo with existing ClientID but with different key size should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=128
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
	local key_size=256
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0072: Generate symmetric keys with RC4 algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RC4
        local key_size=256
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_size=1024
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0073: Generate symmetric keys with DESede algo with --usages wrap"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd


        rlPhaseStartTest "pki_kra_key_generate-0074: Generate symmetric keys with DESede algo with --usages unwrap"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0075: Generate symmetric keys with DESede algo with --usages sign"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=unwrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0076: Generate symmetric keys with DESede algo with --usages verify"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=verify
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1114"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0077: Generate symmetric keys with DESede algo --usages encrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0078: Generate symmetric keys with DESede algo with --usages decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0079: Generate symmetric keys with DESede algo with --usages wrap,unwrap,sign,encrypt,decrypt"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action approve > $key_generate_output-approve.out" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_generate_output-approve.out"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output-approve.out"
        rlAssertGrep "Status: complete" "$key_generate_output-approve.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0080: Generate symmetric keys with DESede algo with --usages <no-data-passed>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1 "No data passed to --usages"
        rlAssertGrep "Error: Missing argument for option: usages" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0081: Generate symmetric keys with DESede algo with --usages <junk data>"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0082: Generating symmetric keys with DESede algo with --usages wrap,unwrap,sign,encrypt,decrypt,junk-data should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=wrap,unwrap,sign,encrypt,decrypt,$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "IllegalArgumentException: Invalid usage \"$tmp_junk_data\" specified." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0083: Generating symmetric keys with DESede algo should fail when no client id is provided"
        local rand=$RANDOM
        local client_id=
        local algo=DESede
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages 2> $key_generate_output" 255,1
        rlAssertGrep "Error: Missing Client Key Id." "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0084: Generate symmetric keys with DESede algo with existing ClientID should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DESede
        local usages=wrap,unwrap,sign,encrypt,decrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertGrep "BadRequestException: Can not archive already active existing key!" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0084: Generating symmetric keys using valid admin cert should fail"
	local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1 
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
	rlAssertGrep "ForbiddenException: Authorization Error" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0085: Generating symmetric keys using revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "PKIException: Unauthorized" "$key_generate_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1117"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0086: Generating symmetric keys using admin(not a member of Agents Group) cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_generate_output"	
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0087: Generating symmetric key using Expired admin(not a member of Agents Group) cert should fail" 
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n CA_adminE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$expired_admin_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_generate_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0088: Generating using symmetric key using Expired agent cert should fail"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n CA_agentE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$expired_agent_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_generate_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0089: Generating symmetric key using valid audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_generate_output"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_kra_key_generate-0090: Generate symmetric key using valid operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$valid_operatorV_cert\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0091: Generate symmetric key using normal user cert(without any privileges) should fail"
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
                certdb_nick:caadmincert \
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
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"$pki_user_fullName\" \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 255,1
        rlAssertNotGrep "Key generation request info" "$key_generate_output"
        rlAssertNotGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertNotGrep "Status: complete" "$key_generate_output"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0092: Generate symmetric key using host URI parameter(https)"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlLog "Executing pki -d $CERTDB_DIR -U https://$tmp_kra_host:$target_secure_port key-generate"
        rlRun "pki -d $CERTDB_DIR \
                -U https://$tmp_kra_host:$target_secure_port \
                -c $CERTDB_DIR_PASSWORD \
		-n \"$valid_agent_cert\" \
		kra-key-generate $client_id \
		--key-algorithm $algo \
		--key-size $key_size \
		--usages $usages > $key_generate_output"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0093:Generate symmetric key using valid user should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        rlLog "Executing pki cert-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $tmp_kra_host -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                kra-key-generate $client_id \
		--key-algorithm $algo \
		--key-size $key_size \
		--usages $usages > $key_generate_output 2>&1" 1,255
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_generate_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_generate-0093: Generating symmetric key using in-valid user should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki cert-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $tmp_kra_host -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd  \
                kra-key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$key_generate_output"
	rlPhaseEnd

	rlPhaseStartCleanup "pki key-generate cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd

}
