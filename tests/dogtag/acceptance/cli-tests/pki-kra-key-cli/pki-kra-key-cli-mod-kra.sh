#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki kra key cli commands needs to be tested:
#  pki kra-key-mod
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
run_pki-kra-key-mod-kra_tests()
{
	
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki kra-key-mod
        rlPhaseStartSetup "pki kra-key-mod Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

	#Local Variables
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
        local key_generate_output=$TmpDir/key-generate.out
	local key_show_output=$TmpDir/key-show.out
	local key_mod_output=$TmpDir/key-mod.out
	local key_archive_output=$TmpDir/key-archive.out
        local rand=$RANDOM
        local cert_request_submit="$TEMP_NSS_DB/pki-cert-request-submit.out"
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
        local profile=caUserCert

        # Config test of pki kra-key-mod
        rlPhaseStartTest "pki_key_cli-configtest: pki kra-key-mod --help configuration test"
        rlRun "pki kra-key-mod --help > $key_mod_output" 0 "pki key-mod --help"
        rlAssertGrep "usage: kra-key-mod <Key ID> --status <status> \[OPTIONS...\]" "$key_mod_output"
        rlAssertGrep "    --help              Show help options" "$key_mod_output"
        rlAssertGrep "    --status <status>   Status of the key." "$key_mod_output"
        rlAssertGrep "                        Valid values: active, inactive" "$key_mod_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-001: Modifying the status of valid key of type SymmetricKey  from active to Inactive should be successful"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
	local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
	rlLog "Modify the status of the request from Active to Inactive"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		kra-key-mod $tmp_key_id \
		--status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
	rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_kra_key_mod-002: Modifying the status of Valid key of type SymmetricKey from Inactive to Active should be successful"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from In-Active to Active"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
	local state_change=active
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from In-active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-003: Modifying the status of Rejected key of type Symmetric Key to active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=reject
        local key_size=128
        local usages=wrap
        local state_change=active
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: rejected" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
	rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
	rlAssertGrep "Algorithm: $algo" "$key_mod_output"
	rlAssertGrep "Size: $key_size" "$key_mod_output"
	rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-004: Modifying the status of Rejected key of type Symmetric Key to inactive should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=reject
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: rejected" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-005: Modifying the status of canceled key of type Symmetric Key to active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=cancel
        local key_size=128
        local usages=wrap
        local state_change=active
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: canceled" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-006: Modifying the status of canceled key of type Symmetric Key to inactive should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=cancel
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: canceled" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-007: Modifying the status of valid key from Active state to Unknown State(not inactive) should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=InValidState
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change"
	rlAssertGrep "IllegalArgumentException: Invalid status value" "$key_mod_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-008: Modifying the status of valid key from Existing state to it's same existing should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=active
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"			
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-009: Modifying the status of valid key of type securityDataEnrollment  from active to Inactive should be successful"
        local rand=$RANDOM
        local client_id=temp$rand
	local passphrase=Secret123
	local action=approve
	local state_change=inactive
	rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
		0 "Archive $passphrase with client ID $client_id"
	local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0010: Modifying the status of Valid key of type securityDataEnrollment from Inactive to Active should be successful"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=approve
        local state_change=inactive
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	local state_change=inactive
	rlLog "Modify the status of the request from InActive to Active"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from inactive to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_kra_key_mod-0011: Modifying the status of Rejected key of type securityDataEnrollment key to active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=reject
        local state_change=active
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: rejected" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0012: Modifying the status of Rejected key of type securityDataEnrollment key to in-active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=reject
        local state_change=inactive
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: rejected" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0013: Modifying the status of Canceled key of type securityDataEnrollment key to active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=cancel
        local state_change=active
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: canceled" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0014: Modifying the status of Canceled key of type securityDataEnrollment key to in-active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=cancel
        local state_change=inactive
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: canceled" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		kra-key-mod $tmp_key_id \
		--status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd	

        rlPhaseStartTest "pki_kra_key_mod-0015: Modifying the status of valid key of type securityDataEnrollment from active to Invalid State should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=approve
        local state_change=inValidState
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change"	
	rlAssertGrep "IllegalArgumentException: Invalid status value" "$key_mod_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0016: Modifying the status of valid key of type securityDataEnrollment from Existing state to it's same state should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=approve
        local state_change=active
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local tmp_key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0017: Modifying the status of Key using Admin Cert(not a member of agent group) should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$key_mod_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0018: Modifying the status of Key from Active to Inactive using Revoked Admin Cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_admin_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $valid_agent_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_mod_output"
	rlLog "PKI TICKET::https://fedorahosted.org/pki/ticket/1117"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0019: Modifying the status of Key from Active to Inactive using Revoked Agent Cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $revoked_agent_cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_mod_output"
	rlLog "PKI TICKET::https://fedorahosted.org/pki/ticket/1117"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0018: Modifying the status of Key using expired Admin Cert should fail"
        rlLog "Executing pki key-mod as $expired_admin_cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_admin_cert | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out" 0 "Extend date to $end_date + 1 day ahead"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$expired_admin_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $expired_admin_cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_mod_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"	
	rlPhaseEnd


        rlPhaseStartTest "pki_kra_key_mod-0018: Modifying the status of Key using expired Agent Cert should fail"
        rlLog "Executing pki key-mod as $expired_admin_cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_admin_cert | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out" 0 "Extend date to $end_date + 1 day ahead"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$expired_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $expired_agent_cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_mod_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0019: Modifying the status of Key using audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $valid_audit_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_mod_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0020: Modifying the status of Key using operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_operator_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $valid_operator_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_mod_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0023: Modifying the status of Key by connecting to KRA using https URI using valid agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve 
        local key_size=128
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -U https://$tmp_kra_host:$target_secure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
	rlPhaseEnd


	rlPhaseStartTest "pki_kra_key_mod-0024: Modifying the status of key using Normal user(Not a member of any group) cert should fail"
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
                cert_info:$cert_info" 0 "Generate User Cert with for $pki_user_fullName"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $tmp_ca_agent \
                -h $tmp_ca_host \
                -p $target_unsecure_port cert-show $cert_serialNumber \
                --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out" 0 "Get the $pki_user cert in a output file"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $tmp_ca_agent \
                -h $tmp_ca_host \
                -p $target_unsecure_port cert-show 0x1 \
                --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out" 0 "Copy the CA Cert to a file"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD -h $tmp_kra_host -p $target_unsecure_port \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out" 0 "Add $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD -h $tmp_kra_host -p $target_unsecure_port \
                -n \"CA Signing Certificate - $CA_DOMAIN Security Domain\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out" 0 "Add CA cert to $TEMP_NSS_DB NSS DB"
        rlAssertGrep "Imported certificate \"CA Signing Certificate - $CA_DOMAIN Security Domain\"" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
                -n $valid_admin_cert \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -t kra user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
        rlLog "Executing pki key-mod as $pki_user_fullName"
        rlRun "pki -d $TEMP_NSS_DB\
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
		-n \"$pki_user\" \
		kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change using $pki_user_fullName"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_mod_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0025: Modifying the status of key using Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki key-mod using user $invalid_pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -h $tmp_kra_host -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd  \
                kra-key-mod $tmp_key_id --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status of key $tmp_key_id as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$key_mod_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_mod-0026: Modifying the status of key using Normal user(Not a member of any group) should fail"
       	rlRun "pki -d $CERTDB_DIR\
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                kra-key-mod $tmp_key_id --status $state_change > $key_mod_output 2>&1" 255,1 "Search key requests as $pki_user_fullName"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_mod_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0027: Modifying the status of valid key of type asymmetric from active to Inactive should be successful"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local action=approve
        local key_size=2048
        local usages=derive
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0028: Modifying the status of Valid key of type asymmetric from Inactive to Active should be successful"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local action=approve
        local key_size=2048
        local usages=derive
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from In-Active to Active"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        local state_change=active
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from In-active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0029: Modifying the status of Rejected key of type asymmetric to active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local action=reject
        local key_size=1024
        local usages=wrap
        local state_change=active
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: rejected" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client Key ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0030: Modifying the status of Rejected key of type asymmetric to inactive should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local action=reject
        local key_size=1024
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: rejected" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client Key ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0031: Modifying the status of canceled key of type asymmetric to active should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local action=cancel
        local key_size=1024
        local usages=wrap
        local state_change=active
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: canceled" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client Key ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0032: Modifying the status of Canceled key of type asymmetric to inactive should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local action=cancel
        local key_size=1024
        local usages=wrap
        local state_change=inactive
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: canceled" "$key_generate_output"
        rlLog "Modify the status of the request which has been rejected"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from canceled to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Client Key ID: $client_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1137"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0033: Modifying the status of valid Asymmetric key from Active state to Unknown State(not inactive) should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local action=approve
        local key_size=2048
        local usages=derive
        local state_change=InValidState
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output 2>&1" 255,1 "Modify status from active to $state_change"
        rlAssertGrep "IllegalArgumentException: Invalid status value" "$key_mod_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_mod-0034: Modifying the status of valid Asymmetric key from Existing state to it's same existing should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local action=approve
        local key_size=1024
        local usages=derive
        local state_change=active
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $tmp_key_id > $key_show_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlLog "Modify the status of the request from Active to Inactive"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-mod $tmp_key_id \
                --status $state_change > $key_mod_output" 0 "Modify status from active to $state_change"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_mod_output"
        rlAssertGrep "Status: $state_change" "$key_mod_output"
        rlAssertGrep "Algorithm: $algo" "$key_mod_output"
        rlAssertGrep "Size: $key_size" "$key_mod_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_mod_output"                       
        rlPhaseEnd

        rlPhaseStartCleanup "pki kra-key-mod cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
