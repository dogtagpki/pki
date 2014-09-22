#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki kra-key-retrieve
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

run_pki-kra-key-retrieve-kra_tests()
{
        local cs_Id=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki kra-key-retrieve
        rlPhaseStartSetup "pki key-recover Temporary Directory"
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
        local cert_info="$TmpDir/cert_info"
        local key_generate_output=$TmpDir/key-generate.out
        local key_archive_output=$TmpDir/key-archive.out
        local key_recover_output=$TmpDir/key-recover.out
        local key_ret_output=$TmpDir/key-retrieve.out
	local key_store=$TmpDir/key-store.out
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local tmp_passphrase=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
        local tmp_junk_data=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 200 | head -n 1)


        # Config test of pki key-recover
        rlPhaseStartTest "pki_key_cli-configtest: pki kra-key-retrieve --help configuration test"
        rlRun "pki kra-key-retrieve --help > $key_ret_output" 0 "pki key-recover --help"
        rlAssertGrep "usage: key-retrieve \[OPTIONS...\]" "$key_ret_output"
        rlAssertGrep "    --help                                          Show help options" "$key_ret_output"
        rlAssertGrep "    --input <Input file path>                       Location of the" "$key_ret_output"
        rlAssertGrep "    --keyID <Key Identifier>                        Key Identifier for the" "$key_ret_output"
        rlAssertGrep "                                                    secret to be" "$key_ret_output"
	rlAssertGrep "                                                    recovered." "$key_ret_output"
	rlAssertGrep "    --output <File path to store key information>   Location to store the" "$key_ret_output"
	rlAssertGrep "                                                    retrieved key" "$key_ret_output"
	rlAssertGrep "                                                    information" "$key_ret_output"
	rlAssertGrep "    --passphrase <Passphrase>                       Passphrase to encrypt" "$key_ret_output"
	rlAssertGrep "                                                    the key information" "$key_ret_output"
        rlPhaseEnd

	rlPhaseStartSetup "Generate a approved symmetric key and archive it"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local algo_1=AES
        local action=approve
        local key_size_1=128
        local usages=wrap
        rlRun "generate_key $client_id $algo_1 $key_size_1 $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id_1=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	rlPhaseEnd
	
	rlPhaseStartTest "pki-kra-key-retrieve-001: Retrieve archived symmetric key using valid agent cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		kra-key-retrieve --keyID $key_id_1 > $key_ret_output" 0 "Retrieve $key_id"
	rlAssertGrep "Key Algorithm: $algo_1" "$key_ret_output"
	rlAssertGrep "Key Size: $key_size_1" "$key_ret_output"
	local archived_data_1=$(cat $key_ret_output | grep "Actual archived data" | awk -F ":" '{print $2}')
	local nonce_data_1=$(cat $key_ret_output | grep "Nonce data" | awk -F ":" '{print $2}')
	rlLog "Archived Private key: $archived_data_1"
	rlLog "Nonce Data: $nonce_data_1"
	rlPhaseEnd

	rlPhaseStartSetup "Generate asymmetric keys and archive"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local algo_2=RSA
        local action=approve
        local key_size_2=2048
        local usages=sign_recover
        rlRun "generate_key $client_id $algo_2 $key_size_2 $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id_2=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-002: Retrieve archived asymmetric key using valid agent cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_2 > $key_ret_output" 0 "Retrieve $key_id"
        rlAssertGrep "Key Algorithm: $algo_2" "$key_ret_output"
        rlAssertGrep "Key Size: $key_size_2" "$key_ret_output"
        local archived_data_2=$(cat $key_ret_output | grep "Actual archived data" | awk -F ":" '{print $2}')
        local nonce_data_2=$(cat $key_ret_output | grep "Nonce data" | awk -F ":" '{print $2}'| tr -d '\n')
        rlLog "Archived Private key : $archived_data_2"
        rlLog "Nonce Data: $nonce_data_2"
        rlPhaseEnd

        rlPhaseStartSetup "Archive Passphrase in KRA"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase_1=Secret123
        local action=approve
        local state_change=inactive
        rlRun "archive_passphrase $client_id $passphrase_1 $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local key_id_3=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-003: Retrieve archived passphrase using valid agent cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_3 > $key_ret_output" 0 "Retrieve $key_id"
        local archived_data_3=$(cat $key_ret_output | grep "Actual archived data" | awk -F ":" '{print $2}'| tr -d '\n')
        local nonce_data_3=$(cat $key_ret_output | grep "Nonce data" | awk -F ":" '{print $2}'| tr -d '\n')
        rlLog "Archived Private key : $archived_data_3"
        rlLog "Nonce Data: $nonce_data_3"
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-004: Verify when no keyID is given, key-retrieve fails with command help"
	local key_id=''
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id > $key_ret_output 2>&1" 255,1 "Passing no keyId to key-retrieve"
        rlAssertGrep "usage: key-retrieve \[OPTIONS...\]" "$key_ret_output"
        rlAssertGrep "    --help                                          Show help options" "$key_ret_output"
        rlAssertGrep "    --input <Input file path>                       Location of the" "$key_ret_output"
        rlAssertGrep "    --keyID <Key Identifier>                        Key Identifier for the" "$key_ret_output"
        rlAssertGrep "                                                    secret to be" "$key_ret_output"
        rlAssertGrep "                                                    recovered." "$key_ret_output"
        rlAssertGrep "    --output <File path to store key information>   Location to store the" "$key_ret_output"
        rlAssertGrep "                                                    retrieved key" "$key_ret_output"
        rlAssertGrep "                                                    information" "$key_ret_output"
        rlAssertGrep "    --passphrase <Passphrase>                       Passphrase to encrypt" "$key_ret_output"
        rlAssertGrep "                                                    the key information" "$key_ret_output"
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-005: Verify when invalid keyID is given, key-retrieve command fails"
        local key_id=123456789
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id > $key_ret_output 2>&1" 255,1 "Passing no keyId to key-retrieve"
	rlAssertGrep "Key ID 0x75bcd15 not found" "$key_ret_output"
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-006: verify when junk data is passed to KeyID, key-retrieve command fails"
        local key_id=$tmp_junk_data
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id > $key_ret_output 2>&1" 255,1 "Passing no keyId to key-retrieve"
	rlAssertGrep "NumberFormatException: For input string:" "$key_ret_output"
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-007: Retrieve archived symmetric key and save it to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_1 --output $key_store" 0 "Save the Retrieve symmetric key to $key_out file" 
	local xml_algorithm=$(xmlstarlet sel -t -m "Key" -v "algorithm" -n  < $key_store)
	local xml_size=$(xmlstarlet sel -t -m "Key" -v "size" -n < $key_store)
	local xml_archive_data=$( xmlstarlet sel -t -m "Key" -v "data" -n  < $key_store)
	local xml_noncedata=$( xmlstarlet sel -t -m "Key" -v "nonceData" -n  < $key_store)
        rlLog "Archived Private key: $xml_archive_data"
        rlLog "Nonce Data: $xml_noncedata"
	rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-008: Retrieve archived asymmetric key and save it to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_2 --output $key_store" 0 "Save the Retrieve symmetric key to $key_out file"
        local xml_algorithm=$(xmlstarlet sel -t -m "Key" -v "algorithm" -n  < $key_store)
        local xml_size=$(xmlstarlet sel -t -m "Key" -v "size" -n < $key_store)
        local xml_archive_data=$( xmlstarlet sel -t -m "Key" -v "data" -n  < $key_store)
        local xml_noncedata=$( xmlstarlet sel -t -m "Key" -v "nonceData" -n  < $key_store)
        rlLog "Archived Private key: $xml_archive_data"
        rlLog "Nonce Data: $xml_noncedata"
        rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-009: Retrieve archived passphrase and save it to a file"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_3 --output $key_store" 0 "Save the Retrieve symmetric key to $key_out file"
        local xml_algorithm=$(xmlstarlet sel -t -m "Key" -v "algorithm" -n  < $key_store)
        local xml_size=$(xmlstarlet sel -t -m "Key" -v "size" -n < $key_store)
        local xml_archive_data=$(xmlstarlet sel -t -m "Key" -v "data" -n  < $key_store)
        local xml_noncedata=$(xmlstarlet sel -t -m "Key" -v "nonceData" -n  < $key_store)
	rlLog "xml_archive_data = $xml_archive_data"
	rlLog "xml_noncedata=$xml_noncedata"
        rlLog "Archived Private key: $xml_archive_data"
        rlLog "Nonce Data: $xml_noncedata"
        rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0010: Verify when no file is passed to --output, pki key-retrieve fails with command help"
	local key_store=''
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_3 --output $key_store > $key_ret_output 2>&1" 255,1 "Save the Retrieve symmetric key to $key_out file"	
	rlAssertGrep "Error: Missing argument for option: output" "$key_ret_output"
        rlAssertGrep "usage: key-retrieve \[OPTIONS...\]" "$key_ret_output"
        rlAssertGrep "    --help                                          Show help options" "$key_ret_output"
        rlAssertGrep "    --input <Input file path>                       Location of the" "$key_ret_output"
        rlAssertGrep "    --keyID <Key Identifier>                        Key Identifier for the" "$key_ret_output"
        rlAssertGrep "                                                    secret to be" "$key_ret_output"
        rlAssertGrep "                                                    recovered." "$key_ret_output"
        rlAssertGrep "    --output <File path to store key information>   Location to store the" "$key_ret_output"
        rlAssertGrep "                                                    retrieved key" "$key_ret_output"
        rlAssertGrep "                                                    information" "$key_ret_output"
        rlAssertGrep "    --passphrase <Passphrase>                       Passphrase to encrypt" "$key_ret_output"
        rlAssertGrep "                                                    the key information" "$key_ret_output"
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0011: Retrieve archived symmetric key and encrypt it with passphrase"
	local encrypt_passphrase=Secret123
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_1 --passphrase $encrypt_passphrase > $key_ret_output" 0 "Encrypt the retrieved symmetric key"
	local encrypted_symm_key=$(cat $key_ret_output | grep "Encrypted Data" | awk -F ":" '{print $2}' | tr -d '\n')
        rlAssertGrep "Key Algorithm: $algo_1" "$key_ret_output"
        rlAssertGrep "Key Size: $key_size_1" "$key_ret_output"
	rlLog "Encrypted Data: $encrypted_symm_key" 
	rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0012: Retrieve archived asymmetric key and encrypt it with passphrase"
        local encrypt_passphrase=Secret123
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_2 --passphrase $encrypt_passphrase > $key_ret_output" 0 "Encrypt the retrieved symmetric key"
        local encrypted_symm_key=$(cat $key_ret_output | grep "Encrypted Data" | awk -F ":" '{print $2}' | tr -d '\n')
        rlAssertGrep "Key Algorithm: $algo_2" "$key_ret_output"
        rlAssertGrep "Key Size: $key_size_3" "$key_ret_output"
        rlLog "Encrypted Data: $encrypted_symm_key"
        rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0013: Retrieve archived passphrase and encrypt it with passphrase"
        local encrypt_passphrase=Secret123
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_3 --passphrase $encrypt_passphrase > $key_ret_output" 0 "Encrypt the retrieved symmetric key"
        local encrypted_symm_key=$(cat $key_ret_output | grep "Encrypted Data" | awk -F ":" '{print $2}' | tr -d '\n')
        rlLog "Encrypted Data: $encrypted_symm_key"
        rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0014: Verify when no passphrase is passed to --passphrase, pki key-retrieve fails with command help"
        local encrypt_passphrase=''
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_3 --passphrase $encrypt_passphrase > $key_ret_output" 255,1 "Pass no data to --passphrase"
        rlAssertGrep "Error: Missing argument for option: passphrase" "$key_ret_output"
        rlAssertGrep "usage: key-retrieve \[OPTIONS...\]" "$key_ret_output"
        rlAssertGrep "    --help                                          Show help options" "$key_ret_output"
        rlAssertGrep "    --input <Input file path>                       Location of the" "$key_ret_output"
        rlAssertGrep "    --keyID <Key Identifier>                        Key Identifier for the" "$key_ret_output"
        rlAssertGrep "                                                    secret to be" "$key_ret_output"
        rlAssertGrep "                                                    recovered." "$key_ret_output"
        rlAssertGrep "    --output <File path to store key information>   Location to store the" "$key_ret_output"
        rlAssertGrep "                                                    retrieved key" "$key_ret_output"
        rlAssertGrep "                                                    information" "$key_ret_output"
        rlAssertGrep "    --passphrase <Passphrase>                       Passphrase to encrypt" "$key_ret_output"
        rlAssertGrep "                                                    the key information" "$key_ret_output"	
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0015: Retrieveing archived symmetric key using admin Cert(not a member of agents group) should fail"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1
	rlAssertGrep "Authorization Error" "$key_ret_output"
	rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0016: Retrieveing archived symmetric key using Revoked admin Cert should fail"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_admin_cert\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1
        rlAssertGrep "Authorization Error" "$key_ret_output"
        rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0017: Retrieveing archived symmetric key using Revoked agent Cert should fail"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve symmetric key as $revoked_agent_cert"
        rlAssertGrep "Authorization Error" "$key_ret_output"
        rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0018: Retrieveing archived symmetric key using Expired admin Cert should fail"
        rlLog "Executing pki key-retrieve as $expired_admin_cert"
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
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve symmetric key as $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$key_ret_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0019: Retrieveing archived symmetric key using Expired agent Cert should fail"
        rlLog "Executing pki key-retrieve as $expired_agent_cert"
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
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve symmetric key as $expired_agent_cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_ret_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0020: Retrieveing archived symmetric key using Valid audit Cert should fail"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve symmetric key as $valid_audit_cert"
        rlAssertGrep "Authorization Error" "$key_ret_output"
        rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0021: Retrieveing archived symmetric key using Valid operator Cert should fail"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_operator_cert\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve symmetric key as $valid_operator_cert"
        rlAssertGrep "Authorization Error" "$key_ret_output"
        rlPhaseEnd

	rlPhaseStartSetup "Create a  Normal KRA user including Certificate for the user"
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
        rlPhaseEnd

        rlPhaseStartTest "pki-kra-key-retrieve-0022: Retrieveing archived symmetric key using Normal Cert should fail"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$pki_user\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve symmetric key as $valid_operator_cert"
        rlAssertGrep "Authorization Error" "$key_ret_output"
        rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0023: Retrieve archived symmetric key using https URI using Agent Cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -U https://$tmp_kra_host:$target_secure_port \
                -n \"$valid_agent_cert\" \
                kra-key-retrieve --keyID $key_id_1 > $key_ret_output" 0 "Retrieve $key_id"
        rlAssertGrep "Key Algorithm: $algo_1" "$key_ret_output"
        rlAssertGrep "Key Size: $key_size_1" "$key_ret_output"
        local archived_data_1=$(cat $key_ret_output | grep "Actual archived data" | awk -F ":" '{print $2}')
        local nonce_data_1=$(cat $key_ret_output | grep "Nonce data" | awk -F ":" '{print $2}')
        rlLog "Archived Private key: $archived_data_1"
        rlLog "Nonce Data: $nonce_data_1"
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve-0024: Retrieveing archived symmetric key using Normal user (Not a member of any group) should fail"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD\
		-p $target_unsecure_port \
		-u $pki_user \
		-w $pki_pwd \
		kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve $key_id as $pki_user"
	rlAssertGrep "Authentication method not allowed" "$key_ret_output"		
	rlPhaseEnd

	rlPhaseStartTest "pki-kra-key-retrieve--0025: REtrieveing archived symmetric key using invalid user should fail"
	local invalid_pki_user=test1
	local invalid_pki_user_pwd=Secret123
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD\
		-p $target_unsecure_port \
		-u $invalid_pki_user \
		-w $invalid_pki_user_pwd \
		kra-key-retrieve --keyID $key_id_1 > $key_ret_output 2>&1" 255,1 "Retrieve $key_id as $pki_user"
	rlAssertGrep "PKIException: Unauthorized" "$key_ret_output"		
	rlPhaseEnd

        rlPhaseStartCleanup "pki kra-key-retrieve cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
