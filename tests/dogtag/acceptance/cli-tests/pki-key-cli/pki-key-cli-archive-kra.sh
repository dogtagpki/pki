#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-key-cli
#   Description: PKI KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki key-archive
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

run_pki-key-archive-kra_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki key-archive
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
        local expired_admin_cert=$KRA_INST\_adminE
        local expired_agent_cert=$KRA_INST\_agentE
        local i18n_passphrase1="Örjan_Äke"
        local i18n_passphrase2="Éric_Têko"
        local i18n_passphrase3="éénentwintig_dvidešimt"
        local i18n_passphrase4="kakskümmend_üks"
        local i18n_passphrase5="двадцять_один_тридцять"
	local i18n_array=("Örjan_Äke" "Éric_Têko" "éénentwintig_dvidešimt" "kakskümmend_üks" "двадцять_один_тридцять")
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local key_generate_output=$TmpDir/key-generate.out
	local key_archive_output=$TmpDir/key-archive.out
	local key_request_review_output=$TmpDir/key-request-review.out
	local key_retrieve_output=$TmpDir/key-retrieve.out
        local cert_request_submit="$TEMP_NSS_DB/pki-cert-request-submit.out"
        local tmp_junk_data=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 200 | head -n 1)
	local tmp_passphrase=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
        local profile=caUserCert


        # Config test of pki key-archive
        rlPhaseStartTest "pki_key_cli-configtest: pki key-archive --help configuration test"
        rlRun "pki key-archive --help > $key_archive_output" 0 "pki key-archive --help"
        rlAssertGrep "usage: key-archive \[OPTIONS...\]" "$key_archive_output"
        rlAssertGrep "    --clientKeyID <Client Key Identifier>   Unique client key identifier" "$key_archive_output"
        rlAssertGrep "    --help                                  Show help options" "$key_archive_output"
	rlAssertGrep "    --input <Input file path>               Location of the request" "$key_archive_output"
	rlAssertGrep "                                            template file" "$key_archive_output"
	rlAssertGrep "                                            Used for archiving already" "$key_archive_output"
	rlAssertGrep "                                            encrypted data." "$key_archive_output"
	rlAssertGrep "    --passphrase <Passphrase>               Passphrase to be stored" "$key_archive_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_key_archive-001: Create a passphrase archival request and verify by approving the request"
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
	local client_id=temp$rand
	local passphrase=$tmp_passphrase
	local base64_passphrase=$(echo -n $passphrase | base64)
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		key-archive --clientKeyID $client_id \
		--passphrase $passphrase > $key_archive_output" 0 "Create request to archive $passphrase"
	local request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
	local key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
	rlAssertGrep "Request ID: $request_id" "$key_archive_output"
	rlAssertGrep "Key ID: $key_id" "$key_archive_output"
	rlAssertGrep "Type: securityDataEnrollment" "$key_archive_output"
	rlAssertGrep "Status: complete" "$key_archive_output"
	rlLog "Verify by approving the request"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-n \"$valid_agent_cert\" \
		key-request-review $request_id \
		--action approve > $key_request_review_output" 0 "Approve request $request_id"
	rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
	rlAssertGrep "Status: complete" "$key_request_review_output"
	rlLog "Retreive the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
		key-retrieve --keyID $key_id > $key_retrieve_output" 0 "Retrieve KeyID $key_id"
	rlAssertGrep "Key Size: null" "$key_retrieve_output"
	rlAssertGrep "Actual archived data: $base64_passphrase" "$key_retrieve_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_key_archive-002: Create a passphrase archival request with passphrase containing special characters"
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
	local tmp_passphrase=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
	local spl_characters=$(cat /dev/urandom | tr -dc '*?%^()+@!#{\}/-' | fold -w 10 | head -n 1)
	local client_id=temp$rand
        local passphrase=$tmp_passphrase-$spl_characters
        local base64_passphrase=$(echo -n "$passphrase" | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase \"$passphrase\" > $key_archive_output" 0 "Create request to archive $passphrase"
        local request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
        local key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$key_archive_output"
        rlAssertGrep "Key ID: $key_id" "$key_archive_output"
        rlAssertGrep "Type: securityDataEnrollment" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlLog "Verify by approving the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-review $request_id \
                --action approve > $key_request_review_output" 0 "Approve request $request_id"
        rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
        rlAssertGrep "Status: complete" "$key_request_review_output"
        rlLog "Retreive the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-retrieve --keyID $key_id > $key_retrieve_output" 0 "Retrieve KeyID $key_id"
        rlAssertGrep "Key Size: null" "$key_retrieve_output"
        rlAssertGrep "Actual archived data: $base64_passphrase" "$key_retrieve_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_key_archive-003: Create a passphrase of 100 characters and verify by archiving the passphrase"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local tmp_passphrase=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 100 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
	local base64_limit=$(echo $base64_passphrase | head -c 64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output" 0 "Create request to archive $passphrase"
        local request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
        local key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$key_archive_output"
        rlAssertGrep "Key ID: $key_id" "$key_archive_output"
        rlAssertGrep "Type: securityDataEnrollment" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlLog "Verify by approving the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-review $request_id \
                --action approve > $key_request_review_output" 0 "Approve request $request_id"
        rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
        rlAssertGrep "Status: complete" "$key_request_review_output"
        rlLog "Retreive the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-retrieve --keyID $key_id > $key_retrieve_output" 0 "Retrieve KeyID $key_id"
        rlAssertGrep "Key Size: null" "$key_retrieve_output"
        rlAssertGrep "Actual archived data: $base64_limit" "$key_retrieve_output"
	rlPhaseEnd


	rlPhaseStartTest "pki_key_archive-004: Create a archival request of passphrase containing i18n characters"
	for i in "${i18n_array[@]}"; do
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local passphrase=$i
        local client_id=temp$rand
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output" 0 "Create request to archive $passphrase"
        local request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
        local key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$key_archive_output"
        rlAssertGrep "Key ID: $key_id" "$key_archive_output"
        rlAssertGrep "Type: securityDataEnrollment" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlLog "Verify by approving the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-review $request_id \
                --action approve > $key_request_review_output" 0 "Approve request $request_id"
        rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
        rlAssertGrep "Status: complete" "$key_request_review_output"
        rlLog "Retreive the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-retrieve --keyID $key_id > $key_retrieve_output" 0 "Retrieve KeyID $key_id"
        rlAssertGrep "Key Size: null" "$key_retrieve_output"
        rlAssertGrep "Actual archived data: $base64_passphrase" "$key_retrieve_output"
	done
	rlPhaseEnd

	rlPhaseStartTest "pki_key_archive-005: Verify when no data is passed to --clientKeyId key-archive should fail with command help"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=''
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "usage: key-archive \[OPTIONS...\]" "$key_archive_output"
        rlAssertGrep "    --clientKeyID <Client Key Identifier>   Unique client key identifier" "$key_archive_output"
        rlAssertGrep "    --help                                  Show help options" "$key_archive_output"
        rlAssertGrep "    --input <Input file path>               Location of the request" "$key_archive_output"
        rlAssertGrep "                                            template file" "$key_archive_output"
        rlAssertGrep "                                            Used for archiving already" "$key_archive_output"
        rlAssertGrep "                                            encrypted data." "$key_archive_output"
        rlAssertGrep "    --passphrase <Passphrase>               Passphrase to be stored" "$key_archive_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-006: Verify when no data is passed to --passphrase key-archive should fail with command help"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=''
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "usage: key-archive \[OPTIONS...\]" "$key_archive_output"
        rlAssertGrep "    --clientKeyID <Client Key Identifier>   Unique client key identifier" "$key_archive_output"
        rlAssertGrep "    --help                                  Show help options" "$key_archive_output"
        rlAssertGrep "    --input <Input file path>               Location of the request" "$key_archive_output"
        rlAssertGrep "                                            template file" "$key_archive_output"
        rlAssertGrep "                                            Used for archiving already" "$key_archive_output"
        rlAssertGrep "                                            encrypted data." "$key_archive_output"
        rlAssertGrep "    --passphrase <Passphrase>               Passphrase to be stored" "$key_archive_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_key_archive-007: creating passphrase archival request using Admin cert(not a member of agents group) should fail"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
	rlAssertGrep "Authorization Error" "$key_archive_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-008: creating passphrase archival request using Revoked Agent cert(not a member of agents group) should fail"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "Authorization Error" "$key_archive_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-009: creating passphrase archival request using Revoked Admin cert(not a member of agents group) should fail"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_admin_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "Authorization Error" "$key_archive_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_key_archive-0010: creating passphrase archival request using Expired Admin cert(not a member of agents group) should fail"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n \"$expired_admin_cert\" | grep "Not After" | awk -F ": " '{print $2}')
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
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_archive_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-0011: creating passphrase archival request using Expired Agent cert(not a member of agents group) should fail"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n \"$expired_agent_cert\" | grep "Not After" | awk -F ": " '{print $2}')
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
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_archive_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-0012: creating passphrase archival request using valid Audit cert should fail"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "Authorization Error" "$key_archive_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-0013: creating passphrase archival request using valid operator cert should fail"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_operator_cert\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
        rlAssertGrep "Authorization Error" "$key_archive_output"
        rlPhaseEnd

	rlPhaseStartSetup "Create Normal KRA User & Cert"
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

	rlPhaseStartTest "pki_key_archive-0014: creating passphrase archival request using User (not a member of any group) Cert should fail"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$pki_user\" \
                key-archive --clientKeyID $client_id \
                --passphrase $passphrase > $key_archive_output 2>&1" 255,1 "Create request to archive $passphrase"
	rlAssertGrep "Authorization Error" "$key_archive_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-0015: creating passphrase archival request using host URI parameter(https)"
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local base64_passphrase=$(echo -n $passphrase | base64)
        rlLog "Executing pki key-archive using http host URI parameter(https)"
        rlRun "pki -d $CERTDB_DIR \
                -U https://$tmp_kra_host:$target_secure_port \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                key-archive --clientKeyID $client_id \
		--passphrase $passphrase > $key_archive_output" 0 "Archive $passphrase as $valid_agent_cert"
        local request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
        local key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $request_id" "$key_archive_output"
        rlAssertGrep "Key ID: $key_id" "$key_archive_output"
        rlAssertGrep "Type: securityDataEnrollment" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_key_archive-0016: creating passphrase archival request using valid user(Not a member of any group) should fail"
        rlRun "pki -d $CERTDB_DIR\
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                key-archive --clientKeyID $client_id \
		--passphrase $passphrase  > $key_archive_output 2>&1" 255,1 "Archive $passphrase as $pki_user_fullName"
        rlAssertGrep "'PKIException: Unauthorized" "$key_archive_output"

        rlPhaseStartTest "pki_key_archive_0017: creating passphrase archival request using in-valid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki key-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -h $tmp_kra_host -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd  \
                key-archival --clientKeyId $client_id \
		--passphrase $passphrase > $key_archive_output 2>&1" 255,1 "create passphrase archival request as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$key_archive_output"
        rlPhaseEnd

        rlPhaseStartCleanup "pki key-archive cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd

}
