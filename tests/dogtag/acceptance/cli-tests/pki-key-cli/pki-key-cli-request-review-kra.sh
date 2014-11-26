#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-key-cli
#   Description: PKI KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki key-request-review
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

run_pki-key-request-review-kra_tests()
{
        local cs_Id=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki key-request-review
        rlPhaseStartSetup "pki key-request-review Temporary Directory"
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
        local key_request_review_output=$TmpDir/key-request-review.out
        local rand=$RANDOM
        local tmp_passphrase=$(openssl rand -base64 10 |  perl -p -e 's/\n//')
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


        # Config test of pki key-request-review
        rlPhaseStartTest "pki_key_cli-configtest: pki key-request-review --help configuration test"
        rlRun "pki key-request-review --help > $key_request_review_output" 0 "pki key-request-review --help"
        rlAssertGrep "usage: key-request-review <Request ID> --action <action> \[OPTIONS...\]" "$key_request_review_output"
        rlAssertGrep "    --action <Action to perform>   Action to be performed on the request" "$key_request_review_output"
        rlAssertGrep "                                   Valid values: approve, reject, cancel" "$key_request_review_output"
        rlAssertGrep "    --help                         Show help options" "$key_request_review_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-001: Approving symmetric key archival request as valid agent cert should succeed"
	local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
	local request_action=approve
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
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
                 --action $request_action > $key_request_review_output" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_request_review_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_request_review_output"
        rlAssertGrep "Status: complete" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-002: Rejecting symmetric key archival request as valid agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
	local request_action=reject
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD  \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action reject > $key_request_review_output" 0 "Reject $key_request_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-003: Canceling symmetric key archival requestas as valid agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
	local request_action=cancel
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Verify by canceling request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output" 0 "Cancel $key_request_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-004: Specifying invalid action to symmetric key archival request should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=invalid_action
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Verify by canceling request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Pass invalid action to key-request-review"
	rlAssertGrep "usage: key-request-review <Request ID> --action <action> \[OPTIONS...\]" "$key_request_review_output"
	rlAssertGrep "Error: Invalid action" "$key_request_review_output"
        rlAssertGrep "    --action <Action to perform>   Action to be performed on the request" "$key_request_review_output"
        rlAssertGrep "                                   Valid values: approve, reject, cancel" "$key_request_review_output"
        rlAssertGrep "    --help                         Show help options" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-005: Approving assymmetric key archival request as valid agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output" 0 "Approve $key_request_id"
        rlAssertGrep "Request ID: $key_request_id" "$key_request_review_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_request_review_output"
        rlAssertGrep "Status: complete" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-006: Rejecting asymmetric key archival request by agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=encrypt
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action reject > $key_request_review_output" 0 "Reject $key_request_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-007: Canceling asymmetric key archival request by agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Verify by canceling request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output" 0 "Cancel $key_request_id"
        rlAssertGrep "Key ID: $tmp_key_id" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-008: Passing invalid action to asymetric key archival request should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local key_size=512
        local usages=wrap
        local request_action=invalid_action
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Verify by canceling request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$valid_agent_cert\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Pass invalid action to key-request-review"
        rlAssertGrep "usage: key-request-review <Request ID> --action <action> \[OPTIONS...\]" "$key_request_review_output"
        rlAssertGrep "Error: Invalid action" "$key_request_review_output"
        rlAssertGrep "    --action <Action to perform>   Action to be performed on the request" "$key_request_review_output"
        rlAssertGrep "                                   Valid values: approve, reject, cancel" "$key_request_review_output"
        rlAssertGrep "    --help                         Show help options" "$key_request_review_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-009: Approving passphrase archival request by agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
	local request_action=approve
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
                --action $request_action > $key_request_review_output" 0 "Approve request $request_id"
        rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
        rlAssertGrep "Status: complete" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0010: Rejecting passphrase archival request by agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=reject
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
                --action $request_action > $key_request_review_output" 0 "Reject request $request_id"
        rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
        rlAssertGrep "Status: rejected" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0011: Canceling passphrase archival request by agent cert should succeed"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=cancel
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
                --action $request_action > $key_request_review_output" 0 "$request_action  request $request_id"
        rlAssertGrep "Type: securityDataEnrollment" "$key_request_review_output"
        rlAssertGrep "Status: Canceled" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0012: Pass invalid action to passphrase archival request should fail" 
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=invalid_request
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
		key-request-review $key_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "pass invalid action to pki request-review $request_id"
        rlAssertGrep "usage: key-request-review <Request ID> --action <action> \[OPTIONS...\]" "$key_request_review_output"
        rlAssertGrep "Error: Invalid action" "$key_request_review_output"
        rlAssertGrep "    --action <Action to perform>   Action to be performed on the request" "$key_request_review_output"
        rlAssertGrep "                                   Valid values: approve, reject, cancel" "$key_request_review_output"
        rlAssertGrep "    --help                         Show help options" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0013: Approving symmetric key archival request by admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
	local cert_used=$valid_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
	rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0014: Approving symmetric key archival request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
	local cert_used=$revoked_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                 -h $tmp_kra_host \
                 -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

exit 1;
        rlPhaseStartTest "pki_request_review-0015: Approving symmetric key archival request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
        local cert_used=$revoked_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0016: Approving symmetric key archival request by Expired Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
        local cert_used=$expired_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0017: Approving symmetric key archival request by Expired Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
        local cert_used=$expired_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0018: Approving symmetric key archival request by Audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0019: Approving symmetric key archival request by operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
        local cert_used=$valid_operator_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
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

        rlPhaseStartTest "pki_request_review-0020: Approving symmetric key archival request by Normal user cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=approve
        local cert_used=$pki_user
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $TEMP_NSS_DB \
                 -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0021: Approving symmetric key archival request by Normal user should fail "
	local request_action=approve
	rlLog "Approve Archival request as $pki_user"
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
		-w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $pki_user should fail"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0022: Approving symmetric key archival request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
	local request_action=approve
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $invalid_pki_user"
	rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0023: Approving asymmetric key archival request by admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local key_size=512
        local usages=wrap
        local request_action=approve
        local cert_used=$valid_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0024: Approving asymmetric key archival request by Revoked agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$revoked_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                 -h $tmp_kra_host \
                 -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0025: Approving asymmetric key archival request by Revoked admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$revoked_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0026: Approving asymmetric key archival request by Expired agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$expired_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0027: Approving asymmetric key archival request by Expired admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$expired_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0028: Approving asymmetric key archival request by audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0029: Approving asymmetric key archival request by operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$valid_operator_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0030: Approving asymmetric key archival request by Normal User cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=approve
        local cert_used=$pki_user
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by approving the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $TEMP_NSS_DB \
                 -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0031: Approving asymmetric key archival request by Normal user cert should fail"
        rlLog "Approve Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $pki_user should fail"
	rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0032: Approving asymmetric key archival request by Normal user should fail"
        rlLog "Approve Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $pki_user should fail"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0033: Approving asymmetric key archival request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving $key_request_id as $invalid_pki_user"
	rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0034: Approving passphrase archival request admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=approve
	local cert_used=$valid_admin_cert
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0035: Approving passphrase archival request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=approve
        local cert_used=$revoked_agent_cert
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0036: Approving passphrase archival request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=approve
        local cert_used=$revoked_admin_cert
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0037: Approving passphrase archival request by Expired Admin cert should fail"	
	local cert_used=$expired_admin_cert
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0038: Approving passphrase archival request by Expired Admin cert should fail"
        local cert_used=$expired_agent_cert
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0039: Approving passphrase archival request by Audit cert should fail"
	local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
	rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0040: Approving passphrase archival request by Audit cert should fail"
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0041: Approving passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0042: Approving passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0043: Approving passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0044: Approving passphrase archival request by Normal User should fail"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
		-w $pki_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $pki_user should fail"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0045: Approving passphrase archival request by Invalid User should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving request $request_id by $invalid_pki_user should fail"
        rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0046: Rejecting symmetric key archival request by admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$valid_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0047: Rejecting symmetric archival request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$revoked_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                 -h $tmp_kra_host \
                 -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0048: Rejecting symmetric key archival request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$revoked_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0049: Rejecting symmetric key archival request by Expired Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$expired_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0050: Rejecting symmetric key archival request by Expired Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$expired_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0051: Rejecting symmetric key archival request by Audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0052: Rejecting symmetric key archival request by operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$valid_operator_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0053: Rejecting symmetric key archival request by Normal user cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=reject
        local cert_used=$pki_user
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $TEMP_NSS_DB \
                 -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0054: Rejecting symmetric key archival request by Normal user should fail"
	local request_action=reject
        rlLog "Reject Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $pki_user should fail"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0055: Rejecting symmetric key archival request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
	local request_action=reject
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $invalid_pki_user"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0056: Rejecting asymmetric key archival request by admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local key_size=512
        local usages=wrap
        local request_action=reject
        local cert_used=$valid_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Rejecting key request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0057: Rejecting asymmetric key archival request by Revoked agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$revoked_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Rejecting key request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                 -h $tmp_kra_host \
                 -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0058: Rejecting asymmetric key archival request by Revoked admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$revoked_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Rejecting key request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0059: Rejecting asymmetric key archival request by Expired agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$expired_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0060: Rejecting asymmetric key archival request by Expired admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$expired_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0061: Rejecting asymmetric key archival request by audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0062: Rejecting asymmetric key archival request by operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$valid_operator_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0063: Rejecting asymmetric key archival request by Normal User cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=reject
        local cert_used=$pki_user
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by rejecting the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $TEMP_NSS_DB \
                 -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0064: Rejecting asymmetric key archival request by Normal user cert should fail"
	local request_action=reject
        rlLog "Reject Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Reject $key_request_id as $pki_user should fail"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0065: Rejecting asymmetric key archival request by Normal user should fail"
	local request_action=reject
        rlLog "Rejecting Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $pki_user should fail"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0066: Rejecting asymmetric key archival request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
	local request_action=reject
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting $key_request_id as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0067: Rejecting passphrase archival request admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=reject
        local cert_used=$valid_admin_cert
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
        rlLog "Verify by rejecting the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0068: Rejecting passphrase archival request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=reject
        local cert_used=$revoked_agent_cert
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
        rlLog "Verify by rejecting the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0069: Rejecting passphrase archival request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=reject
        local cert_used=$revoked_admin_cert
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
        rlLog "Verify by rejecting the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0070: Rejecting passphrase archival request by Expired Admin cert should fail"
        local cert_used=$expired_admin_cert
	local request_action=reject
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0071: Rejecting passphrase archival request by Expired Admin cert should fail"
        local cert_used=$expired_agent_cert
	local request_action=reject
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0072: Rejecting passphrase archival request by Audit cert should fail"
	local request_action=reject
        local cert_used=$valid_audit_cert
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0073: Rejecting passphrase archival request by Audit cert should fail"
        local cert_used=$valid_audit_cert
	local request_action=reject
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0074: Rejecting passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
	local request_action=reject
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0075: Rejecting passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
	local request_action=reject
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0076: Rejecting passphrase archival request by Normal User should fail"
	local request_action=reject
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $pki_user should fail"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0077: Rejecting passphrase archival request by Invalid User should fail"
        local invalid_pki_user=test1
	local request_action=reject
        local invalid_pki_user_pwd=Secret123
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Rejecting request $request_id by $invalid_pki_user should fail"
        rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0078: Canceling symmetric key archival request by admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$valid_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlLog "Cancel request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0079: Canceling symmetric archival request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$revoked_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Cancel request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                 -h $tmp_kra_host \
                 -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0080: Canceling symmetric key archival request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$revoked_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Cancel request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0081: Canceling symmetric key archival request by Expired Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$expired_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0082: Canceling symmetric key archival request by Expired Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$expired_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0083: Canceling symmetric key archival request by Audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Reject request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0084: Canceling symmetric key archival request by operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$valid_operator_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Cancel request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0085: Canceling symmetric key archival request by Normal user cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local key_size=128
        local usages=wrap
        local request_action=cancel
        local cert_used=$pki_user
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: symkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $TEMP_NSS_DB \
                 -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0086: Canceling symmetric key archival request by Normal user should fail"
	local request_action=cancel
        rlLog "Reject Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $pki_user should fail"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0087: Canceling symmetric key archival request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
	local request_action=cancel
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $invalid_pki_user"
	rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0088: Canceling asymmetric key archival request by admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local key_size=512
        local usages=wrap
        local request_action=cancel
        local cert_used=$valid_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Canceling key request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD -h $tmp_kra_host -p $target_unsecure_port \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0089: Canceling asymmetric key archival request by Revoked agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$revoked_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Canceling key request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                 -h $tmp_kra_host \
                 -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0090: Canceling asymmetric key archival request by Revoked admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$revoked_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate asymmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	rlLog "Canceling key request $key_request_id"
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0091: Canceling asymmetric key archival request by Expired agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$expired_agent_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0092: Canceling asymmetric key archival request by Expired admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$expired_admin_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request as $cert_used"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0093: Canceling asymmetric key archival request by audit cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$valid_audit_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0094: Canceling asymmetric key archival request by operator cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$valid_operator_cert
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                 -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0095: Canceling asymmetric key archival request by Normal User cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local key_size=2048
        local usages=wrap
        local request_action=cancel
        local cert_used=$pki_user
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-generate $client_id \
                --key-algorithm $algo \
                --key-size $key_size \
                --usages $usages > $key_generate_output" 0 "Generate symmetric key of size $key_size using Algorithm $algo"
        rlAssertGrep "Key generation request info" "$key_generate_output"
        rlAssertGrep "Type: asymkeyGenRequest" "$key_generate_output"
        rlAssertGrep "Status: complete" "$key_generate_output"
        rlLog "Verify by Canceling the request"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
        rlRun "pki -d $TEMP_NSS_DB \
                 -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                 -n \"$cert_used\" \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0096: Canceling asymmetric key archival request by Normal user cert should fail"
	local request_action=cancel
        rlLog "Reject Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Reject $key_request_id as $pki_user should fail"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0097: Canceling asymmetric key archival request by Normal user should fail"
	local request_action=cancel
        rlLog "Canceling Archival request as $pki_user"
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $pki_user should fail"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0098: Canceling asymmetric key archival request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
	local request_action=cancel
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                 key-request-review $key_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling $key_request_id as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0099: Canceling passphrase archival request admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=cancel
        local cert_used=$valid_admin_cert
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
        rlLog "Verify by Canceling the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0101: Canceling passphrase archival request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=cancel
        local cert_used=$revoked_agent_cert
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
        rlLog "Verify by Canceling the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0102: Canceling passphrase archival request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=$tmp_passphrase
        local request_action=cancel
        local cert_used=$revoked_admin_cert
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
        rlLog "Verify by Canceling the request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0103: Canceling passphrase archival request by Expired Admin cert should fail"
        local cert_used=$expired_admin_cert
	local request_action=cancel
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0104: Canceling passphrase archival request by Expired Admin cert should fail"
        local cert_used=$expired_agent_cert
	local request_action=cancel
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0105: Canceling passphrase archival request by Audit cert should fail"
	local request_action=cancel
        local cert_used=$valid_audit_cert
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0106: Canceling passphrase archival request by Audit cert should fail"
        local cert_used=$valid_audit_cert
	local request_action=cancel
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0107: Canceling passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
	local request_action=cancel
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0108: Canceling passphrase archival request by Normal User cert should fail"
        local cert_used=$pki_user
	local request_action=cancel
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0109: Canceling passphrase archival request by Normal User should fail"
	local request_action=cancel
	rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $pki_user should fail"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
        rlPhaseEnd


        rlPhaseStartTest "pki_request_review-0110: Canceling passphrase archival request by Invalid User should fail"
        local invalid_pki_user=test1
	local invalid_pki_user_pwd=Secret123
	local request_action=cancel
        local invalid_pki_user_pwd=Secret123
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Canceling request $request_id by $invalid_pki_user should fail"
        rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd


        rlPhaseStartSetup "Generate Approved Symmetric key"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	rlLog "Create Recovery reqeuest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-recover --keyID $key_id > $key_recover_output" 0 "Recover key $key_id as $valid_agent_cert"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
	rlPhaseEnd


        rlPhaseStartTest "pki_request_review-0111: Approving Recovery requests by Agent cert should succeed"
        local cert_used=$valid_agent_cert
        local request_action=approve
        rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output" 0 "Approving Recover request $request_id by $cert_used should fail"
	rlAssertGrep "Request ID: $recover_request_id" "$key_request_review_output"
	rlAssertGrep "Key ID: $key_id" "$key_request_review_output"
	rlAssertGrep "Type: securityDataRecovery" "$key_request_review_output"
	rlAssertGrep "Status: approved" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartSetup "Generate Approved Asymmetric key"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local action=approve
        local key_size=2048
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlLog "Create Recovery reqeuest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-recover --keyID $key_id > $key_recover_output" 0 "Recover key $key_id as $valid_agent_cert"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0112: Approving Recovery requests by Admin cert should fail"
        local cert_used=$valid_admin_Cert
        local request_action=approve
        rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0113: Approving Recovery request by Revoked Agent cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=DSA
        local action=approve
        local key_size=512
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlLog "Create Recovery reqeuest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-recover --keyID $key_id > $key_recover_output" 0 "Recover key $key_id as $valid_agent_cert"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
        local cert_used=$revoked_agent_Cert
        local request_action=approve
        rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0114: Approving Recovery request by Revoked Admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlLog "Create Recovery reqeuest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-recover --keyID $key_id > $key_recover_output" 0 "Recover key $key_id as $valid_agent_cert"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
        local cert_used=$revoked_admin_Cert
        local request_action=approve
        rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartSetup "Generate Approved Symmetric key"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlLog "Create Recovery reqeuest"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-recover --keyID $key_id > $key_recover_output" 0 "Request recover request as $valid_agent_cert"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0115: Approving Recovery request by Expired Admin cert should fail"
        local request_action=approve
        local cert_used=$expired_admin_cert
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                 -n \"$cert_used\" \
                 key-request-review $recover_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recover request $recover_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd


        rlPhaseStartTest "pki_request_review-0116: Approving Recovery request by Expired Agent cert should fail"
        local request_action=approve
        local cert_used=$expired_agent_cert
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $cert_used | grep "Not After" | awk -F ": " '{print $2}')
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
                 -n \"$cert_used\" \
                 key-request-review $recover_request_id \
                 --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recover request $recover_request_id as $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0117: Approving Recovery request by Valid audit cert should fail"
        local cert_used=$valid_audit_Cert
        local request_action=approve
        rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $recover_request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0118: Approving Recovery request by Valid operator cert should fail"
        local cert_used=$valid_operator_Cert
        local request_action=approve
        rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $recover_request_id by $cert_used should fail"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0119: Approving Recovery request by Normal User cert should fail"
        local cert_used=$pki_user
        local request_action=approve
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$cert_used\" \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $recover_request_id by $cert_used should fail"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_request_review_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_request_review-0120: Approving Recovery request by Normal user authentication should fail"
        local cert_used=$pki_user
        local request_action=approve
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
		-w $pki_pwd \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
		-w $pki_pwd \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $recover_request_id by $cert_used should fail"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_request_review_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_request_review-0121: Approving Recovery request by Invalid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        local cert_used=$pki_user
        local request_action=approve
        rlLog "Executing pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                key-request-review $recover_request_id \
                --action $request_action > $key_request_review_output 2>&1" 255,1 "Approving Recovery request $recover_request_id by $cert_used should fail"
        rlAssertGrep "PKIException: Unauthorized" "$key_request_review_output"
        rlPhaseEnd

        rlPhaseStartCleanup "pki key-request-review cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
