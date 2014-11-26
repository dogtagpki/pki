#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki kra-key-recover
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

run_pki-kra-key-recover-kra_tests()
{
        local cs_Id=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki kra-key-recover
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
        local rand=$RANDOM
	local tmp_passphrase=$(openssl rand -base64 10 |  perl -p -e 's/\n//')
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')

	# Config test of pki key-recover
	rlPhaseStartTest "pki_key_cli-configtest: pki key-recover --help configuration test"
        rlRun "pki kra-key-recover --help > $key_recover_output" 0 "pki key-recover --help"
	rlAssertGrep "usage: key-recover \[OPTIONS...\]" "$key_recover_output"
	rlAssertGrep "    --help                      Show help options" "$key_recover_output"
	rlAssertGrep "    --input <Input file path>   Location of the request file." "$key_recover_output"
	rlAssertGrep "    --keyID <Key Identifier>    Key Identifier for the secret to be" "$key_recover_output"
	rlAssertGrep "                                recovered" "$key_recover_output"
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
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_recover-001: Generating symmetric key recovery request using valid agent cert should succeed"
	rlLog "Executing pki -d -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
		kra-key-recover --keyID $key_id > $key_recover_output" 0 "Recover key $key_id as $valid_agent_cert"
	local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
	rlAssertGrep "Key ID: $key_id" "$key_recover_output"
	rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
	rlAssertGrep "Status: svc_pending" "$key_recover_output"
	rlPhaseEnd
	
	rlPhaseStartSetup "Generate Approve Asymmetric Keys"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=RSA
        local action=approve
        local key_size=2048
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Asymmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-002: Generating Asymmetric key recovery request using valid agent cert should succeed"
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output" 0 "Recover key $key_id as $valid_agent_user"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
        rlPhaseEnd

	rlPhaseStartSetup "Archive Passphrase in KRA"
        local rand=$RANDOM
        local client_id=temp$rand
        local passphrase=Secret123
        local action=approve
        local state_change=inactive
        rlRun "archive_passphrase $client_id $passphrase $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_archive_output" \
                0 "Archive $passphrase with client ID $client_id"
        local key_id=$(cat $key_archive_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $tmp_key_id" "$key_archive_output"
        rlAssertGrep "Status: complete" "$key_archive_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_recover-003: Issue a passphrase recovery request using valid agent cert should succeed"
	rlLog "Executing pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $key_id > $key_archive_output"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-show $key_id > $key_archive_output" 0 "pki key-show $tmp_key_id"
        rlAssertGrep "Key ID: $key_id" "$key_archive_output"
        rlAssertGrep "Status: active" "$key_archive_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_archive_output"
	rlLog "Create a recovery of key $key_id request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_recover-004: Verify when no keyID is passed key-recover fails with command help"
	local key_id=''
        rlLog "Create a recovery of key $key_id request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Recover key with No data passed to --keyID"
        rlAssertGrep "usage: key-recover \[OPTIONS...\]" "$key_recover_output"
        rlAssertGrep "    --help                      Show help options" "$key_recover_output"
        rlAssertGrep "    --input <Input file path>   Location of the request file." "$key_recover_output"
	rlAssertGrep "    --keyID <Key Identifier>    Key Identifier for the secret to be" "$key_recover_output"
        rlAssertGrep "                                recovered" "$key_recover_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-004: Verify when no keyID is passed key-recover fails"
	local invalid_key=1234545
        local key_id=$invalid_key
        rlLog "Create a recovery of key $key_id request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Recover key with No data passed to --keyID"
	rlAssertGrep "NotFoundException: Key ID 0x12d671 not found" "$key_recover_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_recover-005: Verify when junk data is passed to ID, key-recover fails"
        local key_id=$tmp_junk_data
        rlLog "Create a recovery of key $key_id request"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID \"$key_id\" > $key_recover_output 2>&1" 255,1 "Recover key with No data passed to --keyID"
        rlAssertGrep "NumberFormatException: For input string:" "$key_recover_output"	
	rlPhaseEnd


        rlPhaseStartSetup: "Generate symmetric key"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-006: Approving Recovery requests using Admin cert (not a member of agents group) should fail"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for  ID $key_id"
        rlAssertGrep "Authorization Error" "$key_recover_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-007: Approving recovery request using Revoked Agent cert should fail"
	rlLog "Executing pki -d <CERTDB_DIR> -c <CERTDB_PWD> -h $tmp_kra_host -c $target_unsecure_port -n $revoked_agent_cert kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for  ID $key_id"
        rlAssertGrep "Authorization Error" "$key_recover_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-008: Approving recovery requests using  Revoked Admin cert should fail"
	rlLog "Executing pki -d <CERTDB_DIR> -c <CERTDB_PWD> -h $tmp_kra_host -c $target_unsecure_port -n $revoked_admin_cert kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_admin_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for Key ID $key_id"
        rlAssertGrep "Authorization Error" "$key_recover_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-009: Approving recovery requests using Expired Admin cert should fail"
        rlLog "Executing pki key-recover as $expired_admin_cert"
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
	rlLog "Executing pki -d <CERTDB_DIR> -c <CERTDB_PWD> -h $tmp_kra_host -c $target_unsecure_port -n $expired_admin_cert kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$expired_admin_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for Key ID $key_id"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_recover_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-0010: Approving recovery requests using Expired Agent cert should fail"
        rlLog "Executing pki key-recover as $expired_agent_cert"
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
	rlLog "Executing pki -d <CERTDB_DIR> -c <CERTDB_PWD> -h $tmp_kra_host -c $target_unsecure_port -n $expired_agent_cert kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$expired_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for Key ID $key_id"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_recover_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-0011: Approving recovery requests using Audit cert should fail"
	rlLog "Executing pki -d <CERTDB_DIR> -c <CERTDB_PWD> -h $tmp_kra_host -c $target_unsecure_port -n $valid_audit_cert kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for Key ID $key_id"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_recover_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-0012: Approving recovery request using Operator cert should fail"
	rlLog "Executing pki -d <CERTDB_DIR> -c <CERTDB_PWD> -h $tmp_kra_host -c $target_unsecure_port -n $valid_operator_cert kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_operator_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Create Approve request for Key ID $key_id"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_recover_output"
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

	rlPhaseStartTest "pki_kra_key_recover-0013: Approving recovery requests using Normal user cert should fail" 
	rlLog "Executing pki -d $TEMP_NSS_DB -c $TEMP_NSS_DB_PWD -h $tmp_kra_host -c $target_unsecure_port -n $pki_user kra-key-recover --KeyID $Key_id"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$pki_user\" \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Issuing Symmetric key recovery request user $pki_user cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$key_recover_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-0014: Approving recovery request using valid agent cert over https URI should succed"
	rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -U https://$tmp_kra_host:$target_secure_port -n $valid_agent_cert kra-key-recover --keyID $key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -U https://$tmp_kra_host:$target_secure_port \
                -n \"$valid_agent_cert\" \
                kra-key-recover --keyID $key_id > $key_recover_output" 0 "Issue recover request for $key_id"
        local recover_request_id=$(cat $key_recover_output | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Key ID: $key_id" "$key_recover_output"
        rlAssertGrep "Type: securityDataRecovery" "$key_recover_output"
        rlAssertGrep "Status: svc_pending" "$key_recover_output"
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_recover-0015: Approving recovery requests using Normal user authentication should fail"
	rlLog "Executing pki -d $TEMP_NSS_DB -c $TEMP_NSS_DB_PWD -h $tmp_kra_host -c $target_unsecure_port -u $pki_user -w $pki_pwd kra-key-recover --KeyID $Key_id"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-u $pki_user \
		-w $pki_pwd \
		kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "Issue a key recovery request as $pki_user"
	rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_recover_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_recover-0015: Approving recovery requests using Invalid user authentication should fail"
	local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
	rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD \
		-h $tmp_kra_host \
		-p $target_unsecure_port \
		-u $invalid_pki_user \
		-w $invalid_pki_user_pwd \
		key-recover --KeyID $Key_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                kra-key-recover --keyID $key_id > $key_recover_output 2>&1" 255,1 "key recovery request as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$key_recover_output"
        rlPhaseEnd

        rlPhaseStartCleanup "pki key-recover cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd


}
