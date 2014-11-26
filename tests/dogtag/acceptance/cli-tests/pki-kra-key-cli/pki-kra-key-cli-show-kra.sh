#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki kra-key-show 
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

run_pki-kra-key-show-kra_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki kra-key-show
        rlPhaseStartSetup "pki kra-key-show Temporary Directory"
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
        local key_show_output=$TmpDir/kra-key-show.out
        local tmp_request_review_out=$TmpDir/key-request-review.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')

	# Config test of pki kra-key-show 
	rlPhaseStartTest "pki_kra_key_show_cli-configtest: pki kra-key-show --help configuration test"
	rlRun "pki kra-key-show --help > $key_show_output" 0 "pki kra-key-show --help"
	rlAssertGrep "usage: kra-key-show <Key ID> \[OPTIONS...\]" "$key_show_output"
	rlAssertGrep "    --help   Show help options" "$key_show_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_show-001: pki kra-key-show < valid Key ID(hexadecimal) > should show key details"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-show $tmp_key_id > $key_show_output" 0 "pki kra-key-show $tmp_key_id"
	rlAssertGrep "Key ID: $temp_key_id" "$key_show_output"
	rlAssertGrep "Status: active" "$key_show_output"
	rlAssertGrep "Algorithm: $algo" "$key_show_output"
	rlAssertGrep "Size: $key_size" "$key_show_output"
	rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-002: pki kra-key-show < valid Key ID(decimal) > should show key details"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
	STRIP_HEX_KEY_ID=$(echo $tmp_key_id | cut -dx -f2)
	CONV_UPP_VAL_KEY_ID=${STRIP_HEX_KEY_ID^^}
	decimal_valid_keyId=$(echo "ibase=16;$CONV_UPP_VAL_KEY_ID"|bc)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-show $decimal_valid_keyId > $key_show_output" 0 "pki kra-key-show $tmp_key_id"
        rlAssertGrep "Key ID: $temp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Algorithm: $algo" "$key_show_output"
        rlAssertGrep "Size: $key_size" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
        rlPhaseEnd	

	rlPhaseStartTest "pki_kra_key_show-003: pki kra-key-show < In-valid Key ID(hexadecimal) > should show key details"
	tmp_key_id=0xfffffff
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "pki kra-key-show $tmp_key_id"
	rlAssertGrep "KeyNotFoundException: Key ID $tmp_key_id not found" "$key_show_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-004: pki kra-key-show < In-valid Key ID(decimal) > should show key details"
        tmp_key_id=123456789
	local invalid_hex_sno=$(echo "obase=16;$tmp_key_id"|bc)
	local conv_lower_hex_invalidserialNum=${invalid_hex_sno,,}
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "pki kra-key-show $tmp_key_id"
        rlAssertGrep "KeyNotFoundException: Key ID 0x$conv_lower_hex_invalidserialNum not found" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-005: Archive a passphrase and issue pki kra-key-show against the Key ID to verify the output is correct"
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
        local tmp_request_id=$(cat $key_archive_output | grep "Request ID" | awk -F ": " '{print $2}')
	rlLog "Approve Key request id $tmp_request_id"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                key-request-review $tmp_request_id --action approve > $tmp_request_review_out" 
	local tmp_key_id=$(cat $tmp_request_review_out | grep "Key ID" | awk -F ": " '{print $2}')	
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_agent_cert\" \
                kra-key-show $tmp_key_id > $key_show_output" 0 "pki kra-key-show $tmp_key_id"
        rlAssertGrep "Key ID: $temp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Client Key ID: $client_id" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"	
        rlPhaseEnd
        rlPhaseStartTest "pki_kra_key_show-006: Executing pki kra-key-show <Key ID> using valid admin cert should fail"
        local rand=$RANDOM
        local client_id=temp$rand
        local algo=AES
        local action=approve
        local key_size=128
        local usages=wrap
        rlRun "generate_key $client_id $algo $key_size $usages $action $tmp_kra_host $target_unsecure_port $valid_agent_cert $key_generate_output" \
                0 "Generate Symmetric key with client $client_id, algo $algo, key_size $key_size, usages $usages"
        local tmp_key_id=$(cat $key_generate_output | grep "Key ID" | awk -F ": " '{print $2}')
        rlLog "Executing pki kra-key-show <Key ID> as $valid_admin_cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_admin_cert\" \
                kra-key-show $tmp_key_id  > $key_show_output 2>&1" 255,1 "Execute pki kra-key-show $tmp_key_ida as $valid_admin_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-007: Executing pki kra-key-show <Key ID> using revoked Agent cert should fail"
        rlLog "Executing pki kra-key-show as $revoked Agent Cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$revoked_agent_cert\" \
                kra-key-show $tmp_key_id  > $key_show_output 2>&1" 255,1 "Execute pki kra-key-show $tmp_key_id as $revoked_agent_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-008: Executing pki kra-key-show <key ID> using Expired admin(not a member of agents Group)cert should fail"
        rlLog "Executing pki kra-key-show $tmp_key_id as $expired_admin_cert"
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
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "Execute pki kra-key-show $tmp_key_id as $expired_admin_cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_show_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd


        rlPhaseStartTest "pki_kra_key_show-009: Executing pki kra-key-show <key ID> using Expired agent cert should fail"
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
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "Execute pki kra-key-show $tmp_key_id as $expired_agent_cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$key_show_output"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-0010: Executing pki kra-key-show <Key ID> using valid Audit cert should fail"
        rlLog "Executing pki kra-key-show $tmp_key_id as $valid_audit_cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_audit_cert\" \
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "Execute pki kra-key-show $tmp_key_id as $valid_audit_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-0011: Executing pki kra-key-show <Key ID> using valid Operator cert should fail"
        rlLog "Executing pki kra-key-show <Key ID> as $valid_operator_cert"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$valid_operator_cert\" \
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "Execute pki kra-key-show $tmp_key_id as $valid_operator_cert"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-0012: Executing pki kra-key-show <Key ID> using normal user cert(without any privileges) should fail"
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
        rlLog "Executing pki kra-key-show as $pki_user_fullName"
        rlRun "pki -d $TEMP_NSS_DB\
                -c $TEMP_NSS_DB_PWD \
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -n \"$pki_user\" \
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "Executing pki kra-key-show $tmp_key_id as $pki_user_fullName"
        rlAssertGrep "ForbiddenException: Authorization Error" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-0013: Executing pki kra-key-show using host URI parameter(https) should succeed"
        rlLog "Executing pki key-request-find using http host URI parameter(https)"
        rlLog "tmp_kra_host=$tmp_kra_host"
        rlLog "tmp_secure_port=$target_secure_port"
        rlRun "pki -d $CERTDB_DIR \
                -U https://$tmp_kra_host:$target_secure_port \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                kra-key-show $tmp_key_id  > $key_show_output" 0 "Executing pki kra-key-show as $valid_agent_cert"
        rlAssertGrep "Key ID: $temp_key_id" "$key_show_output"
        rlAssertGrep "Status: active" "$key_show_output"
        rlAssertGrep "Algorithm: $algo" "$key_show_output"
        rlAssertGrep "Size: $key_size" "$key_show_output"
        rlAssertGrep "Owner: $valid_agent_cert" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_show-0014: Executing pki kra-key-show <Key ID> using valid user(Not a member of any group) should fail"
        rlRun "pki -d $CERTDB_DIR\
                -h $tmp_kra_host \
                -p $target_unsecure_port \
                -u $pki_user \
                -w $pki_pwd \
                kra-key-show $tmp_key_id  > $key_show_output 2>&1" 255,1 "Executing pki kra-key-show $tmp_key_id as $pki_user_fullName"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$key_show_output"

        rlPhaseStartTest "pki_kra_key_show-0015: Executing pki kra-key-show <Key ID> as in-valid user should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki key-request-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -h $tmp_kra_host -p $target_unsecure_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd  \
                kra-key-show $tmp_key_id > $key_show_output 2>&1" 255,1 "Search key requests as $invalid_pki_user"
        rlAssertGrep "PKIException: Unauthorized" "$key_show_output"
        rlPhaseEnd

        rlPhaseStartCleanup "pki kra-key-show cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
