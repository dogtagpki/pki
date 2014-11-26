#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-cert-release-hold
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

run_pki-cert-release-hold-ca_tests()
{
	local cs_Type=$1
	local cs_Role=$2

        # Creating Temporary Directory for pki cert-show
        rlPhaseStartSetup "pki cert-release-hold Temporary Directory"
        rlRun "TmpDir=$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
	get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local CA_agentV_user=$CA_INST\_agentV
        local CA_auditV_user=$CA_INST\_auditV
        local CA_operatorV_user=$CA_INST\_operatorV
        local CA_adminV_user=$CA_INST\_adminV
        local CA_agentR_user=$CA_INST\_agentR
        local CA_adminR_user=$CA_INST\_adminR
        local CA_adminE_user=$CA_INST\_adminE
        local CA_agentE_user=$CA_INST\_agentE
 	local TEMP_NSS_DB="$TmpDir/nssdb"
	local TEMP_NSS_DB_PWD="redhat123"
	local exp="$TmpDir/expfile.out"
        local invalid_Number=$RANDOM
	local junk=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	local temp_cert_out="$TmpDir/cert-request.out"
        local temp_out="$TmpDir/cert-request-show.out"
	local expout="$TmpDir/exp_out"
	local certout="$TmpDir/cert_out"
	local cert_info="$TmpDir/cert_info"
	local target_host=$(eval echo \$${cs_Role})
	local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
	local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
	
	rlPhaseStartTest "pki_cert_release_hold-configtest: pki cert-release-hold --help configuration test"
	rlRun "pki cert-release-hold --help > $TmpDir/cert-release-hold.out 2>&1" 0 "pki cert-release-hold --help"
	rlAssertGrep "usage: cert-release-hold <Serial Number> \[OPTIONS...]" "$TmpDir/cert-release-hold.out"	
	rlAssertGrep "--force   Force" "$TmpDir/cert-release-hold.out"
	rlAssertGrep "--help    Show help options" "$TmpDir/cert-release-hold.out"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_release_hold_001: Release a valid cert on Hold using Agent Certificate"
	rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
	local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
	rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 
	rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: VALID" "$expout"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_release_hold_002: Release a Valid cert not on Hold using Agent Certificate"	
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
	rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "One or more certificates could not be unrevoked" "$expout"
	rlAssertGrep "Could not place certificate \"$cert_serialNumber\" off-hold" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_003: Release a invalid cert using Agent Certificate"
	invalid_cert_serialNumber=0x$invalid_Number
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-release-hold $invalid_cert_serialNumber 2> $certout" 1,255 "Release a invalid cert"
	rlAssertGrep "CertNotFoundException: Certificate ID $invalid_cert_serialNumber not found" "$certout"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_release_hold_004: Release a valid Cert on Hold (in decimalNumber) using Agent Certificate"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
	rlLog "Release valid certificate(serialNumber in decimals) using Agent cert"
	local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $decimal_cert_serialNumber"
        rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd	

	rlPhaseStartTest "pki_cert_release_hold_005: Test-1 Release a valid cert with subject name having i18n characters on Hold using Agent Certificate"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:\"Örjan Äke\" subject_uid:ÖrjanÄke \
                subject_email:test@example.org subject_ou:Engineering organization:Example.com \
		country:US archive:false profile:caUserCert target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
        rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_release_hold_006: Test-2 Release a valid cert with subject name having i18n characters on Hold using Agent Certificate"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:\"Éric Têko\" subject_uid:ÉricTêko \
                subject_email:test@example.org subject_ou: subject_o: subject_c: archive:false \
                profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
        rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_007: Test-3 Release a valid cert with subject name having i18n characters on Hold using Agent Certificate"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:\"éénentwintig dvidešimt.example.org\" \
		subject_uid: subject_email:test@example.org subject_ou: subject_o: subject_c: archive:false \
                profile:caServerCert target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
        rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_008: Test-4 Release a valid cert with subject name having i18n characters on Hold using Agent Certificate"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:\"двадцять один тридцять.example.org\" \
		subject_uid: subject_email:test@example.org subject_ou: subject_o: subject_c: archive:false \
                profile:caSignedLogCert target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
        rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_009: Test-5 Release a valid cert with subject name having i18n characters on Hold using Agent Certificate"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:\"kakskümmend üks.example.org\" \
		subject_uid: subject_email:test@example.org subject_ou: subject_o: subject_c: archive:false \
                profile:caServerCert target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-release-hold $cert_serialNumber"
        rlRun "cert-release-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_release_hold_0010: Release a Invalid certificate (in decimalNumber) using Agent Certificate"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-release-hold $invalid_Number \
		2> $certout" 1,255 "Release hold invalid certificate as agent cert"
	local invalid_hex_serialNumber=$(echo "obase=16;$invalid_Number"|bc)
        local conv_lower_hex_invalidserialNum=${invalid_hex_serialNumber,,}
	rlAssertGrep "CertNotFoundException: Certificate ID 0x$conv_lower_hex_invalidserialNum not found" "$certout"
	rlPhaseEnd	

	rlPhaseStartTest "pki_cert_release_hold_0011: Release a valid certificate(hexadecimal) on Hold using Agent Certificate (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-release-hold $cert_serialNumber \
		--force 1> $certout" 0  "Release valid certificate on hold"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$certout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$certout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$certout"
        rlAssertGrep "Status: VALID" "$certout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_0012: Release a valid certificate(Decimal) on Hold using Agent Certificate  (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-release-hold $decimal_cert_serialNumber \
		 --force 1> $certout" 0 "Release hold a cert with serialNumber given in decimals"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$certout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$certout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$certout"
        rlAssertGrep "Status: VALID" "$certout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_0013: Release a invalid certificate (Junk characters) using Agent Certificate"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" cert-release-hold \"$junk\" \
		2> $certout" 1,255 "cert-release-hold when junk characters given in input"
	rlAssertGrep "NumberFormatException: For input string:" "$certout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0014: Release a invalid certificate (Junk characters) using Agent Certificate(--force)"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-release-hold \"$junk\" \
		--force 2> $certout" 1,255 "Release hold a cert serial Number given as junk characters"
        rlAssertGrep "NumberFormatException: For input string:" "$certout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0015: Release a valid certificate(hexadecimal) on Hold using Admin Certificate (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put certificate on hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n $CA_adminV_user \
		-h $target_host \
		-p $target_port cert-release-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Release Hold using valid Admin cert"
	rlAssertGrep "Authorization Error" "$certout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0016: Release a valid certificate(hexadecimal) on Hold using Admin Cert(--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put certificate on hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n $CA_adminR_user \
		-h $target_host \
		-p $target_port cert-release-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Release hold using revoked admin cert"
        rlAssertGrep "PKIException: Unauthorized" "$certout"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_release_hold_0017: Release valid certificate(hexadecimal) on Hold using Revoked Agent cert (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put certificate on hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n $CA_agentR_user \
		-h $target_host \
		-p $target_port cert-release-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Release hold using revoked agent cert"
        rlAssertGrep "PKIException: Unauthorized" "$certout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0018: Release valid certificate(hexadecimal) on Hold using Audit cert (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n $CA_auditV_user \
		-h $target_host \
		-p $target_port cert-release-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Release hold using valid audit cert"
        rlAssertGrep "Authorization Error" "$certout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0019: Release valid certificate(hexadecimal) on Hold using CA Operator cert (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber \
		--force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n $CA_operatorV_user \
		-h $target_host \
		-p $target_port \
		cert-release-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Release hold using valid operator cert"
        rlAssertGrep "Authorization Error" "$certout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0020: Release a cert revoked with reason key compromise using Agent cert"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber \
		--force --reason Key_Compromise 1> $certout" 0 "Revoke cert with Key_Compromise"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-release-hold $cert_serialNumber \
		--force 1> $certout" 0 "Release hold using valid agent cert"
        rlAssertGrep "One or more certificates could not be unrevoked" "$certout"
        rlAssertGrep "Could not place certificate \"$cert_serialNumber\" off-hold" "$certout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_release_hold_0021: Hold and release a agent cert and verify released agent cert is usable"
	rlLog "Get the serial number of Agent Cert"
	local agent_cert_sno=$(certutil -L -d $CERTDB_DIR -n "CA_agentV" | grep "Serial Number:" | tr -d '()' | awk -F " " '{print $4}')
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"caadmincert\" \
		-h $target_host \
		-p $target_port \
		cert-hold \
		--force $agent_cert_sno 1> $TmpDir/cert-hold.out" 0 "Hold Agent cert"
	rlAssertGrep "Placed certificate \"$agent_cert_sno\" on-hold" "$TmpDir/cert-hold.out"
	rlAssertGrep "Serial Number: 0x10" "$TmpDir/cert-hold.out"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$TmpDir/cert-hold.out"
	rlAssertGrep "Status: REVOKED" "$TmpDir/cert-hold.out"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"caadmincert\" \
		-h $target_host \
		-p $target_port \
                cert-release-hold --force $agent_cert_sno 1> $TmpDir/cert-release-hold.out" 0 "Hold Agent cert"
	rlAssertGrep "Placed certificate \"$agent_cert_sno\" off-hold" "$TmpDir/cert-release-hold.out"
        rlAssertGrep "Serial Number: 0x10" "$TmpDir/cert-release-hold.out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$TmpDir/cert-release-hold.out"
        rlAssertGrep "Status: VALID" "$TmpDir/cert-release-hold.out"
	rlLog "With released Agent Cert hold a user cert"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
                cert-hold $cert_serialNumber \
                --force 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-release-hold $decimal_cert_serialNumber \
                 --force 1> $certout" 0 "Release hold a cert with serialNumber given in decimals"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$certout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$certout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$certout"
        rlAssertGrep "Status: VALID" "$certout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0022: Release valid certificate(hexadecimal) on Hold using Expired Admin Certificate (--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host \
		-p $target_port \
		cert-revoke $cert_serialNumber \
                --force --reason Certificate_Hold 1> $certout" 0 "Put certificate on hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n CA_adminE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Date & Time before Modifying system date: $cur_date"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $CA_adminE_user \
		-h $target_host \
		-p $target_port \
		cert-release-hold $cert_serialNumber \
                --force 2> $certout" 1,255 "Release hold using expired admin cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$certout"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_release_hold_0023: Release valid certificate(hexadecimal) on Hold using Expired Agent cert(--force)"
        rlLog "Generate Temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber \
                --force --reason Certificate_Hold 1> $certout" 0 "Put Certificate on Hold"
        rlAssertGrep "Status: REVOKED" "$certout"
        local cur_date=$(date) # Save current date
        local end_date=$(certutil -L -d $CERTDB_DIR -n CA_agentE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Date & Time before Modifying system date: $cur_date"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $CA_agentE_user \
		-h $target_host \
		-p $target_port \
		cert-release-hold $cert_serialNumber \
                --force 2> $certout" 1,255 "Release hold using Expired agent cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$certout"
        rlLog "Set the date back to original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date & Time after setting date back using chrony:$(date)"
        rlPhaseEnd

        rlPhaseStartCleanup "pki cert-release-hold cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
