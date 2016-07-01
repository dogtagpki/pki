#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki cert-hold
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

run_pki-cert-hold-ca_tests()
{
	local cs_Type=$1
	local cs_Role=$2

        # Creating Temporary Directory for pki cert-show
        rlPhaseStartSetup "pki cert-hold Temporary Directory"
	rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
	get_topo_stack $cs_Role $TmpDir/topo_file
	local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
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
	local expout="$TmpDir/exp_out"
	local certout="$TmpDir/cert_out"
	local cert_info="$TmpDir/cert_info"
	local rand=$RANDOM
	local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
	local tmp_ca_host=$(eval echo \$${cs_Role})
	local target_host=$tmp_ca_host
	local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)

	# pki  cert-hold config test
	rlPhaseStartTest "pki_cert_hold-configtest: pki cert-release-hold --help configuration test"
	rlRun "pki -h $target_host -p $target_port cert-hold --help > $TmpDir/cert-hold.out 2>&1" 0 "pki cert-hold --help"
	rlAssertGrep "usage: cert-hold <Serial Number> \[OPTIONS...]" "$TmpDir/cert-hold.out"	
	rlAssertGrep "    --comments <comments>   Comments" "$TmpDir/cert-hold.out"
	rlAssertGrep "    --force                 Force" "$TmpDir/cert-hold.out"
	rlAssertGrep "    --help                  Show help options" "$TmpDir/cert-hold.out"
	rlPhaseEnd
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid-cert-sno>
        rlPhaseStartTest "pki_cert_hold_001: Hold valid cert using Agent Certificate"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
		subject_email: subject_ou: subject_o: subject_c: archive:false \
		req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info" 
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -h $target_host -p $target_port -n \"$CA_agentV_user\" cert-hold $cert_serialNumber"
	rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 
	rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid-cert-sno> --comments
	rlPhaseStartTest "pki_cert_hold_002: Hold valid cert using Agent Certificate and pass comments with --comments"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-hold $cert_serialNumber --comments \"Test Comment1\""
        rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <invalid serialnumber>
	rlPhaseStartTest "pki_cert_hold_003: Hold invalid cert(hexadecimal) using Agent cert"
	invalid_cert_serialNumber=0x$invalid_Number
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold $invalid_cert_serialNumber 2> $certout" 1,255
	rlAssertGrep "CertNotFoundException: Certificate ID $invalid_cert_serialNumber not found" "$certout"
	rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid-serialNumber-in decimal>
	rlPhaseStartTest "pki_cert_hold_004: Hold valid Cert(decimal) using Agent Cert"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:crmf algo:rsa key_size:1024 subject_cn: subject_uid: \
		subject_email: subject_ou: subject_o: subject_c: archive:false \
		req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info" 
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	rlLog "cert_info=$cert_info"
	rlLog "Hold valid certificate(serialNumber in decimals) using Agent cert"
	local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-hold $decimal_cert_serialNumber"
        rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd	
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <invalid-serialNumber in decimal>
	rlPhaseStartTest "pki_cert_hold_005: Hold invalid cert(decimalNumber) using Agent cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold $invalid_Number 2> $certout" 1,255 "hold invalid cert as agent cert"
	local invalid_hex_serialNumber=$(echo "obase=16;$invalid_Number"|bc)
        local conv_lower_hex_invalidserialNum=${invalid_hex_serialNumber,,}
	rlAssertGrep "CertNotFoundException: Certificate ID 0x$conv_lower_hex_invalidserialNum not found" "$certout"
	rlPhaseEnd	


	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid-serialNumber in hex> --force
	rlPhaseStartTest "pki_cert_hold_006: Hold valid cert(hexadecimal) using Agent cert(--force)"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:crmf algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_subject=$(cat $cert_info| grep cert_requestdn | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold $cert_serialNumber \
		--force 1> $certout" 0  "Hold a valid cert"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$certout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$certout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$certout"
	rlAssertGrep "Subject: $cert_subject" "$certout"
        rlAssertGrep "Status: REVOKED" "$certout"
	rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <serialNumber in decimal>  --force --comments
	rlPhaseStartTest "pki_cert_hold_007: Hold valid cert(decimal) using Agent cert(--force) and pass comments with --comments"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:crmf algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_subject=$(cat $cert_info| grep cert_requestdn | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold $decimal_cert_serialNumber \
		 --force --comments \"Test Comment1\" 1> $certout" 0 "hold a cert with serialNumber given in decimals"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$certout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$certout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$certout"
	rlAssertGrep "Subject: $cert_subject" "$certout"
        rlAssertGrep "Status: REVOKED" "$certout"
	rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid serialNumber>
	rlPhaseStartTest "pki_cert_hold_008: Test-1 Hold valid cert created using i18n characters"
	local profile=caUserSMIMEcapCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
              myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"ÖrjanÄke\" \
              subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
              archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "cert_info=$cert_info"
        rlLog "Hold valid certificate(serialNumber in decimals) using Agent cert"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-hold $decimal_cert_serialNumber"
        rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid serialNumber>
	rlPhaseStartTest "pki_cert_hold_009: Test-2 Hold valid cert created using i18n characters"
	local profile=caDualCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:crmf algo:rsa key_size:2048 subject_cn:\"Éric Têko\" subject_uid:FooBar \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:true req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "cert_info=$cert_info"
        rlLog "Hold valid certificate(serialNumber in decimals) using Agent cert"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-hold $decimal_cert_serialNumber"
        rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid serialNumber>
	rlPhaseStartTest "pki_cert_hold_0010: Test-3 Hold valid cert created using i18n characters"
        local profile=caTPSCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"éénentwintig dvidešimt.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "cert_info=$cert_info"
        rlLog "Hold valid certificate(serialNumber in decimals) using Agent cert"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-hold $decimal_cert_serialNumber"
        rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid serialNumber>
	rlPhaseStartTest "pki_cert_hold_0011: Test-4 Hold valid cert created using i18n characters"
        local profile=caSignedLogCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"двадцять один тридцять Signed Log Certificate\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local decimal_cert_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlLog "cert_info=$cert_info"
        rlLog "Hold valid certificate(serialNumber in decimals) using Agent cert"
        local cmd="pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-hold $decimal_cert_serialNumber"
        rlRun "cert-hold_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"	
	rlPhaseEnd
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <valid serialNumber> --force
	rlPhaseStartTest "pki_cert_hold_0012: Test-5 Hold valid cert created using i18n characters (use --force)"
        local profile=caServerCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"kakskümmend üks.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info| grep cert_requestdn | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold $cert_serialNumber \
                --force 1> $certout" 0  "Hold a valid cert"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$certout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$certout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$certout"
        rlAssertGrep "Subject: $cert_subject" "$certout"
        rlAssertGrep "Status: REVOKED" "$certout"
	rlPhaseEnd
	
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <SerialNumber in Junk Characters>
	rlPhaseStartTest "pki_cert_hold_0013: Hold in-valid cert(serialNumber in Junk characters) using Agent cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold \"$junk\" \
		2> $certout" 1,255 "hold a in-valid cert when serial number is given in junk characters"
	rlAssertGrep "NumberFormatException: For input string:" "$certout"
	rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent Certificate"> cert-hold <Serial Number Junk Characters> --force
        rlPhaseStartTest "pki_cert_hold_0014: Hold in-valid cert(serialNumber in Junk characters) using Agent cert(--force)"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port \
		cert-hold \"$junk\" --force 2> $certout" 1,255 "hold a in-valid cert when serial number is given in junk characters"
        rlAssertGrep "NumberFormatException: For input string:" "$certout"
	rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Admin Certificate"> cert-hold <valid-serialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0015: Hold valid cert(SerialNumber in hexadecimal)using Admin Certificate (--force)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:crmf algo:rsa key_size:1024 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n $CA_adminV_user cert-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Release Hold using valid Admin cert"
	rlAssertGrep "Authorization Error" "$certout"
        rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Revoked Admin Certificate"> cert-hold <valid-serialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0016: Hold valid cert(SerialNumber in hexadecimal) using Admin Cert(--force)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n $CA_adminR_user cert-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "hold cert using revoked admin cert"
        rlAssertGrep "PKIException: Unauthorized" "$certout"
        rlPhaseEnd

        #pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Revoked Agent Certificate"> cert-hold <valid-serialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0017: Hold valid cert(SerialNumber in hexadecimal) using Revoked Agent cert (--force)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n $CA_agentR_user cert-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Hold cert using revoked agent cert"
        rlAssertGrep "PKIException: Unauthorized" "$certout"
        rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Audit Certificate"> cert-hold <valid-serialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0018: Hold valid certificate on Hold using Audit cert (--force)"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n $CA_auditV_user cert-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "Hold cert using using audit cert"
        rlAssertGrep "Authorization Error" "$certout"
        rlPhaseEnd

        #pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Operator cert"> cert-hold <valid-serialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0019: Hold valid certificate on Hold using CA Operator cert (--force)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n $CA_operatorV_user \
		-h $target_host \
		-p $target_port \
		cert-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "hold valid cert using operator cert"
        rlAssertGrep "Authorization Error" "$certout"
        rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Agent cert"> cert-hold <Revoked_with_keycompromise_serialNumber>
        rlPhaseStartTest "pki_cert_hold_0020: Hold already Revoked cert revoked using Agent cert"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
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
		-p $target_port \
		cert-hold $cert_serialNumber \
		--force 2> $certout" 1,255 "hold a Revoked cert using agent cert"
	local certsno=$(echo $cert_serialNumber | awk -F "0x" '{print $2}')
        rlAssertGrep "BadRequestException: certificate #$certsno has already been revoked" "$certout"
        rlPhaseEnd
	
	# pki -d <TEMP_NSS_DB> -c <TEMP_NSS_DB_PWD> -n <"User Cert"> cert-hold <valid cert serialNumber>
	rlPhaseStartTest "pki_cert_hold_0021: Hold a cert using a normal user without any privileges"
        local profile=caUserCert
        local pki_user="pki_user_$rand"
        local pki_user_fullName="Pki User $rand"
        local pki_pwd="Secret123"
	rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
		ca-user-add $pki_user \
                --fullName \"$pki_user_fullName\" \
                --password $pki_pwd" 0 "Create $pki_user User"
	rlLog "Generate cert for user $pki_user"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"$pki_user_fullName\" subject_uid:$pki_user \
                subject_email:$pki_user@example.org subject_ou: subject_o: subject_c: archive:false \
                req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlLog "Get the $pki_user cert in a output file"
	rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
	rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
	rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
	rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
	rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
	rlRun "pki -d $TEMP_NSS_DB \
		-c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $target_port \
		-n "$pki_user" client-cert-import \
		--cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
	rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
	rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
	rlRun "pki -d $TEMP_NSS_DB \
		-c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $target_port \
		-n \"casigningcert\" client-cert-import \
		--ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out" 
	rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"
	rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-t ca user-cert-add $pki_user \
		--input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
	rlLog "Generate temporary cert to put on hold $pki_user"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
              myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
              subject_email: subject_ou: subject_o: subject_c: archive:false \
              req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local rev_cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d $TEMP_NSS_DB \
		-c $TEMP_NSS_DB_PWD \
		-n "$pki_user" \
		-h $target_host \
		-p $target_port \
		cert-hold $rev_cert_serialNumber --force 2> $certout" 1,255 "Hold a valid cert using user with no privileges"
	rlAssertGrep "Authorization Error" "$certout"
	rlPhaseEnd
	        
	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Expired Agent Certificate"> cert-hold <valid-serialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0022: Hold valid certificate(hexadecimal) on Hold using Expired Agent cert(--force)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_agentE_user | grep "Not After" | awk -F ": " '{print $2}')
	rlLog "Current Date/Time: before modifying using chrony $(date)"
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
		cert-hold $cert_serialNumber \
                --force 2> $certout" 1,255 "hold cert using Expired agent cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$certout"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

	#pki -d <CERTDB_DIR> -c <CERTDB_PASSWORD> -n <"Expired Admin Certificate"> cert-hold <valid-SerialNumber> --force
        rlPhaseStartTest "pki_cert_hold_0023: Hold valid cert(SerialNumber in hexadecimal)using Expired Admin Certificate (--force)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_adminE_user | grep "Not After" | awk -F ": " '{print $2}')
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
                -n $CA_adminE_user \
		-h $target_host \
		-p $target_port \
		 cert-hold $cert_serialNumber \
                --force 2> $certout" 1,255 "Hold valid cert using expired admin cert"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$certout"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)" 
        rlPhaseEnd

        rlPhaseStartCleanup "pki cert-hold cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
