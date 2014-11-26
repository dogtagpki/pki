#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-cert-cli
#   Description: PKI CA CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-ca-cert-request-submit
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

run_pki-ca-cert-show-ca_tests()
{
	local cs_Type=$1
	local cs_Role=$2

	# Creating Temporary Directory for pki ca-cert-show
        rlPhaseStartSetup "pki ca-cert-show Temporary Directory"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local temp_out="$TmpDir/cert-show.out"
	local cert_info="$TmpDir/cert_info"
        rlPhaseEnd

	#local variables
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
        local invalid_serialNumber=$RANDOM
        local invalid_hex_serialNumber=0x$(echo "ibase=16;$invalid_serialNumber"|bc)
        local pkcs10_reqstatus
        local pkcs10_requestid
        local crmf_reqstatus
        local crmf_requestid
        local decimal_valid_serialNumber
        local i18n_ret_requestid
        local i18n_req_subject
        local 18n_ret_req_status
        local i18n_user1_fullname="Örjan Äke"
        local i18n_user1="Örjan_Äke"
        local i18n_user2_fullname="Éric Têko"
        local i18n_user2="Éric_Têko"
        local i18n_user3_fullname="éénentwintig dvidešimt"
        local i18n_user3="éénentwintig_dvidešimt"
        local i18n_user4_fullname="kakskümmend üks"
        local i18n_user4="kakskümmend_üks"
        local i18n_user5_fullname="двадцять один тридцять"
        local i18n_user5="двадцять_один_тридцять"
        local rand=$RANDOM
        local junk="axb124?$5@@_%^$#$@\!(_)043112321412321"
        local cert_req_info="$TmpDir/cert_req_info.out"
        local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$(eval echo \$${cs_Role})

	
	# Create a Temporary NSS DB Directory and generate Certificate

	rlPhaseStartSetup "Generating temporary Cert to be used pki ca-cert-show automation Tests"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD myreq_type:pkcs10 \
	algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: subject_ou: org: country: archive:false \
        req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
	certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info" 0 "Generate certificate based on pkcs10 request"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD myreq_type:crmf \
	algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: subject_ou: org: country: archive:false \
        req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
	certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info" 0 "Generate certificate based on crmf request"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
        STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
        CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlPhaseEnd

	# pki cert cli config test
	rlPhaseStartTest "pki_cert_cli-configtest: pki ca-cert-show --help configuration test"
	rlRun "pki -h $target_host -p $target_port ca-cert-show --help > $TmpDir/cert-show.out 2>&1" 0 "pki ca-cert-show --help"
	rlAssertGrep "usage:" "$TmpDir/cert-show.out"
    	rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/cert-show.out"
    	rlAssertGrep "--output <file>   Output file" "$TmpDir/cert-show.out"
    	rlAssertGrep "--pretty          Pretty print" "$TmpDir/cert-show.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/cert-show.out"
	rlLog "FAIL :: https://engineering.redhat.com/trac/pki-tests/ticket/490"
	rlPhaseEnd
	
	#Run pki ca-cert-show with valid serial number in HexaDecimal
	rlPhaseStartTest "pki_ca_cert_show-001: pki ca-cert-show < valid serialNumber(HexaDecimal) >  should show Certificate Details"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $valid_pkcs10_serialNumber > $temp_out" 0 "Executing pki ca-cert-show $valid_pkcs10_serialNumber"
	rlAssertGrep "Certificate \"$valid_pkcs10_serialNumber\"" "$temp_out"
	rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$temp_out"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"	
	rlAssertGrep "Subject: $pkcs10_requestdn" "$temp_out"
	rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd
	
	#Run pki ca-cert-show with No serial Number 
	rlPhaseStartTest "pki_ca_cert_show-002: pki ca-cert-show should show usage details when no serial Number is given"
	rlRun "pki -h $target_host -p $target_port ca-cert-show  > $temp_out" 1,255 "pki ca-cert-show without any serial number fails"
	rlAssertGrep "usage: cert-show" "$temp_out"
	rlPhaseEnd
	
	# Run pki ca-cert-show with Invalid Serial Number in decimal
	rlPhaseStartTest "pki_ca_cert_show-003: pki ca-cert-show < invalid serialNumber(Decimal) > should Fail"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $invalid_serialNumber 2> $temp_out" 1,255 "command pki ca-cert-show $invalid_serialNumber"
	rlAssertGrep "CertNotFoundException" "$temp_out"
	rlPhaseEnd

	# Run pki ca-cert-show with valid serial Number given in decimal 
	rlPhaseStartTest "pki_ca_cert_show-004: pki ca-cert-show < valid serialNumber(Decimal) > should show Certificate Details"
	rlLog "Decimal value : $decimal_valid_serialNumber_pkcs10"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $decimal_valid_serialNumber_pkcs10 > $temp_out" 0 "Executing pki ca-cert-show $decimal_valid_serialNumber_pkcs10"
	rlAssertGrep "Certificate \"$valid_pkcs10_serialNumber\"" "$temp_out"
	rlAssertGrep "Serial Number: $valid_pkcs10_serialNumber" "$temp_out"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"
	rlAssertGrep "Subject: $pkcs10_requestdn" "$temp_out"
	rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd

	#Run pki ca-cert-show with invalid serialNumber given in Hexadecimal
	rlPhaseStartTest "pki_ca_cert_show-005: pki ca-cert-show < invalid serialNumber(hexadecimal) > should fail"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $invalid_hex_serialNumber 2> $temp_out" 1,255 "Executing pki ca-ca-cert-show $invalid_hex_serialNumber"
	rlAssertGrep "CertNotFoundException" "$temp_out"
	rlPhaseEnd

	# Run pki ca-cert-show with Junk Characters
	rlPhaseStartTest "pki_ca_cert_show-006: pki ca-cert-show < junk characters > should fail to show any certificate Details"
	rlRun "pki -h $target_host -p $target_port ca-cert-show \"$junk\" 2> $temp_out" 1,255 "Executing pki ca-cert-show $junk"
	rlAssertGrep "NumberFormatException: For input string" "$temp_out"
	rlPhaseEnd	
	
	# Run pki ca-cert-show <valid serialNumber> --encoded to produce a valid pem output
	rlPhaseStartTest "pki_ca_cert_show-007: pki ca-cert-show <valid SerialNumber>  --encoded should produce a valid pem output"
	rlLog "Running pki ca-cert-show $valid_pkcs10_serialNumber"
        rlRun "pki -h $target_host -p $target_port ca-cert-show $valid_pkcs10_serialNumber --encoded > $temp_out" 0 "command pki ca-cert-show $valid_pkcs10_serialNumber --encoded"
        rlLog "Get the Subject Name of the Certificate with $valid_pkcs10_serialNumber"
        rlLog "$(cat $temp_out | grep Subject | awk -F":" '{print $2}')"
	rlRun "openssl x509 -in $temp_out -noout -serial 1> $temp_out-openssl" 0 "Run openssl to verify PEM output"
	rlAssertGrep "serial=$CONV_UPP_VAL_PKCS10" "$temp_out-openssl"
	rlPhaseEnd
		
	#Run pki ca-cert-show --encoded with No serial Number
	rlPhaseStartTest "pki_ca_cert_show-008: pki ca-cert-show <No SerialNumber> --encoded should fail"
	rlRun "pki -h $target_host -p $target_port ca-cert-show --encoded 1> $temp_out" 1,255 "Running pki ca-cert-show <No-serial-Number> --encoded"
	rlAssertGrep "usage: cert-show" "$temp_out"
	rlPhaseEnd
	
	# Run pki ca-cert-show --encoded with Invalid Serial Number
	rlPhaseStartTest "pki_ca_cert_show-009: pki ca-cert-show <In-Valid SerialNumber> --encoded should fail"
	rlLog "Running pki ca-cert-show <invalid-serial-Number> --encoded"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $invalid_serialNumber --encoded 2> $temp_out" 1,255 "pki ca-cert-show $serialNumber"
	local invalid_hex_sno=$(echo "obase=16;$invalid_serialNumber"|bc)
        local conv_lower_hex_invalidserialNum=${invalid_hex_sno,,}
	rlAssertGrep "CertNotFoundException: Certificate ID 0x$conv_lower_hex_invalidserialNum not found" "$temp_out"
	rlPhaseEnd
	
	# Run pki ca-cert-show <valid serialNumber> --output <filename>(pkcs10)
	rlPhaseStartTest "pki_ca_cert_show-0010: pki ca-cert-show <valid SerialNumber(Hexadecimal)> --output <filename> should save the Certificate in File"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $valid_pkcs10_serialNumber --output $temp_out" 0 "Executing pki ca-cert-show $valid_pkcs10_serialNumber --output <file-name>"
	rlAssertGrep "-----BEGIN CERTIFICATE-----" "$temp_out"
	rlAssertGrep "\-----END CERTIFICATE-----" "$temp_out"
	rlRun "openssl x509 -in $temp_out -noout -serial 1> $temp_out-openssl" 0 "Run openssl x509 on the output file"
	rlAssertGrep "serial=$CONV_UPP_VAL_PKCS10" "$temp_out-openssl"
	rlPhaseEnd

	#Run pki ca-cert-show <valid serialNumber> --output <filename> (crmf)
	rlPhaseStartTest "pki_ca_cert_show-0011: pki ca-cert-show <valid SerialNumber(Hexadecimal)> (crmf) --output <filename> should save the Certificate in File"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $valid_crmf_serialNumber --output $temp_out" 0 "Executing pki ca-cert-show $valid_crmf_serialNumber --output <file-name>"
	rlAssertGrep "-----BEGIN CERTIFICATE-----" "$temp_out"
	rlAssertGrep "\-----END CERTIFICATE-----" "$temp_out"
	rlRun "openssl x509 -in $temp_out -noout -serial 1> $temp_out-openssl" 0 "Run openssl x509 on the output file"
	rlAssertGrep "serial=$CONV_UPP_VAL_CRMF" "$temp_out-openssl"
	rlPhaseEnd
	
	# Run pki ca-cert-show <invalid-serial-number> --output 
	rlPhaseStartTest "pki_ca_cert_show-0012: pki ca-cert-show <invalid-serial-Number> --output <filename> should not create any file"
	rlLog "Running pki ca-cert-show <invalid-serialNumber> --output <filename>"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $invalid_serialNumber --output $temp_out" 1,255 "pki ca-cert-show <invalid-serial-number> --output <file>"
	rlAssertExists $temp_out
	rlPhaseEnd

	# Run pki ca-cert-show <No serial number> --output <filename>
	rlPhaseStartTest "pki_ca_cert_show-0013: pki ca-cert-show <No serialNumber> --output <filename> should fail"
	local temp_out13=$TmpDir/cert-show13.out
	local temp_out13_err=$TmpDir/cert-err13.out
	rlLog "Running pki ca-cert-show --output $temp_out13 0> $temp_out13_err" 
	rlRun "pki -h $target_host -p $target_port ca-cert-show --output $temp_out13 >> $temp_out13_err 2>&1" 1,255
	rlAssertGrep "Error: Missing Serial Number" "$temp_out13_err"
	rlAssertGrep "usage:" "$temp_out13_err"  	
	rlAssertGrep "--encoded         Base-64 encoded" "$temp_out13_err"
	rlAssertGrep "--output <file>   Output file" "$temp_out13_err"
	rlAssertGrep "--pretty          Pretty print" "$temp_out13_err"	
	rlPhaseEnd
		
	# Run pki ca-cert-show <valid-serial-number> --pretty 
        rlPhaseStartTest "pki_ca_cert_show-0014: pki ca-cert-show <valid SerialNumber(decimal)> --pretty <filename> should show PrettyPrint output of cert and save the the Cert in File."
        rlLog "Running pki ca-cert-show $valid_pkcs10_serialNumber --pretty"
        rlRun "pki -h $target_host -p $target_port ca-cert-show $valid_pkcs10_serialNumber --pretty > $temp_out" 0
        rlAssertGrep "Certificate:" "$temp_out"
        rlAssertGrep "Version:" "$temp_out"
	rlAssertGrep "Subject:" "$temp_out"
        rlPhaseEnd

	 # Run pki ca-cert-show <in-valid-serial-number> --pretty 
	rlPhaseStartTest "pki_ca_cert_show-0015: pki ca-cert-show < $invalid_serialNumber > --pretty <filename> should fail to produce any PrettyPrint output"
	local temp_out1="$TmpDir/cert-show1.out"
	rlRun "pki -h $target_host -p $target_port ca-cert-show $invalid_hex_serialNumber --pretty 2> $temp_out1" 1,255 "Executing pki ca-cert-show $invalid_hex_serialNumber --pretty"
	rlAssertGrep "CertNotFoundException: Certificate ID $invalid_hex_serialNumber not found" "$temp_out1"
	rlPhaseEnd

	# Run pki ca-cert-show <No serial Number> --pretty
	rlPhaseStartTest "pki_ca_cert_show-0016: pki ca-cert-show <No serialNumber> --pretty <filename> should fail to produce any PrettyPrint output"
	rlLog "Running pki ca-cert-show --pretty" 1
	rlRun "pki -h $target_host -p $target_port ca-cert-show --pretty 1> $temp_out" 1,255
	rlAssertGrep "usage:" "$temp_out"
	rlAssertGrep "--encoded         Base-64 encoded" "$temp_out"
	rlAssertGrep "--output <file>   Output file" "$temp_out"
	rlAssertGrep "--pretty          Pretty print" "$temp_out" 
	rlPhaseEnd

	# Run pki ca-cert-show with i18n characters 
	rlPhaseStartTest "pki_ca_cert_show-0017: Test-1 Verify pki ca-cert-show with i18n Characters"
	rlLog "Generate cert request for $i18n_user1_fullname"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:pkcs10 \
	algo:rsa key_size:2048 subject_cn:\"$i18n_user1_fullname\" subject_uid:$i18n_user1 subject_email:i18nuser@example.org \
	organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
	target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
	certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info" 
	local i18n_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local i18n_requestdn=$(cat $cert_info | grep Request_DN | cut -d- -f2)
	rlRun "pki -h $target_host -p $target_port ca-cert-show $i18n_serialNumber 1> $temp_out" 0 "Executing pki ca-ca-cert-show $i18n_serialNumber"
	rlAssertGrep "Certificate \"$i18n_serialNumber\"" "$temp_out"
        rlAssertGrep "Serial Number: $i18n_serialNumber" "$temp_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"
        rlAssertGrep "Subject: $i18n_requestdn" "$temp_out"
        rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert_show-0018: Test-2 Verify pki ca-cert-show with i18n Characters"
	rlLog "Generate cert request for $i18n_user2_fullname"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$i18n_user2_fullname\" subject_uid:$i18n_user2 subject_email:i18nuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local i18n_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local i18n_requestdn=$(cat $cert_info | grep Request_DN | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port ca-cert-show $i18n_serialNumber 1> $temp_out" 0 "Executing pki ca-ca-cert-show $i18n_serialNumber"
        rlAssertGrep "Certificate \"$i18n_serialNumber\"" "$temp_out"
        rlAssertGrep "Serial Number: $i18n_serialNumber" "$temp_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"
        rlAssertGrep "Subject: $i18n_requestdn" "$temp_out"
        rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd 

	rlPhaseStartTest "pki_ca_cert_show-0019: Test-3 Verify pki ca-cert-show with i18n Characters"
        rlLog "Generate cert request for $i18n_user3_fullname"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$i18n_user3_fullname\" subject_uid:$i18n_user3 subject_email:i18nuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local i18n_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local i18n_requestdn=$(cat $cert_info | grep Request_DN | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port ca-cert-show $i18n_serialNumber 1> $temp_out" 0 "Executing pki ca-ca-cert-show $i18n_serialNumber"
        rlAssertGrep "Certificate \"$i18n_serialNumber\"" "$temp_out"
        rlAssertGrep "Serial Number: $i18n_serialNumber" "$temp_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"
        rlAssertGrep "Subject: $i18n_requestdn" "$temp_out"
        rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd 


	rlPhaseStartTest "pki_ca_cert_show-0020: Test-4 Verify pki ca-cert-show with i18n Characters"
        rlLog "Generate cert request for $i18n_user4_fullname"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$i18n_user4_fullname\" subject_uid:$i18n_user4 subject_email:i18nuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local i18n_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local i18n_requestdn=$(cat $cert_info | grep Request_DN | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port ca-cert-show $i18n_serialNumber 1> $temp_out" 0 "Executing pki ca-ca-cert-show $i18n_serialNumber"
        rlAssertGrep "Certificate \"$i18n_serialNumber\"" "$temp_out"
        rlAssertGrep "Serial Number: $i18n_serialNumber" "$temp_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"
        rlAssertGrep "Subject: $i18n_requestdn" "$temp_out"
        rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd 
	
	rlPhaseStartTest "pki_ca_cert_show-0021: Test-5 Verify pki ca-cert-show with i18n Characters"
        rlLog "Generate cert request for $i18n_user5_fullname"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"$i18n_user5_fullname\" subject_uid:$i18n_user5 subject_email:i18nuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local i18n_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local i18n_requestdn=$(cat $cert_info | grep Request_DN | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port ca-cert-show $i18n_serialNumber 1> $temp_out" 0 "Executing pki ca-ca-cert-show $i18n_serialNumber"
        rlAssertGrep "Certificate \"$i18n_serialNumber\"" "$temp_out"
        rlAssertGrep "Serial Number: $i18n_serialNumber" "$temp_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$temp_out"
        rlAssertGrep "Subject: $i18n_requestdn" "$temp_out"
        rlAssertGrep "Status: VALID" "$temp_out"
	rlPhaseEnd 

	rlPhaseStartCleanup "pki ca-cert-show cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
