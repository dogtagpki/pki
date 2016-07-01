#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ocsp-tests/ocsp-ag-tests
#   Description: OCSP Agent Tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following legacy test is being tested:
#   OCSP Agent Tests
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
. /opt/rhqa_pki/pki-auth-plugin-lib.sh
. /opt/rhqa_pki/env.sh

run_ocsp-ag_tests()
{


        # Creating Temporary Directory for legacy test
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        local cs_Type=$1
        local cs_Role=$2
	get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        disable_ca_nonce $tomcat_name
        rlPhaseEnd

        # Local Variables
	local OCSP_INST=$(cat $TmpDir/topo_file | grep MY_OCSP | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
	local tmp_ocsp_host=$(eval echo \$${cs_Role})
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_ca_agent_cert=$CA_INST\_agentV
	local valid_agent_cert=$OCSP_INST\_agentV
	local valid_audit_cert=$OCSP_INST\_auditV
	local valid_operator_cert=$OCSP_INST\_operatorV
	local valid_admin_cert=$OCSP_INST\_adminV
	local revoked_agent_cert=$OCSP_INST\_agentR
	local revoked_admin_cert=$OCSP_INST\_adminR
	local expired_admin_cert=$OCSP_INST\_adminE
	local expired_agent_cert=$OCSP_INST\_agentE	
        local admin_out="$TmpDir/admin_out"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local cert_show_out="$TmpDir/cert_show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
        local SSL_DIR=$CERTDB_DIR

	rlPhaseStartSetup "Remove existing CA cert"
	local caID="CN=PKI $CA_INST Signing Cert,O=redhat"
	local test_out=remove_ca.out
	rlLog "list existing CA's"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
	local caID=$(cat $TmpDir/list_ca.out | grep record.Id= | cut -d\" -f2)
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"caID=$caID\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/removeCA\" > $TmpDir/$test_out" 0 "Remove Existing CA"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"caID=$caID\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/removeCA\" > $TmpDir/$test_out" 0 "Remove Existing CA"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
	rlAssertNotGrep "record.Id" "$TmpDir/list_ca.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_ag-tests-001: OCSP Agent: Add CA Cert"
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "Get CA Cert"
	local op='displayIND'
        local mimetype='application/x-x509-ca-cert'
        local test_out=cacert.out
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	local certificate_in_base64=$(cat -v $TmpDir/$test_out | grep record.base64= | awk -F\" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"cert=$certificate_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCA\" > $TmpDir/addCA.out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlLog "list existing CA's"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "record.Id=\"CN=PKI $CA_INST Signing Cert,O=redhat\"" "$TmpDir/list_ca.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_ag-tests-002: OCSP Agent: List CAs"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "record.Id=\"CN=PKI $CA_INST Signing Cert,O=redhat\"" "$TmpDir/list_ca.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_ag-tests-003: OCSP Agent: Add CRL's"
	rlLog "Add CRL's"
        local crlIssuingPoint="MasterCRL"
        local certSerialNumber=''
        local op="displayCRL"
        local crlDisplayType="base64Encoded"
        local pageStart='1'
        local pageSize='50'
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/get_crls.out"
        rlRun "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/get_crls.out"
        local crl_in_base64=$(cat -v $TmpDir/get_crls.out | grep record.crlBase64Encoded= | awk -F\" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE REVOCATION LIST-----/' | sed 's/$/-----END CERTIFICATE REVOCATION LIST-----/' | sed 's/\\r\\n//g')
        rlAssertGret "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/get_crls.out"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"crl=$crl_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCRL\" > $TmpDir/add_crl.out" 0 "Add CRL to OCSP"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"crl=$crl_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCRL\" > $TmpDir/add_crl.out" 0 "Add CRL to OCSP"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "fixed.unexpectedError = \"CRL sent is older than the current CRL.\"" "$TmpDir/add_crl.out"
	rlPhaseEnd

	rlPhaseStartSetup "Generate 5 Certs of revoke all of them"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        local i=1
        local upperlimit=6
	local serial_number_array=()
	local request_dn_array=()
        while [ $i -ne $upperlimit ];do
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$usercn-$i\" \
                subject_uid:$userid-$i \
                subject_email:$usermail \
                subject_ou:IDM \
                subject_organization:RedHat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-$i-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-$i-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-$i-subject.out | grep Request_DN | cut -d ":" -f2)
	request_dn_array+=($cert_requestdn)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-$i-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-$i-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid-$i&sn_cn=$usercn-$i&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-$i-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid-$i&sn_cn=$usercn-$i&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-$i-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
        rlLog "Approve $request_id using $valid_agent_cert"
        local Second=`date +'%S' -d now`
        local Minute=`date +'%M' -d now`
        local Hour=`date +'%H' -d now`
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local Year=`date +'%Y' -d now`
        local start_year=$Year
        let end_year=$Year+1
        local end_day="1"
        local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
        local notAfter="$end_year-$Month-$end_day $Hour:$Minute:$Second"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid-$i\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid-$i\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
	local CONV_LOW_VAL=${STRIP_HEX,,}
	serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="0"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
        let i=$i+1
        done
	rlPhaseEnd


	rlPhaseStartSetup "Update CRL"
	local caID="CN=PKI $CA_INST Signing Cert,O=redhat"
        local test_out=remove_ca.out
        rlLog "list existing CA's"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
        local caID=$(cat $TmpDir/list_ca.out | grep record.Id= | cut -d\" -f2)
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"caID=$caID\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/removeCA\" > $TmpDir/$test_out" 0 "Remove Existing CA"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -d \"caID=$caID\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/removeCA\" > $TmpDir/$test_out" 0 "Remove Existing CA"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
        rlAssertNotGrep "record.Id" "$TmpDir/list_ca.out"
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Get CA Cert"
        local op='displayIND'
        local mimetype='application/x-x509-ca-cert'
        local test_out=cacert.out
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local certificate_in_base64=$(cat -v $TmpDir/$test_out | grep record.base64= | awk -F\" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"cert=$certificate_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCA\" > $TmpDir/addCA.out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlLog "list existing CA's"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "record.Id=\"CN=PKI $CA_INST Signing Cert,O=redhat\"" "$TmpDir/list_ca.out"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/listCAs\" > $TmpDir/list_ca.out" 0 "List existing CAs"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "record.Id=\"CN=PKI $CA_INST Signing Cert,O=redhat\"" "$TmpDir/list_ca.out"
	local crlIssuingPoint="MasterCRL"
	local signatureAlgorithm="SHA512withRSA"
	local test_out=updatecrl.out
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
	rlAssertGrep "header.crlUpdate = \"Scheduled\"" "$TmpDir/$test_out"
	rlLog "Add CRL's"
        local crlIssuingPoint="MasterCRL"
        local certSerialNumber=''
        local op="displayCRL"
        local crlDisplayType="base64Encoded"
        local pageStart='1'
        local pageSize='50'
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/get_crls.out"
        rlRun "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/get_crls.out"
        local crl_in_base64=$(cat -v $TmpDir/get_crls.out | grep record.crlBase64Encoded= | awk -F\" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE REVOCATION LIST-----/' | sed 's/$/-----END CERTIFICATE REVOCATION LIST-----/' | sed 's/\\r\\n//g')
        rlAssertGret "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/get_crls.out"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"crl=$crl_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCRL\" > $TmpDir/add_crl.out" 0 "Add CRL to OCSP"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"crl=$crl_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCRL\" > $TmpDir/add_crl.out" 0 "Add CRL to OCSP"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "fixed.unexpectedError = \"CRL sent is older than the current CRL.\"" "$TmpDir/add_crl.out"
	rlPhaseEnd
	

	rlPhaseStartSetup "Add the latest crl to OCSP"
	rlLog "Dump the crl to a file"
	local crlIssuingPoint="MasterCRL"
        local certSerialNumber=''
        local op="displayCRL"
        local crlDisplayType="base64Encoded"
        local pageStart='1'
        local pageSize='50'
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/get_crls.out"
        rlRun "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/get_crls.out"
	local crl_in_base64=$(cat -v $TmpDir/get_crls.out | grep record.crlBase64Encoded= | awk -F\" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE REVOCATION LIST-----/' | sed 's/$/-----END CERTIFICATE REVOCATION LIST-----/' | sed 's/\\r\\n//g')
	rlAssertGret "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/get_crls.out"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"crl=$crl_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCRL\" > $TmpDir/add_crl.out" 0 "Add CRL to OCSP"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"crl=$crl_in_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/addCRL\" > $TmpDir/add_crl.out" 0 "Add CRL to OCSP"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "fixed.unexpectedError = \"CRL sent is older than the current CRL.\"" "$TmpDir/add_crl.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_ag-tests-004: OCSP Agent: Verify the revoked cert status"
	for i in $(seq 0 $((${#serial_number_array[@]} - 1)))
	do
		
		rlLog "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=${serial_number_array[$i]}\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
		rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=${serial_number_array[$i]}\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
		local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
		rlLog "certificate_base64=$certificate_base64"
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"cert=$certificate_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/checkCert\" > $TmpDir/check_cert.out" 0 "Check certificate status"
	        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD --data-urlencode \"cert=$certificate_base64\" -k \"https://$tmp_ocsp_host:$target_secure_port/ocsp/agent/ocsp/checkCert\" > $TmpDir/check_cert.out" 0 "Check certificate status"	
		rlAssertGrep "header.status = \"revoked\"" "$TmpDir/check_cert.out"
		rlAssertGrep "header.serialno = \"${serial_number_array[$i]}\"" "$TmpDir/check_cert.out"
		rlAssertGrep "header.subjectDN = \"${request_dn_array[$i]}\"" "$TmpDir/check_cert.out"
		rlAssertGrep "header.issuerDN = \"CN=PKI $CA_INST Signing Cert,O=redhat\""  "$TmpDir/check_cert.out"
	done
	rlPhaseEnd
	
	rlPhaseStartCleanup "Delete temporary dir and enable nonce"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        enable_ca_nonce $tomcat_name
        rlPhaseEnd
}
verify_cert()
{
        local serial_number=$1
        local request_dn=$2
        STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        CONV_LOW_VAL=${STRIP_HEX,,}
        rlRun "pki -h $tmp_ca_host -p $target_unsecure_port cert-show $serial_number > $cert_show_out" 0 "Executing pki cert-show $serial_number"
        rlAssertGrep "Serial Number: 0x$CONV_LOW_VAL" "$cert_show_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}

