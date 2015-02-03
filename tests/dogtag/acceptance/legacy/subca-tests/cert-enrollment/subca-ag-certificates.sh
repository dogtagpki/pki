#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca-tests/cert-enrollment/subca-ag-certificates
#   Description: Subordiate CA Agent Certificates
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following legacy tests is being tested:
#   subca-ag-certificates
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

run_subca-ag-certificates_tests()
{
	
	 # Creating Temporary Directory
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "export PYTHONPATH=$PYTHONPATH:/opt/rhqa_pki/"
        rlPhaseEnd

        # Disable Nonce
        rlPhaseStartSetup "Disable Nonce"
        local cs_Type=$1
        local cs_Role=$2
        get_topo_stack $cs_Role $TmpDir/topo_file
        if [ $cs_Role="MASTER" ]; then
                 SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
        local tomcat_name=$(eval echo \$${SUBCA_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "disable_ca_nonce $tomcat_name"
        rlPhaseEnd
	
        # Local Variables
        local target_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local tmp_ca_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$SUBCA_INST\_agentV
        local valid_audit_cert=$SUBCA_INST\_auditV
        local valid_operator_cert=$SUBCA_INST\_operatorV
        local valid_admin_cert=$SUBCA_INST\_adminV
        local cert_find_info="$TmpDir/cert_find_info"
        local revoked_agent_cert=$SUBCA_INST\_agentR
        local revoked_admin_cert=$SUBCA_INST\_adminR
        local expired_admin_cert=$SUBCA_INST\_adminE
        local expired_agent_cert=$SUBCA_INST\_agentE
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



	rlPhaseStartTest "pki_subca_ag-certificates-001: CA Agent Page: List Certificates"
	local op=listCerts
	local queryCertFilter='(|(certStatus=VALID)(certStatus=REVOKED))'
	local serialFrom=''
	local serialTo=''
	local skipNonValid=''
	local querySentinelDown='0'
	local querySentinelUp=''
	local direction=''
	local maxCount='10'
	local test_out=$op
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" \
		-k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/listCerts\" > $TmpDir/$test_out" 0 "List Certificates"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" \
		-k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/listCerts\" > $TmpDir/$test_out" 0 "List Certificates"
	local no_of_records=$(cat $TmpDir/$test_out | grep record.subject= | wc -l)
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertEquals "Verify number of records is $maxCount" $maxCount $no_of_records
	rlPhaseEnd	
	
        rlPhaseStartSetup "Generate Cert which will be revoked"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser"
        local usercn="fooUser"
        local phone="1234"
        local usermail="fooUser@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$usercn\" \
                subject_uid:$userid \
                subject_email:$usermail \
                subject_ou:IDM \
                subject_organization:RedHat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
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
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-certificates-002: CA Agent Page: Revoke Certificates"
        local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="0"
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "Revoked cert with serial Number: $serial_number"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
	rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-certificates-003: CA Agent Page: Display Revocation List(type: Entire CRL)"
	rlLog "Display Cached CRL"
	rlRun "export SSL_DIR=$CERTDB_DIR"
	local crlIssuingPoint='MasterCRL'
	local crlDisplayType='cachedCRL'
	local pageStart='1'
	local pageSize='50'
	local test_out=$crlDisplayType
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
	rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"	
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-certificates-004: CA Agent Page: Display Revocation List(type: Entire CRL)"
	rlLog "Display Entire CRL"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='entireCRL'
        local pageStart='1'
        local pageSize='50'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"	
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-certificates-005: CA Agent Page: Display Revocation List(type: CRLHeader)"
        rlLog "Display CRL Header"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='crlHeader'
        local pageStart='1'
        local pageSize='50'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-certificates-006: CA Agent Page: Display Revocation List(type: Base64 Encoded)"
        rlLog "Display Base64 Encoded CRL"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='base64Encoded'
        local pageStart='1'
        local pageSize='50'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_ag-certificates-007: CA Agent Page: Update Revocation List"
	rlLog "Update Revocation List"
	local crlIssuingPoint=MasterCRL
	local signatureAlgorithm='SHA512withRSA'
	local test_out=updateCRL
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update Revocation List"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
	rlAssertGrep "header.crlUpdate = \"Scheduled\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartCleanup "Delete temp dir and enable nonce"
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
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Cert,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}

