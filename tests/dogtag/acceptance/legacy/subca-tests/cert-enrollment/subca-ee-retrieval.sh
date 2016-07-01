#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca-tests/cert-enrollment/cert-ee-retrieval
#   Description: Legacy cert retrieval tests
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

run_ee-subca-retrieval_tests()
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
        disable_ca_nonce $tomcat_name
        rlPhaseEnd

        # Local Variables
        local target_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local tmp_ca_agent=$SUBCA_INST\_agentV
        local tmp_ca_admin=$SUBCA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$SUBCA_INST\_agentV
        local valid_audit_cert=$SUBCA_INST\_auditV
        local valid_operator_cert=$SUBCA_INST\_operatorV
        local valid_admin_cert=$SUBCA_INST\_adminV
	local cert_find_info="$TmpDir/cert_find_info"
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

	rlPhaseStartTest "pki_subca_ee-retrieval-001: CA Cert Retrieval -  Check Request Status servlet(pending request)"
	rlLog "Create a pkcs10 cert request"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="foo1"
        local usercn="foo1"
        local phone="1234"
        local usermail="foo1@example.org"
        local test_out=ca-$profile-test1.txt
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
        rlLog "cert_requestdn=$cert_requestdn"
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
	rlLog "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\"" 
	rlRun "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\" >> $TmpDir/$test_out" 0 "Check certificate request status of $request_id"
	rlAssertGrep "header.status = \"pending\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-002: CA Cert Retrieval -  Check Request Status servlet(completed request)"
	local request_id="1"
	rlLog "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\""
	rlRun "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\" > $TmpDir/$test_out" 0 "Check certificate request status of $request_id"
	rlAssertGrep "header.status = \"complete\"" "$TmpDir/$test_out"
	rlPhaseEnd


        rlPhaseStartTest "pki_subca_ee-retrieval-003: CA Cert Retrieval -  Check Request Status servlet(Negative Value)"
        local request_id="-1"
        rlLog "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\""
        rlRun "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\" > $TmpDir/$test_out" 0 "Check certificate request status of $request_id"
        rlAssertGrep "Request ID -1 was not found in the request queue" "$TmpDir/$test_out"
        rlPhaseEnd	

        rlPhaseStartTest "pki_subca_ee-retrieval-004: CA Cert Retrieval -  Check Request Status servlet(Non numerical characters)"
        local request_id="abcd"
        rlLog "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\""
        rlRun "curl --basic --dump-header $admin_out -d \"format=id&requestId=$request_id&submit=Submit\" -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/checkRequest\" > $TmpDir/$test_out" 0 "Check certificate request status of $request_id"
        rlAssertGrep "Invalid number format: abcd" "$TmpDir/$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-005: CA Cert Retrieval -  List Certificates(Default values list first 20 records)"
	local op=listCerts
	local queryCertFilter="(|(certStatus=VALID)(certStatus=REVOKED))"
	local serialFrom=""
	local serialTo=""
	local skipNonValid="on"
	local querySentinelDown="0"
	local querySentinelUp=""
	local direction="begin"
	local maxCount="20"
	rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts" 
	rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts > $TmpDir/$test_out" 0 "List certificate with $queryCertFilter of maxCount $maxCount"
	local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
	rlAssertEquals "Verify No of records displayed is equal to $maxCount" $no_of_records $maxCount
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-006: CA Cert Retrieval - List Certificates from range 0x5 to 0x20"
        local op=listCerts
        local queryCertFilter="(|(certStatus=VALID)(certStatus=REVOKED))"
        local serialFrom="0x5"
        local serialTo="0x1c"
        local skipNonValid="on"
        local querySentinelDown="0x5"
        local querySentinelUp="0x5"
        local direction="down"
        local maxCount="20"
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts > $TmpDir/$test_out" 0 "List certificate with $queryCertFilter of maxCount $maxCount"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertEquals "Verify No of records displayed is equal to $maxCount" $no_of_records $maxCount
	rlAssertGrep "record.serialNumberDecimal=\"5\"" "$TmpDir/$test_out"
	rlAssertNotGrep "record.serialNumber=\"1d\"" "$TmpDir/$test_out"
	rlAssertNotGrep "record.serialNumber=\"4\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartSetup "Generate 10 Certs of which 5 will be revoked"
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
	local i=1
	local upperlimit=10
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
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid-$i\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid-$i\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	if [ $i -le 5 ]; then
		local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
		local serial=$STRIP_HEX
		local CONV_UPP_VAL=${STRIP_HEX^^}
		local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
		local Day=`date +'%d' -d now`
		local Month=`date +'%m' -d now`
		local revocationReason="0"
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
		rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
		rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
		rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	fi
	let i=$i+1
	done

	rlPhaseStartTest "pki_subca_ee-retrieval-007: CA Cert Retrieval - List only valid certificates"
        local op=listCerts
        local queryCertFilter="(certStatus=VALID)"
        local serialFrom="0"
        local serialTo="300"
        local skipNonValid="on"
        local querySentinelDown="0"
        local querySentinelUp="0"
        local direction="down"
        local maxCount="1000"
	local test_out="retrieval.txt"
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts > $TmpDir/$test_out" 0 "List certificate with $queryCertFilter of maxCount $maxCount"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
	rlLog "no_of_records=$no_of_records"
        rlAssertNotGrep "record.revokedBy=\"$valid_agent_cert\"" "$TmpDir/$test_out"
	rlPhaseEnd
        
	rlPhaseStartTest "pki_subca_ee-retrieval-008: CA Cert Retrieval - List certs with max count of 10"
        local op=listCerts
        local queryCertFilter="(certStatus=VALID)"
        local serialFrom="0"
        local serialTo="20"
        local skipNonValid="on"
        local querySentinelDown="0"
        local querySentinelUp="0"
        local direction="down"
        local maxCount="10"
        local test_out="retrieval.txt"
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialFrom=$serialFrom&serialTo=$serialTo&skipNonValid=$skipNonValid&querySentinelDown=$querySentinelDown&querySentinelUp=$querySentinelUp&direction=$direction&maxCount=$maxCount\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/listCerts > $TmpDir/$test_out" 0 "List certificate with $queryCertFilter of maxCount $maxCount"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlLog "no_of_records=$no_of_records"
	local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
	rlAssertEquals "Verify No of records displayed is equal to $maxCount" $no_of_records $maxCount
        rlPhaseEnd


	rlPhaseStartTest "pki_subca_ee-retrieval-009: CA Cert Retrieval - Search certs with max count of 10"
	local test_out=srcCerts.txt
	local op=srchCerts
	local serialNumberRangeInUse="on"
	local serialFrom=0
	local serialTo=300
	local queryCertFilter="(&(certRecordId>=$serialFrom)(certRecordId<=$serialTo))"
	local subjectInUse=''
	local eMail=''
	local commonName=''
	local userID=''
	local orgUnit=''
	local org=''
	local locality=''
	local state=''
	local country=''
	local match='partial'
	local revokedBy=''
	local revokedOnInUse=''
	local revokedOnFrom=''
	local revokedOnTo=''
	local revocationReasonInUse=''
	local revocationReason=''
	local issuedByInUse=''
	local issuedBy=''
	local issuedOnInUse=''
	local issuedOnFrom=''
	local issuedOnTo=''
	local validNotBeforeInUse=''
	local validNotBeforeFrom=''
	local validNotBeforeTo=''
	local validNotAfterInUse=''
	local validNotAfterFrom=''
	local validNotAfterTo=''
	local validityLengthInUse=''
	local validityOp=''
	local count=''
	local unit="2592000000"
	local certTypeInUse=''
	local SubordinateEmailCA=''
	local SubordinateSSLCA=''
	local SecureEmail=''
	local SSLClient=''
	local SSLServer=''
	local maxResults='10'
	local timeLimit='5'
	rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
	rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certs with serialNumber range starting from $serialFrom to $serialTo with maxCount of $maxResults"
	local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertEquals "Verify No of records displayed is equal to $maxCount" $no_of_records $maxResults
	rlPhaseEnd	

        rlPhaseStartSetup "Generate a user cert"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
        local phone="1234-$RANDOM"
        local usermail="$userid@example.org"
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
	local serial_number_without_hex=$(echo $serial_number | cut -dx -f2)
	local serial_number_without_hex_lower=${serial_number_without_hex,,}
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-retrieval-0010: CA Cert Retrieval - Search certs with subject Name matching Email Address(method=exact)"
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(&(|(x509Cert.subject=*E=$usermail,*)(x509Cert.subject=*E=$usermail))))"
        local subjectInUse='on'
        local eMail="$usermail"
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='exact'
        local revokedBy=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='10'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certificate with subject DN containing $usermail"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certificate with subject DN containing $usermail"
	rlAssertGrep "record.subject=\"$cert_requestdn\"" "$TmpDir/$test_out"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertEquals "Verify No of records displayed is equal to 1" $no_of_records 1
	rlAssertGrep "record.serialNumber=\"$serial_number_without_hex_lower\"" "$TmpDir/$test_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-retrieval-0011: CA Cert Retrieval - Search certs with subject Name matching userID(method=exact)"
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(&(|(x509Cert.subject=*UID=$userid,*)(x509Cert.subject=*UID=$userid))))"
        local subjectInUse='on'
        local eMail=''
        local commonName=''
        local userID="$userid"
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='exact'
        local revokedBy=''
        local revokedOnInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='10'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certificate with subject DN containing $usermail"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search Certificate with subject DN containing $userid"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
	rlAssertGrep "record.subject=\"$cert_requestdn\"" "$TmpDir/$test_out"
        rlAssertEquals "Verify No of records displayed is equal to 1" $no_of_records 1
	rlAssertGrep "record.serialNumber=\"$serial_number_without_hex_lower\"" "$TmpDir/$test_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_subca_ee-retrieval-0012: CA Cert Retrieval - Search revoked certs with revoked by valid agent"
        local test_out=srcCerts.txt
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certRevokedBy=$valid_agent_cert))"
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy="$valid_agent_cert"
        local revokedOnInUse=''
	local revokedByInUse='on'
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp=''
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='10'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=(&(certRevokedBy=ROOTCA_agentV))&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=(&(certRevokedBy=ROOTCA_agentV))&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
	rlAssertGrep "record.revokedBy=\"$valid_agent_cert\"" "$TmpDir/$test_out"
        rlAssertGreater "Verify No of records displayed is greater than 3" $no_of_records 3
        rlPhaseEnd

	
	rlPhaseStartTest "pki_subca_ee-retrieval-0013: CA Cert Retrieval - Search revoked certs with revoked by reason Unspecified"
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(x509cert.certRevoInfo=0))"
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedOnInUse=''
        local revokedByInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse='on'
        local revocationReason='0'
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp='<='
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='10'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlAssertGrep "record.revokedBy=\"$valid_agent_cert\"" "$TmpDir/$test_out"
        rlAssertGreater "Verify No of records displayed is greater than 3" $no_of_records 3
	rlPhaseEnd	


	
        rlPhaseStartSetup "Generate a user cert and revoke with reason Key compromised"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser$RANDOM"
        local usercn="fooUser$RANDOM"
        local phone="1234-$RANDOM"
        local usermail="$userid@example.org"
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
        local serial_number_without_hex=$(echo $serial_number | cut -dx -f2)
        local serial_number_without_hex_lower=${serial_number_without_hex,,}
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="1"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_subca_ee-retrieval-0014: CA Cert Retrieval - Search revoked certs with revoked by reason Unspecified & key compromise"
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(|(x509cert.certRevoInfo=0)(x509cert.certRevoInfo=1)))"
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedOnInUse=''
        local revokedByInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse='on'
        local revocationReason='0,1'
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp='<='
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
	rlAssertGrep "record.revocationReason=0" "$TmpDir/$test_out"
	rlAssertGrep "record.revocationReason=1" "$TmpDir/$test_out"
	rlAssertNotGrep "record.revocationReason=2" "$TmpDir/$test_out"
	rlAssertNotGrep "record.revocationReason=3" "$TmpDir/$test_out"
	rlAssertNotGrep "record.revocationReason=4" "$TmpDir/$test_out"
	rlAssertNotGrep "record.revocationReason=5" "$TmpDir/$test_out"
	rlAssertNotGrep "record.revocationReason=6" "$TmpDir/$test_out"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.subject=" | wc -l)
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-0015: CA Cert Retrieval - Search certs issued by Valid agent cert"
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(certIssuedBy=$valid_agent_cert))"
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedOnInUse=''
        local revokedByInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local issuedByInUse='on'
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse=''
        local validityOp='<='
        local count=''
        local unit="2592000000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.issuedBy=\"$valid_agent_cert\"" | wc -l)	
	rlAssertGrep "record.issuedBy=\"$valid_agent_cert\"" "$TmpDir/$test_out"
	rlAssertGreater "Verify No of records displayed is greater than 10" $no_of_records 10
	rlPhaseEnd

	rlPhaseStartSetup "Create custom user profile which is valid for 15 days"
        local profile="caUserCert$RANDOM"
        local pki_user="pki_foo_bar2"
        local pki_user_fullName="pki1 Foo Bar2"
        local profilename="$profile Enrollment Profile"
        rlRun "python -m PkiLib.pkiprofilecli \
            --new user --profileId "$profile" \
            --profilename=\"$profilename\" \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile\.xml"
        rlLog "Add $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-add $TmpDir/$profile\.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlLog "Verify by creating a user cert using the profile"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
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
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
	local NotAfterDate=$(date +"%A, %B %d, %Y" --date "15 days")
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Not  After: $NotAfterDate" "$cert_out"

	rlPhaseStartTest "pki_subca_ee-retrieval-0016: CA Cert Retrieval - Search certs with a validity period of 15 days"
        local op=srchCerts
        local serialNumberRangeInUse=''
        local serialFrom=''
        local serialTo=''
        local queryCertFilter="(&(x509cert.duration<=1296000000))"
        local subjectInUse=''
        local eMail=''
        local commonName=''
        local userID=''
        local orgUnit=''
        local org=''
        local locality=''
        local state=''
        local country=''
        local match='partial'
        local revokedBy=""
        local revokedOnInUse=''
        local revokedByInUse=''
        local revokedOnFrom=''
        local revokedOnTo=''
        local revocationReasonInUse=''
        local revocationReason=''
        local issuedByInUse=''
        local issuedBy=''
        local issuedOnInUse=''
        local issuedOnFrom=''
        local issuedOnTo=''
        local validNotBeforeInUse=''
        local validNotBeforeFrom=''
        local validNotBeforeTo=''
        local validNotAfterInUse=''
        local validNotAfterFrom=''
        local validNotAfterTo=''
        local validityLengthInUse='on'
        local validityOp='<='
        local count='15'
        local unit="86400000"
        local certTypeInUse=''
        local SubordinateEmailCA=''
        local SubordinateSSLCA=''
        local SecureEmail=''
        local SSLClient=''
        local SSLServer=''
        local maxResults='1000'
        local timeLimit='5'
        rlLog "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert"
        rlRun "curl --basic --dump-header $admin_out -d \"op=$op&queryCertFilter=$queryCertFilter&serialNumberRangeInUse=$serialNumberRangeInUse&serialFrom=$serialFrom&serialTo=$serialTo&subjectInUse=$subjectInUse&eMail=$eMail&commonName=$commonName&userID=$userID&orgUnit=$orgUnit&org=$org&locality=$locality&state=$state&country=$country&match=$match&revokedBy=$revokedBy&revokedOnInUse=$revokedOnInUse&revokedByInUse=$revokedByInUse&revokedOnFrom=$revokedOnFrom&revokedOnTo=$revokedOnTo&revocationReasonInUse=$revocationReasonInUse&revocationReason=$revocationReason&issuedByInUse=$issuedByInUse&issuedBy=$issuedBy&issuedOnInUse=$issuedOnInUse&issuedOnFrom=$issuedOnFrom&issuedOnTo=$issuedOnTo&validNotBeforeInUse=$validNotBeforeInUse&validNotBeforeFrom=$validNotBeforeFrom&validNotBeforeTo=$validNotBeforeTo&validNotAfterInUse=$validNotAfterInUse&validNotAfterFrom=$validNotAfterFrom&validNotAfterTo=$validNotAfterTo&validityLengthInUse=$validityLengthInUse&validityOp=$validityOp&count=$count&unit=$unit&certTypeInUse=$certTypeInUse&SubordinateEmailCA=$SubordinateEmailCA&SubordinateSSLCA=$SubordinateSSLCA&SecureEmail=$SecureEmail&SSLClient=$SSLClient&SSLServer=$SSLServer&maxResults=$maxResults&timeLimit=$timeLimit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/srchCerts > $TmpDir/$test_out" 0 "Search certs revoked by $valid_agent_cert with a validity period of 15 days"
        local no_of_records=$(cat $TmpDir/$test_out | grep "record.issuedBy=\"$valid_agent_cert\"" | wc -l)
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "record.subject=\"$cert_subject\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-0017: CA Cert Retrieval - Import CA Certificate chain"
	local op='download'
	local mimetype='application/x-x509-ca-cert'
	local test_out=cacert.out
	rlLog "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
	rlRun "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-0018: CA Cert Retrieval - Download CA certificate in binary format"
	local op='downloadBin'
	local mimetype='application/x-x509-ca-cert'
	local test_out=cacert.out
	rlLog "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
	rlRun "curl --basic --dump-header $admin_out -d \"op=$op&mimeType=$mimetype&submit=Submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCAChain 1> $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-retrieval-0019: CA Cert Retrieval - Import latest CRL"
	local crlIssuingPoint='MasterCRL'
	local certSerialNumber=''
	local op='importCRL'
	local crlDisplayType='cachedCRL'
	local pageStart='1'
	local pageSize='50'
	local submit='Submit'
	local test_out='crl.out'
	rlLog "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=$submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/$test_out"
	rlRun "curl --basic --dump-header $admin_out -d \"crlIssuingPoint=$crlIssuingPoint&certSerialNumber=$certSerialNumber&op=$op&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize&submit=$submit\" -k https://$tmp_ca_host:$target_secure_port/ca/ee/ca/getCRL 1> $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlPhaseEnd

        rlPhaseStartCleanup "Delete Temporary Directory and enable nonce"
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
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Certificate,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}
