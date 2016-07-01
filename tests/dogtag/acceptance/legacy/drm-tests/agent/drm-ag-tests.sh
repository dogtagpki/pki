#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/drm-tests/drm-ag-tests
#   Description: DRM Agent Tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following legacy test is being tested:
#  DRM Agent Tests
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

run_kra-ag_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)

        # Creating Temporary Directory for legacy test
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        disable_ca_nonce $tomcat_name
        rlPhaseEnd

        # Local Variables
	get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
	local tmp_kra_host=$(eval echo \$${cs_Role})
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_ca_agent_cert=$CA_INST\_agentV
	local valid_agent_cert=$KRA_INST\_agentV
	local valid_audit_cert=$KRA_INST\_auditV
	local valid_operator_cert=$KRA_INST\_operatorV
	local valid_admin_cert=$KRA_INST\_adminV
	local revoked_agent_cert=$KRA_INST\_agentR
	local revoked_admin_cert=$KRA_INST\_adminR
	local expired_admin_cert=$KRA_INST\_adminE
	local expired_agent_cert=$KRA_INST\_agentE	
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

        rlPhaseStartSetup "Generate  caDualCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caDualCert
        local userid="foo$RANDOM"
        local usercn="$userid user"
        local usermail="$userid@example.org"
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
                subject_archive:true \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&enckeyParam=$request_key_size&signKeyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&sn_uid=$userid&sn_e=$useremail&sn_cn=$usercn&sn_ou3=&sn_ou2=&sn_ou1=&sn_ou=IDM&sn_o=RedHat&sn_c=US&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&enckeyParam=$request_key_size&signKeyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&sn_uid=$userid&sn_e=$useremail&sn_cn=$usercn&sn_ou3=&sn_ou2=&sn_ou1=&sn_ou=IDM&sn_o=RedHat&sn_c=US&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_ca_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4&subjAltNameExtCritical=false&subjAltNames=null&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id1"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	local certificate_in_base64=$(cat -v $TmpDir/$test_out | grep 'outputList.outputVal' | awk -F 'outputList.outputVal=\"' '{print $2}'  | awk -F '-----BEGIN CERTIFICATE-----' '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/-----END CERTIFICATE-----\\n\";/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd	

	rlPhaseStartTest "pki_kra_ag-tests-001: DRM Agent: List requests"
	local reqType='enrollment'
	local reqState='reqState'
	local lastEntryOnPage=''
	local direction='first'
	local maxCount='1000'
	local minValue='1'
	local test_out=drm$reqState
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"reqType=$reqType&reqState=$reqState&lastEntryOnPage=$lastEntryOnPage&direction=$direction&maxCount=$maxCount\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/queryReq\" > $TmpDir/$test_out" 
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"reqType=$reqType&reqState=$reqState&lastEntryOnPage=$lastEntryOnPage&direction=$direction&maxCount=$maxCount\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/queryReq\" > $TmpDir/$test_out" 0 
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	local no_of_records=$(cat $TmpDir/$test_out |  grep record.subject= | wc -l)
	rlAssertGreaterOrEqual "Verify if the no_of_reocrds is 1 or more" $no_of_records $minValue
	rlAssertGrep "record.subject=\"$cert_requestdn\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ag-tests-002: DRM Agent: View Request details"
	local seqNum='1'
	local test_out=request.out
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"seqNum=$seqNum\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/processReq\"  > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"seqNum=$seqNum\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/processReq\"  > $TmpDir/$test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "header.keyAlgorithm = \"1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"	
	rlAssertGrep "header.requestType = \"enrollment\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ag-tests-003: DRM Agent: Search Requests by owner"
	local op='srchKey'
	local maxResults='10'
	local maxCount='5'
	local queryFilter="(keyOwnerName=$cert_requestdn)"
	local test_out=$op\.out
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKey\" > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKey\"> $TmpDir/$test_out" 0 "Search Archival requests with queryfilter as $queryFilter"
	rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "record.state=\"VALID\"" "$TmpDir/$test_out"
	rlAssertGrep "record.ownerName=\"$cert_requestdn\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ag-tests-004:DRM Agent: Search request by key Identifiers"
        local op='srchKey'
        local maxResults='1000'
        local maxCount='5'
        local queryFilter="(keySerialNumber >= 1)"
        local test_out=$op\.out
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKey\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKey\"> $TmpDir/$test_out" 0 "Search Archival requests with queryfilter as $queryFilter"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "record.state=\"VALID\"" "$TmpDir/$test_out"
        rlAssertGrep "record.ownerName=\"$cert_requestdn\"" "$TmpDir/$test_out"
	local no_of_records=$(cat $TmpDir/$test_out |  grep record.ownerName= | wc -l)
	rlAssertGreaterOrEqual "Verify if the no_of_reocrds is 1 or more" $no_of_records $minValue
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_ag-tests-005:DRM Agent: Search request by Archiver"
        local op='srchKey'
        local maxResults='1000'
        local maxCount='5'
        local queryFilter="(keyArchivedBy = CA-$tmp_ca_host-$target_secure_port)"
        local test_out=$op\.out
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKey\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKey\"> $TmpDir/$test_out" 0 "Search Archival requests with queryfilter as $queryFilter"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "record.state=\"VALID\"" "$TmpDir/$test_out"
        rlAssertGrep "record.ownerName=\"$cert_requestdn\"" "$TmpDir/$test_out"
        local no_of_records=$(cat $TmpDir/$test_out |  grep record.ownerName= | wc -l)
        rlAssertGreaterOrEqual "Verify if the no_of_reocrds is 1 or more" $no_of_records $minValue
        rlPhaseEnd

	rlPhaseStartTest "pki_kra_ag-tests-006: DRM Agent: Recover Archived keys"
	local localAgents='yes'
	local test_out=search.out
	local op=srchKeyForRecovery
	local maxResults=10
	local maxCount=5
	local queryFilter="(keyOwnerName=$cert_requestdn)"
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "Cert Serial Number: $serial_number"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_ca_agent_cert -h $tmp_ca_host -p $tmp_ca_port cert-show $serial_number --encoded --output $TmpDir/$serial_number-cert.out" 0 "Store the $serial_number cert in a file"
	rlLog "Convert $TmpDir/$serial_number-cert.out to unix format"
	rlRun "dos2unix $TmpDir/$serial_number-cert.out"
	local CERT=$(cat $TmpDir/$serial_number-cert.out)
	# search and retrieve the key Identifier
	rlLog "curl --cacert $CERTDB_DIr/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKeyForRecovery\" > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIr/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=$op&maxResults=$maxResults&maxCount=$maxCount&queryFilter=$queryFilter\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/srchKeyForRecovery\" > $TmpDir/$test_out"
	local kraSerialNumber=$(cat $TmpDir/$test_out | grep record.serialNumber= |awk -F "\"" '{print $2}')
	# Display by serial for recovery
	local test_out=display.out
	rlLog "curl --cacert $CERTDB_DIr/ca_cert.pem \
		--dump-header  $admin_out \
		 -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=displayBySerialForRecovery&serialNumber=$kraSerialNumber\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/displayBySerialForRecovery\" > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIr/ca_cert.pem \
		--dump-header  $admin_out \
		 -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"op=displayBySerialForRecovery&serialNumber=$kraSerialNumber\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/displayBySerialForRecovery\" > $TmpDir/$test_out"
	rlAssertGrep "header.state = \"VALID\"" "$TmpDir/$test_out"
	local recoveryID=$(cat $TmpDir/$test_out | grep "header.recoveryID = " |awk -F "\"" '{print $2}')
	rlLog "recoveryID=$recoveryID"
	local test_out=recovery.out
	#Recover cert
	rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
		--dump-header  $admin_out \
		-E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
		-d \"initAsyncRecovery=ON&localAgents=$localAgents&recoveryID=$recoveryID&serialNumber=$kraSerialNumber\" --data-urlencode \"cert=$certificate_in_base64\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/recoverBySerial\" > $TmpDir/$test_out"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                -d \"initAsyncRecovery=ON&localAgents=$localAgents&recoveryID=$recoveryID&serialNumber=$kraSerialNumber\" --data-urlencode \"cert=$certificate_in_base64\" -k \"https://$tmp_kra_host:$target_secure_port/kra/agent/kra/recoverBySerial\" > $TmpDir/$test_out" 0 "Recover $serialNumber"
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

