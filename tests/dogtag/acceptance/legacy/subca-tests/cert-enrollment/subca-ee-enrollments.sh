#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca-tests/cert-enrollment/subca-ee-enrollments
#   Description:  Legacy cert end-entity enrollment tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following Legacy tests needs to be tested:
#   Subordiate CA End Entity Enrollment Tests
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

run_ee-subca-enrollment_tests()
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



        rlPhaseStartTest "pki_subca_ee-001: SUBCA Profile Enrollment - AgentFileSigning using CRMF Request of key size 4096"
        rlLog "Create a new certificate request of type"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local filename=SecureFile-$RANDOM
        local filelocation=$TmpDir/$filename
	local profile="caAgentFileSigning"
	local test_out=ca-$profile-1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Write some random text in $filename"
        rlRun "echo "Secret123" > $filelocation" 0 "Create a file with text Secret123"
        rlRun "chmod 777 $TmpDir" 0 "Set Directory permissions to 777"
        rlRun "chmod 777 $TmpDir/$filename" 0 "Set file permsions to 777"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$filename \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create CRMF request for file signing"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header $admin_out \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&file_signing_url=file://$filelocation&file_signing_text=&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
	local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
	rlAssertNotGrep "Request Rejected" "$TmpDir/$test_out"
	rlLog "BUGZILLA: https://bugzilla.redhat.com/show_bug.cgi?id=1175269"
        rlPhaseEnd


	rlPhaseStartTest "pki_subca_ee-002: SUBCA Profile Enrollment - AgentFileSigning using CRMF Request of key size 3072"
	rlLog "Create a new certificate request of type"
	local request_type=crmf
	local request_key_type=rsa
	local request_key_size=3072
	local filename=SecureFile-$RANDOM
	local filelocation=$TmpDir/$filename
        local profile="caAgentFileSigning"
        local test_out=ca-$profile-2.txt
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "Write some random text in $filename"
	rlRun "echo "Secret123" > $filelocation" 0 "Create a file with text Secret123"
	rlRun "chmod 777 $TmpDir" 0 "Set Directory permissions to 777"
	rlRun "chmod 777 $TmpDir/$filename" 0 "Set file permsions to 777"
	rlRun "create_new_cert_request \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_password:$TEMP_NSS_DB_PWD \
		request_type:$request_type \
		request_algo:$request_key_type \
		request_size:$request_key_size \
		subject_cn:$filename \
		subject_uid: \
		subject_email: \
		subject_ou:IDM \
		subject_organization:Redhat \
		subject_country:US \
		subject_archive:false \
		cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
		cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create CRMF request for file signing"
	rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header $admin_out \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&file_signing_url=file://$filelocation&file_signing_text=&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
	rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlLog "Serial Number: $serial_number"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        rlAssertNotGrep "Request Rejected" "$TmpDir/$test_out"
	rlLog "BUGZILLA: https://bugzilla.redhat.com/show_bug.cgi?id=1175269"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-003: SUBCA Profile Enrollment - AgentFileSigning using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local filename=SecureFile-$RANDOM
        local filelocation=$TmpDir/$filename
        local profile="caAgentFileSigning"
        local test_out=ca-$profile-3.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Write some random text in $filename"
        rlRun "echo "Secret123" > $filelocation" 0 "Create a file with text Secret123"
        rlRun "chmod 777 $TmpDir" 0 "Set Directory permissions to 777"
        rlRun "chmod 777 $TmpDir/$filename" 0 "Set file permsions to 777"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$filename \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create CRMF request for file signing"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		 --dump-header $admin_out \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&file_signing_url=file://$filelocation&file_signing_text=&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlLog "Serial Number=$serial_number"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        rlAssertNotGrep "Request Rejected" "$TmpDir/$test_out"
	rlLog "BUGZILLA: https://bugzilla.redhat.com/show_bug.cgi?id=1175269"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-004: SUBCA Profile Enrollment - AgentFileSigning using CRMF Request of key size 1024"
        rlLog "Create a new certificate request of type"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local filename=SecureFile-$RANDOM
        local filelocation=$TmpDir/$filename
        local profile="caAgentFileSigning"
        local test_out=ca-$profile-4.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Write some random text in $filename"
        rlRun "echo "Secret123" > $filelocation" 0 "Create a file with text Secret123"
        rlRun "chmod 777 $TmpDir" 0 "Set Directory permissions to 777"
        rlRun "chmod 777 $TmpDir/$filename" 0 "Set file permsions to 777"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$filename \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create CRMF request for file signing"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header $admin_out \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&file_signing_url=file://$filelocation&file_signing_text=&requestor_name=&requestor_email=&requestor_phone=&profileId=caAgentFileSigning&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlLog "Serial Number=$serial_number"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        rlAssertNotGrep "Request Rejected" "$TmpDir/$test_out"
	rlLog "BUGZILLA: https://bugzilla.redhat.com/show_bug.cgi?id=1175269"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-005: SUBCA Profile Enrollment - caSignedLogCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test1-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlAssertNotGrep "Request Rejected" "$TmpDir/$test_out"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-006: SUBCA Profile Enrollment - caSignedLogCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
	local profile=caSignedLogCert
	local subject="PKI-$RANDOM Audit Signing Certificate"
	local test_out=ca-$profile-test1-out.txt
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
	local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
	rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlLog "serial_number=$serial_number"
        rlAssertNotGrep "Request Rejected" "$TmpDir/$test_out"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-007: SUBCA Profile Enrollment - caSignedLogCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test2-out.txt
	rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
	rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        local Hour=`date +'%H' -d now`
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local Year=`date +'%Y' -d now`
        local start_year=$Year
        let end_year=$Year+1
        local end_day="1"
        local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
        local notAfter="$end_year-$Month-$end_day $Hour:$Minute:$Second"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_ee-008: SUBCA Profile Enrollment - caSignedLogCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test3-out.txt
	rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
	rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-009: SUBCA Profile Enrollment - caSignedLogCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test4-out.txt
	rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd 

        rlPhaseStartTest "pki_subca_ee-0010: SUBCA Profile Enrollment - caSignedLogCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test5-out.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd 

        rlPhaseStartTest "pki_subca_ee-0011: SUBCA Profile Enrollment - caSignedLogCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test6-out.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd 

        rlPhaseStartTest "pki_subca_ee-0012: SUBCA Profile Enrollment - caSignedLogCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caSignedLogCert
        local subject="PKI-$RANDOM Audit Signing Certificate"
        local test_out=ca-$profile-test6-out.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0013: SUBCA Profile Enrollment - caAgentServerCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0014: SUBCA Profile Enrollment - caAgentServerCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
		-E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
		-E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0015: SUBCA Profile Enrollment - caAgentServerCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd


        rlPhaseStartTest "pki_subca_ee-0016: SUBCA Profile Enrollment - caAgentServerCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0017: SUBCA Profile Enrollment - caAgentServerCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0018: SUBCA Profile Enrollment - caAgentServerCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0019: SUBCA Profile Enrollment - caAgentServerCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0020: SUBCA Profile Enrollment - caAgentServerCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caAgentServerCert
        local subject="Server-$RANDOM-1.example.com"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem  --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"

        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out  \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0021: SUBCA Profile Enrollment - caCACert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test1-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0022: SUBCA Profile Enrollment - caCACert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test1-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0023: SUBCA Profile Enrollment - caCACert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test2-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0024: SUBCA Profile Enrollment - caCACert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test3-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0025: SUBCA Profile Enrollment - caCACert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test4-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0026: SUBCA Profile Enrollment - caCACert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test4-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0027: SUBCA Profile Enrollment - caCACert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test5-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0028: SUBCA Profile Enrollment - caCACert using pkcs10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caCACert
        local subject="PKI-$RANDOM CA Signing Certificate"
        local test_out=ca-$profile-test6-out.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&bypassCAnotafter=false&basicConstraintsCritical=true&basicConstraintsIsCA=true&basicConstraintsPathLen=-1&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=true&keyUsageCrlSign=true&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd


	rlPhaseStartSetup "Enable UidPwdDirAuth Plugin"
	local LDAP_PORT=20389
	local INSTANCE_NAME=ldap-$RANDOM
	local LDAP_ROOTDN="cn=Directory Manager"
	local LDAP_ROOTDNPWD="Secret123"
	local LDAP_BASEDN="DC=example,DC=org"
	local count=100
	rlRun "rhcs_install_set_ldap_vars"
	rlRun "rhds_install $LDAP_PORT $INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0
        if [ $? != 0 ]; then
                rlFail "Unable to setup ldap instance"
                return 1
        fi
	rlRun "UidPwdDirAuth $cs_Role $SUBCA_INST subcaadmin Secret123 add $tmp_ca_host \"$LDAP_BASEDN\" $LDAP_PORT" 
	rlLog "Add 100 users to ou=People,$LDAP_BASEDN"
	rlRun "create_dir_user $LDAP_BASEDN 100 > $TmpDir/ldapusers.ldif"
	rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_ca_host -p $LDAP_PORT -f $TmpDir/ldapusers.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
	rlAssertGrep "adding new entry \"cn=idmusers,ou=Groups,$LDAP_BASEDN\"" "$TmpDir/ldapadd.out"
	rlPhaseEnd



        rlPhaseStartTest "pki_subca_ee-0029: SUBCA Profile Enrollment - caDirUserCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caDirUserCert
        local userid="idmuser1"
        local password="redhat"
        local test_out=ca-$profile-test1.txt
	local LDAP_BASEDN="DC=example,DC=org"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email: \
                subject_ou:People \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0030: SUBCA Profile Enrollment - caDirUserCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caDirUserCert
        local userid="idmuser1"
	local password="redhat"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
	rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
	local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0031: SUBCA Profile Enrollment - caDirUserCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caDirUserCert
        local userid="idmuser2"
        local password="redhat"
        local test_out=ca-$profile-test2.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0032: SUBCA Profile Enrollment - caDirUserCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caDirUserCert
        local userid="idmuser3"
        local password="redhat"
        local test_out=ca-$profile-test3.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0033: SUBCA Profile Enrollment - caDirUserCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caDirUserCert
        local userid="idmuser4"
        local password="redhat"
        local test_out=ca-$profile-test4.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_subca_ee-0034: SUBCA Profile Enrollment - caDirUserCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caDirUserCert
        local userid="idmuser5"
        local password="redhat"
        local test_out=ca-$profile-test5.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0035: SUBCA Profile Enrollment - caDirUserCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caDirUserCert
        local userid="idmuser5"
        local password="redhat"
        local test_out=ca-$profile-test6.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0036: SUBCA Profile Enrollment - caDirUserCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caDirUserCert
        local userid="idmuser6"
        local password="redhat"
        local test_out=ca-$profile-test7.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0037: SUBCA Profile Enrollment - caDirUserCert using pkcs10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caDirUserCert
        local userid="idmuser7"
        local password="redhat"
        local test_out=ca-$profile-test8.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        #local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
	local cert_requestdn="UID=$userid,OU=People,$LDAP_BASEDN"
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"
        rlRun "curl --basic --dump-header $admin_out  \
                -d \"uid=$userid&pwd=$password&cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&profileId=$profile&renewal=false&xmlOutput=false\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd


        rlPhaseStartTest "pki_subca_ee-0038: SUBCA Profile Enrollment - caOCSPCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0039: SUBCA Profile Enrollment - caOCSPCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test2.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0040: SUBCA Profile Enrollment - caOCSPCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test3.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0041: SUBCA Profile Enrollment - caOCSPCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test4.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0042: SUBCA Profile Enrollment - caOCSPCert using pkcs10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test5.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0043: SUBCA Profile Enrollment - caOCSPCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test6.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0044: SUBCA Profile Enrollment - caOCSPCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test7.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0045: SUBCA Profile Enrollment - caOCSPCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caOCSPCert
        local subject="PKI-$RANDOM OCSP Signing Certificate"
        local test_out=ca-$profile-test8.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.9&ocspNoCheckCritical=false&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0046: SUBCA Profile Enrollment - caOtherCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0047: SUBCA Profile Enrollment - caOtherCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test2.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0048: SUBCA Profile Enrollment - caOtherCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test3.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0049: SUBCA Profile Enrollment - caOtherCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test4.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0050: SUBCA Profile Enrollment - caOtherCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test5.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd


        rlPhaseStartTest "pki_subca_ee-0051: SUBCA Profile Enrollment - caOtherCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test6.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0052: SUBCA Profile Enrollment - caOtherCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test7.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0053: SUBCA Profile Enrollment - caOtherCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caOtherCert
        local subject="PKI-$RANDOM Certificate"
        local test_out=ca-$profile-test8.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2&signingAlg=SHA1withRSA&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0054: SUBCA Profile Enrollment - caTPSCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test1.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0055: SUBCA Profile Enrollment - caTPSCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test2.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0056: SUBCA Profile Enrollment - caTPSCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test3.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0057: SUBCA Profile Enrollment - caTPSCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test4.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0058: SUBCA Profile Enrollment - caTPSCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test5.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0059: SUBCA Profile Enrollment - caTPSCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test6.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0060: SUBCA Profile Enrollment - caTPSCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test7.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0061: SUBCA Profile Enrollment - caTPSCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caTPSCert
        local subject="PKI-$RANDOM TPS Signing Certificate"
        local test_out=ca-$profile-test8.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0062: SUBCA Profile Enrollment - caTransportCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caTransportCert 
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test1.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0063: SUBCA Profile Enrollment - caTransportCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test2.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0064: SUBCA Profile Enrollment - caTransportCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test3.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0065: SUBCA Profile Enrollment - caTransportCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test4.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0066: SUBCA Profile Enrollment - caTransportCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test5.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0067: SUBCA Profile Enrollment - caTransportCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test6.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0068: SUBCA Profile Enrollment - caTransportCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test7.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0069: SUBCA Profile Enrollment - caTransportCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caTransportCert
        local subject="PKI-$RANDOM Transport Certificate"
        local test_out=ca-$profile-test8.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd


        rlPhaseStartTest "pki_subca_ee-0070: SUBCA Profile Enrollment - caServerCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caServerCert
        local subject="PKI-$RANDOM-1.example.org"
        local test_out=ca-$profile-test1.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0071: SUBCA Profile Enrollment - caServerCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caServerCert
        local subject="PKI-$RANDOM-2.example.org"
        local test_out=ca-$profile-test2.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0072: SUBCA Profile Enrollment - caServerCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caServerCert
        local subject="PKI-$RANDOM-3.example.org"
        local test_out=ca-$profile-test3.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0073: SUBCA Profile Enrollment - caServerCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caServerCert
        local subject="PKI-$RANDOM-4.example.org"
        local test_out=ca-$profile-test4.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0074: SUBCA Profile Enrollment - caServerCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caServerCert
        local subject="PKI-$RANDOM-5.example.org"
        local test_out=ca-$profile-test5.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0075: SUBCA Profile Enrollment - caServerCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caServerCert
        local subject="PKI-$RANDOM-6.example.org"
        local test_out=ca-$profile-test6.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0076: SUBCA Profile Enrollment - caServerCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caServerCert
        local subject="PKI-$RANDOM-7.example.org"
        local test_out=ca-$profile-test7.txt
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0077: SUBCA Profile Enrollment - caServerCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caServerCert
        local subject="PKI-$RANDOM-8.example.org"
        local test_out=ca-$profile-test8.txt
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$subject\" \
                subject_uid: \
                subject_email: \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        rlLog "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        rlRun "curl --basic --dump-header $admin_out  \
                -d \"cert_request_type=$request_type&keyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                -k https://$tmp_ca_host:$target_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
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
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&signingAlg=SHA1withRSA&authInfoAccessCritical=false&authInfoAccessGeneralNames=&requestNotes=&op=approve&submit=submit\" \
                     -k \"https://$tmp_ca_host:$target_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Approve $request_id"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
        rlPhaseEnd

        rlPhaseStartTest "pki_subca_ee-0078: SUBCA Profile Enrollment - caUserCert using CRMF Request of key size 4096"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caUserCert
	local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser1"
        local usercn="fooUser1"
	local phone="1234"
        local usermail="fooUser1@example.org"
        local test_out=ca-$profile-test1.txt
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$usercn \
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
                    -k \"https://$tmp_ca_host:$target_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out"	0 "Submit Certificate request to $profile"
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

        rlPhaseStartTest "pki_subca_ee-0079: SUBCA Profile Enrollment - caUserCert using CRMF Request of key size 3072"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser2"
        local usercn="fooUser2"
        local phone="1234"
        local usermail="fooUser2@example.org"
        local test_out=ca-$profile-test2.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$usercn \
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

        rlPhaseStartTest "pki_subca_ee-0080: SUBCA Profile Enrollment - caUserCert using CRMF Request of key size 2048"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser3"
        local usercn="fooUser3"
        local phone="1234"
        local usermail="fooUser3@example.org"
        local test_out=ca-$profile-test3.txt
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

        rlPhaseStartTest "pki_subca_ee-0081: SUBCA Profile Enrollment - caUserCert using CRMF Request of key size 1024"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser4"
        local usercn="fooUser4"
        local phone="1234"
        local usermail="fooUser4@example.org"
        local test_out=ca-$profile-test4.txt
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

        rlPhaseStartTest "pki_subca_ee-0082: SUBCA Profile Enrollment - caUserCert using PKCS10 Request of key size 4096"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=4096
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser5"
        local usercn="fooUser5"
        local phone="1234"
        local usermail="fooUser5@example.org"
        local test_out=ca-$profile-test5.txt
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

        rlPhaseStartTest "pki_subca_ee-0083: SUBCA Profile Enrollment - caUserCert using PKCS10 Request of key size 3072"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=3072
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser6"
        local usercn="fooUser6"
        local phone="1234"
        local usermail="fooUser6@example.org"
        local test_out=ca-$profile-test6.txt
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

        rlPhaseStartTest "pki_subca_ee-0084: SUBCA Profile Enrollment - caUserCert using PKCS10 Request of key size 2048"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser7"
        local usercn="fooUser7"
        local phone="1234"
        local usermail="fooUser7@example.org"
        local test_out=ca-$profile-test7.txt
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

        rlPhaseStartTest "pki_subca_ee-0085: SUBCA Profile Enrollment - caUserCert using PKCS10 Request of key size 1024"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser8"
        local usercn="fooUser8"
        local phone="1234"
        local usermail="fooUser8@example.org"
        local test_out=ca-$profile-test8.txt
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
        rlAssertGrep "Issuer: CN=PKI $SUBCA_INST Signing Certificate,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}

