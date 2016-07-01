#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy-tests/ca-tests
#   Description: PKI CA certificate renewal manually approved by agents tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki commands needs to be tested:
#  /ca/ee/ca/ProfileSubmit with profile id caManualRenewal
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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
#
# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

run_pki-legacy-ca-renew_manual_tests()
{
	local subsystemType=$1
        local csRole=$2

        # Creating Temporary Directory for pki ca-renew-manual
        rlPhaseStartSetup "pki ca renew manual Temporary Directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	        rlRun "pushd $TmpDir"
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Forward the clock 40 days to test grace period
		forward_system_clock 40
        rlPhaseEnd

        # Local Variables
        get_topo_stack $csRole $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local ca_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local ca_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local ca_host=$(eval echo \$${csRole})
        local valid_agent_user=$CA_INST\_agentV
        local valid_agent_user_password=$CA_INST\_agentV_password
        local valid_admin_user=$CA_INST\_adminV
        local valid_admin_user_password=$CA_INST\_adminV_password
        local valid_audit_user=$CA_INST\_auditV
        local valid_audit_user_password=$CA_INST\_auditV_password
        local valid_operator_user=$CA_INST\_operatorV
        local valid_operator_user_password=$CA_INST\_operatorV_password
        local valid_agent_cert=$CA_INST\_agentV
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local ca_admin_user=$(eval echo \$${CA_INST}_ADMIN_USER)
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local ca_db_suffix=$(eval echo \$${CA_INST}_DB_SUFFIX)
	local ldap_conn_port=$(eval echo \$${CA_INST}_LDAP_PORT)
	local ldap_rootdn=$(eval echo $LDAP_ROOTDN)
	local ldap_rootdn_password=$(eval echo $LDAP_ROOTDNPWD)
	disable_ca_nonce $tomcat_name

        rlPhaseStartTest "pki_ca_renew_manual-001: Renew a cert that expires with in the renew grace period - manually approved by a valid agent"
		local userid="renm2"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

		#Create a certificate request 
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=2048
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_001_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_001_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_001_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_001_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_001_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Approve certificate request
		#10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
		local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_001_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_001_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_001_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_001_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_001_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
		serial_length=${#serial_number}
		if [ $serial_length -le 0 ] ; then
			rlFail "Certificate Serial Number is invalid : $serial_number"
		fi
	
		serial_number_in_decimal=$((${serial_number}))
		#Submit Renew certificate request
		local renew_profile_id="caManualRenewal"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_001_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""	
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_001_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
	   		     -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_001_004_2.txt" 0 "Submit Certificate renew request"
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_001_004.txt"
		request_id=$(cat -v  $TmpDir/ca_renew_manual_001_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Agent Approve renew request
		#180 days validity for certs
		local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
		local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_001_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_001_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_001_005_2.txt" 0 "Submit Certificate approve request"
		lAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_001_005.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_001_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"
		
		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-002: Renew a cert that expired and with in the renew grace period - manually approved by a valid agent"
		# Set System Clock 40 days older from today
		reverse_system_clock 40

		#user cert enrollment using profile
		local userid="renm3"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=2048
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_002_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_002_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_002_002_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_002_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_002_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Approve certificate request
                #20 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+20 days' '+%Y')
                local end_month=$(date -d '+20 days' '+%m')
                local end_day=$(date -d '+20 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_002_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_002_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_002_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_002_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_002_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Set System Clock back to today
		forward_system_clock 40

		#Now the certificate is expired and in the renew grace period 30 days
		#Renew certificate
		serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_001_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_001_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_001_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_001_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_001_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Verify requestid
		if [ $request_id -le 0 ] ; then
                        rlFail "Request id not found."
                fi

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_002_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_002_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_002_005_2.txt" 0 "Submit Certificate approve request"
                lAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_002_005.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_002_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"
		
		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-003: Renew a cert that expires outside the renew grace period BZ1182353"
		local userid="renm4"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_003_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_003_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_003_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_003_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_003_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #31 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+31 days' '+%Y')
                local end_month=$(date -d '+31 days' '+%m')
                local end_day=$(date -d '+31 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_003_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_003_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_003_003_2.txt" 0 "Submit Certificate approve request"
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_003_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_003_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Renew cert
		serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_003_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_003_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_003_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_003_004.txt"
		rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_manual_003_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-004: Renew a cert that expired and not with in the renew grace period BZ1182353"
		#Set System Clock 40 days older from today
		reverse_system_clock 40

		#user cert enrollment using profile
		local userid="renm5"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_004_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_004_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_004_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_004_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_004_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
		rlLog "requestid=$request_id"

                #Approve certificate request
                #6 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+6 days' '+%Y')
                local end_month=$(date -d '+6 days' '+%m')
                local end_day=$(date -d '+6 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_004_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_004_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_004_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_004_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_004_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Set System Clock back to today
		forward_system_clock 40

		#Now the certificate is expired and outside the renew grace period 30 days
                #Renew certificate
                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_004_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_004_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_004_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_004_004.txt"
		rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_manual_004_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"
	rlPhaseEnd	

	rlPhaseStartTest "pki_ca_renew_manual-005: Serial number provided for a renewal does not exist in the certificate system"
		local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_005_001.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=123456789\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_005_001.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=123456789\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_005_001_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_005_001.txt"
		rlAssertGrep "errorReason=\"Record not found\"" "$TmpDir/ca_renew_manual_005_001_2.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-006: Renew a dual cert that expires in the renew grace period - manually approved by a valid agent"
		local request_type=crmfdual
	        local request_key_type=rsa
	        local request_key_size=2048
        	local profile=caDualCert
	        local userid="renm6"
		local usercn="renm6User1"
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
                subject_archive:true \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out" 0 "Create $request_type request for $profile"

	        local cert_requestdn=$(cat $TEMP_NSS_DB/$rand-subject.out | grep Request_DN | cut -d ":" -f2)
        	rlLog "cert_requestdn=$cert_requestdn"
	        rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
        	rlLog "curl --basic --dump-header $TmpDir/ca_admin_out_1  \
                	-d \"cert_request_type=$request_type&enckeyParam=$request_key_size&signKeyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&sn_uid=$userid&sn_e=$useremail&sn_cn=$usercn&sn_ou3=&sn_ou2=&sn_ou1=&sn_ou=IDM&sn_o=RedHat&sn_c=US&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
	                -k https://$ca_host:$ca_secure_port/ca/eeca/ca/profileSubmitSSLClient"

        	rlRun "curl --basic --dump-header $TmpDir/ca_admin_out_1  \
                	-d \"cert_request_type=$request_type&enckeyParam=$request_key_size&signKeyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&sn_uid=$userid&sn_e=$useremail&sn_cn=$usercn&sn_ou3=&sn_ou2=&sn_ou1=&sn_ou=IDM&sn_o=RedHat&sn_c=US&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput=false\"  \
	                -k https://$ca_host:$ca_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
        	rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_admin_out_1"
	        rlAssertNotGrep "Sorry, your request has been rejected" "$TmpDir/ca_admin_out_1"
        	local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
		local request_id1=$(echo $request_id | cut -d " " -f1)
		local request_id2=$(echo $request_id | cut -d " " -f2)
		rlLog "request_id1=$request_id1"
		rlLog "request_id2=$request_id2"
		#approve request id 1
		rlLog "Approve $request_id1 using $valid_agent_cert"
		# 10 days validity for certs
		local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+10 days'  '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_006_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
			     -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_006_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
			     -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_006_005_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_006_005.txt"
                local serial_number1=$(cat -v  $TmpDir/ca_renew_manual_006_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number1=$serial_number1"

		#Verify length of the serial number
                serial_length=${#serial_number1}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number1"
                fi

		#Approve request_id2
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_006_006.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_006_006.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_006_006_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_006_006.txt"
                local serial_number2=$(cat -v  $TmpDir/ca_renew_manual_006_006_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number2=$serial_number2"

		#Verify length of the serial number
                serial_length=${#serial_number2}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number2"
                fi

		#Renew serial_number1
		local renew_profile_id="caManualRenewal"
		serial_number1_in_decimal=$((${serial_number1}))
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_006_007.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number1_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_006_007.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number1_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_006_007_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_006_007.txt"
                request_id1=$(cat -v  $TmpDir/ca_renew_manual_006_007_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid1=$request_id1"

                #Verify requestid
                if [ $request_id1 -le 0 ] ; then
                        rlFail "Request id not found."
                fi

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_006_008.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
			     -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_006_008.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
			     -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_006_008_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_006_008.txt"
                local serial_number1=$(cat -v  $TmpDir/ca_renew_manual_006_008_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number1"

                #Verify length of the serial number
                serial_length=${#serial_number1}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number1"
                fi


		#Renew serial_number2
		local renew_profile_id="caManualRenewal"
		serial_number2_in_decimal=$((${serial_number2}))
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_006_009.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number2_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_006_009.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number2_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_006_009_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_006_009.txt"
                request_id2=$(cat -v  $TmpDir/ca_renew_manual_006_009_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid2=$request_id2"

                #Verify requestid
                if [ $request_id2 -le 0 ] ; then
                        rlFail "Request id not found."
                fi

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_006_010.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_006_010.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_006_010_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_006_010.txt"
                local serial_number2=$(cat -v  $TmpDir/ca_renew_manual_006_010_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number2=$serial_number2"

                #Verify length of the serial number
                serial_length=${#serial_number2}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number2"
                fi
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-007: Renew a dual cert that is expired and is in the renew grace period - manually approved by a valid agent"
		# Set System Clock 40 days older from today
		 reverse_system_clock 40

		 local request_type=crmfdual
                local request_key_type=rsa
                local request_key_size=2048
                local profile=caDualCert
                local userid="renm7"
                local usercn="renm7User1"
                local usermail="renm7@example.org"
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
                rlLog "curl --basic --dump-header $TmpDir/ca_admin_out_1  \
                        -d \"cert_request_type=$request_type&enckeyParam=$request_key_size&signKeyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&sn_uid=$userid&sn_e=$useremail&sn_cn=$usercn&sn_ou3=&sn_ou2=&sn_ou1=&sn_ou=IDM&sn_o=RedHat&sn_c=US&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput\"  \
                        -k https://$ca_host:$ca_secure_port/ca/eeca/ca/profileSubmitSSLClient"

                rlRun "curl --basic --dump-header $TmpDir/ca_admin_out_1  \
                        -d \"cert_request_type=$request_type&enckeyParam=$request_key_size&signKeyParam=$request_key_size&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)&sn_uid=$userid&sn_e=$useremail&sn_cn=$usercn&sn_ou3=&sn_ou2=&sn_ou1=&sn_ou=IDM&sn_o=RedHat&sn_c=US&requestor_name=&requestor_email=&requestor_phone=&profileId=$profile&renewal=false&xmlOutput=false\"  \
                        -k https://$ca_host:$ca_secure_port/ca/eeca/ca/profileSubmitSSLClient > $TmpDir/$test_out"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_admin_out_1"
                rlAssertNotGrep "Sorry, your request has been rejected" "$TmpDir/ca_admin_out_1"
                local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                local request_id1=$(echo $request_id | cut -d " " -f1)
                local request_id2=$(echo $request_id | cut -d " " -f2)
                rlLog "request_id1=$request_id1"
                rlLog "request_id2=$request_id2"
                #approve request id 1
                rlLog "Approve $request_id1 using $valid_agent_cert"
                # 10 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+10 days'  '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_007_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_007_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_007_005_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_007_005.txt"
                local serial_number1=$(cat -v  $TmpDir/ca_renew_manual_007_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number1=$serial_number1"

                #Verify length of the serial number
                serial_length=${#serial_number1}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number1"
                fi

                #Approve request_id2
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_007_006.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_007_006.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_007_006_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_007_006.txt"
                local serial_number2=$(cat -v  $TmpDir/ca_renew_manual_007_006_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number2=$serial_number2"
		
		 #Verify length of the serial number
                serial_length=${#serial_number2}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number2"
                fi
		
		#Set System Clock back to today
		forward_system_clock 40

		#Renew serial_number1
                local renew_profile_id="caManualRenewal"
                serial_number1_in_decimal=$((${serial_number1}))
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_007_007.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number1_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_007_007.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number1_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_007_007_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_007_007.txt"
                request_id1=$(cat -v  $TmpDir/ca_renew_manual_007_007_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid1=$request_id1"

                #Verify requestid
                if [ $request_id1 -le 0 ] ; then
                        rlFail "Request id not found."
                fi

		 #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_007_008.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_007_008.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id1&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=false&keyUsageNonRepudiation=false&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_007_008_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_007_008.txt"
                local serial_number1=$(cat -v  $TmpDir/ca_renew_manual_007_008_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number1"

		#Verify length of the serial number
                serial_length=${#serial_number1}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number1"
                fi


                #Renew serial_number2
                local renew_profile_id="caManualRenewal"
                serial_number2_in_decimal=$((${serial_number2}))
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_007_009.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number2_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_007_009.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number2_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_007_009_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_007_009.txt"
                request_id2=$(cat -v  $TmpDir/ca_renew_manual_007_009_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid2=$request_id2"

                #Verify requestid
                if [ $request_id2 -le 0 ] ; then
                        rlFail "Request id not found."
                fi

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_007_010.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_007_010.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id2&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=false&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_007_010_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_007_010.txt"
                local serial_number2=$(cat -v  $TmpDir/ca_renew_manual_007_010_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number2=$serial_number2"

                #Verify length of the serial number
                serial_length=${#serial_number2}
		if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number2"
                fi	
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-008: Renew a directory user cert that is expired and is in the renew grace period - manually approved by a valid agent"
		# Set System Clock 40 days older from today
		 reverse_system_clock 40
	
		#Change caDirUserCert.cfg profile to have cert validity range to be 20 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=20"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_008_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UserDirEnrollment&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_008_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UserDirEnrollment&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_manual_008_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_008_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=renm8$rand
		local ldap_user_password=renm8password
		cat > $TmpDir/adduser1.ldif << adduser1.ldif_EOF

version: 1

 entry-id: 10
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/sh
userPassword: $ldap_user_password
adduser1.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser1.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_008_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_008_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_008_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_008_002.txt"	
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_008_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request

		#Set System Clock back to today
		forward_system_clock 40

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string 
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Renew cert
		local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_008_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_008_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_008_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_008_004.txt"
		request_id=$(cat -v  $TmpDir/ca_renew_manual_008_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Verify requestid
                if [ $request_id -le 0 ] ; then
                        rlFail "Request id not found."
                fi

                #Agent Approve renew request
		#180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_008_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$ldap_uid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$ldap_uid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_008_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$ldap_uid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$ldap_uid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_008_005_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_008_005.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_008_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-009: Manually approved by agent -when agent rejects the request "
		local userid="renm9"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_009_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_009_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_009_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_009_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_009_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_009_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_009_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_009_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_009_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_009_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_009_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_009_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_009_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_009_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_009_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_009_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=reject&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
			-k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_009_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=reject&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_009_005_2.txt" 0 "Submit Certificate reject request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_009_005.txt"
                rlAssertGrep "requestStatus=\"rejected\"" "$TmpDir/ca_renew_manual_009_005_2.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-010: Manually approved by agent -when agent cancel the request"
		local userid="renm10"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_010_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                            -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_010_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_010_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_010_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_010_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_010_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_010_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_010_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_010_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_010_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_010_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_010_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_010_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_010_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_010_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
		local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_010_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=cancel&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_010_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=cancel&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_010_005_2.txt" 0 "Submit Certificate cancel request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_010_005.txt"
                rlAssertGrep "requestStatus=\"canceled\"" "$TmpDir/ca_renew_manual_010_005_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-011: Manually approved by agent -when agent assign the request"
		local userid="renm11"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_011_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_011_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_011_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_011_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_011_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_011_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_011_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_011_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_011_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_011_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_011_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_011_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_011_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_011_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_011_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
		local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_011_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=assign&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_011_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=assign&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_011_005_2.txt" 0 "Submit Certificate assign request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_011_005.txt"
                rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/ca_renew_manual_011_005_2.txt"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_manual-012: Manually approved by agent -when agent unassign the request"
		local userid="renm12"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_012_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_012_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_012_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_012_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_012_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_012_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_012_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_012_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_012_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_012_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_012_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_012_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_012_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_012_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_012_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
		local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_012_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=unassign&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_012_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=unassign&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_012_005_2.txt" 0 "Submit Certificate unassign request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_012_005.txt"
                rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/ca_renew_manual_012_005_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-013: Manually approved by agent -when agent validate the request"
		local userid="renm13"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_013_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_013_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_013_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_013_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_013_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_013_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_013_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_013_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_013_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_013_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_013_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_013_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_013_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_013_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_013_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
		local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_013_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=validate&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_013_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=validate&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_013_005_2.txt" 0 "Submit Certificate validate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_013_005.txt"
                rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/ca_renew_manual_013_005_2.txt"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_manual-014: Manually approved by agent -when agent update the request"
		local userid="renm14"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_014_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_014_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_014_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_014_002.txt"
		local request_id=$(cat -v  $TmpDir/ca_renew_manual_014_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_014_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_014_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_014_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_014_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_014_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_014_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_014_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_014_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_014_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_014_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                #Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
		local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_014_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=update&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_014_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=update&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_014_005_2.txt" 0 "Submit Certificate update request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_014_005.txt"
                rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/ca_renew_manual_014_005_2.txt"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_renew_manual-015: Renew a cert when graceBefore value is a negative - manually approved by a valid agent"
		#Change grace period graceBefore value to a negative number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=-10"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm15"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_015_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_015_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_015_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_015_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_015_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_015_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_015_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_015_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_015_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_015_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_015_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_015_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_015_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_015_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_015_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_015_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=update&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_015_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=update&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_015_005_2.txt" 0 "Submit Certificate update request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_015_005.txt"
                rlAssertGrep "requestStatus=\"pending\"" "$TmpDir/ca_renew_manual_015_005_2.txt"

		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd

	
	rlPhaseStartTest "pki_ca_renew_manual-016: Renew a cert when graceBefore value is a smaller number - manually approved by a valid agent"
		
		#Change grace period graceBefore value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=1"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm16"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_016_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_016_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_016_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_016_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_016_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #1 day validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+1 day' '+%Y')
                local end_month=$(date -d '+1 day' '+%m')
                local end_day=$(date -d '+1 day'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_016_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_016_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_016_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_016_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_016_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_016_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_016_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_016_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_016_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_016_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_016_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_016_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_016_005_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_016_005.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_016_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                #Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string 
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_manual-017: Renew a cert when graceBefore value is a smaller number and cert is outside renew grace period BZ1182353"
		
		#Change grace period graceBefore value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=1"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm17"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_017_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_017_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_017_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_017_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_017_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_017_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_017_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_017_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_017_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_017_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_017_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_017_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_017_004_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_017_004.txt"
		rlAssertGrep "Request Rejected - Outside of Renewal Grace Period"  "$TmpDir/ca_renew_manual_017_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

	 	#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd

	
	rlPhaseStartTest "pki_ca_renew_manual-018: Renew a cert when graceBefore value is a bigger number - manually approved by a valid agent"
		
		#Change grace period graceBefore value to a bigger number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=360"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm18"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_018_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_018_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_018_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_018_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_018_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #359 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+359 days' '+%Y')
                local end_month=$(date -d '+359 days' '+%m')
                local end_day=$(date -d '+359 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_018_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_018_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_018_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_018_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_018_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_018_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_018_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_018_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_018_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_018_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_018_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_018_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_018_005_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_018_005.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_018_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                #Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
		        rhcs_start_instance $tomcat_name
                fi
        rlPhaseEnd

	
	rlPhaseStartTest "pki_ca_renew_manual-019: Renew a cert when graceBefore value is a bigger number and cert is outside renew grace period BZ1182353"
		
		#Change grace period graceBefore value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=360"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm19"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_019_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_019_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_019_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_019_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_019_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #362 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+362 days' '+%Y')
                local end_month=$(date -d '+362 days' '+%m')
                local end_day=$(date -d '+362 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_019_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_019_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_019_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_019_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_019_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_019_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_019_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_019_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_019_004.txt"
		rlAssertGrep "Request Rejected - Outside of Renewal Grace Period"  "$TmpDir/ca_renew_manual_019_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

	 	#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-020: Renew a cert when graceAfter value is a smaller number - manually approved by a valid agent"
	
		# Set System Clock 40 days older from today
		reverse_system_clock 40

		#Change grace period graceAfter value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=2"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm20"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_020_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_020_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_020_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_020_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_020_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #39 day validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+39 days' '+%Y')
                local end_month=$(date -d '+39 days' '+%m')
                local end_day=$(date -d '+39 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_020_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_020_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_020_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_020_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_020_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                #Set System Clock back to today
		forward_system_clock 40

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_020_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_020_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_020_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_020_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_020_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_020_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_020_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_020_005_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_020_005.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_020_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                #Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string 
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_manual-021: Renew a cert when graceAfter value is a smaller number and cert is expired before renew grace period BZ1182353"
		# Set System Clock 40 days older from today
		reverse_system_clock 40

		#Change grace period graceAfter value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=1"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm21"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_021_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_021_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_021_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_021_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_021_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #38 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+38 days' '+%Y')
                local end_month=$(date -d '+38 days' '+%m')
                local end_day=$(date -d '+38 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_021_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_021_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_021_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_021_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_021_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Set System Clock back to today
		forward_system_clock 40

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_021_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_021_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_021_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_021_004.txt"
		rlAssertGrep "Request Rejected - Outside of Renewal Grace Period"  "$TmpDir/ca_renew_manual_021_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

	 	#Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd

		
	rlPhaseStartTest "pki_ca_renew_manual-022: Renew a cert when graceAfter value is a bigger number - manually approved by a valid agent"
	
		# Set System Clock 40 days older from today
		reverse_system_clock 40
	
		#Change grace period graceAfter value to a bigger number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=360"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm22"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_022_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_022_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_022_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_022_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_022_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #1 day validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+1 day' '+%Y')
                local end_month=$(date -d '+1 day' '+%m')
                local end_day=$(date -d '+1 day'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_022_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_022_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_022_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_022_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_022_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Set System Clock back to today
		forward_system_clock 40

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_022_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_022_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_022_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_022_004.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_manual_022_004_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Agent Approve renew request
                #180 days validity for certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                let end_year=$(date -d '+180 days'  '+%Y')
                local end_month=$(date -d '+180 days' '+%m')
                local end_day=$(date -d '+180 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_022_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                        -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_022_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_022_005_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_022_005.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_022_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                #Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
		        rhcs_start_instance $tomcat_name
                fi
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-023: Renew a cert when graceAfter value is a bigger number, cert is expired and outside renew grace period BZ1182353"
		# Set System Clock 40 days older from today
		reverse_system_clock 40

		#Change grace period graceAfter value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceAfter=38"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
		local userid="renm23"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=1024
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_023_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_023_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_023_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_023_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_023_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
	
		#Approve certificate request
                #1 day validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+1 day' '+%Y')
                local end_month=$(date -d '+1 day' '+%m')
                local end_day=$(date -d '+1 day'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_023_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_023_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_023_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_023_003.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_manual_023_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                 #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Set System Clock back to today
		forward_system_clock 40

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_023_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_023_004.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_023_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_023_004.txt"
		rlAssertGrep "Request Rejected - Outside of Renewal Grace Period"  "$TmpDir/ca_renew_manual_023_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

	 	#Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual-024: Renew a revoked cert that expires in renew grace period - manually approved by a valid agent"
                local userid="renm24"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=2048
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_024_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_024_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_024_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_024_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_024_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_024_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_024_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_024_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_024_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_024_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Revoke the cert
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local invalidity_time=$(($(date +%s%N)/1000000))

		serial_number_in_decimal=$((${serial_number}))
		serial_number_only=${serial_number:2:$serial_length}
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_024_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_024_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/ca_renew_manual_024_004_2.txt" 0 "Submit Certificate Rovoke request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_024_004.txt"
                rlAssertGrep "revoked = \"yes\"" "$TmpDir/ca_renew_manual_024_004_2.txt"

                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_024_005.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_024_005.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_024_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_024_005.txt"
                rlAssertGrep "Cannot renew a revoked certificate"  "$TmpDir/ca_renew_manual_024_005_2.txt"
        rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_manual-025: Renew a expired revoked cert that is in renew grace period - manually approved by a valid agent"
		# Set System Clock 40 days older from today
		reverse_system_clock 40

		#User cert request using profile
                local userid="renm25"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=2048
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_025_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_025_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_025_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_025_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_manual_025_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_025_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_025_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_manual_025_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_025_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_manual_025_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Revoke the cert
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local invalidity_time=$(($(date +%s%N)/1000000))
		serial_number_in_decimal=$((${serial_number}))
		serial_number_only=${serial_number:2:$serial_length}
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_manual_025_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_manual_025_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/ca_renew_manual_025_004_2.txt" 0 "Submit Certificate Revoke request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_025_004.txt"
                rlAssertGrep "revoked = \"yes\"" "$TmpDir/ca_renew_manual_025_004_2.txt"

		#Set System Clock back to today
		forward_system_clock 40

                #Submit Renew certificate request
                local renew_profile_id="caManualRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_025_005.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_manual_025_005.txt \
                             -d \"profileId=$renew_profile_id&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_manual_025_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_manual_025_005.txt"
                rlAssertGrep "Cannot renew a revoked certificate"  "$TmpDir/ca_renew_manual_025_005_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_manual_cleanup: Enable nonce and delete temporary directory"
		#set system clock 40 days older, backto today's datetime
		reverse_system_clock 40
		rlLog "tomcat name=$tomcat_name"
                enable_ca_nonce $tomcat_name
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
