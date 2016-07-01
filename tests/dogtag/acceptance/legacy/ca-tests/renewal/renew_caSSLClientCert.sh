#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy-tests/ca-tests/renewal
#   Description: Self renew user SSL client certificates
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki commands needs to be tested:
#  /ca/ee/ca/ProfileSubmit profile caSSLClientSelfRenewal
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

run_pki-legacy-ca-renew_self_ca_user_ssl_client_cert_tests()
{
	local subsystemType=$1
        local csRole=$2

        # Creating Temporary Directory for pki Self Renew ca_user_ssl_client_cert
        rlPhaseStartSetup "pki ca self renew caSSLClient cert - Temporary Directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	        rlRun "pushd $TmpDir"
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Forward the clock 40 days to test grace period
	#	forward_system_clock 40
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

        rlPhaseStartTest "pki_ca_renew_self_sslclientcert-001: Self Renew a SSLClient cert that expires within the renew grace period"
                local userid="rens1"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_001_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_001_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_001_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_001_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_001_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_001_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_001_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_001_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_001_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_001_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_001_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_001_005.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_001_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_001_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Make sure cerificate has 180 days validity
		local notBefore=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_001_005_2.txt | grep 'Not Before' |  awk -F 'Not Before: ' '{print $2}' | awk -F"Not  After:" '{print $1}' |  awk '{$NF="";sub(/\n+$/,"")}1')
		local notAfter=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_001_005_2.txt | grep 'Not  After' |  awk -F 'Not  After: ' '{print $2}'  | awk -F"Subject:" '{print $1}' | awk '{$NF="";sub(/\n+$/,"")}1')
		rlLog "notBefore=$notBefore"
		rlLog "notAfter=$notAfter"
		local notBefore_date=$(date --utc --date "$notBefore" +%s)
		local notAfter_date=$(date --utc --date "$notAfter" +%s)
		local number_of_days=$(( ($notAfter_date-$notBefore_date)/(3600*24) ))
		rlLog "Certificate serial number $serial_number valid for $number_of_days days"
		local expected_number_of_days=180
		if [ $number_of_days -ne $expected_number_of_days ] ; then
                        rlFail "Certificate range is not valid, expected:$expected_number_of_days got:$number_of_days"
                fi
                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		
		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_self_sslclientcert-002: Self Renew a SSLClient cert that expires outside the renew grace period BZ1182353"
                local userid="rens2"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_002_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_002_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_002_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		#Approve certificate request
                #32 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+32 days' '+%Y')
                local end_month=$(date -d '+32 days' '+%m')
                local end_day=$(date -d '+32 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_002_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_002_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_002_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_002_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_002_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_002_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_002_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_002_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_002_005.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_002_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_self_sslclientcert_002_005_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_self_sslclientcert-003: Self Renew a server cert that expires within the renew grace period"
                local userid="rens3"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caServerCert"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_003_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_003_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_003_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=CN=$userid.example.com&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid.example.com\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=CN=$userid.example.com&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=true&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid.example.com\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_003_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_003_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_003_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_003_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_003_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_003_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_003_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_003_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_003_005.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_003_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_003_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Make sure cerificate has 180 days validity
		local notBefore=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_003_005_2.txt | grep 'Not Before' |  awk -F 'Not Before: ' '{print $2}' | awk -F"Not  After:" '{print $1}' |  awk '{$NF="";sub(/\n+$/,"")}1')
		local notAfter=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_003_005_2.txt | grep 'Not  After' |  awk -F 'Not  After: ' '{print $2}'  | awk -F"Subject:" '{print $1}' | awk '{$NF="";sub(/\n+$/,"")}1')
		rlLog "notBefore=$notBefore"
		rlLog "notAfter=$notAfter"
		local notBefore_date=$(date --utc --date "$notBefore" +%s)
		local notAfter_date=$(date --utc --date "$notAfter" +%s)
		local number_of_days=$(( ($notAfter_date-$notBefore_date)/(3600*24) ))
		rlLog "Certificate serial number $serial_number valid for $number_of_days days"
		local expected_number_of_days=720
		if [ $number_of_days -ne $expected_number_of_days ] ; then
                        rlFail "Certificate range is not valid, expected:$expected_number_of_days got:$number_of_days"
                fi
                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_self_sslclientcert-004: Self Renew when a cert does not exist in nss db"
                local userid="rens4"

                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_004_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_004_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_004_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_004_005.txt"
                rlAssertGrep "You have no certificates to be renewed or the certificates are malformed." "$TmpDir/ca_renew_self_sslclientcert_004_005_2.txt"

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_self_sslclientcert-005: Self Renew when graceBefore value is a smaller number and cert is in the renew grace period"
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
                local userid="rens5"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_005_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_005_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_005_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_005_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_005_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_005_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_005_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_005_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_005_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_005_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_005_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_005_005.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_005_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_005_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Make sure cerificate has 180 days validity
		local notBefore=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_005_005_2.txt | grep 'Not Before' |  awk -F 'Not Before: ' '{print $2}' | awk -F"Not  After:" '{print $1}' |  awk '{$NF="";sub(/\n+$/,"")}1')
		local notAfter=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_005_005_2.txt | grep 'Not  After' |  awk -F 'Not  After: ' '{print $2}'  | awk -F"Subject:" '{print $1}' | awk '{$NF="";sub(/\n+$/,"")}1')
		rlLog "notBefore=$notBefore"
		rlLog "notAfter=$notAfter"
		local notBefore_date=$(date --utc --date "$notBefore" +%s)
		local notAfter_date=$(date --utc --date "$notAfter" +%s)
		local number_of_days=$(( ($notAfter_date-$notBefore_date)/(3600*24) ))
		rlLog "Certificate serial number $serial_number valid for $number_of_days days"
		local expected_number_of_days=180
		if [ $number_of_days -ne $expected_number_of_days ] ; then
                        rlFail "Certificate range is not valid, expected:$expected_number_of_days got:$number_of_days"
                fi
                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		
		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
		if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_self_sslclientcert-006: Self Renew when graceBefore value is a smaller number and cert is expiring outside the renew grace period BZ1182353"
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
                local userid="rens6"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_006_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_006_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_006_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		#Approve certificate request
                #5 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+5 days' '+%Y')
                local end_month=$(date -d '+5 days' '+%m')
                local end_day=$(date -d '+5 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_006_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_006_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_006_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_006_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_006_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_006_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_006_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_006_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_006_005.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_self_sslclientcert_006_005_2.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_006_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
		if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd

	
	rlPhaseStartTest "pki_ca_renew_self_sslclientcert-007: Self Renew when graceBefore value is a bigger number and cert is in the renew grace period"
		#Change grace period graceBefore value to a smaller number
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=364"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
                local userid="rens7"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_007_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_007_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_007_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		#Approve certificate request
                #364 day validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+364 days' '+%Y')
                local end_month=$(date -d '+364 days' '+%m')
                local end_day=$(date -d '+364 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_007_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_007_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_007_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_007_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_007_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_007_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_007_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_007_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_007_005.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_007_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_007_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Make sure cerificate has 180 days validity
		local notBefore=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_007_005_2.txt | grep 'Not Before' |  awk -F 'Not Before: ' '{print $2}' | awk -F"Not  After:" '{print $1}' |  awk '{$NF="";sub(/\n+$/,"")}1')
		local notAfter=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_007_005_2.txt | grep 'Not  After' |  awk -F 'Not  After: ' '{print $2}'  | awk -F"Subject:" '{print $1}' | awk '{$NF="";sub(/\n+$/,"")}1')
		rlLog "notBefore=$notBefore"
		rlLog "notAfter=$notAfter"
		local notBefore_date=$(date --utc --date "$notBefore" +%s)
		local notAfter_date=$(date --utc --date "$notAfter" +%s)
		local number_of_days=$(( ($notAfter_date-$notBefore_date)/(3600*24) ))
		rlLog "Certificate serial number $serial_number valid for $number_of_days days"
		local expected_number_of_days=180
		if [ $number_of_days -ne $expected_number_of_days ] ; then
                        rlFail "Certificate range is not valid, expected:$expected_number_of_days got:$number_of_days"
                fi
                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		
		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string 
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_self_sslclientcert-008: Self Renew when graceBefore value is a bigger number and cert is expiring outside the renew grace period BZ1182353"
		#Change grace period graceBefore value to a bigger number
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caUserCert.cfg"
                local search_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string="policyset.userCertSet.10.constraint.params.renewal.graceBefore=363"
                replace_string_in_a_file $profile_file $search_string $replace_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#user cert request using profile
                local userid="rens8"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_008_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_008_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_008_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		#Approve certificate request
                #365 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+365 days' '+%Y')
                local end_month=$(date -d '+365 days' '+%m')
                local end_day=$(date -d '+365 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_008_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_008_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_008_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_008_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_008_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_008_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_008_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_008_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_008_005.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_self_sslclientcert_008_005_2.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_008_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd


	rlPhaseStartTest "pki_ca_renew_self_sslclientcert-009: Self Renew when graceBefore value is a negative number and cert is in the renew grace period"
		#Change grace period graceBefore value to a smaller number
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
                local userid="rens9"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_009_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_009_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_009_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		#Approve certificate request
                #50 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+50 days' '+%Y')
                local end_month=$(date -d '+50 days' '+%m')
                local end_day=$(date -d '+50 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_009_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_009_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_009_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_009_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_009_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_009_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_009_005.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_009_005_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_009_005.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_009_005_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_009_005_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Make sure cerificate has 180 days validity
		local notBefore=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_009_005_2.txt | grep 'Not Before' |  awk -F 'Not Before: ' '{print $2}' | awk -F"Not  After:" '{print $1}' |  awk '{$NF="";sub(/\n+$/,"")}1')
		local notAfter=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_009_005_2.txt | grep 'Not  After' |  awk -F 'Not  After: ' '{print $2}'  | awk -F"Subject:" '{print $1}' | awk '{$NF="";sub(/\n+$/,"")}1')
		rlLog "notBefore=$notBefore"
		rlLog "notAfter=$notAfter"
		local notBefore_date=$(date --utc --date "$notBefore" +%s)
		local notAfter_date=$(date --utc --date "$notAfter" +%s)
		local number_of_days=$(( ($notAfter_date-$notBefore_date)/(3600*24) ))
		rlLog "Certificate serial number $serial_number valid for $number_of_days days"
		local expected_number_of_days=180
		if [ $number_of_days -ne $expected_number_of_days ] ; then
                        rlFail "Certificate range is not valid, expected:$expected_number_of_days got:$number_of_days"
                fi
                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		
		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi
	rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_self_sslclientcert-010: Self Renew a revoked SSLClient cert that expires within the renew grace period"
                local userid="rens10"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_010_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_010_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_010_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_010_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_010_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_010_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_010_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_010_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_010_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
		#Revoke the cert
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local invalidity_time=$(($(date +%s%N)/1000000))

                serial_number_in_decimal=$((${serial_number}))
                serial_number_only=${serial_number:2:$serial_length}
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/ca_renew_self_sslclientcert_010_005_2.txt" 0 "Submit Certificate Rovoke request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_010_005.txt"
                rlAssertGrep "revoked = \"yes\"" "$TmpDir/ca_renew_self_sslclientcert_010_005_2.txt"

                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_006.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_010_006.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_010_006_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_010_006.txt"
                rlAssertGrep "Cannot renew a revoked certificate" "$TmpDir/ca_renew_self_sslclientcert_010_006_2.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_010_006_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlPhaseEnd

        rlPhaseStartTest "pki_ca_renew_self_sslclientcert-011: Self Renew a revoked SSLClient cert when its outside the renew grace period"
                local userid="rens11"
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
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_011_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_011_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_011_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"
		#Approve certificate request
                #50 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+50 days' '+%Y')
                local end_month=$(date -d '+50 days' '+%m')
                local end_day=$(date -d '+50 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_self_sslclientcert_011_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_011_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_011_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Import the user certificate to a nssdb
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_004.txt \
                             -d \"op=displayBySerial&serialNumber=$serial_number\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/displayBySerial\" > $TmpDir/ca_renew_self_sslclientcert_011_004_2.txt" 0 "Submit displayBySerial request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_011_004.txt"
		local certificate_in_base64=$(cat -v $TmpDir/ca_renew_self_sslclientcert_011_004_2.txt |  grep 'header.certChainBase64' | awk -F 'header.certChainBase64 = "' '{print $2}' |  awk 'gsub("\";$","")' | sed 's/\\r\\n//g')
		local certificate_header="-----BEGIN CERTIFICATE-----"
		local certificate_footer="-----END CERTIFICATE-----"
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		local certificate_file=$TmpDir/ca_renew_self_sslclientcert_1.pem
		echo "$certificate_header" > $certificate_file
		echo "$certificate_in_base64" >> $certificate_file
		echo "$certificate_footer" >> $certificate_file
		install_and_trust_user_cert $certificate_file $userid $TEMP_NSS_DB
		
		#Revoke the cert
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local invalidity_time=$(($(date +%s%N)/1000000))

                serial_number_in_decimal=$((${serial_number}))
                serial_number_only=${serial_number:2:$serial_length}
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_005.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/ca_renew_self_sslclientcert_011_005_2.txt" 0 "Submit Certificate Rovoke request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_011_005.txt"
                rlAssertGrep "revoked = \"yes\"" "$TmpDir/ca_renew_self_sslclientcert_011_005_2.txt"

                #Submit Renew certificate request
        	rlRun "export SSL_DIR=$TEMP_NSS_DB"
                local renew_profile_id="caSSLClientSelfRenewal"
                rlLog "curl  --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_006.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_self_sslclientcert_011_006.txt \
			     -E $userid:$TEMP_NSS_DB_PWD \
                             -d \"profileId=$renew_profile_id&renewal=true\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_self_sslclientcert_011_006_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_self_sslclientcert_011_006.txt"
                rlAssertGrep "Cannot renew a revoked certificate" "$TmpDir/ca_renew_self_sslclientcert_011_006_2.txt"
                request_id=$(cat -v  $TmpDir/ca_renew_self_sslclientcert_011_006_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
                rlLog "requestid=$request_id"

		#Cleanup:
        	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_self_sslclientcert_cleanup: Enable nonce and delete temporary directory"
		rlLog "tomcat name=$tomcat_name"
                enable_ca_nonce $tomcat_name
		#Delete temporary directory
        	rlRun "popd"
	        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
