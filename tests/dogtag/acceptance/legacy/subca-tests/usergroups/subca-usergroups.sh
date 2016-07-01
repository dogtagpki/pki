#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy-tests/subca-tests/usergroups
#   Description: Subordinate CA user and group tests 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki commands needs to be tested:
#  Subordinate CA /ca/ug
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

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

run_pki-legacy-subca-usergroup_tests()
{
	local subsystemType=$1
        local csRole=$2

        # Creating Temporary Directory for pki ca-usergroup
        rlPhaseStartSetup "pki ca usergroup Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	rlRun "export SSL_DIR=$CERTDB_DIR"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $csRole $TmpDir/topo_file
	if [ $cs_Role="MASTER" ]; then
                 SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
	local tomcat_name=$(eval echo \$${SUBCA_INST}_TOMCAT_INSTANCE_NAME)
        local ca_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local ca_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local ca_host=$(eval echo \$${csRole})
        local valid_agent_user=$SUBCA_INST\_agentV
        local valid_agent_user_password=$SUBCA_INST\_agentV_password
        local valid_admin_user=$SUBCA_INST\_adminV
        local valid_admin_user_password=$SUBCA_INST\_adminV_password
        local valid_audit_user=$SUBCA_INST\_auditV
        local valid_audit_user_password=$SUBCA_INST\_auditV_password
        local valid_operator_user=$SUBCA_INST\_operatorV
        local valid_operator_user_password=$SUBCA_INST\_operatorV_password
	local valid_agent_cert=$SUBCA_INST\_agentV
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local ca_admin_user=$(eval echo \$${SUBCA_INST}_ADMIN_USER)
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')        
	local TEMP_NSS_DB="$TmpDir/nssdb"
	local TEMP_NSS_DB_PWD="redhat"
	disable_ca_nonce $tomcat_name

        rlPhaseStartTest "pki_subca_usergroup-001: Valid SUBCA admin add users"
		local userid="ug02"
		local fullname=$userid
		local password="password$userid"
		local email="$userid@redhat.com"
		local phone="12345"
		local state="CA"
		rlLog "curl --basic \
			    --dump-header  $TmpDir/subca_usergroup_001.txt \
	                     -u $valid_admin_user:$valid_admin_user_password \
        	             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                	     -k \"https://$ca_host:$ca_secure_port/ca/ug\""
		rlRun "curl --basic \
			    --dump-header  $TmpDir/subca_usergroup_001.txt \
			     -u $valid_admin_user:$valid_admin_user_password \
			     -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
			     -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_001_2.txt" 0 "Add user $userid to $CA_INST" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_001.txt"
		rlAssertNotGrep "Fail" "$TmpDir/subca_usergroup_001_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-002: Valid CA admin list users"
		local userid="ug02"
		rlLog "curl --basic \
        	            --dump-header  $TmpDir/subca_usergroup_002.txt \
                	     -u $valid_admin_user:$valid_admin_user_password \
	                     -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=users\" \
        	             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
	        rlRun "curl --basic \
        	            --dump-header  $TmpDir/subca_usergroup_002.txt \
                	     -u $valid_admin_user:$valid_admin_user_password \
	                     -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=users\" \
        	             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_002_2.txt" 0 "List all CA user in $CA_INST"
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_002.txt"
		rlAssertGrep "$userid" "$TmpDir/subca_usergroup_002_2.txt"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_subca_usergroup-003: Valid CA admin edit users"
		local userid="ug04"
                local fullname=$userid
                local password=password$userid
                local email="$userid@redhat.com"
                local phone="1234"
                local state="CA"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_003_2.txt" 0 "Add user $userid to $CA_INST"
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_003.txt"
		#Now edit user - phone number change
                phone="4567"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_003_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_003_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_003_002_2.txt" 0 "Modify user $userid to have a new phone number $phone"
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_003_002.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-004: Valid CA admin delete users"
                local userid="ug05"
                local fullname=$userid
                local password="password$userid"
                local email="$userid@redhat.com"
                local phone="1234"
                local state="CA"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_004_2.txt" 0 "Add user $userid to $CA_INST"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_004.txt"
                rlAssertNotGrep "Failed to add user" "$TmpDir/subca_usergroup_004_2.txt"
                #Now delete user
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_004_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=users&RS_ID=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_004_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=users&RS_ID=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_004_002_2.txt" 0 "Delete user $userid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_004_002.txt"
		#Verify user is deleted
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_004_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=users\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_004_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=users\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_004_003_2.txt" 0 "List all CA user in $CA_INST"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_004_003.txt"
                rlAssertNotGrep "$userid" "$TmpDir/subca_usergroup_004_003_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-005: Valid CA admin view certs of users"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_READ&OP_SCOPE=certs&RS_ID=$valid_admin_user\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_READ&OP_SCOPE=certs&RS_ID=$valid_admin_user\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_05_2.txt" 0 "View user $valid_admin_user certificate"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_005.txt"
		rlRun "cat  $TmpDir/subca_usergroup_05_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_05_3.txt"
		rlAssertGrep "BEGIN CERTIFICATE" "$TmpDir/subca_usergroup_05_3.txt"
		rlAssertGrep "END CERTIFICATE" "$TmpDir/subca_usergroup_05_3.txt"
		#view certificate of ca admin user
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_005_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_READ&OP_SCOPE=certs&RS_ID=$ca_admin_user\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_005_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_READ&OP_SCOPE=certs&RS_ID=$ca_admin_user\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_005_002_2.txt" 0 "View user $ca_admin_user certificate"
		rlRun "cat  $TmpDir/subca_usergroup_005_002_2.txt  | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_005_002_3.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_005_002.txt"
		rlAssertGrep "BEGIN CERTIFICATE" "$TmpDir/subca_usergroup_005_002_3.txt"
		rlAssertGrep "END CERTIFICATE" "$TmpDir/subca_usergroup_005_002_3.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-006: Valid CA admin import certs into users"
		local userid="ug06"
                local fullname=$userid
                local password=password$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"
		#Add a user
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_006.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=Administrators&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_006.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=Administrators&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_006_2.txt" 0 "Add user $userid to $CA_INST"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_006.txt"
                rlAssertNotGrep "Failed to add user" "$TmpDir/subca_usergroup_006_2.txt"
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
                            --dump-header  $TmpDir/subca_usergroup_006_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_006_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/subca_usergroup_006_002_2.txt" 0 "Submit Certificare request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_006_002.txt"
		local request_id=$(cat -v  $TmpDir/subca_usergroup_006_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
		rlLog "requestid=$request_id"
		#Approve certificate request
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
		local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
		local cert_ext_subjAltNames="RFC822Name: "
		rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/subca_usergroup_006_003.txt \
			     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/subca_usergroup_006_003.txt \
		 	     -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/subca_usergroup_006_003_2.txt" 0 "Submit Certificare request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_006_003.txt"
		local serial_number=$(cat -v  $TmpDir/subca_usergroup_006_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"
		local certificate_in_base64=$(cat -v $TmpDir/subca_usergroup_006_003_2.txt | grep 'outputList.outputVal' | awk -F 'outputList.outputVal=\"' '{print $2}'  | awk -F '-----BEGIN CERTIFICATE-----' '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/-----END CERTIFICATE-----\\n\";/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
		rlLog "CERTIFICATE_IN_BASE64=$certificate_in_base64"
		#Add certificate to user
		rlLog "curl --basic \
        	            --dump-header  $TmpDir/subca_usergroup_006_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             --data \"OP_TYPE=OP_ADD&OP_SCOPE=certs&RS_ID=$userid\" \
                             --data-urlencode \"cert=$certificate_in_base64\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_006_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             --data \"OP_TYPE=OP_ADD&OP_SCOPE=certs&RS_ID=$userid\" \
                             --data-urlencode \"cert=$certificate_in_base64\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_006_004_2.txt" 0 "Add certificate serial_number $serial_number to $userid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_006_004.txt"	
		#Make sure certificate got added to user
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_006_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_READ&OP_SCOPE=certs&RS_ID=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_006_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_READ&OP_SCOPE=certs&RS_ID=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_006_005_2.txt" 0 "Read certificate of $userid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_006_005.txt"
		rlRun "cat  $TmpDir/subca_usergroup_006_005_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_006_005_3.txt"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/subca_usergroup_006_005_3.txt"
                rlAssertGrep "-----END CERTIFICATE-----" "$TmpDir/subca_usergroup_006_005_3.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-007: Valid CA admin list groups"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_007.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_007.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_007_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_007.txt"	
		rlRun "cat  $TmpDir/subca_usergroup_007_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_007_3.txt"
                rlAssertGrep "Administrators" "$TmpDir/subca_usergroup_007_3.txt"	
                rlAssertGrep "Certificate Manager Agents" "$TmpDir/subca_usergroup_007_3.txt"
                rlAssertGrep "Trusted Managers" "$TmpDir/subca_usergroup_007_3.txt"	
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-008: Valid CA admin add a user to the group"
                local userid="ug08"
                local fullname=$userid
                local password=password$userid
                local email="$userid@redhat.com"
                local phone="1234"
                local state="CA"
                local groupid="group01"
                local groupdesc="group01_desc"
		#Add user
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_008.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_008.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_008_2.txt" 0 "Add user $userid to $CA_INST"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_008.txt"
                rlAssertNotGrep "Failed to add user" "$TmpDir/subca_usergroup_008_2.txt"
                #Add user to group
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_008_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_008_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_008_002_2.txt" 0 "Add group $groupid"
		
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_008_002.txt"
		#List group
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_008_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_008_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_008_003_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_008_003.txt"
                rlRun "cat  $TmpDir/subca_usergroup_008_003_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_008_003_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_008_003_3.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-009: Valid CA admin delete group"
                local groupid="group09"
                local groupdesc="group09_desc"
		#Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_009_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_009.txt"
                rlAssertNotGrep "Failed to add group" "$TmpDir/subca_usergroup_009_2.txt"
		#List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_009_002_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_009_002.txt"
                rlRun "cat  $TmpDir/subca_usergroup_009_002_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_009_002_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_009_002_3.txt"
		#Delete group
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_009_003_2.txt" 0 "Delete group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_009_003.txt"
		#List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_009_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_009_004_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_009_004.txt"
                rlRun "cat  $TmpDir/subca_usergroup_009_004_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_009_004_3.txt"
                rlAssertNotGrep "$groupid" "$TmpDir/subca_usergroup_009_004_3.txt"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_subca_usergroup-010: Valid CA admin edit groups"
                local userid="ug10"
                local fullname=$userid
                local password=password$userid
                local email="$userid@redhat.com"
                local phone="1234"
                local state="CA"
                local groupid="group10"
                local groupdesc="group10_desc"
                #Add user
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_010.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_010.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_010_2.txt" 0 "Add user $userid to $CA_INST"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_010.txt"
                rlAssertNotGrep "Failed to add user" "$TmpDir/subca_usergroup_010_2.txt"
                #Add user to group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_010_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_010_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_010_002_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_010_002.txt"
                rlAssertNotGrep "Failed to add group" "$TmpDir/subca_usergroup_010_002_2.txt"
		#Edit group - change description
                local groupdesc2="group10_desc_changed"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_010_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc2&user=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_010_003.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc2&user=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_010_003_2.txt" 0 "Edit $groupid change desc $groupdesc2"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_010_003.txt"
        rlPhaseEnd 

	rlPhaseStartTest "pki_subca_usergroup-011: Valid CA agent cannot add new user"
		local userid="ug11"
                local fullname=$userid
                local password="password$userid"
                local email="$userid@redhat.com"
                local phone="12345"
                local state="CA"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_011.txt \
                             -u $valid_agent_user:$valid_agent_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_011.txt \
                             -u $valid_agent_user:$valid_agent_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_011_2.txt" 0 "Add user $userid to $CA_INST using a agent user"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_011.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_011_2.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-012: CA Audit user cannot add new user"
                local userid="ug12"
                local fullname=$userid
                local password="password$userid"
                local email="$userid@redhat.com"
                local phone="12345"
                local state="CA"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_012.txt \
                             -u $valid_audit_user:$valid_audit_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_012.txt \
                             -u $valid_audit_user:$valid_audit_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_012_2.txt" 0 "Add user $userid to $CA_INST using a audit user"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_012.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_012_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-013: CA Operator user cannot add new user"
                local userid="ug13"
                local fullname=$userid
                local password="password$userid"
                local email="$userid@redhat.com"
                local phone="12345"
                local state="CA"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_013.txt \
                             -u $valid_operator_user:$valid_operator_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_013.txt \
                             -u $valid_operator_user:$valid_operator_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=users&RS_ID=$userid&fullname=$fullname&password=$password&email=$email&phone=$phone&state=$state&groups=&userType=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_013_2.txt" 0 "Add user $userid to $CA_INST using a operator user"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_013.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_013_2.txt"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_subca_usergroup-014: CA audit user cannot add new group"
		local groupid="group14"
                local groupdesc="group14_desc"
                #Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_014.txt \
                             -u $valid_audit_user:$valid_audit_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_014.txt \
                             -u $valid_audit_user:$valid_audit_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_014_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_014.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_014_2.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-015: CA agent user cannot add new group"
                local groupid="group15"
                local groupdesc="group15_desc"
                #Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_015.txt \
                             -u $valid_agent_user:$valid_agent_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_015.txt \
                             -u $valid_agent_user:$valid_agent_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_015_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_015.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_015_2.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-016: CA operator user cannot add new group"
                local groupid="group16"
                local groupdesc="group16_desc"
                #Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_016.txt \
                             -u $valid_operator_user:$valid_operator_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_016.txt \
                             -u $valid_operator_user:$valid_operator_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_016_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_016.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_016_2.txt"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_subca_usergroup-017: CA agent user cannot delete existing group"
		local groupid="group17"
                local groupdesc="group17_desc"
                #Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_017_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_017.txt"
                rlAssertNotGrep "Failed to add group" "$TmpDir/subca_usergroup_017_2.txt"
                #List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_017_002_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_017_002.txt"
                rlRun "cat  $TmpDir/subca_usergroup_017_002_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_017_002_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_017_002_3.txt"
                #Delete group using agent
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017_003.txt \
                             -u $valid_agent_user:$valid_agent_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017_003.txt \
                             -u $valid_agent_user:$valid_agent_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_017_003_2.txt" 0 "Delete group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_017_003.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_017_003_2.txt"
		 #List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_017_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_017_004_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_017_004.txt"
                rlRun "cat  $TmpDir/subca_usergroup_017_004_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_017_004_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_017_004_3.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup-018: CA Audit user cannot delete existing group"
		local groupid="group18"
                local groupdesc="group18_desc"
                #Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_018_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_018.txt"
                rlAssertNotGrep "Failed to add group" "$TmpDir/subca_usergroup_018_2.txt"
                #List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_018_002_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_018_002.txt"
                rlRun "cat  $TmpDir/subca_usergroup_018_002_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_018_002_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_018_002_3.txt"
                #Delete group using auditor
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018_003.txt \
                             -u $valid_audit_user:$valid_audit_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018_003.txt \
                             -u $valid_audit_user:$valid_audit_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_018_003_2.txt" 0 "Delete group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_018_003.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_018_003_2.txt"
		 #List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_018_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_018_004_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_018_004.txt"
                rlRun "cat  $TmpDir/subca_usergroup_018_004_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_018_004_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_018_004_3.txt"
	rlPhaseEnd


	rlPhaseStartTest "pki_subca_usergroup-019: CA Operator user cannot delete existing group"
		local groupid="group19"
                local groupdesc="group19_desc"
                #Add group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=groups&RS_ID=$groupid&desc=$groupdesc&user=\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_019_2.txt" 0 "Add group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_019.txt"
                rlAssertNotGrep "Failed to add group" "$TmpDir/subca_usergroup_019_2.txt"
                #List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019_002.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_019_002_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_019_002.txt"
                rlRun "cat  $TmpDir/subca_usergroup_019_002_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_019_002_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_019_002_3.txt"
                #Delete group using operator
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019_003.txt \
                             -u $valid_operator_user:$valid_operator_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019_003.txt \
                             -u $valid_operator_user:$valid_operator_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_019_003_2.txt" 0 "Delete group $groupid"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_019_003.txt"
                rlAssertGrep "You are not authorized to perform this operation" "$TmpDir/subca_usergroup_019_003_2.txt"
		 #List group
                rlLog "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_019_004.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=groups\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_019_004_2.txt" 0 "List groups"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/subca_usergroup_019_004.txt"
                rlRun "cat  $TmpDir/subca_usergroup_019_004_2.txt | python -c 'import sys, urllib as ul; print ul.unquote(sys.stdin.read());' | sed 'y/+/ /' > $TmpDir/subca_usergroup_019_004_3.txt"
                rlAssertGrep "$groupid" "$TmpDir/subca_usergroup_019_004_3.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_usergroup_cleanup: Deleting users and groups"
		local group=("group01" "group10" "group17" "group18" "group19")
                i=0
                while [ $i -lt ${#group[@]} ] ; do
                        groupid=${group[$i]}
                        rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_group_cleanup_$i.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=groups&RS_ID=$groupid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/ca_group_cleanup_$i_2.txt" 0 "Delete group $groupid"
                let i=$i+1
                done

		local user=("ug02" "ug04" "ug06:true" "ug08" "ug10")
		i=0
		while [ $i -lt ${#user[@]} ] ; do
			userid=${user[$i]}
			rlRun "curl --basic \
                            --dump-header  $TmpDir/subca_usergroup_cleanup_$i.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=users&RS_ID=$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ug\" > $TmpDir/subca_usergroup_cleanup_$i_2.txt" 0 "Delete user $userid"
		let i=$i+1
		done
		enable_ca_nonce $tomcat_name
		rlRun "popd"
	        rlRun "rm -r $TmpDir" 0 "Removing temp directory"
	rlPhaseEnd
}
