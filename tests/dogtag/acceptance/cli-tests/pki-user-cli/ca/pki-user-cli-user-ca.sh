#!/bin/bash
#!/usr/bin/expect -f

# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-add    Add users to pki subsystems.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Laxmi Sunkara <lsunkara@redhat.com>
#
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

########################################################################
# Test Suite Globals
########################################################################
CA_adminV_user=CA_adminV
CA_adminV_fullName=CA_Admin_ValidCert
CA_adminR_user=CA_adminR
CA_adminR_fullName=CA_Admin_RevokedCert
CA_adminE_user=CA_adminE
CA_adminE_fullName=CA_admin_ExpiredCert
CA_adminUTCA_user=CA_adminUTCA
CA_adminUTCA_fullName=CA_Admin_CertIssuedByUntrustedCA

CA_agentV_user=CA_agentV
CA_agentV_fullName=CA_Agent_ValidCert
CA_agentR_user=CA_agentR
CA_agentR_fullName=CA_Agent_RevokedCert
CA_agentE_user=CA_agentE
CA_agentE_fullName=CA_agent_ExpiredCert
CA_agentUTCA_user=CA_agentUTCA
CA_agentUTCA_fullName=CA_Agent_CertIssuedByUntrustedCA

CA_auditV_user=CA_auditV
CA_auditV_fullName=CA_Audit_ValidCert
CA_operatorV_user=CA_operatorV
CA_operatorV_fullName=CA_Operator_ValidCert

export CA_adminV_user CA_adminR_user CA_adminE_user CA_adminUTCA_user CA_agentV_user CA_agentR_user CA_agentE_user CA_agentUTCA_user CA_auditV_user CA_operatorV_user
######################################################################

run_pki-user-cli-user-ca_tests(){
    rlPhaseStartSetup "pki_user_cli_user_add-startup: Create temp directory and import CA agent cert into a nss certificate db and trust CA root cert"
	admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
	nss_db_password="Password"
	rlRun "source /opt/rhqa_pki/env.sh"
	rlLog "Admin Certificate is located at: $CA_ADMIN_CERT_LOCATION"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	rlLog "Temp Directory = $TmpDir"
	rlRun "mkdir $TmpDir/nssdb"
	rlLog "importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $TmpDir/nssdb $nss_db_password $admin_cert_nickname"
	rlRun "importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $TmpDir/nssdb $nss_db_password $admin_cert_nickname" 0 "Import Admin certificate to $TmpDir/nssdb"
	rlRun "install_and_trust_CA_cert $CA_SERVER_ROOT $TmpDir/nssdb"

	rlRun "mkdir /tmp/dummydb"
	rlLog "Cert Database for untrusted cert's : /tmp/dummydb"
	rlRun "importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD /tmp/dummydb $nss_db_password $admin_cert_nickname" 0 "Import Admin certificate to /tmp/dummydb"
        rlRun "install_and_trust_CA_cert $CA_SERVER_ROOT /tmp/dummydb"

	rlRun "mkdir /tmp/requestdb"
        rlLog "importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD /tmp/requestdb $nss_db_password $admin_cert_nickname"
        rlRun "importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD /tmp/requestdb $nss_db_password $admin_cert_nickname" 0 "Import Admin certificate to /tmp/requestdb"
        rlRun "install_and_trust_CA_cert $CA_SERVER_ROOT /tmp/requestdb"

    rlPhaseEnd



    rlPhaseStartSetup "Creating user, create user and add it to the user, add user to the group"

	 user=($CA_adminV_user $CA_adminV_fullName $CA_adminR_user $CA_adminR_fullName $CA_adminE_user $CA_adminE_fullName $CA_adminUTCA_user $CA_adminUTCA_fullName $CA_agentV_user $CA_agentV_fullName $CA_agentR_user $CA_agentR_fullName $CA_agentE_user $CA_agentE_fullName $CA_agentUTCA_user $CA_agentUTCA_fullName $CA_auditV_user $CA_auditV_fullName $CA_operatorV_user $CA_operatorV_fullName)
	i=0
	while [ $i -lt ${#user[@]} ] ; do
	       userid=${user[$i]}
	       userfullName=${user[$i+1]}

	      #Create $userid  user
	       rlLog "Executing: pki -d $TmpDir/nssdb \
			  -n \"$admin_cert_nickname\" \
			  -c $nss_db_password \
			   user-add --fullName=\"$userfullName\" $userid"
	       rlRun "pki -d $TmpDir/nssdb \
			  -n \"$admin_cert_nickname\" \
			  -c $nss_db_password \
			   user-add --fullName=\"$userfullName\" $userid" \
			   0 \
			   "Add user $userid to CA"

	       #=====Adding user to respective  group. Administrator, Certificate Manager Agent, Auditor=====#
		if [ $userid == $CA_adminV_user -o $userid == $CA_adminR_user -o $userid == $CA_adminE_user -o $userid == $CA_adminUTCA_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t ca \
			    group-member-add Administrators $userid > $TmpDir/pki-user-add-ca-group001$i.out"  \
			    0 \
			    "Add user $userid to Administrators group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-ca-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-ca-group001$i.out"
		elif [ $userid == $CA_agentV_user -o $userid == $CA_agentR_user -o $userid == $CA_agentE_user -o $userid == $CA_agentUTCA_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t ca \
			    group-member-add \"Certificate Manager Agents\" $userid > $TmpDir/pki-user-add-ca-group001$i.out"  \
			    0 \
			    "Add user $userid to Certificate Manager Agents group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-ca-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-ca-group001$i.out"

		elif [ $userid == $CA_auditV_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t ca \
			    group-member-add Auditors $userid > $TmpDir/pki-user-add-ca-group001$i.out"  \
			    0 \
			    "Add user $userid to Auditors group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-ca-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-ca-group001$i.out"

		elif [ $userid == $CA_operatorV_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t ca \
			    group-member-add \"Trusted Managers\"  $userid > $TmpDir/pki-user-add-ca-group001$i.out"  \
			    0 \
			    "Add user $userid to Trusted Managers  group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-ca-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-ca-group001$i.out"
                fi
		#================#

	        if [ $userid == $CA_adminV_user -o $userid == $CA_adminR_user -o $userid == $CA_adminE_user -o $userid == $CA_agentV_user -o $userid == $CA_agentR_user -o $userid == $CA_agentE_user -o $userid == $CA_auditV_user -o $userid == $CA_operatorV_user ]; then

			#Create a cert and add it to the $userid user
			rlLog "Admin Certificate is located at: $CA_ADMIN_CERT_LOCATION"
			local temp_file="/tmp/requestdb/certrequest_001$i.xml"
			rlRun "pki -d $TmpDir/nssdb \
                          -n \"$admin_cert_nickname\" \
                          -c $nss_db_password \
                           cert-request-profile-show caUserCert --output $temp_file" \
                           0 \
                           "Enrollment Template for Profile caUserCert"
			#rlRun "create_certdb \"/tmp/requestdb\" Password" 0 "Create a certificate db"
			rlRun "generate_PKCS10 \"/tmp/requestdb\"  Password rsa 2048 \"/tmp/requestdb/request_001$i.out\" \"CN=adminV\" " 0 "generate PKCS10 certificate"
			rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i /tmp/requestdb/request_001$i.out"
			rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i /tmp/requestdb/request_001$i.out"
			rlRun "dos2unix /tmp/requestdb/request_001$i.out"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v 'pkcs10' $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v /tmp/requestdb/request_001$i.out)\" $temp_file" 0 "adding certificate request"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v $userid $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v $userid@example.com $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v $userfullName $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v Engineering $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v Example $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v US $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v $userid $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v $userid@example.com $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $temp_file"

			if [ $userid == $CA_adminV_user -o $userid == $CA_adminR_user -o $userid == $CA_agentV_user -o $userid == $CA_agentR_user -o $userid == $CA_auditV_user -o $userid == $CA_operatorV_user ]; then
				#cert-request-submit=====
				rlLog "Executing: pki cert-request-submit  $temp_file"
				rlRun "pki cert-request-submit  $temp_file > /tmp/requestdb/certrequest_$i.out" 0 "Executing pki cert-request-submit"
				rlAssertGrep "Submitted certificate request" "/tmp/requestdb/certrequest_$i.out"
				rlAssertGrep "Request ID:" "/tmp/requestdb/certrequest_$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequest_$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequest_$i.out"
				local request_id=`cat /tmp/requestdb/certrequest_$i.out | grep "Request ID:" | awk '{print $3}'`
				rlLog "Request ID=$request_id"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestshow_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestshow_001$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequestshow_001$i.out"
				rlAssertGrep "Operation Result: success" "/tmp/requestdb/certrequestshow_001$i.out"
				 #Agent Approve the certificate after reviewing the cert for the user
				rlLog "Executing: pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t ca \
					    cert-request-review --action=approve $request_id"

				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t ca \
					    cert-request-review --action=approve $request_id > /tmp/requestdb/certapprove_001$i.out" \
					    0 \
					    "CA agent approve the cert"
				rlAssertGrep "Approved certificate request $request_id" "/tmp/requestdb/certapprove_001$i.out"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestapprovedshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Status: complete" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Certificate ID:" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				local certificate_serial_number=`cat /tmp/requestdb/certrequestapprovedshow_001$i.out | grep "Certificate ID:" | awk '{print $3}'`
				rlLog "Cerificate Serial Number=$certificate_serial_number"

				#Verify the certificate is valid
				rlRun "pki cert-show  $certificate_serial_number --encoded > /tmp/requestdb/certificate_show_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
				rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/certificate_show_001$i.out"
				rlAssertGrep "Status: VALID" "/tmp/requestdb/certificate_show_001$i.out"

				rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' /tmp/requestdb/certificate_show_001$i.out > /tmp/requestdb/validcert_001$i.pem"
				rlRun "certutil -d /tmp/requestdb -A -n $userid -i /tmp/requestdb/validcert_001$i.pem  -t "u,u,u""
				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t ca \
					    user-cert-add $userid --input /tmp/requestdb/validcert_001$i.pem  > /tmp/requestdb/useraddcert__001$i.out" \
					    0 \
					    "Cert is added to the user $userid"

			elif [ $userid == $CA_adminE_user -o $userid == $CA_agentE_user ]; then
			 #=======Expired cert waiting on response to --output ticket         https://fedorahosted.org/pki/ticket/674        =======#
				local profile_file="/var/lib/pki/pki-tomcat/ca/profiles/ca/caUserCert.cfg"
				default_days="policyset.userCertSet.2.default.params.range=180"
				change_days="policyset.userCertSet.2.default.params.range=1"
				rlLog "Executing: sed -e 's/$default_days/$change_days/g' -i $profile_file"
	                        rlRun "sed -e 's/$default_days/$change_days/g' -i  $profile_file"
				rlLog "Restart the subsytem"
				rlRun "systemctl restart pki-tomcatd\@pki-tomcat.service"
				#cert-request-submit=====
				#rlLog "Executing: pki cert-request-submit  $temp_file"
				#lRun "pki cert-request-submit  $temp_file > /tmp/requestdb/certrequest_$i.out" 0 "Executing pki cert-request-submit"
				rlRun "cat $profile_file"
				rlRun "sleep 30"
				rlLog "pki -d $TmpDir/nssdb \
                                  -n \"$admin_cert_nickname\" \
                                  -c $nss_db_password \
                                   cert-request-submit  $temp_file  > /tmp/requestdb/certrequest_$i.out"

				rlRun "pki -d $TmpDir/nssdb \
	                          -n \"$admin_cert_nickname\" \
		                  -c $nss_db_password \
			           cert-request-submit  $temp_file  > /tmp/requestdb/certrequest_$i.out" \
				   0 \
				 "Certificate request submit"

				rlAssertGrep "Submitted certificate request" "/tmp/requestdb/certrequest_$i.out"
				rlAssertGrep "Request ID:" "/tmp/requestdb/certrequest_$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequest_$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequest_$i.out"
				local request_id=`cat /tmp/requestdb/certrequest_$i.out | grep "Request ID:" | awk '{print $3}'`
				rlLog "Request ID=$request_id"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestshow_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestshow_001$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequestshow_001$i.out"
				rlAssertGrep "Operation Result: success" "/tmp/requestdb/certrequestshow_001$i.out"
				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t ca \
					    cert-request-review --action=approve  $request_id > /tmp/requestdb/certapprove_001$i.out" \
					    0 \
					    "CA agent approve the cert"
				rlLog "cat /tmp/requestdb/certapprove_001$i.out"
				rlAssertGrep "Approved certificate request $request_id" "/tmp/requestdb/certapprove_001$i.out"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestapprovedshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Status: complete" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Certificate ID:" "/tmp/requestdb/certrequestapprovedshow_001$i.out"
				local certificate_serial_number=`cat /tmp/requestdb/certrequestapprovedshow_001$i.out | grep "Certificate ID:" | awk '{print $3}'`
				rlLog "Cerificate Serial Number=$certificate_serial_number"
				#Verify the certificate is expired
				rlRun "pki cert-show  $certificate_serial_number --encoded > /tmp/requestdb/certificate_show_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
                                rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/certificate_show_001$i.out"
                                rlAssertGrep "Status: VALID" "/tmp/requestdb/certificate_show_001$i.out"
				rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' /tmp/requestdb/certificate_show_001$i.out > /tmp/requestdb/validcert_001$i.pem"
				rlRun "certutil -d /tmp/requestdb -A -n $userid -i /tmp/requestdb/validcert_001$i.pem  -t "u,u,u""
				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t ca \
					    user-cert-add $userid --input /tmp/requestdb/validcert_001$i.pem  > /tmp/requestdb/useraddcert__001$i.out" \
					    0 \
					    "Cert is added to the user $userid"
				rlLog "Modifying profile back to the defaults"
                                rlRun "sed -e 's/$change_days/$default_days/g' -i  $profile_file"
                                rlLog "Restart the subsytem"
                                rlRun "systemctl restart pki-tomcatd\@pki-tomcat.service"
				rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
				rlRun "date"
				rlRun "sleep 30"
				rlRun "pki cert-show  $certificate_serial_number --encoded > /tmp/requestdb/certificate_show_exp_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
				rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/certificate_show_exp_001$i.out"
				rlAssertGrep "Status: EXPIRED" "/tmp/requestdb/certificate_show_exp_001$i.out"
                                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
			fi
     fi
	#Add the certificate to /tmp/requestdb
	#note: certificate b664 at /tmp/requestdb/certificate_show_001$i.out
	if [ $userid == $CA_adminUTCA_user ]; then
		rlRun "certutil -d /tmp/dummydb -A -n $userid -i /opt/rhqa_pki/dummycert1.pem -t ",,""
		rlRun "pki -d /tmp/requestdb/ \
                   -n \"$admin_cert_nickname\" \
                   -c $nss_db_password \
                   -t ca \
                    user-cert-add $userid --input /opt/rhqa_pki/dummycert1.pem  > /tmp/requestdb/useraddcert__001$i.out" \
                    0 \
                    "Cert is added to the user $userid"
	elif [ $userid == $CA_agentUTCA_user ]; then
		rlRun "certutil -d /tmp/dummydb -A -n $userid -i /opt/rhqa_pki/dummycert1.pem -t ",,""
		rlRun "pki -d /tmp/requestdb/ \
                   -n \"$admin_cert_nickname\" \
                   -c $nss_db_password \
                   -t ca \
                    user-cert-add $userid --input /opt/rhqa_pki/dummycert1.pem  > /tmp/requestdb/useraddcert__001$i.out" \
                    0 \
                    "Cert is added to the user $userid"
	#Revoke certificate of user CA_adminR and CA_agentR
	elif [ $userid == $CA_adminR_user -o $userid == $CA_agentR_user ] ;then
			rlLog "$userid"
			rlLog "pki -d /tmp/requestdb/ \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t ca \
			    cert-revoke $certificate_serial_number  --force   --reason = Unspecified  > /tmp/requestdb/revokecert__001$i.out"
			rlRun "pki -d /tmp/requestdb/ \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t ca \
			    cert-revoke $certificate_serial_number  --force   --reason=Unspecified  > /tmp/requestdb/revokecert__001$i.out" \
			    0 \
			    "Certificate of user $userid is revoked"
			rlAssertGrep "Serial Number: $certificate_serial_number" "/tmp/requestdb/revokecert__001$i.out"
			rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/revokecert__001$i.out"
			rlAssertGrep "Status: REVOKED" "/tmp/requestdb/revokecert__001$i.out"
	fi
              let i=$i+2
	done
          rlPhaseEnd
}
