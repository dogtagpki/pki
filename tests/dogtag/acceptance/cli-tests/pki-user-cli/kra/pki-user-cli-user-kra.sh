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
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

########################################################################
# Test Suite Globals
########################################################################
KRA_adminV_user=KRA_adminV
KRA_adminV_fullName=KRA_Admin_ValidCert
KRA_adminR_user=KRA_adminR
KRA_adminR_fullName=KRA_Admin_RevokedCert
KRA_adminE_user=KRA_adminE
KRA_adminE_fullName=KRA_admin_ExpiredCert
KRA_adminUTKRA_user=KRA_adminUTCA
KRA_adminUTKRA_fullName=KRA_Admin_CertIssuedByUntrustedCA

KRA_agentV_user=KRA_agentV
KRA_agentV_fullName=KRA_Agent_ValidCert
KRA_agentR_user=KRA_agentR
KRA_agentR_fullName=KRA_Agent_RevokedCert
KRA_agentE_user=KRA_agentE
KRA_agentE_fullName=KRA_agent_ExpiredCert
KRA_agentUTKRA_user=KRA_agentUTCA
KRA_agentUTKRA_fullName=KRA_Agent_CertIssuedByUntrustedCA

KRA_auditV_user=KRA_auditV
KRA_auditV_fullName=KRA_Audit_ValidCert
KRA_operatorV_user=KRA_operatorV
KRA_operatorV_fullName=KRA_Operator_ValidCert

export KRA_adminV_user KRA_adminR_user KRA_adminE_user KRA_adminUTKRA_user KRA_agentV_user KRA_agentR_user KRA_agentE_user KRA_agentUTKRA_user KRA_auditV_user KRA_operatorV_user
######################################################################

run_pki-user-cli-user-kra_tests(){
    rlPhaseStartSetup "pki_user_cli_user_add-kra-startup:Getting the temp directory and nss certificate db "
         rlLog "nss_db directory = $TmpDir/nssdb"
         rlLog "temp directory = /tmp/requestdb"
    rlPhaseEnd
    rlPhaseStartSetup "pki_user_cli_user_kra-startup: Importing kra agent cert into certificate db and trust KRA root cert"
	rlRun "install_and_trust_KRA_cert $KRA_SERVER_ROOT $TmpDir/nssdb"
        rlRun "install_and_trust_KRA_cert $KRA_SERVER_ROOT /tmp/requestdb"
    rlPhaseEnd
    rlPhaseStartSetup "Creating user, create user and add it to the user, add user to the group"
	 user=($KRA_adminV_user $KRA_adminV_fullName $KRA_adminR_user $KRA_adminR_fullName $KRA_adminE_user $KRA_adminE_fullName $KRA_adminUTKRA_user $KRA_adminUTKRA_fullName $KRA_agentV_user $KRA_agentV_fullName $KRA_agentR_user $KRA_agentR_fullName $KRA_agentE_user $KRA_agentE_fullName $KRA_agentUTKRA_user $KRA_agentUTKRA_fullName $KRA_auditV_user $KRA_auditV_fullName $KRA_operatorV_user $KRA_operatorV_fullName)
	i=0
	while [ $i -lt ${#user[@]} ] ; do
	       userid=${user[$i]}
	       userfullName=${user[$i+1]}

	      #Create $userid  user
	       rlLog "Executing: pki -d $TmpDir/nssdb \
			  -n \"$admin_cert_nickname\" \
			  -c $nss_db_password \
			  -t kra \
			   user-add --fullName=\"$userfullName\" $userid"
	       rlRun "pki -d $TmpDir/nssdb \
			  -n \"$admin_cert_nickname\" \
			  -c $nss_db_password \
			  -t kra \
			   user-add --fullName=\"$userfullName\" $userid" \
			   0 \
			   "Add user $userid to KRA"

	       #=====Adding user to respective  group. Administrator, Date Recovery Manager Agent, Auditor=====#
		if [ $userid == $KRA_adminV_user -o $userid == $KRA_adminR_user -o $userid == $KRA_adminE_user -o $userid == $KRA_adminUTKRA_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t kra \
			    group-add-member Administrators $userid > $TmpDir/pki-user-add-kra-group001$i.out"  \
			    0 \
			    "Add user $userid to Administrators group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-kra-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-kra-group001$i.out"
		elif [ $userid == $KRA_agentV_user -o $userid == $KRA_agentR_user -o $userid == $KRA_agentE_user -o $userid == $KRA_agentUTKRA_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t kra \
			    group-add-member \"Data Recovery Manager Agents\" $userid > $TmpDir/pki-user-add-kra-group001$i.out"  \
			    0 \
			    "Add user $userid to Data Recovery Manager Agents group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-kra-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-kra-group001$i.out"

		elif [ $userid == $KRA_auditV_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t kra \
			    group-add-member Auditors $userid > $TmpDir/pki-user-add-kra-group001$i.out"  \
			    0 \
			    "Add user $userid to Auditors group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-kra-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-kra-group001$i.out"

		elif [ $userid == $KRA_operatorV_user ]; then
			    rlRun "pki -d $TmpDir/nssdb \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t kra \
			    group-add-member \"Trusted Managers\"  $userid > $TmpDir/pki-user-add-kra-group001$i.out"  \
			    0 \
			    "Add user $userid to Trusted Managers  group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-kra-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-kra-group001$i.out"
                fi
		#================#

	        if [ $userid == $KRA_adminV_user -o $userid == $KRA_adminR_user -o $userid == $KRA_adminE_user -o $userid == $KRA_agentV_user -o $userid == $KRA_agentR_user -o $userid == $KRA_agentE_user -o $userid == $KRA_auditV_user -o $userid == $KRA_operatorV_user ]; then

			#Create a cert and add it to the $userid user
			rlLog "Admin Certificate is located at: $KRA_ADMIN_CERT_LOCATION"
			local sample_request_file1="/opt/rhqa_pki/cert_request_caUserCert1_1.in"
			local sample_request_file2="/opt/rhqa_pki/cert_request_caUserCert1_2.in"
			local temp_file="/tmp/requestdb/certrequest_kra_001$i.in"
			#rlRun "create_certdb \"/tmp/requestdb\" Password" 0 "Create a certificate db"
			rlRun "generate_PKCS10 \"/tmp/requestdb\"  Password rsa 2048 \"/tmp/requestdb/request_kra_001$i.out\" \"CN=adminV\" " 0 "generate PKCS10 certificate"

			rlLog "Create a certificate request XML file.."
			local search_string1="<InputAttr name=\"cert_request_type\">crmf<\/InputAttr>"
			local replace_string1="\<InputAttr name=\"cert_request_type\"\>pkcs10\<\/InputAttr\>"
			rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i /tmp/requestdb/request_kra_001$i.out"
			rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i /tmp/requestdb/request_kra_001$i.out"
			#local cert_request=`cat /tmp/request_001$i.out`
			rlRun "cat $sample_request_file1 /tmp/requestdb/request_kra_001$i.out $sample_request_file2 >  $temp_file"
			rlLog "Executing: sed -e 's/$search_string1/$replace_string1/' -i $temp_file"
			rlRun "sed -e 's/$search_string1/$replace_string1/' -i  $temp_file"
			local search_string2="testuser"
			local replace_string2=$userid
			rlLog "Executing: sed -e 's/$search_string2/$replace_string2/g' -i $temp_file"
			rlRun "sed -e 's/$search_string2/$replace_string2/g' -i  $temp_file"
			local search_string3="Test User"
			local replace_string3=$userfullName
			rlLog "Executing: sed -e 's/$search_string3/$replace_string3/g' -i $temp_file"
			rlRun "sed -e 's/$search_string3/$replace_string3/g' -i  $temp_file"

			if [ $userid == $KRA_adminV_user -o $userid == $KRA_adminR_user -o $userid == $KRA_agentV_user -o $userid == $KRA_agentR_user -o $userid == $KRA_auditV_user -o $userid == $KRA_operatorV_user ]; then
				#cert-request-submit=====
				rlLog "Executing: pki cert-request-submit  $temp_file"
				rlRun "pki cert-request-submit  $temp_file > /tmp/requestdb/certrequest_kra_$i.out" 0 "Executing pki cert-request-submit"
				rlAssertGrep "Submitted certificate request" "/tmp/requestdb/certrequest_kra_$i.out"
				rlAssertGrep "Request ID:" "/tmp/requestdb/certrequest_kra_$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequest_kra_$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequest_kra_$i.out"
				local request_id=`cat /tmp/requestdb/certrequest_kra_$i.out | grep "Request ID:" | awk '{print $3}'`
				rlLog "Request ID=$request_id"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestshow_kra_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlAssertGrep "Operation Result: success" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				 #Agent Approve the certificate after reviewing the cert for the user
				rlLog "Executing: pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t kra \
					    cert-request-review --action=approve $request_id"

				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t kra \
					    cert-request-review --action=approve $request_id > /tmp/requestdb/certapprove_kra_001$i.out" \
					    0 \
					    "KRA agent approve the cert"
				rlAssertGrep "Approved certificate request $request_id" "/tmp/requestdb/certapprove_kra_001$i.out"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestapprovedshow_kra_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				rlAssertGrep "Status: complete" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				rlAssertGrep "Certificate ID:" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				local certificate_serial_number=`cat /tmp/requestdb/certrequestapprovedshow_kra_001$i.out | grep "Certificate ID:" | awk '{print $3}'`
				rlLog "Cerificate Serial Number=$certificate_serial_number"

				#Verify the certificate is valid
				rlRun "pki cert-show  $certificate_serial_number --encoded > /tmp/requestdb/certificate_show_kra_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
				rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/certificate_show_kra_001$i.out"
				rlAssertGrep "Status: VALID" "/tmp/requestdb/certificate_show_kra_001$i.out"

				rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' /tmp/requestdb/certificate_show_kra_001$i.out > /tmp/requestdb/validcert_kra_001$i.pem"
				rlRun "certutil -d /tmp/requestdb -A -n $userid -i /tmp/requestdb/validcert_kra_001$i.pem  -t "u,u,u""
				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t kra \
					    user-add-cert $userid --input /tmp/requestdb/validcert_kra_001$i.pem  > /tmp/requestdb/useraddcert_kra_001$i.out" \
					    0 \
					    "Cert is added to the user $userid"

			elif [ $userid == $KRA_adminE_user -o $userid == $KRA_agentE_user ]; then
			 #=======Expired cert waiting on response to --output ticket         https://fedorahosted.org/pki/ticket/674        =======#
				local profile_file="/var/lib/pki/pki-tomcat/ca/profiles/ca/caUserCert.cfg"
				default_days="policyset.userCertSet.2.default.params.range=180"
				change_days="policyset.userCertSet.2.default.params.range=1"
				rlLog "Executing: sed -e 's/$default_days/$change_days/g' -i $profile_file"
	                        rlRun "sed -e 's/$default_days/$change_days/g' -i  $profile_file"
				rlLog "Restart the subsytem"
				rlRun "systemctl restart pki-tomcatd\@pki-tomcat.service"
				#cert-request-submit=====
				rlLog "Executing: pki cert-request-submit  $temp_file"
				rlRun "pki cert-request-submit  $temp_file > /tmp/requestdb/certrequest_kra_$i.out" 0 "Executing pki cert-request-submit"
				rlAssertGrep "Submitted certificate request" "/tmp/requestdb/certrequest_kra_$i.out"
				rlAssertGrep "Request ID:" "/tmp/requestdb/certrequest_kra_$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequest_kra_$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequest_kra_$i.out"
				local request_id=`cat /tmp/requestdb/certrequest_kra_$i.out | grep "Request ID:" | awk '{print $3}'`
				rlLog "Request ID=$request_id"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestshow_kra_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlAssertGrep "Status: pending" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlAssertGrep "Operation Result: success" "/tmp/requestdb/certrequestshow_kra_001$i.out"
				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t kra \
					    cert-request-review --action=approve  $request_id > /tmp/requestdb/certapprove_kra_001$i.out" \
					    0 \
					    "KRA agent approve the cert"
				rlLog "cat /tmp/requestdb/certapprove_kra_001$i.out"
				rlAssertGrep "Approved certificate request $request_id" "/tmp/requestdb/certapprove_kra_001$i.out"
				rlRun "pki cert-request-show $request_id > /tmp/requestdb/certrequestapprovedshow_kra_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				rlAssertGrep "Type: enrollment" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				rlAssertGrep "Status: complete" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				rlAssertGrep "Certificate ID:" "/tmp/requestdb/certrequestapprovedshow_kra_001$i.out"
				local certificate_serial_number=`cat /tmp/requestdb/certrequestapprovedshow_kra_001$i.out | grep "Certificate ID:" | awk '{print $3}'`
				rlLog "Cerificate Serial Number=$certificate_serial_number"
				#Verify the certificate is expired
				rlRun "pki cert-show  $certificate_serial_number --encoded > /tmp/requestdb/certificate_show_kra_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
                                rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/certificate_show_kra_001$i.out"
                                rlAssertGrep "Status: VALID" "/tmp/requestdb/certificate_show_kra_001$i.out"
				rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' /tmp/requestdb/certificate_show_kra_001$i.out > /tmp/requestdb/validcert_kra_001$i.pem"
				rlRun "certutil -d /tmp/requestdb -A -n $userid -i /tmp/requestdb/validcert_kra_001$i.pem  -t "u,u,u""
				rlRun "pki -d /tmp/requestdb/ \
					   -n \"$admin_cert_nickname\" \
					   -c $nss_db_password \
					   -t kra \
					    user-add-cert $userid --input /tmp/requestdb/validcert_kra_001$i.pem  > /tmp/requestdb/useraddcert_kra_001$i.out" \
					    0 \
					    "Cert is added to the user $userid"
				rlLog "Modifying profile back to the defaults"
                                rlRun "sed -e 's/$change_days/$default_days/g' -i  $profile_file"
                                rlLog "Restart the subsytem"
                                rlRun "systemctl restart pki-tomcatd\@pki-tomcat.service"
				rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
				rlRun "date"
				rlRun "pki cert-show  $certificate_serial_number --encoded > /tmp/requestdb/certificate_show_exp_kra_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
				rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/certificate_show_exp_kra_001$i.out"
				rlAssertGrep "Status: EXPIRED" "/tmp/requestdb/certificate_show_exp_kra_001$i.out"
                                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
			fi
     fi
	#Add the certificate to /tmp/requestdb
	#note: certificate b664 at /tmp/requestdb/certificate_show_kra_001$i.out
	if [ $userid == $KRA_adminUTKRA_user ]; then
		rlRun "certutil -d /tmp/dummydb -A -n $userid -i /opt/rhqa_pki/dummycert1.pem -t ",,""
		rlRun "pki -d /tmp/requestdb/ \
                   -n \"$admin_cert_nickname\" \
                   -c $nss_db_password \
                   -t kra \
                    user-add-cert $userid --input /opt/rhqa_pki/dummycert1.pem  > /tmp/requestdb/useraddcert_kra_001$i.out" \
                    0 \
                    "Cert is added to the user $userid"
	elif [ $userid == $KRA_agentUTKRA_user ]; then
		rlRun "certutil -d /tmp/dummydb -A -n $userid -i /opt/rhqa_pki/dummycert1.pem -t ",,""
		rlRun "pki -d /tmp/requestdb/ \
                   -n \"$admin_cert_nickname\" \
                   -c $nss_db_password \
                   -t kra \
                    user-add-cert $userid --input /opt/rhqa_pki/dummycert1.pem  > /tmp/requestdb/useraddcert_kra_001$i.out" \
                    0 \
                    "Cert is added to the user $userid"
	#Revoke certificate of user KRA_adminR and KRA_agentR
	elif [ $userid == $KRA_adminR_user -o $userid == $KRA_agentR_user ] ;then
			rlLog "$userid"
			rlLog "pki -d /tmp/requestdb/ \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t kra \
			    cert-revoke $certificate_serial_number  --force   --reason = Unspecified  > /tmp/requestdb/revokecert_kra_001$i.out"
			rlRun "pki -d /tmp/requestdb/ \
			   -n \"$admin_cert_nickname\" \
			   -c $nss_db_password \
			   -t kra \
			    cert-revoke $certificate_serial_number  --force   --reason=Unspecified  > /tmp/requestdb/revokecert_kra_001$i.out" \
			    0 \
			    "Certificate of user $userid is revoked"
			rlAssertGrep "Serial Number: $certificate_serial_number" "/tmp/requestdb/revokecert_kra_001$i.out"
			rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "/tmp/requestdb/revokecert_kra_001$i.out"
			rlAssertGrep "Status: REVOKED" "/tmp/requestdb/revokecert_kra_001$i.out"
	fi
              let i=$i+2
	done
          rlPhaseEnd
}
