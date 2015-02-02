#!/bin/bash
#!/usr/bin/expect -f

# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/setup
#   Description: Setup needed to run CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# create-role-users    Add role users to pki subsystems.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com>
#            Laxmi Sunkara <lsunkara@redhat.com>
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

run_pki-user-cli-role-user-create-tests(){
subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
rlLog "subsystemId=$subsystemId, SUBSYSTEM_TYPE=$SUBSYSTEM_TYPE, MYROLE=$MYROLE"
if [ "$TOPO9" = "TRUE" ] ; then
	ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
	admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
	CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
elif [ "$MYROLE" = "MASTER" ] ; then
	if [[ $subsystemId == SUBCA* ]]; then
		ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
        	admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
        	CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
	else
		ADMIN_CERT_LOCATION=$ROOTCA_ADMIN_CERT_LOCATION
		admin_cert_nickname=$ROOTCA_ADMIN_CERT_NICKNAME
		CLIENT_PKCS12_PASSWORD=$ROOTCA_CLIENT_PKCS12_PASSWORD
	fi
else
	ADMIN_CERT_LOCATION=$(eval echo \$${MYROLE}_ADMIN_CERT_LOCATION)
	admin_cert_nickname=$(eval echo \$${MYROLE}_ADMIN_CERT_NICKNAME)
	CLIENT_PKCS12_PASSWORD=$(eval echo \$${MYROLE}_CLIENT_PKCS12_PASSWORD)
fi

SUBSYSTEM_HOST=$(eval echo \$${MYROLE})

eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminV_fullName=${subsystemId}_Admin_ValidCert
eval ${subsystemId}_adminV_password=${subsystemId}_adminV_password
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminR_fullName=${subsystemId}_Admin_RevokedCert
eval ${subsystemId}_adminR_password=${subsystemId}_adminR_password
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminE_fullName=${subsystemId}_admin_ExpiredCert
eval ${subsystemId}_adminE_password=${subsystemId}_adminE_password
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_adminUTCA_fullName=${subsystemId}_Admin_CertIssuedByUntrustedCA
eval ${subsystemId}_adminUTCA_password=${subsystemId}_adminUTCA_password
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentV_fullName=${subsystemId}_Agent_ValidCert
eval ${subsystemId}_agentV_password=${subsystemId}_agentV_password
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentR_fullName=${subsystemId}_Agent_RevokedCert
eval ${subsystemId}_agentR_password=${subsystemId}_agentR_password
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_agentE_fullName=${subsystemId}_agent_ExpiredCert
eval ${subsystemId}_agentE_password=${subsystemId}_agentE_password
eval ${subsystemId}_agentUTCA_user=${subsystemId}_agentUTCA
eval ${subsystemId}_agentUTCA_fullName=${subsystemId}_Agent_CertIssuedByUntrustedCA
eval ${subsystemId}_agentUTCA_password=${subsystemId}_agentUTCA_password
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_auditV_fullName=${subsystemId}_Audit_ValidCert
eval ${subsystemId}_auditV_password=${subsystemId}_auditV_password
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
eval ${subsystemId}_operatorV_password=${subsystemId}_operatorV_password
eval ${subsystemId}_operatorV_fullName=${subsystemId}_Operator_ValidCert

export ${subsystemId}_adminV_user ${subsystemId}_adminR_user ${subsystemId}_adminE_user ${subsystemId}_adminUTCA_user ${subsystemId}_agentV_user ${subsystemId}_agentR_user ${subsystemId}_agentE_user ${subsystemId}_agentUT${subsystemId}_user ${subsystemId}_auditV_user ${subsystemId}_operatorV_user
######################################################################

    rlPhaseStartSetup "create-role-user-startup: Create temp directory and import CA agent cert into a nss certificate db and trust CA root cert"
	rlRun "source /opt/rhqa_pki/env.sh"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "export TmpDir"
        rlRun "pushd $TmpDir"

	#rlRun "mkdir -p $CERTDB_DIR"
        rlLog "importP12FileNew $ADMIN_CERT_LOCATION $CLIENT_PKCS12_PASSWORD $CERTDB_DIR $CERTDB_DIR_PASSWORD $admin_cert_nickname"
        rlRun "importP12FileNew $ADMIN_CERT_LOCATION $CLIENT_PKCS12_PASSWORD $CERTDB_DIR $CERTDB_DIR_PASSWORD $admin_cert_nickname" 0 "Import Admin certificate to $CERTDB_DIR"
        rlRun "install_and_trust_CA_cert $ROOTCA_SERVER_ROOT $CERTDB_DIR"
        rlLog "Cert Database for untrusted cert's : $UNTRUSTED_CERT_DB_LOCATION"

	#Create untrusted certificate nss db
	rlRun "create_certdb \"$UNTRUSTED_CERT_DB_LOCATION\" \"$UNTRUSTED_CERT_DB_PASSWORD\"" 0 "Create a nss db for untrusted certs"
        rlRun "install_and_trust_CA_cert $ROOTCA_SERVER_ROOT \"$UNTRUSTED_CERT_DB_LOCATION\""
    rlPhaseEnd

    rlPhaseStartSetup "Creating user and add user to the group"
	 user=($(eval echo \$${subsystemId}_adminV_user) $(eval echo \$${subsystemId}_adminV_fullName) $(eval echo \$${subsystemId}_adminV_password) $(eval echo \$${subsystemId}_adminR_user) $(eval echo \$${subsystemId}_adminR_fullName) $(eval echo \$${subsystemId}_adminR_password) $(eval echo \$${subsystemId}_adminE_user) $(eval echo \$${subsystemId}_adminE_fullName) $(eval echo \$${subsystemId}_adminE_password) $(eval echo \$${subsystemId}_adminUTCA_user) $(eval echo \$${subsystemId}_adminUTCA_fullName) $(eval echo \$${subsystemId}_adminUTCA_password) $(eval echo \$${subsystemId}_agentV_user) $(eval echo \$${subsystemId}_agentV_fullName) $(eval echo \$${subsystemId}_agentV_password)  $(eval echo \$${subsystemId}_agentR_user) $(eval echo \$${subsystemId}_agentR_fullName) $(eval echo \$${subsystemId}_agentR_password) $(eval echo \$${subsystemId}_agentE_user) $(eval echo \$${subsystemId}_agentE_fullName) $(eval echo \$${subsystemId}_agentE_password) $(eval echo \$${subsystemId}_agentUTCA_user) $(eval echo \$${subsystemId}_agentUTCA_fullName) $(eval echo \$${subsystemId}_agentUTCA_password) $(eval echo \$${subsystemId}_auditV_user) $(eval echo \$${subsystemId}_auditV_fullName) $(eval echo \$${subsystemId}_auditV_password) $(eval echo \$${subsystemId}_operatorV_user) $(eval echo \$${subsystemId}_operatorV_fullName) $(eval echo \$${subsystemId}_operatorV_password))
	i=0
	while [ $i -lt ${#user[@]} ] ; do
	       userid=${user[$i]}
	       userfullName=${user[$i+1]}
	       userpasswd=${user[$i+2]}
	      #Create $userid  user
	       rlLog "Executing: pki -d $CERTDB_DIR \
			  -n \"$admin_cert_nickname\" \
			  -c $CERTDB_DIR_PASSWORD \
			  -h $SUBSYSTEM_HOST \
			  -t $SUBSYSTEM_TYPE \
			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   user-add --fullName=\"$userfullName\" --password $userpasswd $userid"
	       rlRun "pki -d $CERTDB_DIR \
			  -n \"$admin_cert_nickname\" \
			  -c $CERTDB_DIR_PASSWORD \
			  -h $SUBSYSTEM_HOST \
			  -t $SUBSYSTEM_TYPE \
			  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   user-add --fullName=\"$userfullName\" --password $userpasswd $userid" 0 "Add user $userid to CA"
	       #=====Adding user to respective  group. Administrator, Certificate Manager Agent, Auditor=====#
		if [ $userid == $(eval echo \$${subsystemId}_adminV_user) -o $userid == $(eval echo \$${subsystemId}_adminR_user) -o $userid == $(eval echo \$${subsystemId}_adminE_user) -o $userid == $(eval echo \$${subsystemId}_adminUTCA_user) ]; then
			    rlRun "pki -d $CERTDB_DIR \
			   -n \"$admin_cert_nickname\" \
			   -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
			   -t $SUBSYSTEM_TYPE \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    group-member-add Administrators $userid > $TmpDir/pki-user-add-${subsystemId}-group001$i.out"  \
			    0 \
			    "Add user $userid to Administrators group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"
		elif [ $userid == $(eval echo \$${subsystemId}_agentV_user) -o $userid == $(eval echo \$${subsystemId}_agentR_user) -o $userid == $(eval echo \$${subsystemId}_agentE_user) -o $userid == $(eval echo \$${subsystemId}_agentUTCA_user) ]; then
			   if [ "$SUBSYSTEM_TYPE" = "ca" ] ; then
                                agent_group_name="Certificate Manager Agents"
                            elif [ "$SUBSYSTEM_TYPE" = "kra" ] ; then
                                agent_group_name="Data Recovery Manager Agents"
                            elif [ "$SUBSYSTEM_TYPE" = "ocsp" ] ; then
                                agent_group_name="Online Certificate Status Manager Agents"
                            elif [ "$SUBSYSTEM_TYPE" = "tks" ] ; then
                                agent_group_name="Token Key Service Manager Agents"
                            elif [ "$SUBSYSTEM_TYPE" = "tps" ] ; then
                                #### Enter correct TPS agent group ####
                                agent_group_name="TPS Manager Agents"
                            fi
                            rlRun "pki -d $CERTDB_DIR \
                                   -n \"$admin_cert_nickname\" \
                                   -c $CERTDB_DIR_PASSWORD \
                                   -h $SUBSYSTEM_HOST \
                                   -t $SUBSYSTEM_TYPE \
                                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                    group-member-add \"$agent_group_name\" $userid > $TmpDir/pki-user-add-${subsystemId}-group001$i.out"  \
                                    0 \
                                    "Add user $userid to $agent_group_name"
                            rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"

		elif [ $userid == $(eval echo \$${subsystemId}_auditV_user) ]; then
			    rlRun "pki -d $CERTDB_DIR \
			   -n \"$admin_cert_nickname\" \
			   -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
			   -t $SUBSYSTEM_TYPE \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    group-member-add Auditors $userid > $TmpDir/pki-user-add-${subsystemId}-group001$i.out"  \
			    0 \
			    "Add user $userid to Auditors group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"

		elif [ $userid == $(eval echo \$${subsystemId}_operatorV_user) ]; then
			    rlRun "pki -d $CERTDB_DIR \
			   -n \"$admin_cert_nickname\" \
			   -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
			   -t $SUBSYSTEM_TYPE \
			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    group-member-add \"Trusted Managers\"  $userid > $TmpDir/pki-user-add-${subsystemId}-group001$i.out"  \
			    0 \
			    "Add user $userid to Trusted Managers  group"
			    rlAssertGrep "Added group member \"$userid\"" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"
			    rlAssertGrep "User: $userid" "$TmpDir/pki-user-add-${subsystemId}-group001$i.out"
                fi
		#================#

	        if [ $userid == $(eval echo \$${subsystemId}_adminV_user) -o $userid == $(eval echo \$${subsystemId}_adminR_user) -o $userid == $(eval echo \$${subsystemId}_adminE_user) -o $userid == $(eval echo \$${subsystemId}_agentV_user) -o $userid == $(eval echo \$${subsystemId}_agentR_user) -o $userid == $(eval echo \$${subsystemId}_agentE_user) -o $userid == $(eval echo \$${subsystemId}_auditV_user) -o $userid == $(eval echo \$${subsystemId}_operatorV_user) ]; then
			if [ "$MYROLE" = "MASTER" ]; then
				get_topo_stack MASTER $TmpDir/topo_file
				if [ $subsystemId = "SUBCA1" ]; then
					MYCAHOST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
				elif [ $subsystemId = "CLONE_CA1" ]; then
                                        MYCAHOST=$(cat $TmpDir/topo_file | grep MY_CLONE_CA | cut -d= -f2)
				else
		                	MYCAHOST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
				fi
			else 
				MYCAHOST=$MYROLE
			fi
			#Create a cert and add it to the $userid user
			rlLog "Admin Certificate is located at: ${subsystemId}_ADMIN_CERT_LOCATION"
			local temp_file="$CERTDB_DIR/certrequest_001$i.xml"
			rlRun "pki -d $CERTDB_DIR \
                          -n \"$admin_cert_nickname\" \
                          -c $CERTDB_DIR_PASSWORD \
			  -h $SUBSYSTEM_HOST \
			  -t ca \
			  -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) \
                           cert-request-profile-show caUserCert --output $temp_file" \
                           0 \
                           "Enrollment Template for Profile caUserCert"
			rlRun "generate_PKCS10 \"$CERTDB_DIR\"  \"$CERTDB_DIR_PASSWORD\" rsa 2048 \"$CERTDB_DIR/request_001$i.out\" \"CN=adminV\" " 0 "generate PKCS10 certificate"
			rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $CERTDB_DIR/request_001$i.out"
			rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $CERTDB_DIR/request_001$i.out"
			rlRun "dos2unix $CERTDB_DIR/request_001$i.out"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v 'pkcs10' $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $CERTDB_DIR/request_001$i.out)\" $temp_file" 0 "adding certificate request"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v $userid $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v $userid@example.com $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v $userfullName $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v Engineering $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v Example $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v US $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v $userid $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v $userid@example.com $temp_file"
			rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $temp_file"

			if [ $userid == $(eval echo \$${subsystemId}_adminV_user) -o $userid == $(eval echo \$${subsystemId}_adminR_user) -o $userid == $(eval echo \$${subsystemId}_agentV_user) -o $userid == $(eval echo \$${subsystemId}_agentR_user) -o $userid == $(eval echo \$${subsystemId}_auditV_user) -o $userid == $(eval echo \$${subsystemId}_operatorV_user) ]; then
				#cert-request-submit=====
				#subsystem can be ca or tps
				subsystem=ca    
				rlLog "Executing: pki cert-request-submit  $temp_file"
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-request-submit $temp_file > $CERTDB_DIR/certrequest_$i.out" 0 "Executing pki cert-request-submit"
				rlAssertGrep "Submitted certificate request" "$CERTDB_DIR/certrequest_$i.out"
				rlAssertGrep "Request ID:" "$CERTDB_DIR/certrequest_$i.out"
				rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequest_$i.out"
				rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequest_$i.out"
				local request_id=`cat $CERTDB_DIR/certrequest_$i.out | grep "Request ID:" | awk '{print $3}'`
				rlLog "Request ID=$request_id"
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-request-show $request_id > $CERTDB_DIR/certrequestshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlAssertGrep "Operation Result: success" "$CERTDB_DIR/certrequestshow_001$i.out"
				 #Agent Approve the certificate after reviewing the cert for the user
				rlLog "Executing: pki -d $CERTDB_DIR \
					   -n \"$admin_cert_nickname\" \
					   -c $CERTDB_DIR_PASSWORD \
					   -h $SUBSYSTEM_HOST \
   		                           -t ca \
   			                   -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) \
					   cert-request-review $request_id --action=approve"

				rlRun "pki -d $CERTDB_DIR \
					   -n \"$admin_cert_nickname\" \
					   -c $CERTDB_DIR_PASSWORD \
					   -h $SUBSYSTEM_HOST \
                 		           -t ca \
    		                           -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) \
					   cert-request-review $request_id --action=approve > $CERTDB_DIR/certapprove_001$i.out" \
					    0 \
					    "CA agent approve the cert"
				rlAssertGrep "Approved certificate request $request_id" "$CERTDB_DIR/certapprove_001$i.out"
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-request-show $request_id > $CERTDB_DIR/certrequestapprovedshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Status: complete" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Certificate ID:" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				local certificate_serial_number=`cat $CERTDB_DIR/certrequestapprovedshow_001$i.out | grep "Certificate ID:" | awk '{print $3}'`
				rlLog "Cerificate Serial Number=$certificate_serial_number"

				#Verify the certificate is valid
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-show  $certificate_serial_number --encoded > $CERTDB_DIR/certificate_show_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
				rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "$CERTDB_DIR/certificate_show_001$i.out"
				rlAssertGrep "Status: VALID" "$CERTDB_DIR/certificate_show_001$i.out"

				rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $CERTDB_DIR/certificate_show_001$i.out > $CERTDB_DIR/validcert_001$i.pem"
				rlRun "certutil -d $CERTDB_DIR -A -n $userid -i $CERTDB_DIR/validcert_001$i.pem  -t "u,u,u""
				rlRun "pki -d $CERTDB_DIR/ \
					   -n \"$admin_cert_nickname\" \
					   -c $CERTDB_DIR_PASSWORD \
				           -h $SUBSYSTEM_HOST \
                        		   -t $SUBSYSTEM_TYPE \
		                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
					   user-cert-add $userid --input $CERTDB_DIR/validcert_001$i.pem  > $CERTDB_DIR/useraddcert_001$i.out" \
					    0 \
					    "Cert is added to the user $userid"

			elif [ $userid == $(eval echo \$${subsystemId}_adminE_user) -o $userid == $(eval echo \$${subsystemId}_agentE_user) ]; then
			 #=======Expired cert waiting on response to --output ticket         https://fedorahosted.org/pki/ticket/674        =======#
				if [ "$MYROLE" = "MASTER" ]; then
                                get_topo_stack MASTER $TmpDir/topo_file
                                if [ $subsystemId = "SUBCA1" ]; then
                                        MYHOSTCA=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
                                elif [ $subsystemId = "CLONE_CA1" ]; then
                                        MYHOSTCA=$(cat $TmpDir/topo_file | grep MY_CLONE_CA | cut -d= -f2)
                                else
                                        MYHOSTCA=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
                                fi
                        else
                                MYHOSTCA=$MYROLE
                        fi

				local profile_file="/var/lib/pki/$(eval echo \$${MYHOSTCA}_TOMCAT_INSTANCE_NAME)/ca/profiles/ca/caUserCert.cfg"
				default_days="policyset.userCertSet.2.default.params.range=180"
				change_days="policyset.userCertSet.2.default.params.range=1"
				rlLog "Executing: sed -e 's/$default_days/$change_days/g' -i $profile_file"
	                        rlRun "sed -e 's/$default_days/$change_days/g' -i  $profile_file"
				rlLog "Restart the subsytem"
				rlRun "systemctl restart pki-tomcatd@$(eval echo \$${MYHOSTCA}_TOMCAT_INSTANCE_NAME).service"
				#cert-request-submit=====
				#rlLog "Executing: pki cert-request-submit  $temp_file"
				#lRun "pki cert-request-submit  $temp_file > $CERTDB_DIR/certrequest_$i.out" 0 "Executing pki cert-request-submit"
				rlRun "cat $profile_file"
				rlRun "sleep 30"
				rlLog "pki -d $CERTDB_DIR \
                                  -n \"$admin_cert_nickname\" \
                                  -c $CERTDB_DIR_PASSWORD \
			          -h $SUBSYSTEM_HOST \
                                  -t ca \
                                  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                                  cert-request-submit  $temp_file  > $CERTDB_DIR/certrequest_$i.out"

				rlRun "pki -d $CERTDB_DIR \
	                          -n \"$admin_cert_nickname\" \
		                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
                                  -t ca \
                                  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			          cert-request-submit  $temp_file  > $CERTDB_DIR/certrequest_$i.out" \
				   0 \
				 "Certificate request submit"

				rlAssertGrep "Submitted certificate request" "$CERTDB_DIR/certrequest_$i.out"
				rlAssertGrep "Request ID:" "$CERTDB_DIR/certrequest_$i.out"
				rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequest_$i.out"
				rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequest_$i.out"
				local request_id=`cat $CERTDB_DIR/certrequest_$i.out | grep "Request ID:" | awk '{print $3}'`
				rlLog "Request ID=$request_id"
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-request-show $request_id > $CERTDB_DIR/certrequestshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlAssertGrep "Operation Result: success" "$CERTDB_DIR/certrequestshow_001$i.out"
				rlRun "pki -d $CERTDB_DIR/ \
					   -n \"$admin_cert_nickname\" \
					   -c $CERTDB_DIR_PASSWORD \
 					   -h $SUBSYSTEM_HOST \
                                           -t ca \
                                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
					   cert-request-review --action=approve  $request_id > $CERTDB_DIR/certapprove_001$i.out" \
					    0 \
					    "CA agent approve the cert"
				rlLog "cat $CERTDB_DIR/certapprove_001$i.out"
				rlAssertGrep "Approved certificate request $request_id" "$CERTDB_DIR/certapprove_001$i.out"
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-request-show $request_id > $CERTDB_DIR/certrequestapprovedshow_001$i.out" 0 "Executing pki cert-request-show $request_id"
				rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Status: complete" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				rlAssertGrep "Certificate ID:" "$CERTDB_DIR/certrequestapprovedshow_001$i.out"
				local certificate_serial_number=`cat $CERTDB_DIR/certrequestapprovedshow_001$i.out | grep "Certificate ID:" | awk '{print $3}'`
				rlLog "Cerificate Serial Number=$certificate_serial_number"
				#Verify the certificate is expired
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-show  $certificate_serial_number --encoded > $CERTDB_DIR/certificate_show_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
                                rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "$CERTDB_DIR/certificate_show_001$i.out"
                                rlAssertGrep "Status: VALID" "$CERTDB_DIR/certificate_show_001$i.out"
				rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $CERTDB_DIR/certificate_show_001$i.out > $CERTDB_DIR/validcert_001$i.pem"
				rlRun "certutil -d $CERTDB_DIR -A -n $userid -i $CERTDB_DIR/validcert_001$i.pem  -t "u,u,u""
				rlRun "pki -d $CERTDB_DIR/ \
					   -n \"$admin_cert_nickname\" \
					   -c $CERTDB_DIR_PASSWORD  \
 					   -h $SUBSYSTEM_HOST \
				 	   -t $SUBSYSTEM_TYPE \
                                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
					    user-cert-add $userid --input $CERTDB_DIR/validcert_001$i.pem > $CERTDB_DIR/useraddcert__001$i.out" \
					    0 \
					    "Cert is added to the user $userid"
				rlLog "Modifying profile back to the defaults"
                                rlRun "sed -e 's/$change_days/$default_days/g' -i  $profile_file"
                                rlLog "Restart the subsytem"
                                rlRun "systemctl restart pki-tomcatd@$(eval echo \$${MYHOSTCA}_TOMCAT_INSTANCE_NAME).service"
				rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
				rlRun "date"
				rlRun "sleep 30"
				rlRun "pki -p $(eval echo \$${MYCAHOST}_UNSECURE_PORT) -h $SUBSYSTEM_HOST ${subsystem}-cert-show  $certificate_serial_number --encoded > $CERTDB_DIR/certificate_show_exp_001$i.out" 0 "Executing pki cert-show $certificate_serial_number"
				rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "$CERTDB_DIR/certificate_show_exp_001$i.out"
				rlAssertGrep "Status: EXPIRED" "$CERTDB_DIR/certificate_show_exp_001$i.out"
                                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
			fi
     fi
	#Add the certificate to $CERTDB_DIR
	#note: certificate b64 at $CERTDB_DIR/certificate_show_001$i.out
	if [ $userid == $(eval echo \$${subsystemId}_adminUTCA_user) ]; then
		rlRun "certutil -d $UNTRUSTED_CERT_DB_LOCATION -A -n role_user_UTCA -i /opt/rhqa_pki/dummycert1.pem -t ",,""
		rlLog "pki -d $CERTDB_DIR/ \
                   -n \"$admin_cert_nickname\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $SUBSYSTEM_HOST \
                   -t ca \
                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   user-cert-add $userid --input /opt/rhqa_pki/dummycert1.pem"

		rlRun "pki -d $CERTDB_DIR/ \
                   -n \"$admin_cert_nickname\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $SUBSYSTEM_HOST \
		   -t $SUBSYSTEM_TYPE \
                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		   user-cert-add $userid --input /opt/rhqa_pki/dummycert1.pem > $CERTDB_DIR/useraddcert__001$i.out" \
                    0 \
                    "Cert is added to the user $userid"
	elif [ $userid == $(eval echo \$${subsystemId}_agentUTCA_user) ]; then
		rlRun "certutil -d $UNTRUSTED_CERT_DB_LOCATION -A -n role_user_UTCA -i /opt/rhqa_pki/dummycert1.pem -t ",,""
		rlRun "pki -d $CERTDB_DIR/ \
                   -n \"$admin_cert_nickname\" \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
		   -t $SUBSYSTEM_TYPE \
                   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-cert-add $userid --input /opt/rhqa_pki/dummycert1.pem > $CERTDB_DIR/useraddcert__001$i.out" \
                    0 \
                    "Cert is added to the user $userid"
	#Revoke certificate of user ${subsystemId}_adminR and ${subsystemId}_agentR
	elif [ $userid == $(eval echo \$${subsystemId}_adminR_user) -o $userid == $(eval echo \$${subsystemId}_agentR_user) ] ;then
			rlLog "$userid"
			rlLog "pki -d $CERTDB_DIR/ \
			   -n \"$admin_cert_nickname\" \
			   -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
                           -t ca \
                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    cert-revoke $certificate_serial_number  --force   --reason = Unspecified  > $CERTDB_DIR/revokecert__001$i.out"
			rlRun "pki -d $CERTDB_DIR/ \
			   -n \"$admin_cert_nickname\" \
			   -c $CERTDB_DIR_PASSWORD \
			   -h $SUBSYSTEM_HOST \
                   	   -t ca \
                   	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			    cert-revoke $certificate_serial_number  --force   --reason=Unspecified  > $CERTDB_DIR/revokecert__001$i.out" \
			    0 \
			    "Certificate of user $userid is revoked"
			rlAssertGrep "Serial Number: $certificate_serial_number" "$CERTDB_DIR/revokecert__001$i.out"
			rlAssertGrep "Subject: UID=$userid,E=$userid@example.com,CN=$userfullName,OU=Engineering,O=Example,C=US" "$CERTDB_DIR/revokecert__001$i.out"
			rlAssertGrep "Status: REVOKED" "$CERTDB_DIR/revokecert__001$i.out"
	fi
              let i=$i+3
	done
   rlPhaseEnd
}
