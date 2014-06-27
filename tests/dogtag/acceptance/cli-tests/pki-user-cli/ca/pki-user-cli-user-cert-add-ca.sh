#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-cert-add    Finding the certs assigned to users in the pki ca subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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

######################################################################################
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-cert-find-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-user-cli-user-cert-add-ca_tests(){

	##### Create a temporary directory to save output files #####
   rlPhaseStartSetup "pki_user_cli_user_cert-add-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

local cert_info="$TmpDir/cert_info"
user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
testname="pki_user_cert_add"
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
##### pki_user_cli_user_cert_add_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-add-configtest-001: pki user-cert-add configuration test"
        rlRun "pki user-cert-add --help > $TmpDir/pki_user_cert_add_cfg.out 2>&1" \
                0 \
                "User cert add configuration"
        rlAssertGrep "user-cert-add <User ID> --input <file> \[OPTIONS...\]" "$TmpDir/pki_user_cert_add_cfg.out"
        rlAssertGrep "--input <file>   Input file" "$TmpDir/pki_user_cert_add_cfg.out"
	rlAssertGrep "--help           Show help options" "$TmpDir/pki_user_cert_add_cfg.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Tests to add certs to CA users ####
	
        ##### Add one cert to a user #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-002-tier1: Add one cert to a user should succeed"
        k=2
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user2fullname\" $user2"
        cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$user2\" \"$user2fullname\" $user2@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$user2\" \"$user2fullname\" $user2@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002pkcs10.out"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out" \
                            0 \
                            "CRMF Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002crmf.out"

	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-del $user2"
	rlPhaseEnd

	##### Add multiple certs to a user #####

    rlPhaseStartTest "pki_user_cli_user_cert-add-CA-003: Add multiple certs to a user should succeed"
        i=0
	k=3
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user1fullname\" $user1"
        while [ $i -lt 4 ] ; do
	cert_type="pkcs10"		
	rlRun "generate_user_cert $cert_info $k \"$user1$(($i+1))\" \"$user1fullname$(($i+1))\" $user1$(($i+1))@example.org $testname $cert_type $i" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
	cert_type="crmf"   
        rlRun "generate_user_cert $cert_info $k \"$user1$(($i+1))\" \"$user1fullname$(($i+1))\" $user1$(($i+1))@example.org $testname $cert_type $i" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003pkcs10$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003pkcs10$i.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out"
	        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out"
        	rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out"
        	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out"
        	rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003pkcs10_$i.out"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003crmf$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003crmf$i.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out"
                rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003crmf_$i.out"

                let i=$i+1
        done
        rlPhaseEnd

        ##### Add expired cert to a user #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-004: Adding expired cert to a user should fail"
	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user2fullname\" $user2"
        local reqstatus
        local requestid
        local requestdn
	local crmf_reqstatus
        local crmf_requestid
        local crmf_requestdn
                rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"$user2fullname\" "$user2" "$user2@example.org" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""

                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_add_CA_certrequestshow_004.out" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004.out"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004.out"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004.out"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004.out"

                exp="$TmpDir/expfile.out"
                expfile="$exp"
                expout="$TmpDir/expout.out"
                local endDate="1 month"
                updateddate=$(date --date="$endDate" +%Y-%m-%d)
                 echo "set timeout 5" > $expfile
                echo "set force_conservative 0" >> $expfile
                echo "set send_slow {1 .1}" >> $expfile
                echo "spawn -noecho pki -d /opt/rhqa_pki/certs_db -n "CA_agentV" -c redhat123  cert-request-review $requestid --file $TEMP_NSS_DB/$requestid-req.xml" >> $expfile
                echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $expfile
                echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" -v \\\"$updateddate 13:37:56\\\" $TEMP_NSS_DB/$requestid-req.xml\"" >> $expfile
                echo "send -- \"approve\r\"" >> $expfile
                echo "expect eof" >> $expfile
                rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
                if [ $? != 0 ]; then
                {
                        rlFail "Request Approval failed"
                        return 1;
                }
                fi
                rlAssertGrep "Approved certificate request $requestid" "$expout"
                local valid_pkcs10_serialNumber=$(pki cert-request-show $requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
                local cert_start_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
                local cert_end_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not After" | awk -F ": " '{print $2}')

                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_add_CA_certapprovedshow_004.out" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004.out"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004.out"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004.out"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004.out"
                local certificate_serial_number=`cat $TmpDir/pki_user_cert_add_CA_certapprovedshow_004.out | grep "Certificate ID:" | awk '{print $3}'`
                rlLog "Cerificate Serial Number=$certificate_serial_number"
                #Verify the certificate is valid
                rlRun "pki cert-show  $certificate_serial_number --encoded > $TmpDir/pki_user_cert_add_CA_certificate_show_004.out" 0 "Executing pki cert-show $certificate_serial_number"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_certificate_show_004.out"
                rlAssertGrep "Status: VALID" "$TmpDir/pki_user_cert_add_CA_certificate_show_004.out"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add_CA_certificate_show_004.out > $TmpDir/pki_user_cert_add_CA_validcert_004.pem"

		 rlRun "create_cert_request $CERTDB_DIR redhat123 crmf rsa 2048 \"$user2fullname\" "$user2" "$user2@example.org" "Engineering" "Example" "US" "--" "crmf_reqstatus" "crmf_requestid" "crmf_requestdn""

                rlRun "pki cert-request-show $crmf_requestid > $TmpDir/pki_user_cert_add_CA_certrequestshow_004crmf.out" 0 "Executing pki cert-request-show $crmf_requestid"
                rlAssertGrep "Request ID: $crmf_requestid" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004crmf.out"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004crmf.out"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004crmf.out"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_add_CA_certrequestshow_004crmf.out"

                exp="$TmpDir/expfilecrmf.out"
                expfile="$exp"
                expout="$TmpDir/expoutcrmf.out"
                 echo "set timeout 5" > $expfile
                echo "set force_conservative 0" >> $expfile
                echo "set send_slow {1 .1}" >> $expfile
                echo "spawn -noecho pki -d /opt/rhqa_pki/certs_db -n "CA_agentV" -c redhat123  cert-request-review $crmf_requestid --file $TEMP_NSS_DB/$crmf_requestid-req.xml" >> $expfile
                echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $expfile
                echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" -v \\\"$updateddate 13:37:56\\\" $TEMP_NSS_DB/$crmf_requestid-req.xml\"" >> $expfile
                echo "send -- \"approve\r\"" >> $expfile
                echo "expect eof" >> $expfile
                rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
                if [ $? != 0 ]; then
                {
                        rlFail "Request Approval failed"
                        return 1;
                }
                fi
                rlAssertGrep "Approved certificate request $crmf_requestid" "$expout"
                local valid_crmf_serialNumber=$(pki cert-request-show $crmf_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
                local cert_crmf_start_date=$(pki cert-show $valid_crmf_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
                local cert_crmf_end_date=$(pki cert-show $valid_crmf_serialNumber | grep "Not After" | awk -F ": " '{print $2}')

                rlRun "pki cert-request-show $crmf_requestid > $TmpDir/pki_user_cert_add_CA_certapprovedshow_004crmf.out" 0 "Executing pki cert-request-show $crmf_requestid"
                rlAssertGrep "Request ID: $crmf_requestid" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004crmf.out"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004crmf.out"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004crmf.out"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_004crmf.out"
                local certificate_serial_number_crmf=`cat $TmpDir/pki_user_cert_add_CA_certapprovedshow_004crmf.out | grep "Certificate ID:" | awk '{print $3}'`
                rlLog "Cerificate Serial Number=$certificate_serial_number_crmf"
                #Verify the certificate is valid
                rlRun "pki cert-show  $certificate_serial_number_crmf --encoded > $TmpDir/pki_user_cert_add_CA_certificate_show_004crmf.out" 0 "Executing pki cert-show $certificate_serial_number_crmf"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_certificate_show_004crmf.out"
                rlAssertGrep "Status: VALID" "$TmpDir/pki_user_cert_add_CA_certificate_show_004crmf.out"
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_add_CA_certificate_show_004crmf.out > $TmpDir/pki_user_cert_add_CA_validcert_004crmf.pem"


		currdate=`date`
		rlLog "$currdate"
                rlRun "ntpdate $NTPDATE_SERVER" 0
                rlRun "date -s '$cert_end_date'"
                rlRun "date -s 'next day'"

                rlRun "certutil -d $CERTDB_DIR -A -n $user2 -i $TmpDir/pki_user_cert_add_CA_validcert_004.pem  -t "u,u,u""
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2 --input $TmpDir/pki_user_cert_add_CA_validcert_004.pem"
		errmsg="BadRequestException: Certificate expired"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding an expired cert to a user should fail"

		rlRun "certutil -d $CERTDB_DIR -A -n $user2 -i $TmpDir/pki_user_cert_add_CA_validcert_004crmf.pem  -t "u,u,u""
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2 --input $TmpDir/pki_user_cert_add_CA_validcert_004crmf.pem"
		errmsg="BadRequestException: Certificate expired"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding an expired cert to a user should fail"

         rlLog "Set the date back to it's original date & time"
        rlRun "date --set='1 day ago'"
        rlRun "date --set='$endDate ago'"
	nowdate=`date`
	rlLog "$nowdate"
        rlRun "ntpdate $NTPDATE_SERVER"

rlPhaseEnd


	##### Add revoked cert to a user #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-005: Add revoked cert to a user should succeed"
                k=5
		cert_type="pkcs10"
                rlRun "generate_user_cert $cert_info $k \"revoke_$user2\" \"Revoke $user2fullname\" revoke_$user2@example.org $testname $cert_type" 0  "Generating temp cert"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
		cert_type="crmf"
		rlRun "generate_user_cert $cert_info $k \"revoke_$user2\" \"Revoke $user2fullname\" revoke_$user2@example.org $testname $cert_type" 0  "Generating temp cert"
                local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)

                rlRun "pki -d $CERTDB_DIR/ \
                           -n \"$admin_cert_nickname\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            cert-revoke $cert_serialNumber_pkcs10 --force > $TmpDir/pki_user_cert_add-CA_revokecert_005pkcs10.out"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005pkcs10.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out" \
                           0 \
                            "Revoked cert can be added to a user"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"
                rlAssertGrep "Subject: UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005pkcs10.out"

		rlRun "pki -d $CERTDB_DIR/ \
                           -n \"$admin_cert_nickname\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            cert-revoke $cert_serialNumber_crmf --force > $TmpDir/pki_user_cert_add-CA_revokecert_005crmf.out"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005crmf.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out" \
                           0 \
                            "Revoked cert can  be added to a user"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"
                rlAssertGrep "Subject: UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005crmf.out"

rlPhaseEnd


	##### Add one cert to a user - User ID missing #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-006-tier1: Add one cert to a user should fail when USER ID is missing"
        	k=6
		cert_type="pkcs10"
		rlRun "generate_user_cert $cert_info $k \"expired__$user2\" \"Expired $user2fullname\" expired__$user2@example.org $testname $cert_type" 0  "Generating temp cert"
		cert_type="crmf"
                rlRun "generate_user_cert $cert_info $k \"expired__$user2\" \"Expired $user2fullname\" expired__$user2@example.org $testname $cert_type" 0  "Generating temp cert"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_006pkcs10.pem"
		errmsg="Error: No User ID specified."
		errorcode=255
	        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - USER ID missing"

		rlRun "generate_user_cert $cert_info $k \"expired__$user2\" \"Expired $user2fullname\" expired__$user2@example.org $testname $cert_type" 0  "Generating temp cert"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_006crmf.pem"
		errmsg="Error: No User ID specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - USER ID missing"
rlPhaseEnd

	##### Add one cert to a user - --input parameter missing #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-007-tier1: Add one cert to a user should fail when --input parameter is missing"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   user-add --fullName=\"New User1\" u1"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2"
	errmsg="Error: Missing required option: input"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Input parameter missing"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   user-del u1"
rlPhaseEnd

	##### Add one cert to a user - argument for --input parameter missing #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-008: Add one cert to a user should fail when argument for the --input param is missing"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2 --input"
	errmsg="Error: Missing argument for option: input"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Argument for input parameter is missing"
rlPhaseEnd

	##### Add one cert to a user - Invalid cert #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-009: Add one cert to a user should fail when the cert is invalid"
        	k=9
		cert_type="pkcs10"
		rlRun "generate_user_cert $cert_info $k \"invalid_$user2\" \"Inavlid $user2fullname\" invalid_$user2@example.org $testname $cert_type" 0  "Generating temp cert"
		cert_type="crmf"
                rlRun "generate_user_cert $cert_info $k \"invalid_$user2\" \"Inavlid $user2fullname\" invalid_$user2@example.org $testname $cert_type" 0  "Generating temp cert"
		rlRun "sed -i -e 's/-----BEGIN CERTIFICATE-----/BEGIN CERTIFICATE-----/g' $TmpDir/pki_user_cert_add-CA_validcert_009pkcs10.pem"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_009pkcs10.pem"
		errmsg="PKIException: Certificate exception"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Invalid Certificate cannot be added to a user"

		rlRun "sed -i -e 's/-----BEGIN CERTIFICATE-----/BEGIN CERTIFICATE-----/g' $TmpDir/pki_user_cert_add-CA_validcert_009crmf.pem"
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_009crmf.pem"
		errmsg="PKIException: Certificate exception"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Invalid Certificate cannot be added to a user"
rlPhaseEnd

        ##### Add one cert to a user - Input file does not exist #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0010: Add one cert to a user should fail when Input file does not exist "
		command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $user2 --input $TmpDir/tempfile.pem"
		errmsg="FileNotFoundException: $TmpDir/tempfile.pem (No such file or directory)"
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Input file does not exist"
rlPhaseEnd


        ##### Add one cert to a user - i18n characters in the Subject name of the cert #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0011: Add one cert to a user - Should be able to add certs with i18n characters in the Subject name of the cert"
                k=11
		cert_type="pkcs10"
                rlRun "generate_user_cert $cert_info $k \"Örjan Äke\" \"Örjan Äke\" "test@example.org" $testname $cert_type" 0  "Generating temp cert"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
		
		cert_type="crmf"
                rlRun "generate_user_cert $cert_info $k \"Örjan Äke\" \"Örjan Äke\" "test@example.org" $testname $cert_type" 0  "Generating temp cert"
                local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)

                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011pkcs10.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out" \
                            0 \
                            "Subject name of the cert has i18n characters"
		rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
	        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
	        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
	        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"
	        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011pkcs10.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011crmf.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out" \
                            0 \
                            "Subject name of the cert has i18n characters"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"
                rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011crmf.out"

rlPhaseEnd

        ##### Add one cert to a user - User type 'Auditors' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0012: Add cert to a user of type 'Auditors'"
        k=12
	local userid="Auditor_user"
	local userFullname="Auditor User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=Auditors $userid"
	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

	cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012pkcs10.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012crmf.out"
rlPhaseEnd

        ##### Add one cert to a user - User type 'Certificate Manager Agents' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0013: Add cert to a user of type 'Certificate Manager Agents'"
        k=13
        local userid="Certificate_Manager_Agent_user"
        local userFullname="Certificate Manager Agent User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=\"Certificate Manager Agents\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013pkcs10.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013crmf.out"

rlPhaseEnd

        ##### Add one cert to a user - User type 'Registration Manager Agents' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0014: Add cert to a user of type 'Registration Manager Agents'"
        k=14
        local userid="Registration_Manager_Agent_user"
        local userFullname="Registration Manager Agent User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=\"Registration Manager Agents\" $userid"

        cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014pkcs10.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014crmf.out"

rlPhaseEnd

        ##### Add one cert to a user - User type 'Subsystem Group' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0015: Add cert to a user of type 'Subsystem Group'"
        k=15
        local userid="Subsystem_group_user"
        local userFullname="Subsystem Group User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=\"Subsystem Group\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015pkcs10.out"

	lLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015crmf.out"
rlPhaseEnd

        ##### Add one cert to a user - User type 'Security Domain Administrators' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0016: Add cert to a user of type 'Security Domain Administrators'"
        k=16
        local userid="Security_Domain_Administrator_user"
        local userFullname="Security Domain Administrator User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=\"Security Domain Administrators\" $userid"

        cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016pkcs10.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016crmf.out"
rlPhaseEnd

        ##### Add one cert to a user - User type 'ClonedSubsystems' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0017: Add cert to a user of type 'ClonedSubsystems'"
        k=17
        local userid="ClonedSubsystems_user"
        local userFullname="Cloned Subsystem User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=ClonedSubsystems $userid"
	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017pkcs10.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017crmf.out"
rlPhaseEnd

        ##### Add one cert to a user - User type 'Trusted Managers' #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0018: Add cert to a user of type 'Trusted Managers'"
        k=18
        local userid="Trusted_Manager_user"
        local userFullname="Trusted Manager User"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" --type=\"Trusted Managers\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018pkcs10.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018crmf.out"

rlPhaseEnd



	##### Usability Tests #####
	
        ##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0019: Add an Admin user \"admin_user\", add a cert to admin_user, add a new user as admin_user"
        k=19
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"Admin User\" --password=Secret123 admin_user"

        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-add Administrators admin_user > $TmpDir/pki-user-add-ca-group0019.out"

        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"Admin User1\" --password=Secret123 admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-add Administrators admin_user1 > $TmpDir/pki-user-add-ca-group00191.out"
        cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"admin_user\" \"Admin User\" "admin_user@example.org" $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"admin_user1\" \"Admin User1\" "admin_user1@example.org" $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_add-CA_validcert_0019pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_add-CA_validcert_0019pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0019.out" \
                            0 \
                            "Cert is added to the user admin_user"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Subject: UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"CA Signing Certificate - $CA_DOMAIN Security Domain\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""
        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin_user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                            user-add --fullName=\"New Test User1\" new_test_user1"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin_user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                            user-add --fullName=\"New Test User1\" new_test_user1 > $TmpDir/pki_user_cert_add_CA_useradd_0019.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user1\"" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
        rlAssertGrep "User ID: new_test_user1" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
        rlAssertGrep "Full name: New Test User1" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add admin_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0019crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add admin_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0019crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out" \
                            0 \
                            "Cert is added to the user admin_user1"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"
        rlAssertGrep "Subject: UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019crmf.out"

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin_user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                            user-add --fullName=\"New Test User2\" new_test_user2"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin_user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                            user-add --fullName=\"New Test User2\" new_test_user2 > $TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user1"
        rlAssertGrep "Added user \"new_test_user2\"" "$TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out"
        rlAssertGrep "User ID: new_test_user2" "$TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out"
        rlAssertGrep "Full name: New Test User2" "$TmpDir/pki_user_cert_add_CA_useradd_0019crmf.out"
	
	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-del Administrators admin_user"

	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-del Administrators admin_user1"

	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-del admin_user"

	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-del admin_user1"

rlPhaseEnd

        ##### Add an Agent user "agent_user", add a cert to agent_user, approve a cert request as agent_user" #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0020: Add an Agent user agent_user, add a cert to agent_user, approve a cert request as agent_user"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"Agent User\" --type=\"Certificate Manager Agents\" agent_user"

                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"Agent User1\" --type=\"Certificate Manager Agents\" agent_user1"
                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-add \"Certificate Manager Agents\" agent_user > $TmpDir/pki-user-add-ca-group0020.out"

                rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-add \"Certificate Manager Agents\" agent_user1 > $TmpDir/pki-user-add-ca-group00201.out"
                k=20
                cert_type="pkcs10"
                rlRun "generate_user_cert $cert_info $k \"agent_user\" \"Agent User\" "agent_user@example.org" $testname $cert_type" 0  "Generating temp cert"
                local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

                cert_type="crmf"
                rlRun "generate_user_cert $cert_info $k \"agent_user1\" \"Agent User1\" "agent_user1@example.org" $testname $cert_type" 0  "Generating temp cert"
                local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add agent_user --input $TmpDir/pki_user_cert_add-CA_validcert_0020pkcs10.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                           -t ca \
                            user-cert-add agent_user --input $TmpDir/pki_user_cert_add-CA_validcert_0020pkcs10.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0020.out" \
                           0 \
                            "Add cert to agent_user"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Subject: UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"

                local pkcs_requestid
                local pkcs_reqstatus
                local pkcs_requestdn
                rlRun "create_cert_request $TEMP_NSS_DB redhat123 pkcs10 rsa 2048 \"New Test User2\" "new_test_user2" "new_test_user2@example.org" "Engineering" "Example" "US" "--" "pkcs_reqstatus" "pkcs_requestid" "pkcs_requestdn""

                rlRun "pki cert-request-show $pkcs_requestid > $TmpDir/pki_user_cert_add_CA_certrequestshow_0020" 0 "Executing pki cert-request-show $pkcs_requestid"
                rlAssertGrep "Request ID: $pkcs_requestid" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $TEMP_NSS_DB/ \
                                      -n \"agent_user-pkcs10\" \
                                      -c $TEMP_NSS_DB_PASSWD \
                                      -t ca \
                                      cert-request-review --action=approve $pkcs_requestid"
                rlRun "pki -d $TEMP_NSS_DB/ \
                           -n \"agent_user-pkcs10\" \
                           -c $TEMP_NSS_DB_PASSWD \
                           -t ca \
                           cert-request-review --action=approve $pkcs_requestid > $TmpDir/pki_user_cert_add_CA_certapprove_0020 2>&1" \
                           0 \
                           "agent_user approve the cert"
                rlAssertGrep "Approved certificate request $pkcs_requestid" "$TmpDir/pki_user_cert_add_CA_certapprove_0020"
                rlRun "pki cert-request-show $pkcs_requestid > $TmpDir/pki_user_cert_add_CA_certapprovedshow_0020" 0 "Executing pki cert-request-show $pkcs_requestid"
                rlAssertGrep "Request ID: $pkcs_requestid" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"

                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add agent_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0020crmf.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add agent_user1 --input $TmpDir/pki_user_cert_add-CA_validcert_0020crmf.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out" \
                           0 \
                            "Add cert to agent_user1"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out"
                rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out"
                rlAssertGrep "Subject: UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020crmf.out"

                local pkcs10_requestid
                local pkcs10_reqstatus
                local pkcs10_requestdn
                rlRun "create_cert_request $TEMP_NSS_DB redhat123 pkcs10 rsa 2048 \"New Test User2\" "new_test_user2" "new_test_user2@example.org" "Engineering" "Example" "US" "--" "pkcs10_reqstatus" "pkcs10_requestid" "pkcs10_requestdn""

                rlRun "pki cert-request-show $pkcs10_requestid > $TmpDir/pki_user_cert_add_CA_certrequestshow_0020crmf" 0 "Executing pki cert-request-show $pkcs10_requestid"
                rlAssertGrep "Request ID: $pkcs10_requestid" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020crmf"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020crmf"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020crmf"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020crmf"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $TEMP_NSS_DB/ \
                                      -n agent_user1-crmf \
                                      -c $TEMP_NSS_DB_PASSWD \
                                      -t ca \
                                      cert-request-review --action=approve $pkcs10_requestid"
                rlRun "pki -d $TEMP_NSS_DB/ \
                           -n agent_user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -t ca \
                           cert-request-review --action=approve $pkcs10_requestid > $TmpDir/pki_user_cert_add_CA_certapprove_0020crmf 2>&1" \
                           0 \
                           "agent_user1 approve the cert"
                rlAssertGrep "Approved certificate request $pkcs10_requestid" "$TmpDir/pki_user_cert_add_CA_certapprove_0020crmf"
                rlRun "pki cert-request-show $pkcs10_requestid > $TmpDir/pki_user_cert_add_CA_certapprovedshow_0020crmf" 0 "Executing pki cert-request-show $pkcs10_requestid"
                rlAssertGrep "Request ID: $pkcs10_requestid" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020crmf"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020crmf"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020crmf"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020crmf"
		
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-del \"Certificate Manager Agents\" agent_user"

        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-del \"Certificate Manager Agents\" agent_user1"

        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-del agent_user"

        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-del agent_user1"
rlPhaseEnd

        ##### Adding a cert as an CA_agentV #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0021: Adding a cert as CA_agentV should fail"
        k=21
	local userid="new_user1"
        local userFullname="New User1"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0021pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentV"

	command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0021crmf.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentV"
rlPhaseEnd

        ##### Adding a cert as an CA_auditorV #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0022: Adding a cert as CA_auditorV should fail"
        k=22
        local userid="new_user2"
        local userFullname="New User2"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc) 
	command="pki -d $CERTDB_DIR -n CA_auditorV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0022pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_auditorV"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"

	command="pki -d $CERTDB_DIR -n CA_auditorV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0022crmf.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_auditorV"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
rlPhaseEnd


        ##### Adding a cert as an CA_adminE #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0023: Adding a cert as CA_adminE should fail"
        k=23
        local userid="new_user3"
        local userFullname="New User3"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"
	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0023pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminE"

	command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0023crmf.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminE"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

        ##### Adding a cert as an CA_adminR #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0024: Adding a cert as CA_adminR should fail"
        k=24
        local userid="new_user4"
        local userFullname="New User4"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0024pkcs10.pem"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminR"

	command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0024crmf.pem"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminR"
rlPhaseEnd

        ##### Adding a cert as an CA_agentR #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0025: Adding a cert as CA_agentR should fail"
        k=25
        local userid="new_user5"
        local userFullname="New User5"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0025pkcs10.pem"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentR"

	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0025crmf.pem"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentR"
rlPhaseEnd

        ##### Adding a cert as an CA_agentE #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0026: Adding a cert as CA_agentE should fail"
        k=26
        local userid="new_user6"
        local userFullname="New User6"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0026pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentE"

	command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0026crmf.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentE"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
rlPhaseEnd

        ##### Adding a cert as CA_adminUTCA #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0027: Adding a cert as CA_adminUTCA should fail"
        k=27
        local userid="new_user7"
        local userFullname="New User7"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n CA_adminUTCA -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0027pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
	errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminUTCA"

	command="pki -d $CERTDB_DIR -n CA_adminUTCA -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0027crmf.pem"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_adminUTCA"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"

rlPhaseEnd

        ##### Adding a cert as CA_agentUTCA #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0028: Adding a cert as CA_agentUTCA should fail"
        k=28
        local userid="new_user8"
        local userFullname="New User8"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n CA_agentUTCA -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0028pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentUTCA"

	command="pki -d $CERTDB_DIR -n CA_agentUTCA -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0028crmf.pem"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_agentUTCA"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"

rlPhaseEnd

        ##### Adding a cert as an CA_operatorV #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0029: Adding a cert as CA_operatorV should fail"
        k=29
        local userid="new_user9"
        local userFullname="New User9"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0029pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_operatorV"

	command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0029crmf.pem"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to a user as CA_operatorV"

rlPhaseEnd

        ##### Adding a cert as a user not associated with any group#####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0030: Adding a cert as user not associated with an group, should fail"
        k=30
        local userid="new_user10"
        local userFullname="New User10"
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$userFullname\" $userid"

	cert_type="pkcs10"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
	command="pki -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0030pkcs10.pem"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to $userid as a user not associated with any group"

	command="pki -d $CERTDB_DIR -n $user1 -c $CERTDB_DIR_PASSWORD -t ca user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0030crmf.pem"
        errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding cert to $userid as a user not associated with any group"

        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"

rlPhaseEnd

        ##### Add one cert to a user - switching position of options #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0031: Add one cert to a user - switching position of options should succeed"
        k=31

	cert_type="pkcs10"
	rlRun "generate_user_cert $cert_info $k \"$user2\" \"$user2fullname\" $user2@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_pkcs10=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber_pkcs10 | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

        cert_type="crmf"
	rlRun "generate_user_cert $cert_info $k \"$user2\" \"$user2fullname\" $user2@example.org $testname $cert_type" 0  "Generating temp cert"
        local cert_serialNumber_crmf=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_CRMF=$(echo $cert_serialNumber_crmf | cut -dx -f2)
        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
        local decimal_valid_serialNumber_crmf=$(echo "ibase=16;$CONV_UPP_VAL_CRMF"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031pkcs10.pem $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031pkcs10.pem $user2 > $TmpDir/pki_user_cert_add_CA_useraddcert_0031.out" \
                            0 \
                            "Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_pkcs10" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031.out"

	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031crmf.pem $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_0031crmf.pem $user2 > $TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out" \
                            0 \
                            "Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_crmf;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Serial Number: $cert_serialNumber_crmf" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0031crmf.out"
rlPhaseEnd


#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 3 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
	j=1
	while [ $j -lt 11 ] ; do
               eval usr="new_user$j"
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  $usr > $TmpDir/pki-user-del-ca-new-user-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-new-user-00$j.out"
                let j=$j+1
        done

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd


}



