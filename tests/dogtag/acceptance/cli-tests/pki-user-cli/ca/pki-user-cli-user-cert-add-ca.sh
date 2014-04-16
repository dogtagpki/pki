#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
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

local cert_info="$TmpDir/cert_info"
user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
testname="pki_user_cert_add"

##### pki_user_cli_user_cert_add_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-add-configtest-001: pki user-cert-add configuration test"
        rlRun "pki user-cert-add > $TmpDir/pki_user_cert_add_cfg.out" \
                1 \
                "User cert add configuration"
        rlAssertGrep "usage: user-cert-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_add_cfg.out"
        rlAssertGrep "--input <file>   Input file" "$TmpDir/pki_user_cert_add_cfg.out"
    rlPhaseEnd

	##### Tests to add certs to CA users ####
	
        ##### Add one cert to a user #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-002: Add one cert to a user should succeed"
        k=2
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user2fullname\" $user2"

        rlRun "generate_user_cert $cert_info $k \"$user2\" \"$user2fullname\" $user2@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_002.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_002.out" \
                            0 \
                            "Cert is added to the user $user2"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_002.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_002.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_002.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_002.out"
        rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_002.out"
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
		
	rlRun "generate_user_cert $cert_info $k \"$user1$(($i+1))\" \"$user1fullname$(($i+1))\" $user1$(($i+1))@example.org $testname $i" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_add-CA_validcert_003$i.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out"
        rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_003_$i.out"
                let i=$i+1
        done
        rlPhaseEnd

        ##### Add expired cert to a user #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-004: Adding expired cert to a user should fail"
        local reqstatus
        local requestid
        local requestdn
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
		currdate=`date`
		rlLog "$currdate"
                rlRun "ntpdate $NTPDATE_SERVER" 0
                rlRun "date -s '$cert_end_date'"
                rlRun "date -s 'next day'"

                rlRun "certutil -d $CERTDB_DIR -A -n $user2 -i $TmpDir/pki_user_cert_add_CA_validcert_004.pem  -t "u,u,u""
                rlLog "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add_CA_validcert_004.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add_CA_validcert_004.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_004.out 2>&1" \
                            1 \
                            "Expired cert cannot be assigned to a user"
                rlAssertGrep "BadRequestException: Certificate expired" "$TmpDir/pki_user_cert_add_CA_useraddcert_004.out"
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
                rlRun "generate_user_cert $cert_info $k \"revoke_$user2\" \"Revoke $user2fullname\" revoke_$user2@example.org $testname" 0  "Generating temp cert"
                local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            cert-revoke $cert_serialNumber --force > $TmpDir/pki_user_cert_add-CA_revokecert_005.out"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_005.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_005.out" \
                           0 \
                            "Revoked cert cannot be added to a user"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_005.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_005.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_005.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_005.out"
                rlAssertGrep "Subject: UID=revoke_$user2,E=revoke_$user2@example.org,CN=Revoke $user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_005.out"

rlPhaseEnd


	##### Add one cert to a user - User ID missing #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-006: Add one cert to a user should fail when USER ID is missing"
        	k=6
		rlRun "generate_user_cert $cert_info $k \"expired__$user2\" \"Expired $user2fullname\" expired__$user2@example.org $testname" 0  "Generating temp cert"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_006.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add --input $TmpDir/pki_user_cert_add-CA_validcert_006.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_006.out 2>&1" \
                            1 \
                            "UserID missing"
		rlAssertGrep "usage: user-cert-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_add_CA_useraddcert_006.out"
	        rlAssertGrep "--input <file>   Input file" "$TmpDir/pki_user_cert_add_CA_useraddcert_006.out"

rlPhaseEnd

	##### Add one cert to a user - --input parameter missing #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-007: Add one cert to a user should fail when --input parameter is missing"
	rlLog "Executing pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-cert-add $user2"

        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-cert-add $user2  > $TmpDir/pki_user_cert_add_CA_useraddcert_007.out 2>&1" \
                    1 \
                   "Input parameter missing"
	rlAssertGrep "Error: Missing required option: input" "$TmpDir/pki_user_cert_add_CA_useraddcert_007.out"
	rlAssertGrep "usage: user-cert-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_add_CA_useraddcert_007.out"
        rlAssertGrep "--input <file>   Input file" "$TmpDir/pki_user_cert_add_CA_useraddcert_007.out"
rlPhaseEnd

	##### Add one cert to a user - argument for --input parameter missing #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-008: Add one cert to a user should fail when argument for the --input param is missing"
        rlLog "Executing pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-cert-add $user2 --input"

        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-cert-add $user2 --input  > $TmpDir/pki_user_cert_add_CA_useraddcert_008.out 2>&1" \
                    1 \
                   "Argument for input parameter is missing"
	rlAssertGrep "Error: Missing argument for option: input" "$TmpDir/pki_user_cert_add_CA_useraddcert_008.out"
        rlAssertGrep "usage: user-cert-add <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_add_CA_useraddcert_008.out"
        rlAssertGrep "--input <file>   Input file" "$TmpDir/pki_user_cert_add_CA_useraddcert_008.out"
rlPhaseEnd

	##### Add one cert to a user - Invalid cert #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-009: Add one cert to a user should fail when the cert is invalid"
        	k=9
		rlRun "generate_user_cert $cert_info $k \"invalid_$user2\" \"Inavlid $user2fullname\" invalid_$user2@example.org $testname" 0  "Generating temp cert"
		rlRun "sed -i -e 's/-----BEGIN CERTIFICATE-----/BEGIN CERTIFICATE-----/g' $TmpDir/pki_user_cert_add-CA_validcert_009.pem"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_009.pem"
		rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_009.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_009.out 2>&1" \
                            1 \
                            "Invalid Certificate cannot be added to a user"
		rlAssertGrep "PKIException: Certificate exception" "$TmpDir/pki_user_cert_add_CA_useraddcert_009.out"
rlPhaseEnd

        ##### Add one cert to a user - Input file does not exist #####
rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0010: Add one cert to a user should fail when Input file does not exist "

                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/tempfile.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/tempfile.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0010.out 2>&1" \
                            1 \
                            "Input file does not exist"
                rlAssertGrep "FileNotFoundException:" "$TmpDir/pki_user_cert_add_CA_useraddcert_0010.out"
rlPhaseEnd


        ##### Add one cert to a user - i18n characters in the Subject name of the cert #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0011: Add one cert to a user - Should be able to add certs with i18n characters in the Subject name of the cert"
                k=11
                rlRun "generate_user_cert $cert_info $k \"Örjan Äke\" \"Örjan Äke\" "test@example.org" $testname" 0  "Generating temp cert"
                local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)

                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_add-CA_validcert_0011.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0011.out" \
                            0 \
                            "Subject name of the cert has i18n characters"
		rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011.out"
	        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011.out"
	        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011.out"
	        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011.out"
	        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0011.out"

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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0012.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0012.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0012.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0013.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0013.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0013.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0014.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0014.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0014.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0015.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0015.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0015.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0016.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0016.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0016.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0017.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0017.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0017.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0018.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0018.out" \
                            0 \
                            "Cert is added to the user $userid"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018.out"
        rlAssertGrep "Subject: UID=$userid,E=$userid@example.org,CN=$userFullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0018.out"
rlPhaseEnd



	##### Usability Tests #####
	
	##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user #####

rlPhaseStartTest "pki_user_cli_user_cert-add-CA-0019: Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user"
        k=19
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"Admin User\" admin_user"

	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            group-member-add Administrators admin_user > $TmpDir/pki-user-add-ca-group0019.out"

        rlRun "generate_user_cert $cert_info $k \"admin_user\" \"Admin User\" "admin_user@example.org" $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_add-CA_validcert_0019.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add admin_user --input $TmpDir/pki_user_cert_add-CA_validcert_0019.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0019.out" \
                            0 \
                            "Cert is added to the user admin_user"
        rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
        rlAssertGrep "Subject: UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0019.out"
	
	rlLog "pki -d $CERTDB_DIR \
                           -n admin_user \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"New Test User\" new_test_user"
	rlRun "pki -d $CERTDB_DIR \
                           -n admin_user \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"New Test User\" new_test_user > $TmpDir/pki_user_cert_add_CA_useradd_0019.out"
			    0 /
			    "Adding a new user as admin_user"
 	rlAssertGrep "Added user \"new_test_user\"" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
        rlAssertGrep "User ID: new_test_user" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
        rlAssertGrep "Full name: New Test User" "$TmpDir/pki_user_cert_add_CA_useradd_0019.out"
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
                           -t ca \
                            group-member-add \"Certificate Manager Agents\" agent_user > $TmpDir/pki-user-add-ca-group0020.out"
                k=20
                rlRun "generate_user_cert $cert_info $k \"agent_user\" \"Agent User\" "agent_user@example.org" $testname" 0  "Generating temp cert"
                local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add agent_user --input $TmpDir/pki_user_cert_add-CA_validcert_0020.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add agent_user --input $TmpDir/pki_user_cert_add-CA_validcert_0020.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0020.out" \
                           0 \
                            "Add cert to agent_user"
                rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"
                rlAssertGrep "Subject: UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_add_CA_useraddcert_0020.out"

		local requestid
		local reqstatus
		local requestdn		
                rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"New Test User2\" "new_test_user2" "new_test_user2@example.org" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""

                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_add_CA_certrequestshow_0020" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_add_CA_certrequestshow_0020"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $CERTDB_DIR/ \
                                      -n agent_user \
                                      -c $CERTDB_DIR_PASSWORD \
                                      -t ca \
                                      cert-request-review --action=approve $requestid"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n agent_user \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                           cert-request-review --action=approve $requestid > $TmpDir/pki_user_cert_add_CA_certapprove_0020" \
                           0 \
                           "agent_user approve the cert"
                rlAssertGrep "Approved certificate request $requestid" "$TmpDir/pki_user_cert_add_CA_certapprove_0020"
		rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_add_CA_certapprovedshow_0020" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_add_CA_certapprovedshow_0020"

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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0021.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0021.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0021.out 2>&1" \
                            1 \
                            "Adding cert to a user as CA_agentV"
	rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki_user_cert_add_CA_useraddcert_0021.out"

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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_auditorV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0022.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_auditorV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0022.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0022.out 2>&1" \
                            1 \
                            "Cert is added to the user $userid"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_add_CA_useraddcert_0022.out"
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

        rlRun "generate_user_cert $cert_info $k \"$userid\" \"$userFullname\" $userid@example.org $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
        rlRun "date"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminE \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0023.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminE \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $userid --input $TmpDir/pki_user_cert_add-CA_validcert_0023.pem  > $TmpDir/pki_user_cert_add_CA_useraddcert_0023.out 2>&1" \
                            1 \
                            "Cert is added to the user $userid"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_add_CA_useraddcert_0023.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
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
    rlPhaseEnd


}



