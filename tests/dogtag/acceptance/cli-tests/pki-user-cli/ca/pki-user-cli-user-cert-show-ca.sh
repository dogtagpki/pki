#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-cert-show    Show the certs assigned to users in the pki ca subsystem.
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-cert-add-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-user-cli-user-cert-show-ca_tests(){

user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"
cert_info="$TmpDir/cert_info"
testname="pki_user_cert_show"

	##### Create temporary directory to save output files #####
    rlPhaseStartSetup "pki_user_cli_user_cert-show-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

##### pki_user_cli_user_cert_show_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-show-configtest-001: pki user-cert-show configuration test"
        rlRun "pki user-cert-show --help > $TmpDir/pki_user_cert_show_cfg.out 2>&1" \
                0 \
                "User cert show configuration"
        rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_cfg.out"
        rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_user_cert_show_cfg.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Tests to find certs assigned to CA users ####

	##### Show certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-CA-002: Show certs assigned to a user - valid UserID and CertID"
                k=2	
        	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user2fullname\" $user2"
		rlRun "generate_user_cert $cert_info $k \"$user2\" \"$user2fullname\" $user2@example.org $testname" 0  "Generating temp cert"
	        cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        	CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        	decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_show-CA_validcert_002.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_002.out" \
                            0 \
                            "Cert is added to the user $user2"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_002.out" \
			0 \
			"Show cert assigned to $user2"

		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"

	rlPhaseEnd

	##### Show certs asigned to a user - invalid Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-003: pki user-cert-show should fail if an invalid Cert ID is provided"
                
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"3;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"3;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_003.out 2>&1" \
                        1 \
                        "Show cert assigned to user - Invalid Cert ID"
		rlAssertGrep "ResourceNotFoundException: No certificates found for $user2" "$TmpDir/pki_user_cert_show_CA_usershowcert_003.out"
	rlPhaseEnd

	##### Show certs asigned to a user - User does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-004: pki user-cert-show should fail if a non-existing User ID is provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show testuser4 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show testuser4 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_004.out 2>&1" \
                        1 \
                        "Show cert assigned to user - User does not exist"
                rlAssertGrep "UserNotFoundException: User testuser4 not found" "$TmpDir/pki_user_cert_show_CA_usershowcert_004.out"
        rlPhaseEnd

	##### Show certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-005: pki user-cert-show should fail is there is a mismatch of User ID and Cert ID"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user1fullname\" $user1"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_005.out 2>&1" \
                        1 \
                        "Show cert assigned to user - User ID and Cert ID mismatch"
                rlAssertGrep "ResourceNotFoundException: No certificates found for $user1" "$TmpDir/pki_user_cert_show_CA_usershowcert_005.out"
        rlPhaseEnd

	##### Show certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-006: pki user-cert-show should fail if User ID is not provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_006.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided"
		rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
	        rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
        	rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
	        rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-007: pki user-cert-show should fail if Cert ID is not provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1  > $TmpDir/pki_user_cert_show_CA_usershowcert_007.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --encoded option #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-CA-008: Show certs assigned to a user - --encoded option - Valid Cert ID and User ID"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_008.out" \
                        0 \
                        "Show cert assigned to user - --encoded option"
		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_008.out"

	rlLog "$(cat $TmpDir/pki_user_cert_show_CA_usershowcert_008.out | grep Subject | awk -F":" '{print $2}')"
        rlRun "openssl x509 -in $TmpDir/pki_user_cert_show_CA_usershowcert_008.out -noout -serial 1> $TmpDir/temp_out-openssl" 0 "Run openssl to verify PEM output"
	rlAssertGrep "serial=$CONV_UPP_VAL_PKCS10" "$TmpDir/temp_out-openssl"
        rlPhaseEnd
	
	  ##### Show certs asigned to a user - --encoded option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-009: pki user-cert-show should fail if User ID is not provided with --encoded option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_009.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided with --encoded option"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0010: pki user-cert-show should fail if Cert ID is not provided with --encoded option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_0010.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0011: Show certs assigned to a user - --output <file> option - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output.out"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output.out > $TmpDir/pki_user_cert_show_CA_usershowcert_0011.out" \
                        0 \
                        "Show cert assigned to user - --output <file> option"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usercertshow_output.out"
        	rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usercertshow_output.out"
		rlRun "openssl x509 -in $TmpDir/pki_user_cert_show_CA_usercertshow_output.out -noout -serial 1> $TmpDir/temp_out-openssl" 0 "Run openssl to verify PEM output"
        rlAssertGrep "serial=$CONV_UPP_VAL_PKCS10" "$TmpDir/temp_out-openssl"
	rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0011.out"

	
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0012: pki user-cert-show should fail if User ID is not provided with --output <file> option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/user_cert_show_output0012"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/user_cert_show_output0012 > $TmpDir/pki_user_cert_show_CA_usershowcert_0012.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided with --output option"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user - --output <file> option - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0013: pki user-cert-show should fail if Cert ID is not provided with --output <file> option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --output $TmpDir/user_cert_show_output0013"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --output $TmpDir/user_cert_show_output0013 > $TmpDir/pki_user_cert_show_CA_usershowcert_0013.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - Directory does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0014: pki user-cert-show should fail if --output <file> directory does not exist"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output /tmp/tmpDir/user_cert_show_output0014"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output /tmp/tmpDir/user_cert_show_output0014 > $TmpDir/pki_user_cert_show_CA_usershowcert_0014.out 2>&1" \
                        1 \
                        "Show cert assigned to user - directory does not exist"
		rlAssertGrep "FileNotFoundException:" "$TmpDir/pki_user_cert_show_CA_usershowcert_0014.out"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - without <file> argument #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0015: pki user-cert-show should fail if --output option file argument is not provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output > $TmpDir/pki_user_cert_show_CA_usershowcert_0015.out 2>&1" \
                        1 \
                        "Show cert assigned to user - --output option <file> argument is not provided"
		rlAssertGrep "Error: Missing argument for option: output" "$TmpDir/pki_user_cert_show_CA_usershowcert_0015.out"

        rlPhaseEnd
	##### Show certs asigned to a user - --pretty option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0016: Show certs assigned to a user - --pretty option - Valid Cert ID, User ID"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0016.out" \
                        0 \
                        "Show cert assigned to user - --pretty option"
		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Signature Algorithm" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Validity" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Extensions" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
		rlAssertGrep "Signature" "$TmpDir/pki_user_cert_show_CA_usershowcert_0016.out"
        rlPhaseEnd

        ##### Show certs asigned to a user - --pretty option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0017: pki user-cert-show should fail if User ID is not provided with --pretty option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0017.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided with --pretty option"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

        ##### Show certs asigned to a user - --pretty option - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0018: pki user-cert-show should fail if Cert ID is not provided with --pretty option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0018.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/967"
        rlPhaseEnd

	##### Show certs asigned to a user - --pretty, --encoded and --output options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0019: Show certs assigned to a user - --pretty, --encoded and --output options - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019 > $TmpDir/pki_user_cert_show_CA_usershowcert_0019.out" \
                        0 \
                        "Show cert assigned to user - --pretty, --output and --encoded options"
		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Signature Algorithm" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Validity" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Subject Public Key Info" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Extensions" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "Signature" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0019.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/user_cert_show_output0019"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/user_cert_show_output0019"
                rlRun "openssl x509 -in $TmpDir/user_cert_show_output0019 -noout -serial 1> $TmpDir/temp_out-openssl" 0 "Run openssl to verify PEM output"
                rlAssertGrep "serial=$CONV_UPP_VAL_PKCS10" "$TmpDir/temp_out-openssl"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_agentV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0020: Show certs assigned to a user - as CA_agentV should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0020.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_agentV"
		rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki_user_cert_show_CA_usershowcert_0020.out"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_auditorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0021: Show certs assigned to a user - as CA_auditorV should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_auditorV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_auditorV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0021.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_auditorV"
		rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_show_CA_usershowcert_0021.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_adminE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0022: Show certs assigned to a user - as CA_adminE should fail"

		rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminE \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminE \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0022.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_adminE"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
		rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_show_CA_usershowcert_0022.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - incomplete Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0023: pki user-cert-show should fail if an incomplete Cert ID is provided"

                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"3;$decimal_valid_serialNumber_pkcs10;O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0023.out 2>&1" \
                        1 \
                        "Show cert assigned to user - Incomplete Cert ID"
                rlAssertGrep "ResourceNotFoundException: No certificates found for $user2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0023.out"
        rlPhaseEnd

        ##### Show certs asigned to a user - as CA_agentE ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0024: Show certs assigned to a user - as CA_agentE should fail"

                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_agentE \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentE \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0024.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_agentE"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_show_CA_usershowcert_0024.out"
                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

       ##### Show certs asigned to a user - as CA_adminR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0025: Show certs assigned to a user - as CA_adminR should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminR \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminR \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0025.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_adminR"
                rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki_user_cert_show_CA_usershowcert_0025.out"
        rlPhaseEnd

       ##### Show certs asigned to a user - as CA_agentR ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0026: Show certs assigned to a user - as CA_agentR should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_agentR \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentR \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0026.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_agentR"
                rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki_user_cert_show_CA_usershowcert_0026.out"
        rlPhaseEnd

        ##### Show certs asigned to a user - as CA_adminUTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0027: Show certs assigned to a user - as CA_adminUTCA should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminUTCA \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminUTCA \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0027.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_adminUTCA"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_show_CA_usershowcert_0027.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_agentUTCA ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0028: Show certs assigned to a user - as CA_agentUTCA should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_agentUTCA \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentUTCA \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0028.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_agentUTCA"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_show_CA_usershowcert_0028.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

        ##### Show certs asigned to a user - as CA_operatorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0029: Show certs assigned to a user - as CA_operatorV should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_operatorV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_operatorV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0029.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as CA_operatorV"
                rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute" "$TmpDir/pki_user_cert_show_CA_usershowcert_0029.out"
        rlPhaseEnd

	##### Show certs asigned to a user - --encoded and --output options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0030: Show certs assigned to a user - --encoded and --output options - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --output $TmpDir/user_cert_show_output0030"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --output $TmpDir/user_cert_show_output0030 > $TmpDir/pki_user_cert_show_CA_usershowcert_0030.out" \
                        0 \
                        "Show cert assigned to user - --output and --encoded options"
                rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/pki_user_cert_show_CA_usershowcert_0030.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/user_cert_show_output0030"
                rlAssertGrep "\-----END CERTIFICATE-----" "$TmpDir/user_cert_show_output0030"
                rlRun "openssl x509 -in $TmpDir/user_cert_show_output0030 -noout -serial 1> $TmpDir/temp_out-openssl" 0 "Run openssl to verify PEM output"
	        rlAssertGrep "serial=$CONV_UPP_VAL_PKCS10" "$TmpDir/temp_out-openssl"

        rlPhaseEnd

        ##### Show certs asigned to a user - as a user not associated with any role##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0031: Show certs assigned to a user - as as a user not associated with any role, should fail"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $user1 \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $user1 \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0031.out 2>&1" \
                        1 \
                        "Show cert assigned to user - as a user not associated with any role"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki_user_cert_show_CA_usershowcert_0031.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Show certs asigned to a user - switch position of the required options#####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0032: Show certs assigned to a user - switch position of the required options"
                
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" $user2"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" $user2 > $TmpDir/pki_user_cert_show_CA_usershowcert_0032.out 2>&1" \
                        1 \
                        "Show cert assigned to $user2"

                rlAssertGrep "User Not Found" "$TmpDir/pki_user_cert_show_CA_usershowcert_0032.out"
		rlAssertNotGrep "UserNotFoundException: User 2 not found" "$TmpDir/pki_user_cert_show_CA_usershowcert_0032.out"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/968"
        rlPhaseEnd

### Tests to show certs assigned to CA users - i18n characters ####

rlPhaseStartTest "pki_user_cli_user_cert-show-CA-033: Show certs assigned to user - Subject name has i18n Characters"
        k=33
        rlRun "generate_user_cert $cert_info $k \"Örjan Äke\" \"Örjan Äke\" "test@example.org" $testname" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_show-CA_validcert_0033.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_0033.out" \
                            0 \
                            "Cert is added to the user $user1"
	rlAssertGrep "Added certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_useraddcert_0033.out"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\""
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_ca_0033.out" \
                    0 \
                    "Show certs assigned to $user1 with i18n chars"
	rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_ca_0033.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_ca_0033.out"

	
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

	Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd

}


