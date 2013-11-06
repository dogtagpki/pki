#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-cert-request-submit
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

user1="ca_agent2"
user1fullname="Test ca_agent"
user2="kra_agent2"
user2fullname="Test kra_agent"
user3="ocsp_agent2"
user3fullname="Test ocsp_agent"


########################################################################

run_pki-cert-request-submit-cli_tests(){
    rlPhaseStartSetup "pki_cert_cli_cert-request-submit-startup: Login as system user, create temp directory and import CA agent cert into a nss certificate db and trust CA root cert"
	admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
	nss_db_password="Password"
	rlRun "chmod 777 $CA_ADMIN_CERT_LOCATION"
        local exp="/tmp/expfile.out"
        local expuserlogin="/tmp/explogin.out"
        local tmpout="/tmp/tmpout.out"
        local tmpusercreate="/tmp/tmpuser.out"
        #Create a new system user if user does not exist already
        local NEW_USER="testuser1"
        local NEW_PASSWORD="Secret"
        rlLog "Creating user $NEW_USER"
        /usr/bin/id $NEW_USER > $tmpusercreate  2>&1
        if [ $? != 0 ] ; then
                echo "$NEW_USER user does not exist"
                /usr/sbin/useradd $NEW_USER
                if [ $? != 0 ] ; then
                        echo "Failed to create $NEW_USER user"
                fi
                local cmd="passwd $NEW_USER"
                echo "set timeout 5" > $exp
                echo "set force_conservative 0" >> $exp
                echo "set send_slow {1 .1}" >> $exp
                echo "spawn $cmd" >> $exp
                echo 'expect "*password: "' >> $exp
                echo "send -s -- \"$NEW_PASSWORD\r\"" >> $exp
                echo 'expect "*password: "' >> $exp
                echo "send -s -- \"$NEW_PASSWORD\r\"" >> $exp
                echo 'expect eof ' >> $exp
                rlRun "cat $exp"
                /usr/bin/expect $exp > $tmpout 2>&1
                if [ $? = 0 ]; then
                        cat $tmpout | grep "all authentication tokens updated successfully"
                else
                        rlFail "User password can not be set"
                fi
        fi
	rlLog "Admin Certificate is located at: $CA_ADMIN_CERT_LOCATION"
	rlRun "chmod 777 $CA_ADMIN_CERT_LOCATION"
        rlRun "su - $NEW_USER -c 'TmpDir=\`mktemp -d\`'" 0 "Creating tmp directory"
        rlRun "su - $NEW_USER -c 'pushd $TmpDir'"
	rlLog "Temp Directory = $TmpDir"
	rlRun "su - $NEW_USER -c 'mkdir $TmpDir/nssdb'"
	rlRun "su - $NEW_USER -c 'importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $TmpDir/nssdb $nss_db_password $admin_cert_nickname" 0 "Import Admin certificate to $TmpDir/nssdb'"
	rlRun "su - $NEW_USER -c 'install_and_trust_CA_cert $CA_SERVER_ROOT $TmpDir/nssdb'"
    rlPhaseEnd

    rlPhaseStartTest "pki_cert_cli_cert-request-submit-configtest: pki cert-request-submit configuration test"
	rlRun "pki cert-request-submit > $TmpDir/pki_cert-request-submit_cfg.out"
	rlAssertGrep "usage: cert-request-submit <filename>" "$TmpDir/pki_cert-request-submit_cfg.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_cert_cli_cert-request-submit-CA-001: Request a RSA certificate of key size 3072 in PKCS#10 format"
	local sample_request_file1="/opt/rhqa_pki/cert_request_caUserCert1_1.in"
	local sample_request_file2="/opt/rhqa_pki/cert_request_caUserCert1_2.in"
	local temp_file="$TmpDir/certrequest_001.in"
	rlRun "create_certdb \"$TmpDir/requestdb\" Password" 0 "Create a certificate db"
	rlRun "generate_PKCS10 \"$TmpDir/requestdb\"  Password rsa 3072 \"$TmpDir/request_001.out\" \"CN=test.example.com\" " 0 "generate PKCS10 certificate"
	rlLog "Create a certificate request XML file.."
	local search_string1="<InputAttr name=\"cert_request_type\">crmf<\/InputAttr>"
	local replace_string1="\<InputAttr name=\"cert_request_type\"\>pkcs10\<\/InputAttr\>"
	rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $TmpDir/request_001.out"
	rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $TmpDir/request_001.out"
	local cert_request=`cat $TmpDir/request_001.out`
	rlRun "cat $sample_request_file1 $TmpDir/request_001.out $sample_request_file2 >  $temp_file"
	rlLog "Executing: sed -e 's/$search_string1/$replace_string1/' -i $temp_file"
	rlRun "sed -e 's/$search_string1/$replace_string1/' -i  $temp_file"
	rlLog "Executing: pki cert-request-submit  $temp_file"
	rlRun "pki cert-request-submit  $temp_file > $TmpDir/certrequest_001.out" 0 "Executing pki cert-request-submit"
	rlAssertGrep "Submitted certificate request" "$TmpDir/certrequest_001.out"
	rlAssertGrep "Request ID:" "$TmpDir/certrequest_001.out"
	rlAssertGrep "Type: enrollment" "$TmpDir/certrequest_001.out"
	rlAssertGrep "Status: pending" "$TmpDir/certrequest_001.out"
	local request_id=`cat $TmpDir/certrequest_001.out | grep "Request ID:" | awk '{print $3}'`
	rlLog "Request ID=$request_id"
	rlRun "pki cert-request-show $request_id > $TmpDir/certrequestshow_001.out" 0 "Executing pki cert-request-show $request_id"
	rlAssertGrep "Request ID: $request_id" "$TmpDir/certrequestshow_001.out"
	rlAssertGrep "Type: enrollment" "$TmpDir/certrequestshow_001.out"
	rlAssertGrep "Status: pending" "$TmpDir/certrequestshow_001.out"
	#Agent Approve the certificate
	rlLog "Executing: pki -d $TmpDir/nssdb \
                   -n \"$admin_cert_nickname\" \
                   -w $nss_db_password \
                   -t ca \
                    cert-request-review --action=approve $request_id"

        rlRun "pki -d $TmpDir/nssdb \
                   -n \"$admin_cert_nickname\" \
                   -w $nss_db_password \
                   -t ca \
                    cert-request-review --action=approve $request_id > $TmpDir/certapprove_001.out" \
                    0 \
                    "CA agent approve the cert"
	rlAssertGrep "Approved certificate request $request_id" "$TmpDir/certapprove_001.out"
	rlRun "pki cert-request-show $request_id > $TmpDir/certrequestapprovedshow_001.out" 0 "Executing pki cert-request-show $request_id"
	rlAssertGrep "Request ID: $request_id" "$TmpDir/certrequestapprovedshow_001.out"
        rlAssertGrep "Type: enrollment" "$TmpDir/certrequestapprovedshow_001.out"
        rlAssertGrep "Status: complete" "$TmpDir/certrequestapprovedshow_001.out"
        rlAssertGrep "Certificate ID:" "$TmpDir/certrequestapprovedshow_001.out"
	local certificate_serial_number=`cat $TmpDir/certrequestapprovedshow_001.out | grep "Certificate ID:" | awk '{print $3}'`
	rlLog "Cerificate Serial Number=$certificate_serial_number"
	#Verify the certificate is valid
        rlRun "pki cert-show  $certificate_serial_number --pretty > $TmpDir/certificate_show_001.out" 0 "Executing pki cert-show $certificate_serial_number"
	rlAssertGrep "Subject: UID=testuser,E=testuser@example.com,CN=Test User,OU=Engineering,O=Example,C=US" "$TmpDir/certificate_show_001.out"
	rlAssertGrep "Status: VALID" "$TmpDir/certificate_show_001.out"
	rlAssertGrep "Public Key Modulus: (3072 bits)" "$TmpDir/certificate_show_001.out"
    rlPhaseEnd

    rlPhaseStartCleanup "pki_cert_cli_cert-request-submit-cleanup: Delete temp dir"
	rlRun "popd"

    #    rlRun "rm -r $TmpDir" 0 "Removing temp directory"
    rlPhaseEnd
}
