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

run_pki_cert_show()
{

	local invalid_serialNumber=`cat /dev/urandom | tr -dc '1-9' | fold -w 10 | head -n 1`
	
	# Creating Temporary Directory for pki cert-show

        rlPhaseStartSetup "pki cert-show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd
	
	rlPhaseStartSetup "Executing pki cert show"
	rlLog "Executing pki cert-show"
	rlRun "pki cert-show 1> $TmpDir/cert-show.out" 1 
	rlAssertGrep "usage:" "$TmpDir/cert-show.out"
    	rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/cert-show.out"
    	rlAssertGrep "--output <file>   Output file" "$TmpDir/cert-show.out"
    	rlAssertGrep "--pretty          Pretty print" "$TmpDir/cert-show.out"
	rlPhaseEnd

	# Import CA Agent and CA Cert to CERTDB Directory

	rlPhaseStartSetup "Import CA agent cert into a nss certificate db and trust CA root cert"
        admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
        rlRun "source /opt/rhqa_pki/env.sh"
	local MY_CERTDB_DIR=$TmpDir/certdb
        rlLog "Admin Certificate is located at: $CA_ADMIN_CERT_LOCATION"
        rlLog "importP12FileNew $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $MY_CERTDB_DIR $CERTDB_DIR_PASSWORD $admin_cert_nickname"
        rlRun "importP12FileNew $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $MY_CERTDB_DIR $CERTDB_DIR_PASSWORD $admin_cert_nickname" 0 "Import Admin certificate to $MY_CERTDB_DIR"
        rlRun "install_and_trust_CA_cert $CA_SERVER_ROOT $MY_CERTDB_DIR"
	rlPhaseEnd
	
	# Create a Temporary NSS DB Directory and generate Certificate

	rlPhaseStartSetup "Generating temporary Cert"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local reqstatus
        local requestid
        rlRun "create_cert_request $TEMP_NSS_DB redhat pkcs10 rsa 2048 \"Test1 User\" "test1" "test1@example.org" "Marketing" "FooBar.Inc" "IN" "--" "reqstatus" "requestid""
	rlLog "To Approve the request we would need CA Admin Cert Nick Name stored in $MY_CERTDB_DIR"
	local MY_ADMIN_NICK=`certutil -L -d $MY_CERTDB_DIR  | grep "PKI Administrator" | awk -F "     " '{print $1}'`
        rlLog "Approve Certificate requeset"
        rlRun "pki -d $MY_CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$MY_ADMIN_NICK\" ca-cert-request-review $requestid --action approve 1> $TmpDir/pki-approve-out"
	rlAssertGrep "Approved certificate request $requestid" "$TmpDir/pki-approve-out"
	rlRun "valid_serialNumber=`pki cert-request-show $requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2`"
        rlPhaseEnd


	#Run pki cert-show with valid serial number in HexDecimal

	rlPhaseStartSetup "pki_cert_show-001: Show certificate of specific serial number"
	rlLog "run get_cert_serialnumber function first to get the serial Number"
	local temp_out1="$TmpDir/cert-show1.out"
	rlLog "Running pki cert-show $valid_serialNumber"
	rlRun "pki cert-show $valid_serialNumber > $temp_out1" 0 "command pki cert-show $serialNumber"
	RETVAL=$?
		if [ $RETVAL != 0 ]; then	
		rlLog "pki cert-show has exited with return status $RETVAL"
		fi
	rlLog "Get the Subject Name of the Certificat with $serialNumber"
	rlLog "`cat $temp_out1 | grep Issuer | awk -F":" '{print $2}'`"
	rlPhaseEnd

	#Run pki cert-show with No serial Number 

	rlPhaseStartSetup "pki_cert_show-002: pki cert-show should fail when no serial Number is given"
	local temp_out2="$TmpDir/cert-show2.out"
	rlRun "pki cert-show  > $temp_out2" 1 "pki cert-show without any serial number fails"
	rlAssertGrep "usage: cert-show" "$temp_out2"
	rlPhaseEnd
	
	# Run pki cert-show with Invalid Serial Number in decimal

	rlPhaseStartSetup "pki_cert_show-003: pki cert-show should fail when invalid serial Number is given"
	local temp_out3="$TmpDir/cert-show3.out"
	rlRun "pki cert-show $invalid_serialNumber 2> $temp_out3" 1 "command pki cert-show $serialNumber"
	rlAssertGrep "CertNotFoundException" "$temp_out3"
	rlPhaseEnd

	# Run pki cert-show with valid serial Number given in decimal 

	rlPhaseStartSetup "pki_cert_show-004: pki cert-show with valid serialNumber given in decimal"
	local temp_out4="$TmpDir/cert-show4.out"
	local decimal_valid_serialNumber
	decimal_valid_serialNumber=$(printf %d $valid_serialNumber)
	rlLog "Running pki cert-show $decimal_valid_serialNumber"
	rlRun "pki cert-show $decimal_valid_serialNumber > $temp_out3" 0 "command pki cert-show $decimal_valid_serialNumber"
	RETVAL=$?
		if [ $RETVAL != 0 ]; then
		rlLog "pki cert-show has exited with return status $RETVAL"
		fi 
	rlLog "Get the Subject Name of the Certificat with $decimal_valid_serialNumber"
	rlLog "Subject: `cat $temp_out4 | grep Subject | awk -F":" '{print $2}'`"
	rlPhaseEnd

	#Run pki cert-show with invalid serialNumber given in Hexadecimal
	
	rlPhaseStartSetup "pki_cert_show-005: pki cert-show with invalid serialNumber given in hexadecimal"
	local temp_out5="$TmpDir/cert-show5.out"
	local rand=`cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1`
	local invalid_hex_serialNumber=`expr $valid_serialNumber$rand`
	rlRun "pki cert-show $invalid_serialNumber 2> $temp_out5" 1 "command pki cert-show $serialNumber"
	rlAssertGrep "CertNotFoundException" "$temp_out5"
	rlPhaseEnd

	# Run pki cert-show with Junk Characters

	rlPhaseStartSetup "pki_cert_show-006: pki cert-show should fail when junk characteres are given are passed as serialNumber"
	local temp_out6="$TmpDir/cert-show6.out"
	local junk="axb124?$5@@_%^$#$@\!(_)043112321412321"
	rlLog "Executing pki cert-show \"$junk\""
	rlRun "pki cert-show \"$junk\" 2> $temp_out6" 1 "pki cert-show $junk"
	rlAssertGrep "NumberFormatException: For input string" "$temp_out6"
	rlPhaseEnd	
	
	# Run pki cert-show <valid serialNumber> --encoded to produce a valid pem output

	rlPhaseStartSetup "pki_cert_show-007: pki cert-show with --encoded should produce a valid pem output"
	local temp_out7="$TmpDir/cert-show7.out"
	rlLog "Running pki cert-show $serialNumber"
        rlRun "pki cert-show $valid_serialNumber --encoded > $temp_out7" 0 "command pki cert-show $serialNumber --encoded"
        RETVAL=$?
                if [ $RETVAL != 0 ]; then
                rlLog "pki cert-show has exited with return status $RETVAL"
                fi
        rlLog "Get the Subject Name of the Certificate with $serialNumber"
        rlLog "`cat $temp_out7 | grep Issuer | awk -F":" '{print $2}'`"
	rlLog "Check if the encoded output is usable"
	rlRun "openssl x509 -in $temp_out7 -noout -serial" 0 "Run openssl x509 pki cert-show --encoded"
        rlPhaseEnd
	
	#Run pki cert-show --encoded with No serial Number

	rlPhaseStartSetup "pki_cert_show-008: pki cert-show with --encoded and No Serial Number should fail"
	local temp_out8=$TmpDir/cert-show8.out
	rlLog "Running pki cert-show <No-serial-Number> --encoded"
	rlRun "pki cert-show --encoded 1> $temp_out8" 1
	rlAssertGrep "usage: cert-show" "$temp_out8"
	rlPhaseEnd
	
	# Run pki cert-show --encoded with Invalid Serial Number

	rlPhaseStartSetup "pki_cert_show-009: pki cert-show with --encoded & In-valid serial number should fail"
	local temp_out9=$TmpDir/cert-show9.out
	rlLog "Running pki cer-show <invalid-serial-Number> --encoded"
	rlRun "pki cert-show $invalid_serialNumber --encoded 2> $temp_out9" 1 "pki cert-show $serialNumber"
	rlPhaseEnd
	
	# Run pki cert-show <valid serialNumber> --output <filename>

	rlPhaseStartSetup "pki_cert_show-0010: pki cert-show with --output <filename>"
	local temp_out10=$TmpDir/cert-show10.out
	rlLog "Running pki cert-show $serialNumber --output <file-name>"
	rlRun "pki cert-show $valid_serialNumber --output $temp_out10" 0
        RETVAL=$?                                                                                                                                                                             
 		if [ $RETVAL != 0 ]; then                                                                                                                                                     
	        rlLog "pki cert-show has exited with return status $RETVAL"
        	fi                                      
	rlAssertGrep "-----BEGIN CERTIFICATE-----" "$temp_out10"
	rlAssertGrep "\-----END CERTIFICATE-----" "$temp_out10"
	rlRun "openssl x509 -in $temp_out10 -noout -serial" 0 "Run openssl x509 on the output file"
	rlPhaseEnd
	
	# Run pki cert-show <invalid-serial-number> --output 

	rlPhaseStartSetup "pki_cert_show-0011: pki cert-show <invalid-serial-Number> --output <filename> should not create any file"
	local temp_out11=$TmpDir/cert-show11.out
	rlLog "Running pki cert-show <invalid-serialNumber> --output <filename>"
	rlRun "pki cert-show $invalid_serialNumber --output $temp_out11" 1 "pki cert-show <invalid-serial-number> --output <file>"
	if `test -f $temp_out11`; then
		rlLog "$temp_out11 exists"	
	else 
		rlLog "$temp_out11 doesn't exist"
	fi
	rlPhaseEnd

	# Run pki cert-show <No serial number> --output <filename>

	rlPhaseStartSetup "pki_cert_show-0012: pki cert-show with <No serialNumber> --output <filename>"
	local temp_out12=$TmpDir/cert-show12.out
	local temp_out12_err=$TmpDir/cert-err12.out
	rlLog "Running pki cert-show --output $temp_out12 1> $temp_out12_err" 
	rlRun "pki cert-show --output $temp_ou12 1> $temp_out12_err" 1
	rlAssertGrep "usage:" "$temp_out12_err"  	
	rlAssertGrep "--encoded         Base-64 encoded" "$temp_out12_err"
	rlAssertGrep "--output <file>   Output file" "$temp_out12_err"
	rlAssertGrep "--pretty          Pretty print" "$temp_out12_err"	
	rlPhaseEnd	
	
	
	# Run pki cert-show <valid-serial-number> --pretty 

        rlPhaseStartSetup "pki_cert_show-0013: pki cert-show with --pretty <filename>"
        local temp_out13=$TmpDir/cert-show13.out
        rlLog "Running pki cert-show $valid_serialNumber --pretty"
        rlRun "pki cert-show $valid_serialNumber --pretty > $temp_out13" 0
        RETVAL=$?
                if [ $RETVAL != 0 ]; then
                rlLog "pki cert-show has exited with return status $RETVAL"
	       fi
        rlAssertGrep "Certificate:" "$temp_out13"
        rlAssertGrep "Version:" "$temp_out13"
	rlAssertGrep "Subject:" "$temp_out13"
        rlPhaseEnd
	
	 # Run pki cert-show <in-valid-serial-number> --pretty 

	rlPhaseStartSetup "pki_cert_show-0014: pki cert-show with $invalid_serialNumber --pretty <filename>"
	local temp_out14=$TmpDir/cert-show14.out
	rlLog "Running pki cert-show $invalid_serialNumber --pretty"
	rlRun "pki cert-show $invalid_serialNumber --pretty 2> $temp_out13" 1
	rlAssertGrep "CertNotFoundException: Certificate ID 0x`printf %x $invalid_serialNumber` not found" "$temp_out13"
	rlPhaseEnd

	# Run pki cert-show <No serial Number> --pretty

	rlPhaseStartSetup "pki_cert_Show-0015: pki cert-show with <No serialNumber --pretty <filename>"
	local temp_out15=$TmpDir/cert-show15.out
	rlLog "Running pki cert-show --pretty" 1
	rlRun "pki cert-show --pretty 1> $temp_out15" 1
	rlAssertGrep "usage:" "$temp_out15"
	rlAssertGrep "--encoded         Base-64 encoded" "$temp_out15"
	rlAssertGrep "--output <file>   Output file" "$temp_out15"
	rlAssertGrep "--pretty          Pretty print" "$temp_out15" 
	rlPhaseEnd
	
	rlPhaseStartCleanup "pki cert-show cleanup: Delete temp dir"
	rlRun "popd"
    	rlPhaseEnd
}

