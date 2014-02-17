#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-cert-request-submit
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mrniranjan@redhat.com>
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

run_pki_cert_request_show()
{

	# Creating Temporary Directory for pki cert-show
        rlPhaseStartSetup "pki cert-request_show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd
	
	# Local Variables
	CA_agentV_user=CA_agentV
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
	local invalid_requestid=`cat /dev/urandom | tr -dc '0-9' | fold -w 10 | head -n 1`
	local junk_requestid=`cat /dev/urandom | tr -dc 'a-bA-Z0-9' | fold -w 40 | head -n 1` 	
	local temp_cert_out="$TmpDir/cert-request.out"
	local hex_invalid_requestid=`printf 0x%x $invalid_requestid`
	
	# Config test of pki cert-request-show
	rlPhaseStartTest "pki_cert_cli-configtest: pki cert-request-show --help configuration test"
	rlRun "pki cert-request-show --help > $TmpDir/cert-show.out 2>&1" 0 "pki cert-request-show --help"
	rlAssertGrep "usage: cert-request-show <Request ID>" "$TmpDir/cert-show.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/cert-show.out"
	rlLog "FAIL :: https://engineering.redhat.com/trac/pki-tests/ticket/490"
	rlPhaseEnd

	# Create a Temporary NSS DB Directory and generate Certificate

	rlPhaseStartSetup "Generating temporary Cert to be used pki cert-show automation Tests"
	rlLog "Generating Certificate Request"
        rlRun "create_cert_request $TEMP_NSS_DB redhat pkcs10 rsa 2048 \"Idm User1\" \"IdmUser1\" \"idmuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 
	rlLog "To Approve the request we would need CA Admin Cert Nick Name stored in $MY_CERTDB_DIR"
        rlLog "Approve Certificate requeset"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" ca-cert-request-review $ret_requestid --action approve 1> $TmpDir/pki-approve-out"
	rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
	rlRun "valid_serialNumber=`pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2`"
        rlPhaseEnd
	

	# pki cert-request-show <valid requestId(decimal) Anonymous>
        rlPhaseStartTest "pki_cert_request_show-001: pki cert-request-show < valid requestid >  should show Certificate Request Details"
        local temp_out1="$TmpDir/cert-request-show1.out"
        rlLog "Running pki cert-request-show $ret_requestid"
        rlRun "pki cert-request-show $ret_requestid > $temp_out1" 0 "command pki cert-request-show $requestid"
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out1"
	rlAssertGrep "Type: enrollment" "$temp_out1"
	rlAssertGrep "Request Status: complete" "$temp_out1"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out1"
	rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out1"
	rlPhaseEnd

	# pki cert-request-show  <valid requestid(hexadecimal)> Anonymous
	rlPhaseStartTest "pki_cert_request_show-002: pki cert-request-show <valid requestid(hexadecimal)> should Show Certificate Request details"
	local temp_out2="$TmpDir/cert-request-show2.out"
	local hex_valid_requestid=`printf 0x%x $ret_requestid`
	rlLog "Running pki cert-request-show $hex_valid_reqid"
	rlRun "pki cert-request-show $hex_valid_requestid > $temp_out2" 0
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out2"
	rlAssertGrep "Type: enrollment" "$temp_out2" 
	rlAssertGrep "Request Status: complete" "$temp_out2"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out2"
	rlAssertGrep "Certificate ID: $valid_serialNumber" "$temp_out2"
	rlPhaseEnd

	# pki cert-request-show <invalid requestid(decimal)> Anonymous
	rlPhaseStartTest "pki_cert_request_show-003: pki cert-request-show <invalid requestid(decimal)> Should fail to display any Request details"
	local temp_out3="$TmpDir/cert-request-show3.out"
	rlLog "Executing pki cert-request-show $invalid_requestid"
	rlRun "pki cert-request-show $invalid_requestid 2> $temp_out3" 1
	rlAssertGrep "RequestNotFoundException: Request ID $hex_invalid_requestid not found" "$temp_out3"
	rlPhaseEnd

	#pki cert-request-show <invalid requestid(hexadecimal)> Anonymous
	rlPhaseStartTest "pki_cert_request_show-004: pki cert-request-show <invalid requestid(hexadecimal)> Should fail to display any Request details"
	local temp_out4="$TmpDir/cert-request-show4.out"
	rlLog "Executing pki cert-request-show $hex_invalid_requestid"
	rlRun "pki cert-request-show $hex_invalid_requestid 2> $temp_out4" 1
	rlAssertGrep "RequestNotFoundException: Request ID $hex_invalid_requestid not found" "$temp_out4"
	rlPhaseEnd
	
	#pki cert-request-show <junk chracters> Anonymous
	rlPhaseStartTest "pki_cert_request_show-005: pki cert-request-show <Junk Characters(decimal)> Should fail to display any Request details"
	local temp_out5="$TmpDir/cert-request-show5.out"
	rlLog "Executing pki cert-request-show \"$junk_requestid~!@#$%^&*()_+|\""
	rlRun "pki cert-request-show \"$junk_requestid~\!@#$%^&*\(\)_+|\" 2> $temp_out5" 255
	rlAssertGrep "Error: Invalid certificate request ID" "$temp_out5"
	rlPhaseEnd
	
	#Pki cert-request-show Verify rejected Request Id is displayed correctly 
	rlPhaseStartTest "pki_cert_request_show-006: Verify rejected RequesId's status is displayed as Rejected"
	local temp_out6="$TmpDir/cert-request-show6.out"
	rlLog "Request a New Certificate Request"
	rlRun "create_cert_request $TEMP_NSS_DB redhat pkcs10 rsa 2048 \"Idm User2\" \"IdmUser2\" \"idmuser2@example.org\" \"MCP Division\" \"Example Org\" "US" "--" "ret_reqstatus" "ret_requestid""
	rlLog "Reject Certificate requeset"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" ca-cert-request-review $ret_requestid --action reject 1> $temp_cert_out"
	rlAssertGrep "Rejected certificate request $ret_requestid" "$temp_cert_out"
	rlLog "Executing pki cert-request-show $ret_requestid" 
	rlRun "pki cert-request-show $ret_requestid 1> $temp_out6" 0 
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out6"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out6"
	rlAssertGrep "Type: enrollment" "$temp_out6"
	rlAssertGrep "Request Status: rejected" "$temp_out6"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out6"
	rlPhaseEnd

	#Pki cert-request-show Verify canceled Request Id is displayed correctly
	rlPhaseStartTest "pki_cert_request_show-007: Verify canceled RequesId's status is displayed as canceled"
	local temp_out7="$TmpDir/cert-request-show7.out"
	rlRun "create_cert_request $TEMP_NSS_DB redhat pkcs10 rsa 2048 \"Idm User3\" \"IdmUser3\" \"idmuser3@example.org\" \"MAP Division\" \"Example Org\" "US" "--" "ret_reqstatus" "ret_requestid""
	rlLog "Cancel Certificate request"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" ca-cert-request-review $ret_requestid --action cancel 1> $temp_cert_out"
	rlAssertGrep "Canceled certificate request $ret_requestid" "$temp_cert_out"
	rlLog "Executing pki cert-request-show $ret_requestid" 
	rlRun "pki cert-request-show $ret_requestid 1> $temp_out7" 0 
	rlAssertGrep "Certificate request \"$ret_requestid\"" "$temp_out7"
	rlAssertGrep "Request ID: $ret_requestid" "$temp_out7"
	rlAssertGrep "Type: enrollment" "$temp_out7"
	rlAssertGrep "Request Status: canceled" "$temp_out7"
	rlAssertGrep "Operation Result: $ret_reqstatus" "$temp_out7"
	rlPhaseEnd
	
	#pki cert-request-show Verify SerialNumber Displayed matches with SerialNumber assigned to Approved request
	rlPhaseStartTest "pki_cert_request_show-008: verify serialNumber displayed matches with serialNumber assigned to Approved request"
	rlLog "Request a New Certificate Request"
	rlRun "create_cert_request $TEMP_NSS_DB redhat pkcs10 rsa 2048 \"Idm User4\" \"IdmUser4\" \"idmuser4@example.org\" \"MNP Division\" \"Example Org\" "US" "--" "ret_reqstatus" "ret_requestid""
	rlLog "Approve the Certificate Request"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" ca-cert-request-review $ret_requestid --action approve 1> $TmpDir/pki-approve-out" 0 
	rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
	rlLog "Get the Certificate Serial Number displayed by pki cert-request-show $ret_requestid"
	rlRun "valid_serialNumber=`pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2`"
	rlLog "Serial Number Displayed by pki cert-request-show $ret_requestid is $valid_serialNumber"
	rlLog "Run ldapsearch against CA Database to get the serial Number assigned to the approve Request $ret_requestid"
	rlRun "sno=`ldapsearch -x -LLL -b \"ou=certificateRepository,ou=ca,O=pki-tomcat-CA\" -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $(hostname) -p $CA_LDAP_PORT \"(metainfo=requestID:$ret_requestid)\" cn | grep -v dn | awk -F ": " '{print $2}'`"
	
		if [ "$sno" == "`printf %d $valid_serialNumber`" ]; then
			rlLog "SerialNumber Matches with serialNumber assigned to Approved Request"
		else
			rlLog "FAIL :: SerialNumber displayed doesn't match with serialNumber assigned to Approved Request"
		fi
	rlPhaseEnd
		
	
	rlPhaseStartCleanup "pki cert-request-show cleanup: Delete temp dir"
	rlRun "popd"
    	rlPhaseEnd
	
}
