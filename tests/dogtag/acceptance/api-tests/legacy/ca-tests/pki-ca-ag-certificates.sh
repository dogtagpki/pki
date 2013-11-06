#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/api-tests/legacy/ca-tests/
#   Description: PKI CA interface API tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following interfaces needs to be tested:
#  pki-ca-ag-certificates -- CA agent interface managing certificates.
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
. /opt/rhqa_pki/pki-user-cli-lib.sh
. /opt/rhqa_pki/env.sh

########################################################################
# Test Suite Globals
########################################################################

user1="test_user1"
CA_DOMAIN=`hostname -d`
CA_AGENT_CERT="PKI Administrator for $CA_DOMAIN"
CERTDB_PW="Password"



########################################################################

run_pki-ca-ag-certificates(){
    rlPhaseStartSetup "pki_ca-ag-certificates-startup: Create temp directory and import CA agent cert into a nss certificate db"
	rlLog "Admin Certificate is located at: $ADMIN_CERT_LOCATION"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	rlLog "Temp Directory = $TmpDir"
	rlRun "importAdminCert $CA_ADMIN_CERT_LOCATION $TmpDir $CERTDB_PW $CA_AGENT_CERT" 0 "Import Agent certificate to $TmpDir"
	rlRun "install_and_trust_CA_cert $CA_SERVER_ROOT $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "pki_ca-ag-certificates-001: CA Agent approve a certificate requested for caUser profile"
	local REQUESTCFG="$TmpDir/cert_request1.out"
	echo "-ca_hostname $CA_HOSTNAME
		-ca_eesslport 8443
		-request_type crmf
		-request_keysize 1024
		-request_keytype RSA
		-client_certdb_dir \"$TmpDir\"
		-client_certdb_pwd \"$CERTDB_PW\"
		-requestor_phone \"12345678\"
		-requestor_email \"test\"
		-UID \"$user1\" -CN \"$user1\" 	-OU \"$user1\" -O \"$user1\" -E \"$user1\"  -C \"US\" -debug true
		 " >  $REQUESTCFG
	rlRun "runJava profile_request_caUserCert $REQUESTCFG >  \"$TmpDir/pki-ca-ag-certificates-001_1.out\""
	rlAssertGrep "REQUEST_ID" "$TmpDir/pki-ca-ag-certificates-001_1.out"
	request_id=`cat $TmpDir/pki-ca-ag-certificates-001_1.out | grep "REQUEST_ID=" | cut -d "=" -f 2`
	rlRun "cat $TmpDir/pki-ca-ag-certificates-001_1.out"
	rlLog "Request id = $request_id"
	# Agent approve the request
	Year=`date +%Y`
	Month=`date +%m`
	Day=`date +%d`
	Hour=`date +%H`
	Minute=`date +%M`
	Second=`date +%S`
	start_year=$Year;
	end_year=$(($Year+1));
	end_day="1"
	local AGENT_APPROVECFG="$TmpDir/cert_approve1.out"
	if [ $request_id  -gt 1 ] ; then
		rlPass "Request id found"
		echo "-ca_hostname $CA_HOSTNAME
			-ca_agent_port 8443
			-client_certdb_dir \"$TmpDir\"
			-client_certdb_pwd $CERTDB_PW
			-agent_cert_name  \"$CA_AGENT_CERT\"
			-request_id $request_id
			-debug true
			-cert_ext_name UID=$user1
			-cert_ext_notBefore \"$start_year-$Month-$Day $Hour:$Minute:$Second\"
			-cert_ext_notAfter \"$end_year-$Month-$end_day $Hour:$Minute:$Second\"
			-cert_ext_authInfoAccessCritical false
			-cert_ext_authInfoAccessGeneralNames \" \"
			-cert_ext_keyUsageCritical true
			-cert_ext_keyUsageDigitalSignature true
			-cert_ext_keyUsageNonRepudiation true
			-cert_ext_keyUsageKeyEncipherment true
			-cert_ext_keyUsageDataEncipherment false
			-cert_ext_keyUsageKeyAgreement false
			-cert_ext_keyUsageKeyCertSign false
			-cert_ext_keyUsageCrlSign false
			-cert_ext_keyUsageEncipherOnly false
			-cert_ext_keyUsageDecipherOnly false
			-cert_ext_exKeyUsageCritical false
			-cert_ext_exKeyUsageOIDs \"1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4\"
			-cert_ext_subjAltNameExtCritical false
			-cert_ext_subjAltNames \"RFC822Name: \"
			-cert_ext_signingAlg SHA1withRSA
			-cert_ext_requestNotes submittingcerts
			-request_op approve
			" > $AGENT_APPROVECFG

		rlRun "runJava ca_ag_ManageProfileRequest_caUserCert $AGENT_APPROVECFG >  \"$TmpDir/pki-ca-ag-certificates-001_2.out\""
		rlRun "cat $TmpDir/pki-ca-ag-certificates-001_2.out"
		rlAssertGrep "SERIAL_NUMBER" "$TmpDir/pki-ca-ag-certificates-001_2.out"
		cert_serial_number=`cat $TmpDir/pki-ca-ag-certificates-001_2.out | grep "SERIAL_NUMBER=" | cut -d "=" -f 2`
		if [ $cert_serial_number ] ; then
			rlLog "SERIAL_NUMBER=$cert_serial_number"
			rlPass "Certificate is approved, Serial Number is $cert_serial_number"
		else
			rlFail "Failed to approve the cert"
		fi
	else
		rlFail "Request id is empty"
	fi
    rlPhaseEnd

    rlPhaseStartCleanup "pki_ca-ag-certificates-cleanup: Delete temp dir"
	rlRun "popd"
    #    rlRun "rm -r $TmpDir" 0 "Removing temp directory"
    rlPhaseEnd
}
