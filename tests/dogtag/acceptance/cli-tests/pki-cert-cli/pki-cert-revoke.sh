#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-cert-revoke
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

run_pki_cert_revoke()
{

	# local variables
	local invalid_serialNumber=$(cat /dev/urandom | tr -dc '1-9' | fold -w 10 | head -n 1)
	local invalid_hex_serialNumber=0x$(echo "ibase=16;$invalid_serialNumber"|bc)
	CA_agentV_user=CA_agentV
	CA_adminR_user=CA_adminR
	CA_audit_user=CA_auditV
	local pkcs10_reqstatus
	local pkcs10_requestid
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
	local sub_ca_ldap_port=1800
	local sub_ca_http_port=14080
	local sub_ca_https_port=14443
	local sub_ca_ajp_port=14009
	local sub_ca_tomcat_port=14005
        local subca_instance_name=pki-example-$rand
        local SUBCA_SERVER_ROOT=/var/lib/pki/$subca_instance_name/ca
        local admin_cert_nickname="PKI Administrator for $CA_DOMAIN"

	# Creating Temporary Directory for pki cert-revoke
        rlPhaseStartSetup "pki cert-show Temporary Directory"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"

	#local variables
	local TEMP_NSS_DB="$TmpDir/nssdb"
	local exp="$TmpDir/expfile.out"
	local expout="$TmpDir/exp_out"
	local cert_info="$TmpDir/cert_info"
        rlPhaseEnd

        # Setup SubCA for pki cert-revoke tests
	rlPhaseStartSetup "Setup a Subordinate CA for pki cert-revoke"
        local install_info=$TmpDir/install_info
        rlLog "Setting up a Subordinate CA instance $subca_instance_name"
        rlRun "rhcs_install_subca-BZ-501088 $subca_instance_name \
                $sub_ca_ldap_port \
                $sub_ca_http_port \
                $sub_ca_https_port \
                $sub_ca_ajp_port \
                $sub_ca_tomcat_port \
                $TmpDir $TmpDir/nssdb $install_info"
        rlLog "Add CA Cert to $TEMP_NSS_DB"
        rlRun "install_and_trust_CA_cert $SUBCA_SERVER_ROOT \"$TEMP_NSS_DB\""
        local subca_serialNumber=$(pki cert-find  --name "SubCA-$subca_instance_name" --matchExactly | grep "Serial Number" | awk -F": " '{print $2}')
        local STRIP_HEX_PKCS10=$(echo $subca_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local subca_deciamal_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlPhaseEnd

	# pki cert cli config test
	rlPhaseStartTest "pki_cert_cli-configtest: pki cert-revoke --help configuration test"
	rlRun "pki cert-revoke --help > $TmpDir/cert-revoke.out 2>&1" 0 "pki cert-revoke --help"
	rlAssertGrep "usage: cert-revoke <Serial Number> \[OPTIONS...]" "$TmpDir/cert-revoke.out"
   	rlAssertGrep "--ca                    CA signing certificate" "$TmpDir/cert-revoke.out"
    	rlAssertGrep "--comments <comments>   Comments" "$TmpDir/cert-revoke.out"
    	rlAssertGrep "--reason <reason>       Revocation reason: Unspecified (default)," "$TmpDir/cert-revoke.out"
	rlAssertGrep "Key_Compromise" "$TmpDir/cert-revoke.out"
	rlAssertGrep "CA_Compromise" "$TmpDir/cert-revoke.out"
	rlAssertGrep "Affiliation_Changed" "$TmpDir/cert-revoke.out"
	rlAssertGrep "Superseded" "$TmpDir/cert-revoke.out"
	rlAssertGrep "Cessation_of_Operation" "$TmpDir/cert-revoke.out"
	rlAssertGrep "Certificate_Hold" "$TmpDir/cert-revoke.out"
	rlAssertGrep "Remove_from_CRL" "$TmpDir/cert-revoke.out"
	rlAssertGrep "Privilege_Withdrawn" "$TmpDir/cert-revoke.out"
	rlAssertGrep "AA_Compromise" "$TmpDir/cert-revoke.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/cert-revoke.out"
	rlLog "FAIL :: https://engineering.redhat.com/trac/pki-tests/ticket/490"
	rlPhaseEnd

	# pki -d <temp_nss_db> -p <subca_port>  -h <host> -c <password> -n "admin cert" cert-revoke <serialNumber>
        rlPhaseStartTest "pki_cert_revoke_001: Revoke a cert using Agent with same serial as Subordinate CA(BZ-501088)"
        local admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
        local i=1
        local upperlimit
        let upperlimit=$subca_deciamal_serialNumber-3
        while [ $i -ne $upperlimit ] ; do
        rlRun "generate_cert2 $sub_ca_http_port \
                \"$admin_cert_nickname\" \
                $(hostname) \
                $TEMP_NSS_DB \
                $CA_CLIENT_PKCS12_PASSWORD \
                \"Foo User$i\" "FooUser$i" "FooUser$i@example.org" $cert_info"
        let i=$i+1
        done
        local revoked_cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Certificate that would be revoked is $revoked_cert_serialNumber"
        rlRun "pki -d $TEMP_NSS_DB \
                -p $sub_ca_http_port \
                -h $(hostname) \
                -c $CA_CLIENT_PKCS12_PASSWORD \
                -n \"$admin_cert_nickname\" \
                cert-revoke $revoked_cert_serialNumber --force --reason Certificate_Hold 1> $expout"
        rlAssertGrep "Placed certificate \"$revoked_cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $revoked_cert_serialNumber" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber>
	rlPhaseStartTest "pki_cert_revoke_002: pki cert-revoke <serialNumber>"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generate Temorary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber"
	rlRun "create_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serilNumber> --comments "Test Comment1"
	rlPhaseStartTest "pki_cert_revoke_003: pki cert-revoke <serialNumber> --comments \"Test Comment1\""
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --comments \"Test Comment1\""
	rlRun "create_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force
        rlPhaseStartTest "pki_cert_revoke_004: pki cert-revoke <serialNumber> --force"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force 1> $expout"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason unspecified
        rlPhaseStartTest "pki_cert_revoke_005: pki cert-revoke <serialNumber> --reason unspecified"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason unspecified"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Key_Compromise
        rlPhaseStartTest "pki_cert_revoke_006: pki cert-revoke <serialNumber> --reason Key_Compromise"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Key_Compromise"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
       
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason CA_Compromise
        rlPhaseStartTest "pki_cert_revoke_007: pki cert-revoke <serialNumber> --reason CA_Compromise"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason CA_Compromise"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd	

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Affiliation_Changed
        rlPhaseStartTest "pki_cert_revoke_008: pki cert-revoke <serialNumber> --reason Affiliation_Changed"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Affiliation_Changed"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Superseded
        rlPhaseStartTest "pki_cert_revoke_009: pki cert-revoke <serialNumber> --reason Superseded"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Superseded"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Cessation_of_Operation
        rlPhaseStartTest "pki_cert_revoke_0010: pki cert-revoke <serialNumber> --reason Cessation_of_Operation"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Cessation_of_Operation"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Certificate_Hold
        rlPhaseStartTest "pki_cert_revoke_0011: pki cert-revoke <serialNumber> --reason Certificate_Hold"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Certificate_Hold"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Privilege_Withdrawn
        rlPhaseStartTest "pki_cert_revoke_0012: pki cert-revoke <serialNumber> --reason Privilege_Withdrawn"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Privilege_Withdrawn"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Remove_from_CRL
	rlPhaseStartTest "pki_cert_revoke_0013: pki cert-revoke <serialNumber> --reason Remove_from_CRL"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $expout"
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Remove_from_CRL"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
	rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --reason Invalid revocation reason
        rlPhaseStartTest "pki_cert_revoke_0014: pki cert-revoke <serialNumber> --reason Invalid revocation reason"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --reason unknown_revocation_reason 2> $expout" 1
	rlAssertGrep "Error: Invalid revocation reason: unknown_revocation_reason" "$expout"
        rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke  <revoked-serialNumber> 
	rlPhaseStartTest "pki_cert_revoke_0015: pki cert-revoke <revoked-serialNumber>"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
	rlAssertGrep "Status: REVOKED" "$expout"
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --reason Key_Compromise"
	rlRun "create_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1"  
	STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
	rlAssertGrep "BadRequestException: certificate #$STRIP_HEX_PKCS10 has already been revoked" "$expout"
	rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason unspecified
	rlPhaseStartTest "pki_cert_revoke_0016: pki cert-revoke <serialNumber> --force --reason unspecified"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason unspecified 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Key_Compromise
	rlPhaseStartTest "pki_cert_revoke_0017: pki cert-revoke <serialNumber> --force --reason Key_Compromise"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason CA_Compromise
        rlPhaseStartTest "pki_cert_revoke_0018: pki cert-revoke <serialNumber> --force --reason CA_Compromise"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason CA_Compromise 1> $expout"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Affiliation_Changed
	rlPhaseStartTest "pki_cert_revoke_0019: pki cert-revoke <serialNumber> --force --reason Affiliation_Changed"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Affiliation_Changed 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Supersede
	rlPhaseStartTest "pki_cert_revoke_0020: pki cert-revoke <serialNumber> --force --reason Superseded"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		 -n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Superseded 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Cessation_of_Operation
	rlPhaseStartTest "pki_cert_revoke_0021: pki cert-revoke <serialNumber> --force --reason Cessation_of_Operation"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Cessation_of_Operation 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Certificate_Hold
	rlPhaseStartTest "pki_cert_revoke_0022: pki cert-revoke <serialNumber> --force --reason Certificate_Hold"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $expout" 0
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	#pki cert-revoke <serialNumber> --force --reason Privilege_Withdrawn
	rlPhaseStartTest "pki_cert_revoke_0023: pki cert-revoke <serialNumber> --force --reason Privilege_Withdrawn"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason  Privilege_Withdrawn 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	#pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Invalid revocation reason
        rlPhaseStartTest "pki_cert_revoke_0024: pki cert-revoke <serialNumber> --force --reason Invalid revocation reason"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason unknown_revocation_reason 2> $expout" 1
        rlAssertGrep "Error: Invalid revocation reason: unknown_revocation_reason" "$expout"
        rlPhaseEnd

	#pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <serialNumber> --force --reason Remove_from_CRL
        rlPhaseStartTest "pki_cert_revoke_0025: pki cert-revoke <serialNumber> --force --reason Remove_from_CRL"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Remove_from_CRL 1> $expout"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd	

	#pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <non_CA_signing_Cert_serialNumber> --ca
	rlPhaseStartTest "pki_cert_revoke_0026: Revoke a non CA signing Cert using pki cert-revoke --ca" 
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --ca --reason unspecified"
        rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "UnauthorizedException: Certificate $cert_serialNumber is not a CA signing certificate" "$expout"
        rlPhaseEnd

	#pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <non_CA_signing_Cert_serialNumber> --ca --force
        rlPhaseStartTest "pki_cert_revoke_0027: Revoke a non CA signing Cert using pki cert-revoke --ca --force"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --ca --reason unspecified 2> $expout" 1
        rlAssertGrep "UnauthorizedException: Certificate $cert_serialNumber is not a CA signing certificate" "$expout"
        rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <CA_signing_cert_serialNumber> --ca 
	rlPhaseStartTest "pki_cert_revoke_0028: Revoke a CA signing Cert using pki cert-revoke --ca"
	cert_serialNumber=0x1
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-revoke $cert_serialNumber --ca --reason Certificate_Hold"
	rlRun "create_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-release-hold $cert_serialNumber --force" 0 "Release Certificate Hold of CA Signing Certificate"
        rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "Revoked Agent" <serialNumber> --force unspecified
	rlPhaseStartTest "pki_cert_revoke_0029: Revoke a cert using Revoked CA Agent Cert"
	rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD \
		-n \"$CA_adminR_user\" cert-revoke $cert_serialNumber \
		--force --reason unspecified 2> $expout" 1
	rlAssertGrep "PKIException: Unauthorized" "$expout"
	rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Audit" cert-revoke <serialNumber> --force --reason unspecified
        rlPhaseStartTest "pki_cert_revoke_0030: Revoke a cert using CA Audit Cert"
        rlRun "generate_cert1 $TEMP_NSS_DB $cert_info" 0 "Generating Temporary Certificate"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_audit_user\" \
		cert-revoke $cert_serialNumber --force --reason unspecified 2> $expout" 1
        rlAssertGrep "ForbiddenException: Authorization failed on resource: certServer.ca.certs, operation: execute" "$expout"	
	rlPhaseEnd
	
	# pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <invalid serialNumber> --force --reason unspecified
	rlPhaseStartTest "pki_cert_revoke_0031: Revoke cert with with Invalid serialNumber"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $invalid_serialNumber --force --reason unspecified 2> $expout" 1
	rlAssertGrep "CertNotFoundException:" "$expout"
	rlPhaseEnd

	#pki -d <certdb> -c <password> -n "CA Agent" cert-revoke <expried_cert_serialNumber> --force --reason Key_Compromise
        rlPhaseStartTest "pki_cert_revoke_0032: Revoke an expired cert"
        local endDate="1 month"
        rlRun "modify_cert $TEMP_NSS_DB $cert_info $exp \"$endDate\"" 0 "Generate Modified Cert"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        rlRun "date -s '$cert_end_date'"
        rlRun "date -s 'next day'"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlLog "Set the date back to it's original date & time"
	rlRun "date --set='1 day ago'" 
	rlRun "date --set='$endDate ago'"
        rlPhaseEnd

	# Remove SubCA instance and DS instance used by SubCA	
	rlPhaseStartCleanup "Destroy SubCA & DS instance"
	rlRun "pkidestroy -s CA -i $subca_instance_name > $TmpDir/$subca_instance_name-ca-clean.out"
	rlAssertGrep "Uninstalling CA from /var/lib/pki/$subca_instance_name" "$TmpDir/$subca_instance_name-ca-clean.out"
	rlAssertGrep "Uninstallation complete" "$TmpDir/$subca_instance_name-ca-clean.out"
	rlRun "remove-ds.pl -i slapd-$subca_instance_name > $TmpDir/subca_instance_name-ds-clean.out"
	rlAssertGrep "Instance slapd-$subca_instance_name removed" "$TmpDir/subca_instance_name-ds-clean.out"
	rlPhaseEnd

	rlPhaseStartCleanup "pki cert-revoke cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
generate_cert1()
{
        local tmp_nss_db="$1"
        local cert_info="$2"
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
	rlRun "create_new_cert_request dir:$tmp_nss_db pass:Secret123 req_type:pkcs10 algo:rsa size:1024 cn: uid: email: ou: org: c: archive:false myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt"
        if [ $? != 0 ]; then
        {
                rlFail "Request Creation failed"
                return 1
        }
	fi
	rlRun "submit_new_request dir:$tmp_nss_db pass:Secret123 cahost: nickname: protocol: port: url: username: userpwd: profile: myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt out:$tmp_nss_db/$rand-request-result.txt"
	if [ $? != 0 ]; then
	{
		rlFail "Request Submission failed"
		return 1
	}
        fi
        rlAssertGrep "Request Status: pending" "$tmp_nss_db/$rand-request-result.txt"
        rlAssertGrep "Operation Result: success" "$tmp_nss_db/$rand-request-result.txt"
	pkcs10_requestid=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        pkcs10_requestdn=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                ca-cert-request-review $pkcs10_requestid \
                --action approve 1> $tmp_nss_db/pki-pkcs10-approve-out" 0 "As $CA_agentV_user Approve Certificate Request"
        if [ $? != 0 ]; then
        {
                rlFail "cert approval failed"
                return 1
        }
        fi
        rlAssertGrep "Approved certificate request $pkcs10_requestid" "$tmp_nss_db/pki-pkcs10-approve-out"
        local valid_pkcs10_serialNumber=$(pki cert-request-show $pkcs10_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
        local cert_end_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not After" | awk -F ": " '{print $2}')
        echo cert_serialNumber-$valid_pkcs10_serialNumber > $cert_info
        echo cert_start_date-$cert_start_date >> $cert_info
        echo cert_end_date-$cert_end_date >> $cert_info
        echo cert_requestdn-$pkcs10_requestdn >> $cert_info
        return 0;
}
create_expect_data()
{
	local expfile=$1
	local cert_info=$2
	local cmdline=$3
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local start_date=$(cat $cert_info | grep cert_start_date | cut -d- -f2)
	local end_date=$(cat $cert_info | grep cert_end_date | cut -d- -f2)
	local requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
	local cmd=$cmdline
	echo "set timeout 5" > $expfile
        echo "spawn $cmdline" >> $expfile
        echo "expect -exact \"Revoking certificate:\\r" >> $expfile
        echo "   Serial Number: $cert_serialNumber\\r" >> $expfile
        echo "   Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain\\r" >> $expfile
        echo "   Subject: $requestdn\\r" >> $expfile
        echo "   Status: VALID\\r" >> $expfile
        echo "   Not Before: $start_date\\r" >> $expfile
        echo "   Not After: $end_date\\r" >> $expfile
        echo "Are you sure \(Y/N\)? \"" >> $expfile
        echo "send -- \"y\\r\"" >> $expfile
        echo "expect eof" >> $expfile
}
# This function creates a modified Certificate , Currently we modify End date(notAfter) of cert request and approve the cert
modify_cert()
{
        local tmp_nss_db="$1"
	local cert_info="$2"
	local expfile="$3"
	local mytime="$4"
        rlRun "create_new_cert_request dir:$tmp_nss_db pass:Secret123 req_type:pkcs10 algo:rsa size:1024 cn: uid: email: ou: org: c: archive:false myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt"
        if [ $? != 0 ]; then
        {
                rlFail "Request Creation failed"
                return 1
        }
        fi
        rlRun "submit_new_request dir:$tmp_nss_db pass:Secret123 cahost: nickname: protocol: port: url: username: userpwd: profile: myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt out:$tmp_nss_db/$rand-request-result.txt"
        if [ $? != 0 ]; then
        {
                rlFail "Request Submission failed"
                return 1
        }
        fi
        rlAssertGrep "Request Status: pending" "$tmp_nss_db/$rand-request-result.txt"
        rlAssertGrep "Operation Result: success" "$tmp_nss_db/$rand-request-result.txt"
        pkcs10_requestid=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        pkcs10_requestdn=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)
	updateddate=$(date --date="$mytime" +%Y-%m-%d)
	echo "set timeout 5" > $expfile
	echo "set force_conservative 0" >> $expfile
	echo "set send_slow {1 .1}" >> $expfile
	echo "spawn -noecho pki -d /opt/rhqa_pki/certs_db -n "CA_agentV" -c redhat123  cert-request-review $pkcs10_requestid --file $tmp_nss_db/$pkcs10_requestid-req.xml" >> $expfile
	echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $expfile
	echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" -v \\\"$updateddate 13:37:56\\\" $tmp_nss_db/$pkcs10_requestid-req.xml\"" >> $expfile
	echo "send -- \"approve\r\"" >> $expfile
	echo "expect eof" >> $expfile
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        if [ $? != 0 ]; then
        {
                rlFail "Request Approval failed"
                return 1;
        }
        fi
        rlAssertGrep "Approved certificate request $pkcs10_requestid" "$expout"
        local valid_pkcs10_serialNumber=$(pki cert-request-show $pkcs10_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
        local cert_start_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
        local cert_end_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not After" | awk -F ": " '{print $2}')
        echo cert_serialNumber-$valid_pkcs10_serialNumber > $cert_info
        echo cert_start_date-$cert_start_date >> $cert_info
        echo cert_end_date-$cert_end_date >> $cert_info
        echo cert_requestdn-$pkcs10_requestdn >> $cert_info
        return 0;
}
generate_cert2()
{
        local tmp_http_port=$1
        local tmp_admin_nick=$2
        local tmp_host=$3
        local tmp_nss_db=$4
        local tmp_nss_db_pass=$5
        local subject_cn=$6
        local subject_uid=$7
        local subject_email=$8
        local CERT_INFO=$9
        local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)

        rlRun "create_new_cert_request dir:$tmp_nss_db pass:$tmp_nss_db_pass req_type:pkcs10 algo:rsa size:1024 cn:\"$subject_cn\" uid:$subject_uid email:$subject_email ou: org: c: archive:false myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt"
        rlRun "submit_new_request dir:$tmp_nss_db pass:$tmp_nss_db_pass cahost: nickname:\"$tmp_admin_nick\" protocol: port:$tmp_http_port url: username: userpwd: profile: myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt out:$tmp_nss_db/$rand-request-result.txt"
        if [ $? != 0 ]; then
        {
                rlFail "Request Creation failed"
                return 1;
        }
        fi
        pkcs10_requestid=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        pkcs10_requestdn=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)
        rlRun "pki -d $tmp_nss_db -p $tmp_http_port -c $tmp_nss_db_pass -n \"$tmp_admin_nick\" ca-cert-request-review $pkcs10_requestid --action approve 1> $tmp_nss_db/pki-pkcs10-approve-out"
        if [ $? != 0 ]; then
        {
                rlFail "Approving cert failed"
                return 1;
        }
        fi
        rlAssertGrep "Approved certificate request $pkcs10_requestid" "$tmp_nss_db/pki-pkcs10-approve-out"
        local valid_pkcs10_serialNumber=$(pki -p $tmp_http_port cert-request-show $pkcs10_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
        rlRun "pki -p $tmp_http_port cert-show  $valid_pkcs10_serialNumber --encoded > $tmp_nss_db/$rand-cert-show.info"
        rlAssertGrep "Subject: $pkcs10_requestdn" "$tmp_nss_db/$rand-cert-show.info"
        rlAssertGrep "Status: VALID" "$tmp_nss_db/$rand-cert-show.info"
        local cert_start_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
        local cert_end_date=$(pki cert-show $valid_pkcs10_serialNumber | grep "Not After" | awk -F ": " '{print $2}')
        echo cert_serialNumber-$valid_pkcs10_serialNumber > $CERT_INFO
        return 0;

}
rhcs_install_subca-BZ-501088()
{
        local SUBCA_INSTANCE_NAME=$1
        local SUBCA_LDAP_PORT=$2
        local SUBCA_HTTP_PORT=$3
        local SUBCA_HTTPS_PORT=$4
        local SUBCA_AJP_PORT=$5
        local SUBCA_TOMCAT_SERVER_PORT=$6
        local SUBCA_WORK_DIR=$7
        local SUBCA_CERTDB_DIR=$8
        local SUBCA_OUTPUT_FILE=$9
        local SUBCA_INSTANCECFG="$SUBCA_WORK_DIR/subca_instance.inf"
        local SUBCA_INSTANCE_CREATE_OUT="$SUBCA_WORK_DIR/subca_instance_create.out"
        local SUBCA_ADMIN_CERT_LOCATION=/root/.dogtag/$SUBCA_INSTANCE_NAME/ca_admin_cert.p12
        local admin_cert_nickname="PKI Administrator for $CA_DOMAIN"

	rhcs_install_prep_disableFirewall

        for i in {$SUBCA_LDAP_PORT $SUBCA_HTTP_PORT $SUBCA_HTTPS_PORT $SUBCA_AJP_PORT $SUBCA_TOMCAT_SERVER_PORT}
        do
                netstat -plant | cut -d" " -f4 | cut -d":" -f2 | grep -v grep | grep $i
                RETVAL=$?
                if [ $RETVAL == 0 ];then
                        echo -e "\nThere are some process which are using those ports"
                        rlFail "Ports already in use installation Failed"
                fi
        done

        rlLog "Creating LDAP server Instance to Sub CA instace $SUBCA_INSTANCE_NAME"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $SUBCA_LDAP_PORT $SUBCA_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0
        if [ $? != 0 ]; then
                rlFail "Unable to setup ldap instance"
                return 1
        fi
        echo -e "[DEFAULT]" > $SUBCA_INSTANCECFG
        echo -e "pki_instance_name = $SUBCA_INSTANCE_NAME" >> $SUBCA_INSTANCECFG
        echo -e "pki_admin_password = $CA_ADMIN_PASSWORD" >> $SUBCA_INSTANCECFG
        echo -e "pki_client_pkcs12_password = $CA_CLIENT_PKCS12_PASSWORD" >> $SUBCA_INSTANCECFG
        echo -e "pki_client_database_password = $CA_CLIENT_PKCS12_PASSWORD" >> $SUBCA_INSTANCECFG
        echo -e "pki_ds_password= $LDAP_ROOTDNPWD" >> $SUBCA_INSTANCECFG
        echo -e "pki_security_domain_password = $CA_SECURITY_DOMAIN_PASSWORD" >> $SUBCA_INSTANCECFG
        echo -e "pki_security_domain_hostname = $(hostname)" >> $SUBCA_INSTANCECFG
        echo -e "pki_security_domain_https_port = $CA_SECURE_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_security_domain_user = $CA_ADMIN_USER" >> $SUBCA_INSTANCECFG
        echo -e "[CA]" >> $SUBCA_INSTANCECFG
        echo -e "pki_subordinate=True" >> $SUBCA_INSTANCECFG
        echo -e "pki_issuing_ca=https://$(hostname):$CA_SECURE_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_ca_signing_subject_dn = cn=SubCA-$SUBCA_INSTANCE_NAME,o=%(pki_security_domain_name)s" >> $SUBCA_INSTANCECFG
        echo -e "pki_http_port = $SUBCA_HTTP_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_https_port = $SUBCA_HTTPS_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_ajp_port = $SUBCA_AJP_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_tomcat_server_port = $SUBCA_TOMCAT_SERVER_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_admin_uid = caadmin" >> $SUBCA_INSTANCECFG
        echo -e "pki_import_admin_cert = False" >> $SUBCA_INSTANCECFG
        echo -e "pki_ds_hostname = $(hostname)" >> $SUBCA_INSTANCECFG
        echo -e "pki_ds_ldap_port = $SUBCA_LDAP_PORT" >> $SUBCA_INSTANCECFG
        echo -e "pki_ds_bind_dn = cn=Directory Manager" >> $SUBCA_INSTANCECFG
        echo -e "pki_ds_password = $LDAP_ROOTDNPWD" >> $SUBCA_INSTANCECFG
        echo -e "pki_ds_base_dn = o=$SUBCA_INSTANCE_NAME-CA" >> $SUBCA_INSTANCECFG
        rlLog "Executing: pkispawn -s CA -f $SUBCA_INSTANCECFG -v "
        rlRun "pkispawn -s CA -f $SUBCA_INSTANCECFG -v > $SUBCA_INSTANCE_CREATE_OUT 2>&1"
        if [ $? != 0 ]; then
                rlFail "FAIL Subca instance $SUBCA_INSTANCE_NAME failed"
                return 1
        fi
        exp_message1="Administrator's username:             $PKI_SECURITY_DOMAIN_USER"
        rlAssertGrep "$exp_message1" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message1_1="Administrator's PKCS #12 file:"
        rlAssertGrep "$exp_message1_1" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message2="$CA_DOMAIN"
        rlAssertGrep "$exp_message2" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message3_1="To check the status of the subsystem:"
        rlAssertGrep "$exp_message3_1" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message3_2="systemctl status pki-tomcatd\@$subca_instance_name.service"
        rlAssertGrep "$exp_message3_2" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message4_1="To restart the subsystem:"
        rlAssertGrep "$exp_message4_1" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message4_2=" systemctl restart pki-tomcatd\@$subca_instance_name.service"
        rlAssertGrep "$exp_message4_2" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message5="The URL for the subsystem is:"
        rlAssertGrep "$exp_message5" "$SUBCA_INSTANCE_CREATE_OUT"
        exp_message5_1="https://$(hostname):$SUBCA_HTTPS_PORT/ca"
        rlAssertGrep "$exp_message5_1" "$SUBCA_INSTANCE_CREATE_OUT"

        echo -e "SUBCA_SERVER_ROOT:/var/lib/pki/$SUBCA_INSTANCE_NAME/ca" >> $SUBCA_OUTPUT_FILE
        echo -e "SUBCA_CERTDB_DIR:$SUBCA_WORK_DIR/certs_db" >> $SUBCA_OUTPUT_FILE
        echo -e "SUBCA_LDAP_INSTANCE_NAME:o=$SUBCA_INSTANCE_NAME-CA" >> $SUBCA_OUTPUT_FILE
        echo -e "SUBCA_ADMIN_USER:$CA_ADMIN_USER" >> $SUBCA_OUTPUT_FILE
        echo -e "SUBCA_ADMIN_PASSWORD:$CA_ADMIN_PASSWORD" >> $SUBCA_OUTPUT_FILE
        echo -e "SUBCA_CLIENT_PKCS12_PASSWORD:$CA_CLIENT_PKCS12_PASSWORD" >> $SUBCA_OUTPUT_FILE
        echo -e "SUBCA_ADMIN_CERT_LOCATION:/root/.dogtag/$SUBCA_INSTANCE_NAME/ca_admin_cert.p12" >> $SUBCA_OUTPUT_FILE
        echo -e "CA_ADMIN_NICK:$ADMIN_NICK" >> $SUBCA_OUTPUT_FILE
        echo -e "$CA_CLIENT_PKCS12_PASSWORD" > $SUBCA_WORK_DIR/pwfile
        rlRun "importP12FileNew $SUBCA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $SUBCA_CERTDB_DIR $CA_CLIENT_PKCS12_PASSWORD $admin_cert_nickname"
        return 0
}

