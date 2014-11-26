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

run_pki-cert-revoke-ca_tests()
{
	local cs_Type=$1
	local cs_Role=$2

	# Creating Temporary Directory for pki cert-revoke
        rlPhaseStartSetup "pki cert-revoke Temporary Directory"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	rlPhaseEnd

	#local variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local CA_agentV_user=$CA_INST\_agentV
        local CA_auditV_user=$CA_INST\_auditV
        local CA_operatorV_user=$CA_INST\_operatorV
        local CA_adminV_user=$CA_INST\_adminV
        local CA_agentR_user=$CA_INST\_agentR
        local CA_adminR_user=$CA_INST\_adminR
        local CA_adminE_user=$CA_INST\_adminE
        local CA_agentE_user=$CA_INST\_agentE
	local invalid_serialNumber=$RANDOM
        local invalid_hex_serialNumber=0x$(echo "ibase=16;$invalid_serialNumber"|bc)
        local pkcs10_reqstatus
        local pkcs10_requestid
	local rand=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
        local sub_ca_ldap_port=1800
        local sub_ca_http_port=14080
        local sub_ca_https_port=14443
        local sub_ca_ajp_port=14009
        local sub_ca_tomcat_port=14005
        local subca_instance_name=pki-example-$rand
        local SUBCA_SERVER_ROOT=/var/lib/pki/$subca_instance_name/ca
	local admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
	local TEMP_NSS_DB="$TmpDir/nssdb"
	local TEMP_NSS_DB_PWD="Secret123"
	local exp="$TmpDir/expfile.out"
	local expout="$TmpDir/exp_out"
	local cert_info="$TmpDir/cert_info"
        local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$(eval echo \$${cs_Role})
      
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
                $TmpDir $TmpDir/nssdb $install_info \
		$CA_INST \
		$target_host \
		$target_port \
		$target_https_port"
        rlLog "Add CA Cert to $TEMP_NSS_DB"
        rlRun "install_and_trust_CA_cert $SUBCA_SERVER_ROOT \"$TEMP_NSS_DB\""
        local subca_serialNumber=$(pki -h $target_host -p $target_port cert-find  --name "SubCA-$subca_instance_name" --matchExactly | grep "Serial Number" | awk -F": " '{print $2}')
        local STRIP_HEX_PKCS10=$(echo $subca_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local subca_decimal_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlPhaseEnd

	# pki cert cli config test
	rlPhaseStartTest "pki_cert_cli-configtest: pki cert-revoke --help configuration test"
	rlRun "pki -h $target_host -p $target_port cert-revoke --help > $TmpDir/cert-revoke.out 2>&1" 0 "pki cert-revoke --help"
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

        rlPhaseStartTest "pki_cert_revoke_001: Revoke a cert using Agent with same serial as Subordinate CA(BZ-501088)"
        local i=1
        local upperlimit
        let upperlimit=$subca_decimal_serialNumber-3
        while [ $i -ne $upperlimit ] ; do
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD  myreq_type:pkcs10 \
		algo:rsa key_size:1024 subject_cn:\"Foo User$i\" subject_uid:FooUser$i subject_email:FooUser$i@example.org \
		subject_ou: subject_o: subject_c: archive:false req_profile: target_host:$target_host protocol: port:$sub_ca_http_port \
		cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PWD certdb_nick:\"$admin_cert_nickname\" cert_info:$cert_info"
        let i=$i+1
        done
        local revoked_cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Certificate that would be revoked is $revoked_cert_serialNumber"
        rlRun "pki -d $TEMP_NSS_DB \
                -p $sub_ca_http_port \
                -h $target_host \
                -c $TEMP_NSS_DB_PWD \
                -n \"$admin_cert_nickname\" \
                cert-revoke $revoked_cert_serialNumber --force --reason Certificate_Hold 1> $expout"
        rlAssertGrep "Placed certificate \"$revoked_cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $revoked_cert_serialNumber" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_002: pki cert-revoke <serialNumber>"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber"
	rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1" 
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_003: pki cert-revoke <serialNumber> --comments \"Test Comment1\""
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --comments \"Test Comment1\""
	rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_revoke_004: pki cert-revoke <serialNumber> --force"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"	
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force 1> $expout"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_revoke_005: pki cert-revoke <serialNumber> --reason unspecified"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason unspecified"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_006: pki cert-revoke <serialNumber> --reason Key_Compromise"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Key_Compromise"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
       
        rlPhaseStartTest "pki_cert_revoke_007: pki cert-revoke <serialNumber> --reason CA_Compromise"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason CA_Compromise"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_revoke_008: pki cert-revoke <serialNumber> --reason Affiliation_Changed"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Affiliation_Changed"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_009: pki cert-revoke <serialNumber> --reason Superseded"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Superseded"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0010: pki cert-revoke <serialNumber> --reason Cessation_of_Operation"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Cessation_of_Operation"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0011: pki cert-revoke <serialNumber> --reason Certificate_Hold"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Certificate_Hold"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_revoke_0012: pki cert-revoke <serialNumber> --reason Privilege_Withdrawn"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Privilege_Withdrawn"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0013: pki cert-revoke <serialNumber> --reason Remove_from_CRL"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $expout"
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Remove_from_CRL"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0014: pki cert-revoke <serialNumber> --reason Invalid revocation reason"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --reason unknown_revocation_reason 2> $expout" 1,255
	rlAssertGrep "Error: Invalid revocation reason: unknown_revocation_reason" "$expout"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_revoke_0015: pki cert-revoke <revoked-serialNumber>"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
	rlAssertGrep "Status: REVOKED" "$expout"
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Key_Compromise"
	rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
	rlRun "/usr/bin/expect -f $exp > $expout 2>&1"  
	STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
	rlAssertGrep "BadRequestException: certificate #$STRIP_HEX_PKCS10 has already been revoked" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0016: pki cert-revoke <serialNumber> --force --reason unspecified"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason unspecified 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0017: pki cert-revoke <serialNumber> --force --reason Key_Compromise"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0018: pki cert-revoke <serialNumber> --force --reason CA_Compromise"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason CA_Compromise 1> $expout"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0019: pki cert-revoke <serialNumber> --force --reason Affiliation_Changed"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Affiliation_Changed 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0020: pki cert-revoke <serialNumber> --force --reason Superseded"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		 -n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Superseded 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_revoke_0021: pki cert-revoke <serialNumber> --force --reason Cessation_of_Operation"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"	
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Cessation_of_Operation 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0022: pki cert-revoke <serialNumber> --force --reason Certificate_Hold"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $expout" 0
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0023: pki cert-revoke <serialNumber> --force --reason Privilege_Withdrawn"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason  Privilege_Withdrawn 1> $expout" 0
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
	rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
	rlAssertGrep "Status: REVOKED" "$expout"
	rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_revoke_0024: pki cert-revoke <serialNumber> --force --reason Invalid revocation reason"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason unknown_revocation_reason 2> $expout" 1,255
        rlAssertGrep "Error: Invalid revocation reason: unknown_revocation_reason" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0025: pki cert-revoke <serialNumber> --force --reason Remove_from_CRL"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Certificate_Hold 1> $expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Remove_from_CRL 1> $expout"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" off-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: VALID" "$expout"
        rlPhaseEnd	

	rlPhaseStartTest "pki_cert_revoke_0026: Revoke a non CA signing Cert using pki cert-revoke --ca" 
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --ca --reason unspecified"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
	rlAssertGrep "UnauthorizedException: Certificate $cert_serialNumber is not a CA signing certificate" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0027: Revoke a non CA signing Cert using pki cert-revoke --ca --force"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --ca --reason unspecified 2> $expout" 1,255
        rlAssertGrep "UnauthorizedException: Certificate $cert_serialNumber is not a CA signing certificate" "$expout"
        rlPhaseEnd
	

	rlPhaseStartTest "pki_cert_revoke_0028: Revoke a CA signing Cert using pki cert-revoke --ca"
	cert_serialNumber=0x1
	local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --ca --reason Certificate_Hold"
	rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" \
		cert-release-hold $cert_serialNumber --force" 0 "Release Certificate Hold of CA Signing Certificate"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0029: Revoke a cert using Revoked CA Agent Cert"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlRun "pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD \
		-n \"$CA_adminR_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber \
		--force --reason unspecified 2> $expout" 1,255
	rlAssertGrep "PKIException: Unauthorized" "$expout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0030: Revoke a cert using CA Audit Cert"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_auditV_user\" \
		-h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason unspecified 2> $expout" 1,255
        rlAssertGrep "Authorization Error" "$expout"	
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_revoke_0031: Revoke cert with with Invalid serialNumber"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		-n \"$CA_agentV_user\" \
		cert-revoke $invalid_serialNumber --force --reason unspecified 2> $expout" 1,255
	rlAssertGrep "CertNotFoundException:" "$expout"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0032: Revoke a cert and verify revoked cert is added to CRL"
        rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason unspecified 1> $expout" 0 "Revoke cert with reason unspecified"
	rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlFail "Unable to query CRL to verify revoked cert is added CRL: https://fedorahosted.org/pki/ticket/944"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_revoke_0033: Test-1 Revoke cert with i18n characters"
	local profile=caUserSMIMEcapCert
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"ÖrjanÄke\" \
		subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
		archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason unspecified 1> $expout" 0 "Revoke cert with reason unspecified"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0034: Test-2 Revoke cert with i18n characters"
        local profile=caUserCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"Éric Têko\" subject_uid:FooBar \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0 "Revoke cert with reason Key_Compromise"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_revoke_0035: Test-3 Revoke cert with i18n characters"
        local profile=caTPSCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"éénentwintig dvidešimt.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason CA_Compromise 1> $expout" 0 "Revoke cert with reason CA_Compromise"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0036: Test-4 Revoke cert with i18n characters"
        local profile=caSignedLogCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"двадцять один тридцять Signed Log Certificate\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Affiliation_Changed 1> $expout" 0 "Revoke cert with reason Affiliation_Changed"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0037: Test-5 Revoke cert with i18n characters"
        local profile=caServerCert
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn:\"kakskümmend üks.example.org\" subject_uid: \
                subject_email:test@example.org subject_ou:Foo_Example_IT subject_org:FooBar.Org subject_c:US \
                archive:false req_profile:$profile target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
              cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Superseded 1> $expout" 0 "Revoke cert with reason Superseded"
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_revoke_0038: Revoke a already revoked cert"
	rlLog "Generating temporary certificate"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 algo:rsa key_size:2048 subject_cn: subject_uid: \
                subject_email: subject_ou: subject_o: subject_c: archive:false \
                req_profile: target_host:$target_host protocol: port:$target_port cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cmd="pki -d  $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" -h $target_host -p $target_port cert-revoke $cert_serialNumber --reason Certificate_Hold"
        rlRun "cert-revoke_expect_data $exp $cert_info \"$cmd\""
        rlRun "/usr/bin/expect -f $exp > $expout 2>&1"
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Superseded 2> $expout" 1,255 "Revoke already revoked cert"
	local certsno=$(echo $cert_serialNumber | awk -F "0x" '{print $2}')
	rlAssertGrep "BadRequestException: certificate #$certsno has already been revoked" "$expout"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_revoke_0039: Revoke an expired cert"
	local validityperiod="1 day"
	rlLog "Generate cert with validity period of $validityperiod"
	rlRun "generate_modified_cert validity_period:\"$validityperiod\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 algo:rsa key_size:2048 cn: uid: email: ou: org: country: archive:false host:$target_host port:$target_port profile: \
		cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$CA_agentV_user\" cert_info:$cert_info expect_data:$exp"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cur_date=$(date) # Save current date
	rlLog "Date & Time before Modifying system date: $cur_date"
	rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlRun "chronyc -a -m 'offline' 'settime $cert_end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out" 
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after modifying using chrony: $(date)"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                -h $target_host -p $target_port cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Set the date back to it's original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out" 
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after running chrony: $(date)"
        rlPhaseEnd
	
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
	local CA_INST=${10}
	local CA_HOST=${11}
	local CA_UNSECURE_PORT=${12}
	local CA_SECURE_PORT=${13}
        local SUBCA_INSTANCECFG="$SUBCA_WORK_DIR/subca_instance.inf"
        local SUBCA_INSTANCE_CREATE_OUT="$SUBCA_WORK_DIR/subca_instance_create.out"
        local SUBCA_ADMIN_CERT_LOCATION=/root/.dogtag/$SUBCA_INSTANCE_NAME/ca_admin_cert.p12
        local admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
	local CA_ADMIN_PASSWORD=$(eval echo \$${CA_INST}\_ADMIN_PASSWORD)
	local CA_ADMIN_USER=$(eval echo \$${CA_INST}\_ADMIN_USER)
	local CA_SECURITY_DOMAIN_PASSWORD=$(eval echo \$${CA_INST}\_SECURITY_DOMAIN_PASSWORD)
	local CA_CLIENT_PKCS12_PASSWORD=$(eval echo \$${CA_INST}\_CLIENT_PKCS12_PASSWORD)
	
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
        echo -e "pki_security_domain_hostname = $CA_HOST" >> $SUBCA_INSTANCECFG
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
        echo -e "pki_ds_hostname = $CA_HOST" >> $SUBCA_INSTANCECFG
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
