#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-cert-find
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
. /opt/rhqa_pki/pki-profile-lib.sh
. /opt/rhqa_pki/env.sh

run_pki-cert-find-ca_tests()
{
	local cs_Type=$1
        local cs_Role=$2

	# Creating Temporary Directory for pki cert-show
        rlPhaseStartSetup "pki cert-find Temporary Directory"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local temp_out="$TmpDir/cert-show.out"
	local cert_info="$TmpDir/cert_info"
	local cert_find_info="$TmpDir/cert_find_info"
	local cert_req_info="$TmpDir/cert_req_info.out"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
	local certout="$TmpDir/cert_out"
        rlPhaseEnd

	#local Variables
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
        local rand=$RANDOM
        local i18n_user1_fullname="Örjan Äke $rand"
        local i18n_user1="Örjan_Äke_$rand"
        local i18n_user2_fullname="Éric Têko $rand"
        local i18n_user2="Éric_Têko_$rand"
        local i18n_user3_fullname="éénentwintig dvidešimt $rand"
        local i18n_user3="éénentwintig_dvidešimt_$rand"
        local i18n_user4_fullname="kakskümmend üks $rand"
        local i18n_user4="kakskümmend_üks_$rand"
        local i18n_user5_fullname="двадцять один тридцять $rand"
        local i18n_user5="двадцять_один_тридцять_$rand"
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
        local admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
        local target_host=$(eval echo \$${cs_Role})
        local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)

	# pki cert cli config test
	rlPhaseStartTest "pki_cert_cli-configtest: pki cert-show --help configuration test"
	rlRun "pki -h $target_host -p $target_port cert-find --help > $TmpDir/cert-find.out 2>&1" 0 "pki cert-find --help"
	rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$TmpDir/cert-find.out"
    	rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$TmpDir/cert-find.out"
    	rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$TmpDir/cert-find.out"
    	rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$TmpDir/cert-find.out"
	rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$TmpDir/cert-find.out"
	rlAssertGrep "                                           CA" "$TmpDir/cert-find.out"
	rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$TmpDir/cert-find.out"
	rlAssertGrep "                                           CA" "$TmpDir/cert-find.out"
	rlAssertGrep "    --country <name>                       Subject's country" "$TmpDir/cert-find.out"
	rlAssertGrep "    --email <email>                        Subject's email address" "$TmpDir/cert-find.out"
	rlAssertGrep "    --help                                 Show help options" "$TmpDir/cert-find.out"
	rlAssertGrep "    --input <file path>                    File containing the search" "$TmpDir/cert-find.out"
	rlAssertGrep "                                           constraints" "$TmpDir/cert-find.out"
	rlAssertGrep "    --issuedBy <user id>                   Issued by" "$TmpDir/cert-find.out"
	rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --locality <name>                      Subject's locality" "$TmpDir/cert-find.out"
	rlAssertGrep "    --matchExactly                         Match exactly with the details" "$TmpDir/cert-find.out"
	rlAssertGrep "                                           provided" "$TmpDir/cert-find.out"
	rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$TmpDir/cert-find.out"
	rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$TmpDir/cert-find.out"
	rlAssertGrep "    --name <name>                          Subject's common name" "$TmpDir/cert-find.out"
	rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$TmpDir/cert-find.out"
	rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$TmpDir/cert-find.out"
	rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --size <size>                          Page size" "$TmpDir/cert-find.out"
	rlAssertGrep "    --start <start>                        Page start" "$TmpDir/cert-find.out"
	rlAssertGrep "    --state <name>                         Subject's state" "$TmpDir/cert-find.out"
	rlAssertGrep "    --status <status>                      Certificate status: VALID," "$TmpDir/cert-find.out"
	rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$TmpDir/cert-find.out"
	rlAssertGrep "                                           REVOKED_EXPIRED" "$TmpDir/cert-find.out"
	rlAssertGrep "    --uid <user id>                        Subject's userid" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validityCount <count>                Validity duration count" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$TmpDir/cert-find.out"
	rlAssertGrep "                                           \"<=\" or \">=\"" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$TmpDir/cert-find.out"
	rlAssertGrep "                                           week, month (default), year" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$TmpDir/cert-find.out"
	rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$TmpDir/cert-find.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/cert-find.out"
	rlPhaseEnd

	rlPhaseStartSetup "Create a new profile based on caUserCert with Netscape Extension nsCertEmail"
	local tmp_profile=caUserCert
	local tmp_new_user_profile=caUserCert$rand
	rlLog "Get $tmp_profile xml file"
	rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_user_profile-Temp1.xml"
	rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml"
	rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\""
	rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
	rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
	rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_user_profile"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-001: Verify no search results are returned with certTypeSecureEmail off when Netscape Ext. are not set ony any certs"
	rlLog "Executing  pki cert-find --certTypeSecureEmail off"
	rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail off 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
	rlAssertNotGrep "20 entries found" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-002: Verify no search results are returned with certTypeSecureEmail on when Netscape Ext. are not set on any certs"
	rlLog "Executing pki cert-find --certTypeSecureEmail on"
	rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail on 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
	rlAssertNotGrep "20 entries found" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-003: Verify no search results are returned with certTypeSSLClient off when Netscape Ext. are not set ony any certs"
        rlLog "Executing  pki cert-find --certTypeSSLClient off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLClient off 1> $cert_find_info"
	rlAssertNotGrep "20 entries found" "$cert_find_info"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-004: Verify no search results are returned with certTypeSSLClient on when Netscape Ext. are not set on any certs"
        rlLog "Executing pki cert-find --certTypeSSLClient on"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLClient on 1> $cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_find-005: Verify no search results are returned with certTypeSSLServer off when Netscape Ext. are not set ony any certs"
        rlLog "Executing  pki cert-find --certTypeSSLServer off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLServer off 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-006: Verify no search results are returned with certTypeSSLServer on when Netscape Ext. are not set on any certs"
        rlLog "Executing pki cert-find --certTypeSSLServer on"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLServer on 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-007: Verify no search results are returned with certTypeSubEmailCA off when Netscape Ext. are not set ony any certs"
        rlLog "Executing  pki cert-find --certTypeSubEmailCA off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA off 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-008: Verify no search results are returned with certTypeSubEmailCA on when Netscape Ext. are not set on any certs"
        rlLog "Executing pki cert-find --certTypeSubEmailCA on"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA on 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_find-009: Verify no search results are returned with certTypeSubSSLCA off when Netscape Ext. are not set ony any certs"
        rlLog "Executing  pki cert-find --certTypeSubSSLCA off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA off 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0010: Verify no search results are returned with certTypeSubSSLCA on when Netscape Ext. are not set on any certs"
        rlLog "Executing pki cert-find --certTypeSubSSLCA on"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA on 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "20 entries found" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0011: verify certs with nsCertEmail extension are returned with --certTypeSecureEmail on"
	rlLog "Enroll a cert with nsCertEmail Extension"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn: \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
		req_profile:$tmp_new_user_profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
	rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail on 1> $cert_find_info"
	rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
	rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
	rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
	rlAssertGrep "Secure Email" "$TmpDir/$cert_serialNumber-cert-show.out"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0012: verify No certs with nsCertEmail extension are returned with --certTypeSecureEmail off"
	rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSecureEmail off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail off 1> $cert_find_info"
	rlAssertNotGrep "20 entries found"  "$cert_find_info"
	rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0013: verify no certs are returned with --certTypeSecureEmail SomeJunkValue"
	rlLog "Executing pki cert-find --certTypeSecureEmail \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0014: verify no certs are returned with when nothing is passed to --certTypeSecureEmail"
	rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSecureEmail"
	rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail >> $cert_find_info 2>&1" 1,255 
	rlAssertGrep "Error: Missing argument for option: certTypeSecureEmail" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartSetup "Create a new profile based on caServerCert with Netscape Extension nsCertSSLClient"
        local tmp_profile=caServerCert
        local tmp_new_sslclient_profile=caServerCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_sslclient_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_sslclient_profile/" $TmpDir/$tmp_new_sslclient_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_sslclient_profile-Temp1.xml\" \"nsCertSSLClient\""
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_sslclient_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_sslclient_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_sslclient_profile"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0015: verify certs with nsCertSSLClient extension are returned with --certTypeSSLClient on"
        rlLog "Enroll a cert with nsCertSSLClient Extension"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn:\"host$rand.example.org\" \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
		req_profile:$tmp_new_sslclient_profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLClient on --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "SSL Client" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0016: verify No certs with nsCertSSLClient extension are returned with --certTypeSSLClient off"
	rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSSLClient off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLClient off 1> $cert_find_info"
        rlAssertNotGrep "20 entries found"  "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0017: verify no certs are returned with --certTypeSSLClient SomeJunkValue"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSSLClient \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLClient \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0018: verify no certs are returned with when nothing is passed to --certTypeSSLClient"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSSLClient"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLClient >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: certTypeSSLClient" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartSetup "Create a new profile based on caServerCert with Netscape Extension nsCertSSLServer"
        local tmp_profile=caServerCert
	local rand=$RANDOM
        local tmp_new_sslserver_profile=caServerCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_sslserver_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_sslserver_profile/" $TmpDir/$tmp_new_sslserver_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_sslserver_profile-Temp1.xml\" \"nsCertSSLServer\""
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_sslserver_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_sslserver_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_sslserver_profile"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0019: verify certs with nsCertSSLServer extension are returned with --certTypeSSLServer on"
        rlLog "Enroll a cert with nsCertSSLServer Extension"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn:\"server$rand.example.org\" \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
		req_profile:$tmp_new_sslserver_profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLServer on --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "SSL Server" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0020: verify No certs with nsCertSSLServer extension are returned with --certTypeSSLServer off"
        rlLog "Executing pki -h $target_host -p $target_port  cert-find --certTypeSSLServer off"
        rlRun "pki -h $target_host -p $target_port  cert-find --certTypeSSLServer off 1> $cert_find_info"
        rlAssertNotGrep "20 entries found"  "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0021: verify no certs are returned with --certTypeSSLServer SomeJunkValue"
        rlLog "Executing pki -h $target_host -p $target_port  cert-find --certTypeSSLServer \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port  cert-find --certTypeSSLServer \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0022: verify no certs are returned with when nothing is passed to --certTypeSSLServer"
        rlLog "Executing pki -h $target_host -p $target_port  cert-find --certTypeSSLServer"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLServer >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: certTypeSSLServer" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartSetup "Create a new profile based on caServerCert with Netscape Extension nsCertSSLServer and nsCertSSLClient"
        local tmp_profile=caServerCert
        local rand=$RANDOM
        local tmp_new_server_client_profile=caServerCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port  -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_server_client_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_server_client_profile/" $TmpDir/$tmp_new_server_client_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_server_client_profile-Temp1.xml\" \"nsCertSSLServer\" \"nsCertSSLClient\""
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_server_client_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_server_client_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_server_client_profile"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0023: verify certs with nsCertSSLServer & nsCertSSLClient extension are returned with --certTypeSSLServer on --certTypeSSLClient on"
        rlLog "Enroll a cert with nsCertSSLServer Extension"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:1024 \
                subject_cn:\"server$rand.example.org\" \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$tmp_new_server_client_profile \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
	rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSSLServer on --certTypeSSLClient on"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSSLServer on --certTypeSSLClient on --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "SSL Server" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlPhaseEnd

	rlPhaseStartSetup "Create a new profile based on caOtherCert with Netscape Extension nsCertEmailCA"
        local tmp_profile=caOtherCert
        local rand=$RANDOM
        local tmp_new_emailca_profile=caOtherCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_emailca_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_emailca_profile/" $TmpDir/$tmp_new_emailca_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_emailca_profile-Temp1.xml\" \"nsCertEmailCA\""
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_emailca_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_emailca_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_emailca_profile"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0024: verify certs with nsCertEmailCA extension are returned with --certTypeSubEmailCA on"
        rlLog "Enroll a cert with nsCertEmailCA Extension"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn:\"Example$rand CA\" \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
		req_profile:$tmp_new_emailca_profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA on --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Secure Email CA" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0025: verify No certs with nsCertEmailCA extension are returned with --certTypeSubEmailCA off"
        rlLog "Executing pki cert-find --certTypeSubEmailCA off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA off 1> $cert_find_info"
        rlAssertNotGrep "20 entries found"  "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0026: verify no certs are returned with --certTypeSubEmailCA SomeJunkValue"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0027: verify no certs are returned with when nothing is passed to --certTypeSubEmailCA"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubEmailCA >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: certTypeSubEmailCA" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartSetup "Create a new profile based on caOtherCert with Netscape Extension nsCertSSLCA"
        local tmp_profile=caOtherCert
        local rand=$RANDOM
        local tmp_new_sslca_profile=caOtherCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_sslca_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_sslca_profile/" $TmpDir/$tmp_new_sslca_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_sslca_profile-Temp1.xml\" \"nsCertSSLCA\""
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_sslca_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_sslca_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_sslca_profile"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0028: verify certs with nsCertSSLCA extension are returned with --certTypeSubSSLCA on"
        rlLog "Enroll a cert with nsCertSSLCA Extension"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn:\"Example$rand CA\" \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
		req_profile:$tmp_new_sslca_profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA on --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "SSL CA" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0029: verify No certs with nsCertSSLServer extension are returned with --certTypeSubSSLCA off"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA off"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA off 1> $cert_find_info"
        rlAssertNotGrep "20 entries found"  "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0030: verify no certs are returned with --certTypeSubSSLCA SomeJunkValue"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/1047"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0031: verify no certs are returned with when nothing is passed to --certTypeSubSSLCA"
        rlLog "Executing pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: certTypeSubSSLCA" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartSetup "Create a new profile based on caOtherCert with Netscape Extension nsCertEmailCA and nsCertSSLCA"
        local tmp_profile=caOtherCert
        local rand=$RANDOM
        local tmp_new_email_ssl_ca_profile=caOtherCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_email_ssl_ca_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_email_ssl_ca_profile/" $TmpDir/$tmp_new_email_ssl_ca_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_email_ssl_ca_profile-Temp1.xml\" \"nsCertEmailCA\" \"nsCertSSLCA\""
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_adminV_user -c $CERTDB_DIR_PASSWORD ca-profile-add $TmpDir/$tmp_new_email_ssl_ca_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_email_ssl_ca_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n $CA_agentV_user -c $CERTDB_DIR_PASSWORD ca-profile-enable $tmp_new_email_ssl_ca_profile"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0032: verify certs with nsCertSSLCA and nsCertEmail CA extension are returned with --certTypeSubSSLCA on --certTypeSubEmailCA on"
        rlLog "Enroll a cert with nsCertSSLCA and nsCertEmailCA Extension"
	rlLog "tmp_new_email_ssl_ca_profile = $tmp_new_email_ssl_ca_profile"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:1024 \
                subject_cn:\"Example$rand CA\" \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$tmp_new_email_ssl_ca_profile \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
	rlLog "Executing pki cert-find --certTypeSubSSLCA on --certTypeSubEmailCA on --size 1000"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSubSSLCA on --certTypeSubEmailCA on --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --pretty 1> $TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "Subject DN: $cert_requestdn" "$cert_find_info"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlAssertGrep "SSL CA" "$TmpDir/$cert_serialNumber-cert-show.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0033: verify certs which have Country US in subject name are returned with --country US"
	rlLog "Executing pki cert-find --country US"
	rlRun "pki -h $target_host -p $target_port cert-find --country US 1> $cert_find_info" 
	rlRun "cat $cert_find_info | grep \"Subject DN:\" | grep US" 0 "verify certs which have Country US in subject name"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0034: verify no certs are returned when junk value is passed to --country"
	rlLog "Executing pki cert-find --country \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --country \"$tmp_junk_data\" 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0035: verify --country <novalue> returns error and command help is returned"
	rlLog "Executing pki cert-find --country"
	rlRun "pki -h $target_host -p $target_port cert-find --country >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: country" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0036: verify certs which have country US in subject name are returned with --country uS (case insensitive test)"
	rlLog "Executing pki cert-find --country uS"
        rlRun "pki -h $target_host -p $target_port cert-find --country uS 1> $cert_find_info"
        rlRun "cat $cert_find_info | grep \"Subject DN:\" | grep US"  0 "verify certs which have Country US in subject name"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0037: search certs with specific email id and verify certs with  that specific email id in Subject name are only returned"
	rlLog "Generate a cert with subject name CN=Foo User$rand,UID=FooUser$rand,E=FooUser$rand@example.org,OU=FOO,O=Example.org,C=US"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn:\"Foo User$rand\" \
		subject_uid:FooUser$rand \
		subject_email:FooUser$rand@example.org \
		subject_ou:FOO subject_o:Example.org \
		subject_c:US \
		archive:false \
		req_profile:caUserCert \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"	
	rlLog "Executing pki cert-find --email FooUser$rand@example.org"
        rlRun "pki -h $target_host -p $target_port cert-find --email FooUser$rand@example.org 1> $cert_find_info"
        rlRun "cat $cert_find_info | grep \"Subject DN:\" | grep FooUser$rand@example.org" \
		0 "Verify search results return cert having E=FooUser$rand@example.org in subject"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0038: Multiple search: Search certs which matches specificy email, Country and has netscape Extension nsCertEmail"
        rlLog "Generate a cert with subject name CN=FooNew User$rand,UID=FooNewUser$rand,E=FooNewUser$rand@example.org,OU=FOO,O=Example.org,C=IN"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:1024 \
                subject_cn:\"FooNew User$rand\" \
                subject_uid:FooNewUser$rand \
                subject_email:FooNewUser$rand@example.org \
                subject_ou:FOO \
		subject_o:Example.org \
                subject_c:IN \
                archive:false \
                req_profile:$tmp_new_user_profile \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info"   
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlLog "Executing pki cert-find --certTypeSecureEmail on --country IN --email FooNewUser$rand@example.org"
        rlRun "pki -h $target_host -p $target_port cert-find --certTypeSecureEmail on --country IN --email FooUser$rand@example.org 1> $cert_find_info"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
	rlAssertGrep "Subject DN: $cert_subject" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0039: verify no certs are returned when junk value is passed to --email"
        rlLog "Executing pki cert-find --email \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --email \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0040: verify --email <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --email"
        rlRun "pki -h $target_host -p $target_port cert-find --email >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: email" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0041: verify certs which have <SpecificEmailid@example.org> in subject name are returned with --email <specificemailid@example.org> (case insensitive test)"
        rlLog "Executing pki cert-find --email foouser$rand@exampl.eorg"
        rlRun "pki -h $target_host -p $target_port cert-find --email foouser$rand@example.org 1> $cert_find_info"
        rlRun "cat $cert_find_info | grep \"Subject DN:\" | grep FooUser$rand@example.org" \
	0 "Verify cert having E=FooUser$rand@example.org in subjectDN is returned"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0042: verify certs which have special characters in email id are properly returned when searched with --email"
	rlLog "Generate a cert with subject name CN=Foo User$rand 2,UID=FooUser$rand\.2,E=FooUser$rand\.2@example.org,OU=FOO,O=Example.org,C=US"
        rlRun "generate_new_cert \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		req_type:pkcs10 \
		algo:rsa \
		key_size:1024 \
		subject_cn:\"Foo User$rand 2\" \
		subject_uid:FooUser$rand\.2 \
		subject_email:FooUser$rand\.2@example.org \
		subject_ou:FOO \
		subject_o:Example.org \
		subject_c:US \
		archive:false \
		req_profile:caUserCert \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        rlLog "Executing pki cert-find --email FooUser$rand\.2@example.org"
        rlRun "pki -h $target_host -p $target_port cert-find --email FooUser$rand\.2@example.org 1> $cert_find_info"
        rlRun "cat $cert_find_info | grep \"Subject DN:\" | grep FooUser$rand\.2@example.org" \
	0 "Verify Cert having E=FooUser$rand\.2@example.org in Subject Name is returned"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0043: Search certs issued by Admin user (caadmin)"
	local profile_user=caadmin
	rlLog "Executing pki cert-find --issuedBy $profile_user"
	rlRun "pki -h $target_host -p $target_port cert-find --issuedBy $profile_user --size 1000 1> $cert_find_info"
	local tmp_result=$(cat $cert_find_info | grep \"Issued By\" | grep -v $profile_user | wc -l)
	if [ $tmp_result != 0 ]; then
	rlFail "Search results include certs not issued by $profile_user"
	fi
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0044: Search certs issued by Admin user (CA_agentV)"
        local profile_user=$CA_INST\_agentV
        rlLog "Executing pki cert-find --issuedBy $profile_user"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedBy $profile_user --size 1000 1> $cert_find_info"
        local tmp_result=$(cat $cert_find_info | grep \"Issued By\" | grep -v $profile_user | wc -l)
        if [ $tmp_result != 0 ]; then
        rlFail "Search results include certs not issued by $profile_user"
        fi
        rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_find-0045: search certs issued by system (system)"
	local profile_user=system
        rlLog "Executing pki cert-find --issuedBy $profile_user"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedBy $profile_user --size 1000 1> $cert_find_info"
        local tmp_result=$(cat $cert_find_info | grep \"Issued By\" | grep -v $profile_user | wc -l)
        if [ $tmp_result != 0 ]; then
        rlFail "Search results include certs not issued by $profile_user"
        fi
	rlPhaseEnd

	rlPhaseStartSetup "Setup a  user with Agent privileges, Approve the certs and later delete the user"
        local pki_user="pki_tmpuser_$rand"
        local pki_user_fullName="PKI Temporary User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminV_user\" \
                -c $CERTDB_DIR_PASSWORD \
		ca-user-add $pki_user \
                --fullName \"$pki_user_fullName\" \
                --password $pki_pwd" 0 "Create $pki_user User"
        rlLog "Generate cert for user $pki_user"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
        	myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"$pki_user_fullName\" \
		subject_uid:$pki_user \
	        subject_email:$pki_user@example.org \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
	        req_profile:$profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
	        cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"$CA_adminV_user\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n $CA_adminV_user \
                -c $CERTDB_DIR_PASSWORD \
                -t ca user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminV_user\" \
		-c $CERTDB_DIR_PASSWORD \
		-t ca group-member-add \"Certificate Manager Agents\" $pki_user > $TmpDir/pki-user-add-ca-group.out"
   	rlAssertGrep "Added group member \"$pki_user\"" "$TmpDir/pki-user-add-ca-group.out"
        rlAssertGrep "User: $pki_user" "$TmpDir/pki-user-add-ca-group.out"
        local i=1
        local upperlimit=3
        while [ $i -ne $upperlimit ] ; do
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"Foo $rand User $i\" \
		subject_uid:Foo-$rand-User$i \
		subject_email:Foo-$rand-User$i@example.org \
		subject_ou: \
		subject_o: \
		subject_c:FR \
		archive:false \
		req_profile: \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$TEMP_NSS_DB \
		cert_db_pwd:$TEMP_NSS_DB_PWD certdb_nick:\"$pki_user\" cert_info:$cert_info"
	let i=$i+1
	done
	rlLog "Delete user $pki_user" 
	rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -n \"$CA_adminV_user\" -c $CERTDB_DIR_PASSWORD ca-user-del $pki_user 1> $TmpDir/delete-user-$pki_user.out"
	rlAssertGrep "Deleted user \"$pki_user\"" "$TmpDir/delete-user-$pki_user.out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_find-0046: search certs issued by deleted Agent user"
	local profile_user=$pki_user
        rlLog "Executing pki cert-find --issuedBy $profile_user"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedBy $profile_user --size 1000 1> $cert_find_info"
        local tmp_result=$(cat $cert_find_info | grep \"Issued By\" | grep -v $profile_user | wc -l)
        if [ $tmp_result != 0 ]; then
        rlFail "Search results include certs not issued by $profile_user"
        fi
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0047: verify no certs are returned when junk value is passed to --issuedBy"
        rlLog "Executing pki cert-find --issuedBy \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --issuedBy \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0048: verify --issuedBy <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --issuedBy"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedBy >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: issuedBy" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0049: Multiple Searches: search certs having specific emailid ,country and issued by Agent which no longer exists"
	rlLog "Executing pki cert-find --email Foo-$rand-User1@example.org --country FR --issuedBy pki_tmpuser_$rand"
	rlRun "pki -h $target_host -p $target_port cert-find --email Foo-$rand-User1@example.org --country FR --issuedBy pki_tmpuser_$rand 1> $cert_find_info"
	rlAssertGrep "Foo-$rand-User1@example.org" "$cert_find_info"
	rlAssertGrep "C=FR" "$cert_find_info"
	rlAssertGrep "Issued By: pki_tmpuser_$rand" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0050: search certs with which are issued from Current date --issuedOnFrom <YYYY-MM-DD>"
	local tmp_cur_date=$(date +%Y-%m-%d)
	rlLog "Generate 5 Certs"
	local i=1
        local upperlimit=6
        while [ $i -ne $upperlimit ] ; do
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"PKI $rand User $i\" \
                subject_uid:pki-$rand-User$i \
                subject_email:pki-$rand-User$i@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        let i=$i+1
        done
	rlRun "pki -h $target_host -p $target_port cert-find --issuedOnFrom $tmp_cur_date --size 1000 1> $cert_find_info"
	local find_tmp_result1=$(cat $cert_find_info | grep "Not Valid Before" | awk -F "Not Valid Before: " '{print $2}' | grep -v "$(date +%b\ %d)" | wc -l)
	local find_tmp_result2=$(cat $cert_find_info | grep "Not Valid Before" | awk -F "Not Valid Before: " '{print $2}' | grep -v "$(date +%Y)" | wc -l)
        if [ $find_tmp_result1 != 0 && $find_temp_result!=0 ]; then
        rlFail "Search results include certs not issued by $tmp_cur_date"
        fi
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0051: verify no certs are returned when invalid date is passed to --issuedOnFrom"
        local tmp_cur_date=$(date +%d-%Y-%m)
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnFrom $tmp_cur_date --size 1000 1> $cert_find_info"
	rlAssertGrep "0 entries found" "$cert_find_info"
	rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0052: verify no certs are returned when junk value is passed to --issuedOnFrom"
        rlLog "Executing pki cert-find --issuedOnFrom \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnFrom \"$tmp_junk_data\" 2> $cert_find_info" 1,255
	rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0053: verify --issuedOnFrom <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --issuedOnFrom"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnFrom >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: issuedOnFrom" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0054: Test-1:search certs with which are issued from Current date --issuedOnTo <YYYY-MM-DD> and verify results returned  have certs issued till today"
        local tmp_cur_date=$(date +%Y-%m-%d)
        local cur_date=$(date)
        local end_date=$(date --date='1 day')
	rlLog "Generate a cert on a future date, which should not show up on pki cert-find --issuedOnTo $tmp_cur_date"
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlLog "Generate certs which will be valid from next day $(date +%d --date='1 day')"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:server$rand\.example.org \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_org: \
                subject_c:US \
                archive:false \
                req_profile:caServerCert \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlLog "Set the date back to it\'s original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnTo $tmp_cur_date --size 1000 1> $cert_find_info"
        local find_tmp_result1=$(cat $cert_find_info  | grep "Not Valid Before" | awk -F "Not Valid Before: " '{print $2}' | grep "$(date +%b --date='1 month')" | wc -l)
	local find_tmp_result2=$(cat $cert_find_info  | grep "Not Valid Before" | awk -F "Not Valid Before: " '{print $2}' | grep "$(date +%d --date='1 day')" | wc -l)
        if [[ $find_tmp_result1 != 0 ]] && [[ $find_temp_result2 != 0 ]] ;  then
        rlFail "Search results include certs that have been issued after $tmp_cur_date"
        fi
	rlAssertNotGrep "$cert_serialNumber" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0055: verify no certs are returned when invalid date is passed to --issuedOnTo"
        local tmp_fail_cur_date=$(date +%Y-%d-%m)
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnTo $tmp_fail_cur_date --size 1000 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0056: verify no certs are returned when junk value is passed to --issuedOnTo"
        rlLog "Executing pki cert-find --issuedOnTo \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnTo \"$tmp_junk_data\" 2> $cert_find_info" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0057: verify --issuedOnTo <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --issuedOnTo"
        rlRun "pki -h $target_host -p $target_port cert-find --issuedOnTo >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: issuedOnTo" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0058: Multiple Searches: search certs having specific emailid ,country, appproved by specific agent on specific date"
	rlLog "Executing pki cert-find --email Foo-$rand-User1@example.org --country FR --issuedBy pki_tmpuser_$rand --issuedOnTo $tmp_cur_date"
        rlRun "pki -h $target_host -p $target_port cert-find --email Foo-$rand-User1@example.org --country FR --issuedBy pki_tmpuser_$rand --issuedOnTo $tmp_cur_date 1> $cert_find_info"
        rlAssertGrep "Foo-$rand-User1@example.org" "$cert_find_info"
        rlAssertGrep "C=FR" "$cert_find_info" 
        rlAssertGrep "Issued By: pki_tmpuser_$rand" "$cert_find_info"
	rlAssertGrep "Issued On: $(date +%a\ %b\ %d)" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0059: search and return all certs which have serial Number less than or equal to specific serial Number using --maxSerialNumber"
	local max_serial_number=0xf
	rlLog "Executing pki cert-find --maxSerialNumber $max_serial_number"
	rlRun "pki -h $target_host -p $target_port cert-find --maxSerialNumber $max_serial_number 1> $cert_find_info"
        local strip_hex_serialNumber=$(echo $max_serial_number | cut -dx -f2)
        local conv_upp_val=${strip_hex_serialNumber^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$conv_upp_val"|bc)
	rlAssertGrep "Number of entries returned $decimal_valid_serialNumber" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0060: search and return all certs which have serialNumber less than or equal to specific serial Number using --maxSerialNumber <decimalNumber>"
        local max_serial_number=15
        rlLog "Executing pki cert-find --maxSerialNumber $max_serial_number"
        rlRun "pki -h $target_host -p $target_port cert-find --maxSerialNumber $max_serial_number 1> $cert_find_info"
        rlAssertGrep "Number of entries returned $max_serial_number" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0061: verify no certs are returned when junk value is passed to --maxSerialNumber"
        rlLog "Executing pki cert-find --maxSerialNumber \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --maxSerialNumber \"$tmp_junk_data\" 2> $cert_find_info" 0
        rlAssertGrep "0 Entries Found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0062: verify --maxSerialNumber <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --maxSerialNumber"
        rlRun "pki -h $target_host -p $target_port cert-find --maxSerialNumber >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: maxSerialNumber" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0063: search and return all certs which have serial Number equal to more than specific serial Number using --minSerialNumber"
        local min_serial_number=0xf
        rlLog "Executing pki cert-find --minSerialNumber $min_serial_number"
        rlRun "pki -h $target_host -p $target_port cert-find --maxSerialNumber $min_serial_number 1> $cert_find_info"
        local strip_hex_serialNumber=$(echo $min_serial_number | cut -dx -f2)
        local conv_upp_val=${strip_hex_serialNumber^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$conv_upp_val"|bc)
        rlAssertGrep "Number of entries returned $decimal_valid_serialNumber" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0064: search and return all certs which have serialNumber more than or equal to specific serial Number using --minSerialNumber <decimalNumber>"
        local min_serial_number=15
        rlLog "Executing pki cert-find --maxSerialNumber $min_serial_number"
        rlRun "pki -h $target_host -p $target_port cert-find --maxSerialNumber $min_serial_number 1> $cert_find_info"
        rlAssertGrep "Number of entries returned $min_serial_number" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0065: verify no certs are returned when junk value is passed to --minSerialNumber"
        rlLog "Executing pki cert-find --minSerialNumber \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --minSerialNumber \"$tmp_junk_data\" 2> $cert_find_info" 1,255
        rlAssertGrep "ParseException: Unparseable serialNumber \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0066: verify --minSerialNumber <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --minSerialNumber"
        rlRun "pki -h $target_host -p $target_port cert-find --minSerialNumber >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: minSerialNumber" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0067: search certs with valid common name using --name"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:\"IDM  User $rand\" \
		subject_uid:idmuser$rand \
		subject_email:IdmUser$rand@example.org \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
		req_profile: \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	rlLog "Executing pki cert-find --name \"IDM User $rand\""
	rlRun "pki -h $target_host -p $target_port cert-find --name \"IDM User $rand\" 1> $cert_find_info"
	rlAssertGrep "CN=IDM User $rand" "$cert_find_info"
	rlAssertGrep "Number of entries returned 1" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0068: search certs with valid common name using --name(case insensitive test)"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"IDM  QAUser $rand\" \
                subject_uid:idmQAuser$rand \
                subject_email:IdmQAUser$rand@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --name \"idm qauser $rand\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"idm qaUser $rand\" 1> $cert_find_info"
        rlAssertGrep "CN=IDM QAUser $rand" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
	rlPhaseEnd 

	rlPhaseStartTest "pki_cert_find-0069: Test-1: search certs with common name having i18n characters using --name"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$i18n_user1_fullname\" \
                subject_uid:$i18n_user1 \
                subject_email:test@example.org \
                subject_ou:ExampleQE1 \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --name \"$i18n_user1_fullname\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"$i18n_user1_fullname\" 1> $cert_find_info"
        rlAssertGrep "CN=$i18n_user1_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0070: Test-2: search certs with common name having i18n characters using --name"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$i18n_user2_fullname\" \
                subject_uid:$i18n_user2 \
                subject_email:test@example.org \
                subject_ou:ExampleQE2 \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --name \"$i18n_user2_fullname\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"$i18n_user2_fullname\" 1> $cert_find_info"
        rlAssertGrep "CN=$i18n_user2_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0071: Test-3: search certs with common name having i18n characters using --name"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$i18n_user3_fullname\" \
                subject_uid:$i18n_user3 \
                subject_email:test@example.org \
                subject_ou:ExampleQE3 \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --name \"$i18n_user3_fullname\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"$i18n_user3_fullname\" 1> $cert_find_info"
        rlAssertGrep "CN=$i18n_user3_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0072: Test-4: search certs with common name having i18n characters using --name"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$i18n_user4_fullname\" \
                subject_uid:$i18n_user4 \
                subject_email:test@example.org \
                subject_ou:ExampleQE4 \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --name \"$i18n_user4_fullname\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"$i18n_user4_fullname\" 1> $cert_find_info"
        rlAssertGrep "CN=$i18n_user4_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0073: Test-5: search certs with common name having i18n characters using --name"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$i18n_user5_fullname\" \
                subject_uid:$i18n_user5 \
                subject_email:test@example.org \
                subject_ou:ExampleQE5 \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --name \"$i18n_user5_fullname\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"$i18n_user5_fullname\" 1> $cert_find_info"
        rlAssertGrep "CN=$i18n_user5_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0074: search certs with common name using --name and --matchExactly"
	rlLog "Generate Temporary Cert with subject Name:UID=pkiqa$rand\user,E=pkiqa$rand\user@example.org,CN=PKIQA $rand User"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"PKIQA $rand User\" \
                subject_uid:pkiqa$rand\User \
                subject_email:pkiqa$rand\User@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"	
	rlLog "Generate 5 Certs with subject Names:UID=pkiqa$rand{user}$i,E=pkiqa$rand{user}$i@example.org,CN=PKIQA $rand User$i"
        local i=1
        local upperlimit=3
        while [ $i -ne $upperlimit ] ; do
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"PKIQA $rand User$i\" \
                subject_uid:pkiqa$rand\User$i \
                subject_email:pkiqa$rand\User$i@example.org \
                subject_ou: \
                subject_o:Foo.Org \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        let i=$i+1
        done
	rlLog "Executing pki cert-find --name \"PKIQA $rand User\" --matchExactly"
        rlRun "pki -h $target_host -p $target_port cert-find --name \"PKIQA $rand User\" --matchExactly 1> $cert_find_info"
        rlAssertGrep "CN=PKIQA $rand User" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0075: verify no certs are returned when junk value is passed to --name"
        rlLog "Executing pki cert-find --name \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --name \"$tmp_junk_data\" 1> $cert_find_info" 
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0076: verify --name <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --name"
        rlRun "pki -h $target_host -p $target_port cert-find --name >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: name" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0077: search certs with valid user id using --uid"
        rlLog "Executing pki cert-find --uid idmuser$rand"
        rlRun "pki -h $target_host -p $target_port cert-find --uid idmuser$rand 1> $cert_find_info"
        rlAssertGrep "UID=idmuser$rand" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0078: search certs with valid user id using --uid(case insensitive test)"
        rlLog "Executing pki cert-find --uid idmqauser$rand"
        rlRun "pki -h $target_host -p $target_port cert-find --uid idmqauser$rand 1> $cert_find_info"
        rlAssertGrep "UID=idmQAuser$rand" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0079: Test-1: search certs with user id having i18n characters using --uid"
        rlLog "Executing pki cert-find --uid $i18n_user1"
        rlRun "pki -h $target_host -p $target_port cert-find --uid $i18n_user1 1> $cert_find_info"
        rlAssertGrep "UID=$i18n_user1" "$cert_find_info"
	rlAssertGrep "CN=$i18n_user1_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0080: Test-2: search certs with user id having i18n characters using --uid"
        rlLog "Executing pki cert-find --uid $i18n_user2"
        rlRun "pki -h $target_host -p $target_port cert-find --uid $i18n_user2 1> $cert_find_info"
        rlAssertGrep "UID=$i18n_user2" "$cert_find_info"
	rlAssertGrep "CN=$i18n_user2_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0081: Test-3: search certs with user id having i18n characters using --uid"
        rlLog "Executing pki cert-find --uid $i18n_user3"
        rlRun "pki -h $target_host -p $target_port cert-find --uid $i18n_user3 1> $cert_find_info"
        rlAssertGrep "UID=$i18n_user3" "$cert_find_info"
	rlAssertGrep "CN=$i18n_user3_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0082: Test-4: search certs with user id having i18n characters using --uid"
        rlLog "Executing pki cert-find --uid $i18n_user4"
        rlRun "pki -h $target_host -p $target_port cert-find --uid $i18n_user4 1> $cert_find_info"
        rlAssertGrep "UID=$i18n_user4" "$cert_find_info"
	rlAssertGrep "CN=$i18n_user4_fullname" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0083: Test-5: search certs with user id having i18n characters using --uid"
        rlLog "Executing pki cert-find --name $i18n_user5"
        rlRun "pki -h $target_host -p $target_port cert-find --uid $i18n_user5 1> $cert_find_info"
        rlAssertGrep "CN=$i18n_user5_fullname" "$cert_find_info"
	rlAssertGrep "UID=$i18n_user5" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0084: search certs with common name using --name and --matchExactly"
        rlLog "Executing pki cert-find --uid pkiqa$rand\User --matchExactly"
        rlRun "pki -h $target_host -p $target_port cert-find --uid pkiqa$rand\User --matchExactly 1> $cert_find_info"
        rlAssertGrep "UID=pkiqa$rand\User" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0085: Multiple Searches: search certs with match specific CN, OrganizationUnit and email id"
	rlLog "Executing pki cert-find --name "$i18n_user1_fullname" --orgUnit ExampleQE1 --email test@example.org --matchExactly"
	rlRun "pki -h $target_host -p $target_port cert-find --name \"$i18n_user1_fullname\" --orgUnit ExampleQE1 --email test@example.org --matchExactly 1> $cert_find_info"
	rlAssertGrep "E=test@example.org" "$cert_find_info"
	rlAssertGrep "CN=$i18n_user1_fullname" "$cert_find_info"
	rlAssertGrep "OU=ExampleQE1" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0086: verify no certs are returned when junk value is passed to --uid"
        rlLog "Executing pki cert-find --uid \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --uid \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd
          
        rlPhaseStartTest "pki_cert_find-0087: verify --uid <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --uid"
        rlRun "pki -h $target_host -p $target_port cert-find --uid >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: uid" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0088: search certs with valid organization name using --org"
	local tmp_org="Example Organization $rand"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o:\"$tmp_org\" \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --org \"$tmp_org\""
        rlRun "pki -h $target_host -p $target_port cert-find --org \"$tmp_org\" 1> $cert_find_info"
        rlAssertGrep "O=$tmp_org" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0089: search certs with valid organization name using --org(case In-sensitive)"
	local case_tmp_org="example orGANizaTION $rand"
        rlLog "Executing pki cert-find --org \"$case_tmp_org\""
        rlRun "pki -h $target_host -p $target_port cert-find --org \"$case_tmp_org\" 1> $cert_find_info"
        rlAssertGrep "O=$tmp_org" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0090: verify no certs are returned when junk value is passed to --org"
        rlLog "Executing pki cert-find --org \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --org \"$tmp_junk_data\" 1> $cert_find_info" 
        rlAssertGrep "0 entries found" "$cert_find_info"
	rlAssertNotGrep "Number of entries" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0091: verify --org <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --org"
        rlRun "pki -h $target_host -p $target_port cert-find --org >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: org" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0092: search certs with valid organization name using --orgUnit"
        local tmp_org_unit="Organization Unit $rand"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou:\"$tmp_org_unit\" \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        rlLog "Executing pki cert-find --orgUnit \"$tmp_org_unit\""
        rlRun "pki -h $target_host -p $target_port cert-find --orgUnit \"$tmp_org_unit\" 1> $cert_find_info"
        rlAssertGrep "OU=$tmp_org_unit" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0093: search certs with valid organization name using --orgUnit(case In-sensitive)"
        local case_tmp_org_unit="orGANizaTION UNIT $rand"
        rlLog "Executing pki cert-find --orgUnit \"$case_tmp_org_unit\""
        rlRun "pki -h $target_host -p $target_port cert-find --orgUnit \"$case_tmp_org_unit\" 1> $cert_find_info"
        rlAssertGrep "OU=$tmp_org_unit" "$cert_find_info"
        rlAssertGrep "Number of entries returned 1" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0094: verify no certs are returned when junk value is passed to --orgUnit"
        rlLog "Executing pki cert-find --orgUnit \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --orgUnit \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "Number of entries" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0095: verify --orgUnit <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --orgUnit"
        rlRun "pki -h $target_host -p $target_port cert-find --orgUnit >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: orgUnit" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0096: search certs which have been revoked with reason unspecified using --revocationReason unspecified"
	local tmp_revoke_reason=unspecified
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
	rlAssertNotGrep "0 entries found" "$cert_find_info"
	rlLog "PKI TICKET:: https//fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_find-0097: search certs which have been revoked with reason Key_Compromise using --revocationReason Key_Compromise"
        local tmp_revoke_reason=Key_Compromise
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0098: search certs which have been revoked with reason CA_Compromise using --revocationReason CA_Compromise"
        local tmp_revoke_reason=CA_Compromise
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_find-0099: search certs which have been revoked with reason Affiliation_Changed using --revocationReason Affiliation_Changed"
        local tmp_revoke_reason=Affiliation_Changed
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd


        rlPhaseStartTest "pki_cert_find-0100: search certs which have been revoked with reason Superseded using --revocationReason Superseded"
        local tmp_revoke_reason=Superseded
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0101: search certs which have been revoked with reason Cessation_of_Operation using --revocationReason Cessation_of_Operation"
        local tmp_revoke_reason=Cessation_of_Operation
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0102: search certs which have been revoked with reason Certificate_Hold using --revocationReason Certificate_Hold"
        local tmp_revoke_reason=Certificate_Hold
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
	rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0103: search certs which have been revoked with reason Privilege_Withdrawn using --revocationReason Privilege_Withdrawn"
        local tmp_revoke_reason=Privilege_Withdrawn
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason 1> $cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1053"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0104: search certs which have been revoked with reason unspecified (Numeric Code 0) using --revocationReason 0"
        local tmp_revoke_reason=unspecified
	local tmp_revoke_reason_code=0
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0105: search certs which have been revoked with reason Key_Compromise (Numeric code 1)  using --revocationReason 1"
        local tmp_revoke_reason=Key_Compromise
	local tmp_revoke_reason_code=1
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0106: search certs which have been revoked with reason CA_Compromise(Numeric code 2) using --revocationReason 2"
        local tmp_revoke_reason=CA_Compromise
	local tmp_revoke_reason_code=2
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0107: search certs which have been revoked with reason Affiliation_Changed(Numeric code 3) using --revocationReason 3"
        local tmp_revoke_reason=Affiliation_Changed
	local tmp_revoke_reason_code=3
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0108: search certs which have been revoked with reason Superseded(Numeric Code 4) using --revocationReason 4"
        local tmp_revoke_reason=Superseded
        local tmp_revoke_reason_code=4
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0109: search certs which have been revoked with reason Cessation_of_Operation(Numeric Code 5) using --revocationReason 5"
        local tmp_revoke_reason=Cessation_of_Operation
        local tmp_revoke_reason_code=5
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0110: search certs which have been revoked with reason Certificate_Hold(Numeric Code 6) using --revocationReason 6"
        local tmp_revoke_reason=Certificate_Hold
        local tmp_revoke_reason_code=6
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Placed certificate \"$cert_serialNumber\" on-hold" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0111: search certs which have been revoked with reason Privilege_Withdrawn(Numeric Code 9) using --revocationReason 9"
        local tmp_revoke_reason=Privilege_Withdrawn
        local tmp_revoke_reason_code=9
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revocationReason $tmp_revoke_reason_code"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason $tmp_revoke_reason_code --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0112: verify no certs are returned when junk value is passed to --revocationReason"
        rlLog "Executing pki cert-find --revocationReason \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0113: verify --revocationReason  <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --revocationReason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: revocationReason" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0114: search certs which have been revoked by Admin User using --revokedBy caadmincert"
	local tmp_revoked_user=caadmin
        local tmp_revoke_reason=unspecified
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
	rlLog "Executing pki cert-find --revokedBy $tmp_revoked_user --minSerialNumber $cert_serialNumber"
	rlRun "pki -h $target_host -p $target_port cert-find --revokedBy $tmp_revoked_user --minSerialNumber $cert_serialNumber 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
	rlAssertGrep "Subject DN: $cert_subject" "$cert_find_info"
	rlAssertGrep "Number of entries" "$cert_find_info"
	rlAssertNotGrep "0 entries found" "$cert_find_info"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1054"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0115: search certs which have been revoked by Agent User using --revokedBy CA_agentV"
        local tmp_revoked_user=$CA_INST\_agentV
        local tmp_revoke_reason=Key_Compromise
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn: \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n $tmp_revoked_user \
                cert-revoke $cert_serialNumber --force --reason $tmp_revoke_reason 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --revokedBy $tmp_revoked_user --minSerialNumber $cert_serialNumber"
        rlRun "pki -h $target_host -p $target_port cert-find --revokedBy $tmp_revoked_user --minSerialNumber $cert_serialNumber 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
	rlAssertGrep "Subject DN: $cert_subject" "$cert_find_info"
        rlAssertGrep "Number of entries" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
	rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1054"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0116: search certs which have been revoked by agent CA_agentV --revoked CA_agentV(case-insensitive)"
	tmp_revoked_user=$CA_INST\_aGENTv
        rlLog "Executing pki cert-find --revokedBy $tmp_revoked_user --size 1000"
        rlRun "pki -h $target_host -p $target_port cert-find --revokedBy $tmp_revoked_user --size 1000 1> $cert_find_info"
        rlAssertGrep "Number of entries" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0117: verify no certs are returned when junk value is passed to --revocationReason"
        rlLog "Executing pki cert-find --name \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason \"$tmp_junk_data\" 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0118: verify --revocationReason  <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --revocationReason"
        rlRun "pki -h $target_host -p $target_port cert-find --revocationReason >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: revocationReason" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd


        rlPhaseStartTest "pki_cert_find-0119: search certs with which have been revoked from Current date --revokedOnFrom <YYYY-MM-DD>"
        local tmp_cur_date=$(date +%Y-%m-%d)
        rlLog "Generate 3 Certs"
        local i=1
        local upperlimit=4
        while [ $i -ne $upperlimit ] ; do
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"PKI Revocation $rand User $i\" \
                subject_uid:pkirev-$rand-User$i \
                subject_email:pkirev-$rand-User$i@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile: \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason unspecified 1> $expout" 0
        let i=$i+1
        done
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnFrom $tmp_cur_date --size 1000 1> $cert_find_info"
	rlAssertGrep "Number of entries" "$cert_find_info"
	rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlLog "PKI TICKET:: https://fedorahosted.org/pki/ticket/1055"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_find-0120: verify no certs are returned when invalid date is passed to --revokedOnFrom"
        local tmp_fail_cur_date=$(date +%d-%Y-%m)
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnFrom $tmp_fail_cur_date --size 1000 1> $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI TICKET::https://fedorahosted.org/pki/ticket/1072"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0121: verify no certs are returned when junk value is passed to --revokedOnFrom"
        rlLog "Executing pki cert-find --revokedOnFrom \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnFrom \"$tmp_junk_data\" 2> $cert_find_info" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0122: verify --revokedOnFrom <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --revokedOnFrom"
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnFrom >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: revokedOnFrom" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0123: search revoked certs which are issued from Current date --revokedOnTo <YYYY-MM-DD>"
        local tmp_cur_date=$(date +%Y-%m-%d)
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnTo $tmp_cur_date --size 1000 1> $cert_find_info"
	rlAssertNotGrep "Status: VALID" "$cert_find_info"
	rlAssertGrep "Number of entries returned" "$cert_find_info"
	rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0124: Test-1 verify no revoked certs are returned when invalid date is passed to --revokedOnTo YYYY-DD-MM" 
        local tmp_cur_date=$(date +%Y-28-%m)
	rlLog "Executing pki cert-find --revokedOnTo $tmp_cur_date"
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnTo $tmp_cur_date --size 1000 1> $cert_find_info"
	rlAssertNotGrep "Status: Revoked" "$cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI TICKET::https://fedorahosted.org/pki/ticket/1072"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0125: Test-2 verify no revoked certs are returned when invalid date is passed to --revokedOnTo 2048-22-06"
	local tmp_cur_date=2048-22-06
        rlLog "Executing pki cert-find --revokedOnTo $tmp_cur_date"
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnTo $tmp_cur_date --size 1000 1> $cert_find_info"
	rlAssertNotGrep "Status: Revoked" "$cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
	rlLog "PKI TICKET::https://fedorahosted.org/pki/ticket/1072"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_find-0126: verify no revoked certs are returned when junk value is passed to --revokedOnTo"
        rlLog "Executing pki cert-find --revokedOnTo \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnTo \"$tmp_junk_data\" 2> $cert_find_info" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0127: verify --revokedOnTo <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --revokedOnTo"
        rlRun "pki -h $target_host -p $target_port cert-find --revokedOnTo >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: revokedOnTo" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0128: return a fixed number of search results using --size <validNumber>"
	local tmp_search_size=15
	rlLog "Executing pki cert-find --size $tmp_search_size"
	rlRun "pki -h $target_host -p $target_port cert-find --size $tmp_search_size 1> $cert_find_info" 
	rlAssertGrep "Number of entries returned $tmp_search_size" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0129: verify if search results are returned if a very large number is passed to --size"
	local tmp_search_size="12345678998765432112345678"
        rlLog "Executing pki cert-find --size $tmp_search_size"
        rlRun "pki -h $target_host -p $target_port cert-find --size $tmp_search_size > $cert_find_info 2>&1" 1,255
	rlAssertGrep "NumberFormatException: For input string: \"$tmp_search_size\"" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0130: verify no search results are returned when junk value is passed to --size"
        rlLog "Executing pki cert-find --size \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --size \"$tmp_junk_data\" 2> $cert_find_info" 1,255
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0131: verify --size <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --size"
        rlRun "pki -h $target_host -p $target_port cert-find --size >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: size" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0132: return a fixed number of search results using --size <validNumber> starting with serialNumber 0x6"
        local tmp_search_size=15
	local tmp_start_from=$(expr 5 + 1)
        rlLog "Executing pki cert-find --size $tmp_search_size --start $tmp_start_from"
        rlRun "pki -h $target_host -p $target_port cert-find --size $tmp_search_size 1> $cert_find_info"
	local cert_start_serialNumber=0x$(echo "obase=16;$tmp_start_from"|bc)
	rlAssertGrep "Serial Number: $cert_start_serialNumber" "$cert_find_info"
        rlAssertGrep "Number of entries returned $tmp_search_size" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0133: verify no search results are returned when junk value is passed to --start"
        rlLog "Executing pki cert-find --start \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --start \"$tmp_junk_data\" 2> $cert_find_info" 1,255
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0134: verify --start <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --start"
        rlRun "pki -h $target_host -p $target_port cert-find --start >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: start" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0135: search certs that have valid Name of the state in subject Name using --state"
	local tmp_cert_state="North Carolina"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:server$rand\.example.org \
		subject_uid: \
		subject_email: \
		subject_ou: \
		subject_org: \
		subject_c:US \
                archive:false \
		req_profile:caServerCert \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
	local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
	rlLog "Executing pki cert-find --state North Carolina"
	rlRun "pki -h $target_host -p $target_port cert-find --state \"$tmp_cert_state\" 1> $cert_find_info"
	rlRun "echo $cert_subject | grep \"$tmp_cert_state\""
	rlAssertGrep "Subject DN: $cert_subject" "$cert_find_info"
	rlAssertGrep "Number of entries returned" "$cert_find_info"
	rlPhaseEnd
        
	rlPhaseStartTest "pki_cert_find-0136: verify no search results are returned when junk value is passed to --state"
        rlLog "Executing pki cert-find --state \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --state \"$tmp_junk_data\" 1> $cert_find_info" 
        rlAssertGrep "0 entries found" "$cert_find_info"
	rlAssertNotGrep "Number of entries returned" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0137: verify --state <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --state"
        rlRun "pki -h $target_host -p $target_port cert-find --state >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: state" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0138: search certs that have valid localit Name  subject Name of the cert using --locality"
        local tmp_cert_locality="Raleigh"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:server$rand\.example.org \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_org: \
                subject_c:US \
                archive:false \
                req_profile:caServerCert \
                target_host:$target_host \
                protocol: \
                port:$target_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info"
	local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlLog "Executing pki cert-find --locality North Carolina"
        rlRun "pki -h $target_host -p $target_port cert-find --locality \"$tmp_cert_locality\" 1> $cert_find_info" 
        rlRun "echo $cert_subject | grep $tmp_cert_locality"
        rlAssertGrep "$tmp_cert_locality" "$cert_find_info"
        rlAssertGrep "Number of entries returned" "$cert_find_info"
        rlAssertNotGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0139: verify no search results are returned when junk value is passed to --locality"
        rlLog "Executing pki cert-find --state \"$tmp_junk_data\""
        rlRun "pki -h $target_host -p $target_port cert-find --locality \"$tmp_junk_data\" 1> $cert_find_info" 
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlAssertNotGrep "Number of entries returned" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0140: verify --locality <novalue> returns error and command help is returned"
        rlLog "Executing pki cert-find --locality"
        rlRun "pki -h $target_host -p $target_port cert-find --locality >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: locality" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0141: search all certs with status VALID"
	local tmp_cert_status=VALID
	rlLog "Executing pki cert-find --state $tmp_cert_status"
	rlRun "pki -h $target_host -p $target_port cert-find --status $tmp_cert_status 1> $cert_find_info"
	rlAssertGrep "Status: $tmp_cert_status" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0142: search all certs with status REVOKED"
        local tmp_cert_status=REVOKED
        rlLog "Executing pki cert-find --state $tmp_cert_status"
        rlRun "pki -h $target_host -p $target_port cert-find --status $tmp_cert_status 1> $cert_find_info"
        rlAssertGrep "Status: $tmp_cert_status" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0143: search all certs with status REVOKED_EXPIRED"
	local validityperiod="1 day"
	local tmp_cert_status=REVOKED_EXPIRED	
        rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		cn: \
		uid: \
		email: \
		ou: \
		org: \
		country: \
		archive:false \
		host:$target_host \
		port:$target_port \
		profile: \
                cert_db:$CERTDB_DIR \
		cert_db_pwd:$CERTDB_DIR_PASSWORD \
		admin_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info \
		expect_data:$exp"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cur_date=$(date) # Save current date
        rlLog "Date & Time before Modifying system date: $cur_date"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlRun "chronyc -a -m 'offline' 'settime $cert_end_date + 3 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlRun "pki -d  $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentV_user\" \
                cert-revoke $cert_serialNumber --force --reason Key_Compromise 1> $expout" 0
        rlAssertGrep "Revoked certificate \"$cert_serialNumber\"" "$expout"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$expout"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$expout"
        rlAssertGrep "Status: REVOKED" "$expout"
        rlLog "Executing pki cert-find --state $tmp_cert_status"
        rlRun "pki -h $target_host -p $target_port cert-find --status $tmp_cert_status 1> $cert_find_info"
        rlAssertGrep "Status: $tmp_cert_status" "$cert_find_info"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after running chrony: $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0144: Search certs which have validity period of 1 day"
        local validityperiod="1 day"
	local validitycount="1"
	local validityoperation="<="
	local validityunit="day"
        rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                cn:\"Test User1 $rand\" \
                uid:testuser1_$rand \
                email:testuser1_$rand@example.org \
                ou: \
                org: \
                country: \
                archive:false \
                host:$target_host \
                port:$target_port \
                profile: \
                cert_db:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info \
                expect_data:$exp"
	local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)	
	local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
	rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
	rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit --size 1000 1> $cert_find_info"
	rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
	rlAssertGrep "Subject DN: $cert_subject"  "$cert_find_info"
	rlAssertGrep "Number of entries returned" "$cert_find_info"
	rlPhaseEnd
        
	rlPhaseStartTest "pki_cert_find-0145: Search certs which have validity period of 7 days"
        local validityperiod="7 days"
	local validitycount="1"
        local validityoperation="<="
        local validityunit="week"
        rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                cn:\"Test User2 $rand\" \
                uid:testuser2_$rand \
                email:testuser2_$rand@example.org \
                ou: \
                org: \
                country: \
                archive:false \
                host:$target_host \
                port:$target_port \
                profile: \
                cert_db:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info \
                expect_data:$exp"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit --size 1000 1> $cert_find_info"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertGrep "Subject DN: $cert_subject"  "$cert_find_info"
        rlAssertGrep "Number of entries returned" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0146: Search certs which have validity period of less than a 1 year"
        local validityperiod="315 days"
        local validitycount="1"
        local validityoperation="<="
        local validityunit="year"
        rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                cn:\"Test User3 $rand\" \
                uid:testuser3_$rand \
                email:testuser3_$rand@example.org \
                ou: \
                org: \
                country: \
                archive:false \
                host:$target_host \
                port:$target_port \
                profile: \
                cert_db:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info \
                expect_data:$exp"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit --size 1000 1> $cert_find_info"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertGrep "Subject DN: $cert_subject"  "$cert_find_info"
        rlAssertGrep "Number of entries returned" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0147: Search certs which have validity period of more than a 3 months"
	local invalidperiod="90 days"
        local validityperiod="95 days"
        local validitycount="3"
        local validityoperation=">="
        local validityunit="month"
	local invalid_cert_info="$TmpDir/invalid_cert_info"	
	rlLog "Generate cert with validity period of $invalidperiod"
        rlRun "generate_modified_cert validity_period:\"$invalidperiod\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                cn:\"Test User4 $rand\" \
                uid:testuser4_$rand \
                email:testuser4_$rand@example.org \
                ou: \
                org: \
                country: \
                archive:false \
                host:$target_host \
                port:$target_port \
                profile: \
                cert_db:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info \
                expect_data:$exp"
	local invalid_cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlLog "invalid_cert_serialNumber=$invalid_cert_serialNumber"
	rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                cn:\"Test User4 $rand\" \
                uid:testuser4_$rand \
                email:testuser4_$rand@example.org \
                ou: \
                org: \
                country: \
                archive:false \
                host:$target_host \
                port:$target_port \
                profile: \
                cert_db:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info \
                expect_data:$exp"
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit --size 1000 1> $cert_find_info"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_find_info"
        rlAssertGrep "Subject DN: $cert_subject"  "$cert_find_info"
        rlAssertGrep "Number of entries returned" "$cert_find_info"
	rlAssertNotGrep "Serial Number: $invalid_cert_serialNumber" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0148: pki cert-find should not run when invalid data is passed to validitycount"
        local validitycount="a"
        local validityoperation=">="
        local validityunit="month"
	rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit --size 1000 > $cert_find_info 2>&1" 1,255
	rlAssertGrep "NumberFormatException: For input string: \"$validitycount\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0149: pki cert-find should not run no data is passed to validitycount"
	local validitycount=
        local validityoperation=">="
        local validityunit="month"
        rlLog "Executing pki cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit --size 1000 > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validityCount" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0150: pki cert-find should not run when invalid data is passed to validityOperation"
        local validitycount="1"
        local validityoperation="dfdfd"
        local validityunit="month"
        rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit > $cert_find_info"
        rlAssertGrep "0 entries found" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0151: pki cert-find should not run no data is passed to validityOperation"
	local validitycount="1"
        local validityoperation=
        local validityunit="month"
        rlLog "Executing pki cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation "$validityoperation" --validityUnit $validityunit > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validityOperation" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0152: pki cert-find should not run when invalid data is passed to validityUnit"
        local validitycount="1"
        local validityoperation=">="
        local validityunit="dkfdlkfaksdfdfdd1212"
        rlLog "Executing pki cert-find --validityCount $validityperiod --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Invalid validity duration unit: $validityunit" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0153: pki cert-find should not run no data is passed to validityUnit"
	local validitycount="1"
        local validityoperation=">="
        local validityunit=
        rlLog "Executing pki cert-find --validityCount --validityOperation \"$validityoperation\" --validityUnit $validityunit"
        rlRun "pki -h $target_host -p $target_port cert-find --validityCount $validitycount --validityOperation \"$validityoperation\" --validityUnit $validityunit > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validityUnit" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd


	rlPhaseStartTest "pki_cert_find-0154: Search all certs which have been issued today using --validNotBeforeFrom and --validNotBeforeTo"
	local tmp_start_date=$(date +%Y-%m-%d)
	local tmp_end_date=$(date +%Y-%m-%d)
	rlLog "Executing pki cert-find --validNotBeforeFrom $tmp_start_date --validNotBeforeTo $tmp_end_date --size 1000"
	rlRun "pki -h $target_host -p $target_port cert-find --validNotBeforeFrom $tmp_start_date --validNotBeforeTo $tmp_end_date --size 1000 1> $cert_find_info"
	rlAssertNotGrep "Not Valid Before: $(date +%a --date='1 day')" "$cert_find_info"
	rlAssertNotGrep "Not Valid Before: $(date +%a --date='1 day ago')" "$cert_find_info"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_find-0155: Search all certs which are going to expire by tomorrow using --validNotAfterFrom and --validNotAfterTo"
        local validityperiod="1 day"
        local tmp_start_date=$(date +%Y-%m-%d --date='1 day')
        local tmp_end_date=$(date +%Y-%m-%d --date='1 day')
        rlLog "Generate cert with validity period of $validityperiod"
        rlRun "generate_modified_cert validity_period:\"$validityperiod\" \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                req_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                cn: \
                uid: \
                email: \
                ou: \
                org: \
                country: \
                archive:false \
                host:$target_host \
                port:$target_port \
                profile: \
                cert_db:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                admin_nick:\"$CA_agentV_user\" \
                cert_info:$cert_info \
                expect_data:$exp"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        local cert_end_date=$(cat $cert_info| grep cert_end_date | cut -d- -f2)
        local cur_date=$(date) # Save current date
        rlLog "Date & Time before Modifying system date: $cur_date"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlRun "chronyc -a -m 'offline' 'settime $cert_end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
	rlLog "Cert End date: $cert_end_date"
        rlLog "Executing pki cert-find --validNotAfterFrom $tmp_start_date --validNotAfterTo $tmp_end_date --size 1000 1> $cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotAfterFrom $tmp_start_date --validNotAfterTo $tmp_end_date --size 1000  1> $cert_find_info"
	rlAssertNotGrep "Not Valid After: $(date +%a --date='2 days ago')" "$cert_find_info"
	rlAssertGrep "Not Valid After: $(date +%a --date='1 day ago')" "$cert_find_info"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after running chrony: $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0156: pki cert-find should not run when invalid data is passed to --validNotAfterTo"
        rlLog "Executing pki cert-find --validNotAfterTo $tmp_junk_data"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotAfterTo \"$tmp_junk_data\" > $cert_find_info 2>&1" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0157: pki cert-find should not run when invalid data is passed to --validNotAfterFrom"
        rlLog "Executing pki cert-find --validNotAfterFrom $tmp_junk_data"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotAfterFrom \"$tmp_junk_data\" > $cert_find_info 2>&1" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0158: pki cert-find should not run when invalid data is passed to --validNotBeforeFrom"
        rlLog "Executing pki cert-find --validNotBeforeFrom $tmp_junk_data"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotBeforeFrom $tmp_junk_data > $cert_find_info 2>&1" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0159: pki cert-find should not run when invalid data is passed to --validNotBeforeTo"
        rlLog "Executing pki cert-find --validNotBeforeTo $tmp_junk_data"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotAfterFrom $tmp_junk_data > $cert_find_info 2>&1" 1,255
        rlAssertGrep "ParseException: Unparseable date: \"$tmp_junk_data\"" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0160: pki cert-find should not run no data is passed to --validNotAfterTo"
        rlLog "Executing pki cert-find --validNotAfterTo"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotAfterTo > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validNotAfterTo" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0161: pki cert-find should not run no data is passed to --validNotAfterFrom"
        rlLog "Executing pki cert-find --validNotAfterFrom"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotAfterFrom > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validNotAfterFrom" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0162: pki cert-find should not run no data is passed to --validNotBeforeTo"
        rlLog "Executing pki cert-find --validNotBeforeTo"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotBeforeTo > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validNotBeforeTo" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0163: pki cert-find should not run no data is passed to --validNotBeforeFrom"
        rlLog "Executing pki cert-find --validNotBeforeFrom"
        rlRun "pki -h $target_host -p $target_port cert-find --validNotBeforeFrom > $cert_find_info 2>&1" 1,255
        rlAssertGrep "Error: Missing argument for option: validNotBeforeFrom" "$cert_find_info"
        rlAssertGrep "usage: cert-find \[OPTIONS...\]" "$cert_find_info"
        rlAssertGrep "    --certTypeSecureEmail <on|off>         Certifiate Type: Secure Email" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLClient <on|off>           Certifiate Type: SSL Client" "$cert_find_info"
        rlAssertGrep "    --certTypeSSLServer <on|off>           Certifiate Type: SSL Server" "$cert_find_info"
        rlAssertGrep "    --certTypeSubEmailCA <on|off>          Certifiate type: Subject Email" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --certTypeSubSSLCA <on|off>            Certificate type: Subject SSL" "$cert_find_info"
        rlAssertGrep "                                           CA" "$cert_find_info"
        rlAssertGrep "    --country <name>                       Subject's country" "$cert_find_info"
        rlAssertGrep "    --email <email>                        Subject's email address" "$cert_find_info"
        rlAssertGrep "    --help                                 Show help options" "$cert_find_info"
        rlAssertGrep "    --input <file path>                    File containing the search" "$cert_find_info"
        rlAssertGrep "                                           constraints" "$cert_find_info"
        rlAssertGrep "    --issuedBy <user id>                   Issued by" "$cert_find_info"
        rlAssertGrep "    --issuedOnFrom <YYYY-MM-DD>            Issued on or after this date" "$cert_find_info"
        rlAssertGrep "    --issuedOnTo <YYYY-MM-DD>              Issued on or before this date" "$cert_find_info"
        rlAssertGrep "    --locality <name>                      Subject's locality" "$cert_find_info"
        rlAssertGrep "    --matchExactly                         Match exactly with the details" "$cert_find_info"
        rlAssertGrep "                                           provided" "$cert_find_info"
        rlAssertGrep "    --maxSerialNumber <serial number>      Maximum serial number" "$cert_find_info"
        rlAssertGrep "    --minSerialNumber <serial number>      Minimum serial number" "$cert_find_info"
        rlAssertGrep "    --name <name>                          Subject's common name" "$cert_find_info"
        rlAssertGrep "    --revocationReason <reason>            Reason for revocation" "$cert_find_info"
        rlAssertGrep "    --revokedBy <user id>                  Certificate revoked by" "$cert_find_info"
        rlAssertGrep "    --revokedOnFrom <YYYY-MM-DD>           Revoked on or after this date" "$cert_find_info"
        rlAssertGrep "    --revokedOnTo <YYYY-MM-DD>             Revoked on or before this date" "$cert_find_info"
        rlAssertGrep "    --size <size>                          Page size" "$cert_find_info"
        rlAssertGrep "    --start <start>                        Page start" "$cert_find_info"
        rlAssertGrep "    --state <name>                         Subject's state" "$cert_find_info"
        rlAssertGrep "    --status <status>                      Certificate status: VALID," "$cert_find_info"
        rlAssertGrep "                                           INVALID, REVOKED, EXPIRED" "$cert_find_info"
        rlAssertGrep "                                           REVOKED_EXPIRED" "$cert_find_info"
        rlAssertGrep "    --uid <user id>                        Subject's userid" "$cert_find_info"
        rlAssertGrep "    --validityCount <count>                Validity duration count" "$cert_find_info"
        rlAssertGrep "    --validityOperation <operation>        Validity duration operation:" "$cert_find_info"
        rlAssertGrep "                                           \"<=\" or \">=\"" "$cert_find_info"
        rlAssertGrep "    --validityUnit <day|week|month|year>   Validity duration unit: day," "$cert_find_info"
        rlAssertGrep "                                           week, month (default), year" "$cert_find_info"
        rlAssertGrep "    --validNotAfterFrom <YYYY-MM-DD>       Valid not after start date" "$cert_find_info"
        rlAssertGrep "    --validNotAfterTo <YYYY-MM-DD>         Valid not after end date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeFrom <YYYY-MM-DD>      Valid not before start date" "$cert_find_info"
        rlAssertGrep "    --validNotBeforeTo <YYYY-MM-DD>        Valid not before end date" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0164: search certs by passing search constraints through an input file"
	rlLog "Executing pki --output $TmpDir cert-find --issuedBy system"
	rlRun "pki -h $target_host -p $target_port --output $TmpDir cert-find --issuedBy system > $cert_find_info"
	rlLog "Get the xml tag data from $TmpDir/http-request-1 to a $TmpDir/cert-find-input.xml"
	rlRun "cat $TmpDir/http-request-1  | grep \"<?xml\" >> $TmpDir/cert-find-input.xml"
	rlLog "Executing pki cert-find --input $TmpDir/cert-find-input.xml"
	rlRun "pki -h $target_host -p $target_port cert-find --input $TmpDir/cert-find-input.xml 1> $cert_find_info"
	rlAssertGrep "Number of entries returned" "$cert_find_info"
	local tmp_check_result=$(cat $cert_find_info  | grep  "Issued By:" | grep -v system | wc -l)
	if [ $tmp_check_result != 0 ]; then
		rlFail "Search results do not match constraints"
	fi
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0165: Issue pki cert-find using valid agent cert"
	rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port  -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-find"
	rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-find 1> $cert_find_info"
	rlAssertGrep "Number of entries returned 20" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0166: Issue pki cert-find using revoked Agent cert and verify no search results are returned"
	rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_agentR_user\" cert-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port  -c $CERTDB_DIR_PASSWORD -n \"$CA_agentR_user\" cert-find >> $cert_find_info 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0167: Issue pki cert-find using valid admin cert and verify search results are returned"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_adminV_user\" cert-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_adminV_user\" cert-find 1> $cert_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0168: Issue pki cert-find using Expired admin cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_INST\_adminE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_adminE_user\" cert-find > $cert_find_info 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_find_info"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0169: Issue pki cert-find using Expired agent cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_INST\_agentE | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$CA_agentE_user\" \
                cert-find > $cert_find_info 2>&1" 1,255 
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_find_info"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0170: Issue pki cert-find using valid audit cert"
        rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_auditV_user\" cert-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_auditV_user\" cert-find 1> $cert_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0171: Issue pki cert-find using valid operator cert"
        rlLog "Executing pki -d $CERTDB_DIR -h $target_host -p $target_port  -c $CERTDB_DIR_PASSWORD -n \"$CA_operatorV_user\" cert-find"
        rlRun "pki -d $CERTDB_DIR -h $target_host -p $target_port -c $CERTDB_DIR_PASSWORD -n \"$CA_operatorV_user\" cert-find 1> $cert_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_find_info"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_find-0172: Issue pki cert-find using normal user cert(without any privileges)"
        local profile=caUserCert
        local pki_user="idm1_user_$rand"
        local pki_user_fullName="Idm1 User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-n \"$CA_adminV_user\" \
                -c $CERTDB_DIR_PASSWORD \
		ca-user-add $pki_user \
                --fullName \"$pki_user_fullName\" \
                --password $pki_pwd" 0 "Create $pki_user User"
        rlLog "Generate cert for user $pki_user"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
		myreq_type:pkcs10 \
		algo:rsa key_size:2048 \
		subject_cn:\"$pki_user_fullName\" \
		subject_uid:$pki_user \
                subject_email:$pki_user@example.org \
		subject_ou: \
		subject_o: \
		subject_c: \
		archive:false \
                req_profile:$profile \
		target_host:$target_host \
		protocol: \
		port:$target_port \
		cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
		certdb_nick:\"$CA_agentV_user\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -h $target_host -p $target_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"$CA_adminV_user\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -n $CA_adminV_user \
                -c $CERTDB_DIR_PASSWORD \
                -t ca user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
       rlRun "pki -d $TEMP_NSS_DB \
		-h $target_host \
		-p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
                cert-find > $cert_find_info"
	rlAssertGrep "Number of entries returned 20" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0173: Issue pki cert-find using host URI parameter(https)"
        rlRun "pki -d $CERTDB_DIR \
		-U https://$target_host:$target_https_port \
		cert-find 1> $cert_find_info"
	rlAssertGrep "Number of entries returned 20" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0174: Issue pki cert-find using valid user"
	rlLog "Executing pki cert-find using user $pki_user"
	rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
		-u $pki_user \
		-w $pki_pwd \
                cert-find 1> $cert_find_info" 
	rlAssertGrep "Number of entries returned 20" "$cert_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_find-0175: Issue pki cert-find using in-valid user"
	local invalid_pki_user=test1
	local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki cert-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
		-h $target_host \
		-p $target_port \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                cert-find > $cert_find_info 2>&1" 1,255
	rlAssertGrep "PKIException: Unauthorized" "$cert_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0176: Issue pki cert-find --start <verybignumber>"
	local tmp_large_number1=1234567890
	local tmp_large_number2=12345678901
	rlLog "Executing pki cert-find --start $tmp_large_number1"
	rlRun "pki -h $target_host -p $target_port cert-find --start $tmp_large_number1 > $cert_find_info"
	rlAssertGrep "entries found" "$cert_find_info"
	rlRun "pki -h $target_host -p $target_port cert-find --start $tmp_large_number2 > $cert_find_info 2>&1" 255
	rlAssertGrep "NumberFormatException: For input string: \"$tmp_large_number2\"" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_find-0177: Issue pki cert-find --size <verybigNumber>"
	local tmp_large_number1=1234567890
	local tmp_large_number2=12345678901
        rlLog "Executing pki cert-find --size $tmp_large_number1"
        rlRun "pki -h $target_host -p $target_port cert-find --size $tmp_large_number1 > $cert_find_info" 
        rlAssertGrep "entries found" "$cert_find_info"
        rlRun "pki -h $target_host -p $target_port cert-find --size $tmp_large_number2 > $cert_find_info 2>&1" 255
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_large_number2\"" "$cert_find_info"
	rlPhaseEnd

	rlPhaseStartCleanup "pki cert-find cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
