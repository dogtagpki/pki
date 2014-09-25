#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-cert-cli
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-cert-request-profile-find
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
. /opt/rhqa_pki/pki-profile-lib.sh

run_pki-cert-request-profile-find-ca_tests()
{
	
	local cs_Type=$1
	local cs_Role=$2
	
	#Creating Temporary Directory for pki cert-request-profile-find
        rlPhaseStartSetup "pki cert-request-profile-find Temporary Directory"
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
	local cert_request_profile_find_info="$TmpDir/cert_req_profile_find_info.out"
	local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local temp_out="$TmpDir/cert-show.out"
        local cert_info="$TmpDir/cert_info"
        local cert_request_profile_find_info="$TmpDir/cert_request_profile_find_info"
        local cert_req_info="$TmpDir/cert_req_info.out"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local certout="$TmpDir/cert_out"
	local tmp_junk_data=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 200 | head -n 1)
        local i18n_user1="Örjan_Äke_$rand"
        local i18n_user2="Éric_Têko_$rand"
        local i18n_user3="éénentwintig_dvidešimt_$rand"
        local i18n_user4="kakskümmend_üks_$rand"
        local i18n_user5="двадцять_один_тридцять_$rand"
        local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
	local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_host=$tmp_ca_host
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)
        
	
	rlPhaseStartTest "pki_cert_cli-configtest: pki cert-request-profile-find --help configuration test"
	rlRun "pki -h $target_host -p $target_port cert-request-profile-find --help 1> $cert_request_profile_find_info" 0 "pki cert-request-profile-find --help"
	rlAssertGrep "usage: cert-request-profile-find \[OPTIONS...\]" "$cert_request_profile_find_info"
    	rlAssertGrep "    --help            Show help options" "$cert_request_profile_find_info"
    	rlAssertGrep "    --size <size>     Page size" "$cert_request_profile_find_info"
	rlAssertGrep "    --start <start>   Page start" "$cert_request_profile_find_info"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$cert_request_profile_find_info"
	
	rlPhaseStartTest "pki_cert_request_profile_find-001: Display the list of profiles"
	rlLog "Executing pki cert-request-profile-find"
	rlRun "pki -h $target_host \
		-p $target_port \
		-h $target_host \
		-p $target_port cert-request-profile-find > $cert_request_profile_find_info" 0 "Display first 20 profiles"
	rlAssertGrep "Profile ID: caUserCert" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: caUserSMIMEcapCert" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: caDualCert" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: AdminCert" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: caSignedLogCert" "$cert_request_profile_find_info"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert_request_profile_find-002: display only 5 profiles"
	rlLog "Executing pki cert-request-profile-find --size 5"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --size 5 > $cert_request_profile_find_info" 0 "Display 5 profiles"
        rlAssertGrep "Profile ID: caUserCert" "$cert_request_profile_find_info"
        rlAssertGrep "Profile ID: caUserSMIMEcapCert" "$cert_request_profile_find_info"
	rlAssertGrep "Number of entries returned 5" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-003: display only 5 profiles starting from 3rd profile"
	rlLog "Executing pki cert-request-profile-find --size 5 --start 3"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find \
		--size 5 \
		--start 3 > $cert_request_profile_find_info" 0 " Display 5 profiles starting from 3rd profile"
	rlAssertGrep "Profile ID: AdminCert" "$cert_request_profile_find_info"
	rlAssertGrep "Name: Manual Administrator Certificate Enrollment" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: caSignedLogCert" "$cert_request_profile_find_info"
	rlAssertGrep "Name: Manual Log Signing Certificate Enrollment" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: caTPSCert" "$cert_request_profile_find_info"
	rlAssertGrep "Name: Manual TPS Server Certificate Enrollment" "$cert_request_profile_find_info"
  	rlAssertGrep "Profile ID: caServerCert" "$cert_request_profile_find_info"
	rlAssertGrep "Name: Manual Server Certificate Enrollment" "$cert_request_profile_find_info"
	rlAssertGrep "Profile ID: caSubsystemCert" "$cert_request_profile_find_info"
	rlAssertGrep "Name: Manual Subsystem Certificate Enrollment" "$cert_request_profile_find_info"
	rlAssertGrep "Number of entries returned 5" "$cert_request_profile_find_info"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_cert_request_profile_find-004: Create a new profile and verify if the new profile shows up in pki cert-request-profile-find"
        local tmp_profile=caUserCert
        local tmp_new_user_profile=caUserCert$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-show $tmp_profile \
		--output $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\""
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_agentV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-enable $tmp_new_user_profile"
	rlRun "pki -h $target_host -p $target_port cert-request-profile-find --size 500 > $cert_request_profile_find_info"
	rlAssertGrep "Profile ID: $tmp_new_user_profile" "$cert_request_profile_find_info"
        rlPhaseEnd	

        rlPhaseStartTest "pki_cert_request_profile_find-005: Issue pki cert-request-profile-find using valid agent cert"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentV_user\" cert-request-profile-find"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentV_user\" \
		-h $target_host \
		-p $target_port cert-request-profile-find 1> $cert_request_profile_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-006: Issue pki cert-request-profile-find using revoked Agent cert and verify no search results are returned"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_agentR_user\" cert-request-profile-find"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_agentR_user\" \
		-h $target_host \
		-p $target_port cert-request-profile-find >> $cert_request_profile_find_info 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-007: Issue pki cert-request-profile-find using valid admin cert and verify search results are returned"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_adminV_user\" cert-request-profile-find"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port cert-request-profile-find 1> $cert_request_profile_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-008: Issue pki cert-request-profile-find using Expired admin cert"
        local cur_date=$(date)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $CA_adminE_user | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_adminE_user\" \
		-h $target_host \
		-p $target_port cert-request-profile-find > $cert_request_profile_find_info 2>&1" 1,255
        rlAssertGrep "ProcessingException: Unable to invoke request" "$cert_request_profile_find_info"
        rlLog "Set the date back to it's original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-009: Issue pki cert-request-profile-find using valid audit cert"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_auditV_user\" cert-request-profile-find"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_auditV_user\" \
		-h $target_host \
		-p $target_port cert-request-profile-find 1> $cert_request_profile_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0010: Issue pki cert-request-profile-find using valid operator cert"
        rlLog "Executing pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"$CA_operatorV_user\" cert-request-profile-find"
        rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-n \"$CA_operatorV_user\" \
		-h $target_host \
		-p $target_port cert-request-profile-find 1> $cert_request_profile_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0011: Issue pki cert-request-profile-find using normal user cert(without any privileges)"
        local profile=caUserCert
        local pki_user="idm1_user_$rand"
        local pki_user_fullName="Idm1 User $rand"
        local pki_pwd="Secret123"
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -n \"$CA_adminV_user\" \
		-h $target_host \
		-p $target_port \
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
                -c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $target_port \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"casigningcert\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
                -n $CA_adminV_user \
                -c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
                -t ca user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
       rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n \"$pki_user\" \
                -h $target_host \
		-p $target_port cert-request-profile-find > $cert_request_profile_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_request_profile_find_info"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_cert_request_profile_find-0012: Issue pki cert-request-profile-find using host URI parameter(https)"
        rlRun "pki -d $CERTDB_DIR \
                -U https://$target_host:$target_https_port \
                -h $target_host -p $target_port cert-request-profile-find 1> $cert_request_profile_find_info"
        rlAssertGrep "Number of entries returned 20" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0013: Issue pki cert-request-profile-find using valid user"
        rlLog "Executing pki cert-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -u $pki_user \
                -w $pki_pwd \
                -h $target_host \
		-p $target_port cert-request-profile-find 1> $cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0014: Issue pki cert-request-profile-find using in-valid user"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        rlLog "Executing pki cert-find using user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                -h $target_host -p $target_port cert-request-profile-find > $cert_request_profile_find_info 2>&1" 1,255
        rlAssertGrep "PKIException: Unauthorized" "$cert_request_profile_find_info"
        rlPhaseEnd

	rlPhaseStartTest "pki_cert_request_profile_find-0015: Issue junk value to --size and verify no search results are returned"
	rlLog "Executing pki cert-request-profile-find --size $tmp_junk_data"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --size $tmp_junk_data  > $cert_request_profile_find_info 2>&1" 1,255 "pass junk data to --size"
        rlAssertNotGrep "Profile ID: caUserCert" "$cert_request_profile_find_info"
	rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$cert_request_profile_find_info"
        rlPhaseEnd

	
	rlPhaseStartTest "pki_cert_request_profile_find-0016: Issue no value to --size and verify no search results are returned"
	rlLog "Executing pki cert-request-profile-find --size"
	rlRun "pki -h $target_host -p $target_port cert-request-profile-find --size > $cert_request_profile_find_info 2>&1" 1,255 
	rlAssertGrep "Error: Missing argument for option: size" "$cert_request_profile_find_info"
	rlAssertGrep "usage: cert-request-profile-find \[OPTIONS...\]" "$cert_request_profile_find_info"
        rlAssertGrep "    --help            Show help options" "$cert_request_profile_find_info"
        rlAssertGrep "    --size <size>     Page size" "$cert_request_profile_find_info"
        rlAssertGrep "    --start <start>   Page start" "$cert_request_profile_find_info"
        rlAssertNotGrep "Error: Unrecognized option: --help" "$cert_request_profile_find_info"
	rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0017: Issue junk value to --start and verify no search results are returned"
        rlLog "Executing pki cert-request-profile-find --start $tmp_junk_data"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --start $tmp_junk_data  > $cert_request_profile_find_info 2>&1" 1,255 "pass junk data to --start"
        rlAssertNotGrep "Profile ID: caUserCert" "$cert_request_profile_find_info"
        rlAssertGrep "NumberFormatException: For input string: \"$tmp_junk_data\"" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0018: Issue no value to --start and verify no search results are returned"
        rlLog "Executing pki cert-request-profile-find --start"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --start > $cert_request_profile_find_info 2>&1" 1,255
	rlAssertNotGrep "Error: Missing Profile ID" "$cert_request_profile_find_info"
        rlAssertGrep "Error: Missing argument for option: start" "$cert_request_profile_find_info"
	rlAssertGrep "usage: cert-request-profile-find \[OPTIONS...\]" "$cert_request_profile_find_info"
        rlAssertGrep "    --help            Show help options" "$cert_request_profile_find_info"
        rlAssertGrep "    --size <size>     Page size" "$cert_request_profile_find_info"
        rlAssertGrep "    --start <start>   Page start" "$cert_request_profile_find_info"
        rlAssertNotGrep "Error: Unrecognized option: --help" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0019: Issue value to --start which is greater than number of profiles and verify no search results are returned"
        rlLog "Executing pki cert-request-profile-find --start 1000"
        rlRun "pki -h $target_host \
		-p $target_port cert-request-profile-find \
		--start 1000 > $cert_request_profile_find_info" 0
	rlAssertGrep "Number of entries returned 0" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0020: Test-1 Create a new profile with i18n characters and verify if the new profile shows up in pki cert-request-profile-find"
        local tmp_profile=caUserCert
        local tmp_new_user_profile=caUserCert$i18n_user1$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-show $tmp_profile \
		--output $TmpDir/$tmp_new_user_profile-Temp1.xml" 0 "Get $tmp_profile xml saved in $tmp_new_user_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml" 0 "Rename $tmp_profile to $tmp_new_user_profile"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\"" 0 "Enable Netscape Extension nsCertEmail"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out" 0 "Add $tmp_new_user_profile-Temp1.xml"
        rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_agentV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-enable $tmp_new_user_profile"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --size 500 > $cert_request_profile_find_info"
        rlAssertGrep "Profile ID: $tmp_new_user_profile" "$cert_request_profile_find_info"
        rlPhaseEnd


        rlPhaseStartTest "pki_cert_request_profile_find-0021: Test-2 Create a new profile with i18n characters and verify if the new profile shows up in pki cert-request-profile-find"
        local tmp_profile=caUserCert
        local tmp_new_user_profile=caUserCert$i18n_user2$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-show $tmp_profile \
		--output $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\""
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_agentV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-enable $tmp_new_user_profile"
        rlRun "pki -h $target_host \
		 -p $target_port \
		cert-request-profile-find --size 500 > $cert_request_profile_find_info"
        rlAssertGrep "Profile ID: $tmp_new_user_profile" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0022: Test-3 Create a new profile with i18n characters and verify if the new profile shows up in pki cert-request-profile-find"
        local tmp_profile=caUserCert
        local tmp_new_user_profile=caUserCert$i18n_user3$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-show $tmp_profile \
		--output $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\""
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_agentV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-enable $tmp_new_user_profile"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --size 500 > $cert_request_profile_find_info"
        rlAssertGrep "Profile ID: $tmp_new_user_profile" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0023: Test-4 Create a new profile with i18n characters and verify if the new profile shows up in pki cert-request-profile-find"
        local tmp_profile=caUserCert
        local tmp_new_user_profile=caUserCert$i18n_user4$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-show $tmp_profile \
		--output $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\""
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_agentV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-enable $tmp_new_user_profile"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find --size 500 > $cert_request_profile_find_info"
        rlAssertGrep "Profile ID: $tmp_new_user_profile" "$cert_request_profile_find_info"
        rlPhaseEnd

        rlPhaseStartTest "pki_cert_request_profile_find-0024: Test-5 Create a new profile with i18n characters and verify if the new profile shows up in pki cert-request-profile-find"
        local tmp_profile=caUserCert
        local tmp_new_user_profile=caUserCert$i18n_user5$rand
        rlLog "Get $tmp_profile xml file"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-show $tmp_profile --output $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "sed -i s/"$tmp_profile"/"$tmp_new_user_profile/" $TmpDir/$tmp_new_user_profile-Temp1.xml"
        rlRun "enable_netscape_ext \"$TmpDir/$tmp_new_user_profile-Temp1.xml\" \"nsCertEmail\""
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_adminV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-add $TmpDir/$tmp_new_user_profile-Temp1.xml 1> $TmpDir/cert-profile-add.out"
        rlAssertGrep "Added profile $tmp_new_user_profile" "$TmpDir/cert-profile-add.out"
        rlRun "pki -d $CERTDB_DIR \
		-n $CA_agentV_user \
		-c $CERTDB_DIR_PASSWORD \
		-h $target_host \
		-p $target_port \
		ca-profile-enable $tmp_new_user_profile"
        rlRun "pki -h $target_host \
		-p $target_port \
		cert-request-profile-find \
		--size 500 > $cert_request_profile_find_info"
        rlAssertGrep "Profile ID: $tmp_new_user_profile" "$cert_request_profile_find_info"
        rlPhaseEnd

	rlPhaseStartCleanup "pki cert-request-profile-find cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    	rlPhaseEnd
}
