#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-profile-cli
#   Description: PKI CA PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki ca-profile-mod
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mniranja@redhat.com>
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

run_pki-ca-profile-mod_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki ca-profile-add
        rlPhaseStartSetup "pki key-show Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "export PYTHONPATH=$PYTHONPATH:/opt/rhqa_pki/"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$CA_INST\_agentV
        local valid_audit_cert=$CA_INST\_auditV
        local valid_operator_cert=$CA_INST\_operatorV
        local valid_admin_cert=$CA_INST\_adminV
        local revoked_agent_cert=$CA_INST\_agentR
        local revoked_admin_cert=$CA_INST\_adminR
        local expired_admin_cert=$CA_INST\_adminE
        local expired_agent_cert=$CA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
        local ca_profile_out="$TmpDir/ca-profile-out"
        local cert_out="$TmpDir/cert-show.out"
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')        

        rlPhaseStartTest "pki_ca_profile_config_test: pki ca-profile-mod --help configuration test"
        rlRun "pki ca-profile-mod --help > $ca_profile_out" 0 "pki ca-profile-add --help"
        rlAssertGrep "usage: ca-profile-mod <file> \[OPTIONS...\]" "$ca_profile_out"
        rlAssertGrep "    --help   Show help options" "$ca_profile_out"

        rlPhaseStartTest "pki_ca_profile_mod-001: Modify user Profile with Maximum Certificate validity for 15 days with a graceperiod of 5 days before and after"
        local pki_user="pki_foo_bar1"
        local pki_user_fullName="pki1 Foo Bar1"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml" 
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml" 0 "Modify Profile xml"
        rlLog "Add $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable Profile $profile"
        rlLog "Generate User Cert using $profilename"
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        local NotAfterDate=$(date +"%A, %B %d, %Y" --date "15 days")
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Not  After: $NotAfterDate" "$cert_out"
        rlLog "Verify by changing the date to 5 Days before the expiry date"
        local cur_date=$(date -u)
        local end_date=$(certutil -L -d $TEMP_NSS_DB_PWD -n \"$pki_user_fullName\" | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date - 5 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date - 5 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $TmpDir/pki-cert-request-submit.out" 0 "Submit renewal request"
        local REQUEST_ID=$(cat $TmpDir/pki-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TmpDir/pki-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TmpDir/pki-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: renewal"  "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TmpDir/pki-cert-request-submit.out"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlLog "PKI Ticket:: https://fedorahosted.org/pki/ticket/999"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-002: Modify User profile which adds key Encipher and decipher extensions to the Key Usage Extensions"
        local pki_user="pki_foo_bar2"
        local pki_user_fullName="pki1 Foo Bar2"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml" 
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlLog "Modify Profile $profile"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --keyusageextensions \"keyUsageCritical,keyUsageDigitalSignature,keyUsageNonRepudiation,keyUsageKeyEncipherment,keyUsageEncipherOnly,keyUsageDecipherOnly\" \
                --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify Profile $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out" 
        rlLog "Verify by creating a user cert using $profilename"
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Encipher Only" "$cert_out"
        rlAssertGrep "Decipher Only" "$cert_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-003: Modify User Profile to add Netscape Extensions nsCertSSLClient and nsCertEmail"
        local pki_user="pki_foo_bar3"
        local pki_user_fullName="pki1 Foo Bar3"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml" 
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --netscapeextensions \"nsCertCritical,nsCertSSLClient,nsCertEmail\" \
                --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify Profile $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Verify by creating a user cert using $profilename"
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$cert_out"
        rlAssertGrep "SSL Client" "$cert_out"
        rlAssertGrep "Secure Email" "$cert_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-004: Modify user profile to add subject Name pattern UID=QAGROUP-.* and rejects if pattern doesn't match"
        local pki_user="pki_foo_bar4"
        local pki_user_fullName="pki1 Foo Bar4"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --subjectNamePattern UID=QAGROUP-.* \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Edit Profile with Subject Name Pattern UID=QAGROUP-.*"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Verify by creating a user cert using $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$pki_user_fullName\" \
                subject_uid:QAGROUP-$pki_user \
                subject_email:$pki_user@example.org \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0 "Generate Cert with UID=QAGROUP-$pki_user"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlLog "Generate Certificate Request which doesn't satisfy Subject Name Pattern"
        rlRun "create_new_cert_request \
            dir:$TEMP_NSS_DB \
            pass:$TEMP_NSS_DB_PWD \
            req_type:pkcs10 \
            algo:rsa \
            size:2048 \
            cn:\"Test User1\" \
            uid:TestUser1 \
            email:testuser1@example.org \
            ou: \
            org: \
            country: \
            archive:false \
            myreq:$TEMP_NSS_DB/testuser1-request.pem \
            subj:$TEMP_NSS_DB/testuser1-request-dn.txt" 0 "Create New Certificate request which doesn't satisfy subject Name Pattern UID=QAGROUP-.*"
        rlRun "submit_new_request dir:$TEMP_NSS_DB \
            pass:$TEMP_NSS_DB_PWD \
            cahost:$tmp_ca_host \
            nickname:\"$valid_agent_cert\" \
            protocol: \
            port:$tmp_ca_port \
            url: \
            username: \
            userpwd: \
            profile:$profile \
            myreq:$TEMP_NSS_DB/testuser1-request.pem \
            subj:$TEMP_NSS_DB/testuser1-request-dn.txt \
            out:$TEMP_NSS_DB/testuser1-request-result.txt" 0 "Submit Request for Approval"
        rlAssertGrep "Request Status: rejected" "$TEMP_NSS_DB/testuser1-request-result.txt"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/testuser1-request-result.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-005: Modify user profile to add dc=cracker,dc=org added to Subject DN by default"
        local pki_user="pki_foo_bar5"
        local pki_user_fullName="pki1 Foo Bar5"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml" 
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --subjectNamePattern "UID=[^,]+,.+" \
                --subjectNameDefault UID=\\\$request.req_subject_name.uid$,dc=cracker,dc=org  \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Create Profile xml  which adds dc=cracker,dc=org to the subject DN"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlLog "Verify by creating a user cert using $profilename"
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0 "Generate Cert with UID=QAGROUP-$pki_user"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out" 
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-006: Modify user profile to add CRL extension with URL https://pki.example.org/fullCRL"
        local pki_user="pki_foo_bar6"
        local pki_user_fullName="pki1 Foo Bar6"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --crlextension \"https://pki.example.org/fullCRL\" \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Create Profile xml which adds CRL Extension"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlLog "Verify by creating a user cert using $profilename"
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0 "Generate Cert with UID=QAGROUP-$pki_user"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Distribution Point: \[URIName: https://pki.example.org/fullCRL\]" "$cert_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-007: Modify user profile to add SubjectAlt Name Extension having Requestor Email"
        local pki_user="pki_foo_bar7"
        local pki_user_fullName="pki1 Foo Bar7"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --altType RFC822Name \
                --altPattern \\\$request.requestor_email$ \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Create Profile xml which adds Requestor Email address in Subject Alt Name."
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlLog "Verify by creating a user cert using $profilename"
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0 "Generate Cert with UID=QAGROUP-$pki_user"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "RFC822Name: $pki_user@example.org" "$cert_out"
        rlPhaseEnd        

        rlPhaseStartTest "pki_ca_profile_mod-008: Modify server profile which rejects request if subject DN doesn't have *.otherexample.org"
        local subject_name="test.otherexample.org"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --subjectNamePattern \"CN=.*\.otherexample\.org.*\" \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify profile $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Verify by creating server cert using $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$subject_name\" \
                subject_uid:\
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlLog "Generate Certificate Request which doesn't satisfy Subject Name Pattern"
        local subject_name="test.cracker.org"
        rlRun "create_new_cert_request \
            dir:$TEMP_NSS_DB \
            pass:$TEMP_NSS_DB_PWD \
            req_type:pkcs10 \
            algo:rsa \
            size:2048 \
            cn:$subject_name \
            uid: \
            email: \
            ou: \
            org: \
            country: \
            archive:false \
            myreq:$TEMP_NSS_DB/$subject-csr.pem \
            subj:$TEMP_NSS_DB/$subect-dn.txt" 0 "Create New Certificate request which doesn't satisfy subject Name Pattern .otherexample.org"
        rlRun "submit_new_request dir:$TEMP_NSS_DB \
            pass:$TEMP_NSS_DB_PWD \
            cahost:$tmp_ca_host \
            nickname:\"$valid_agent_cert\" \
            protocol: \
            port:$tmp_ca_port \
            url: \
            username: \
            userpwd: \
            profile:$profile \
            myreq:$TEMP_NSS_DB/$subject-csr.pem \
            subj:$TEMP_NSS_DB/$subject-dn.txt \
            out:$TEMP_NSS_DB/$subject-result.txt" 0 "Submit Request for Approval"
        rlAssertGrep "Request Status: rejected" "$TEMP_NSS_DB/$subject-result.txt"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/$subject-result.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-009: Modify server profile to add Netscape Extensions nsCertSSlClient and nsCertEmail"
        local subject_name="testServer$RANDOM-1.example.org"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --netscapeextensions \"nsCertCritical,nsCertSSLClient,nsCertEmail\" \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Add Profile with Netscape Certificate Extensions"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Verify by creating a CA cert using $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$subject_name\" \
                subject_uid:\
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$cert_out"
        rlAssertGrep "SSL Client" "$cert_out"
        rlPhaseEnd        

        rlPhaseStartTest "pki_ca_profile_mod-0010: Modify server profile to add subject Name pattern having CN=[^,]+,.+ and adding dc=example,dc=org by default to subject DN"
        local subject_name="John Smith"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --subjectNamePattern CN=[^,]+,.+ \
                --subjectNameDefault CN=\\\$request.req_subject_name.cn$,dc=example,dc=org \
                --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Verify by creating a CA cert using $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$subject_name\" \
                subject_uid:\
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: CN=John Smith,DC=example,DC=org" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"


        rlPhaseStartTest "pki_ca_profile_mod-0011: Modify Server profile with Maximum validity period of 15 days with a graceperiod of 5 days before and after"
        local subject_name="foobar$RANDOM-1.example.org"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlLog "Verify by creating a server cert using $profilename"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:$subject_name \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        local NotAfterDate=$(date +"%A, %B %d, %Y" --date "15 days")
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Not  After: $NotAfterDate" "$cert_out"
        rlLog "Verify by changing the date to 5 Days before the expiry date"
        local cur_date=$(date -u)
        local end_date=$(certutil -L -d $TEMP_NSS_DB_PWD -n \"$pki_user_fullName\" | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date - 5 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date - 5 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                cert-request-profile-show caManualRenewal --output $TmpDir/$cert_serialNumber-renewal.xml" 0 "Get caManualRenewal profile xml"
        local STRIP_HEX=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        rlLog "Modify caManualRenewal profile xml to add serial Number $cert_serialNumber to be submitted for renewal"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/SerialNumber\" -v $decimal_valid_serialNumber $TmpDir/$cert_serialNumber-renewal.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-request-submit $TmpDir/$cert_serialNumber-renewal.xml 1> $TmpDir/pki-cert-request-submit.out" 0 "Submit renewal request"
        local REQUEST_ID=$(cat $TmpDir/pki-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TmpDir/pki-cert-request-submit.out"
        local REQUEST_SUBMIT_STATUS=$(cat $TmpDir/pki-cert-request-submit.out | grep "Operation Result" | awk -F ": " '{print $2}')
        rlAssertGrep "Type: renewal"  "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TmpDir/pki-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TmpDir/pki-cert-request-submit.out"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlLog "PKI Ticket:: https://fedorahosted.org/pki/ticket/999"
        rlPhaseEnd        

        rlPhaseStartTest "pki_ca_profile_mod-0012: Modify server profile which adds key Encipher and decipher extensions to keyUsage Extensions"
        local subject_name="foobar$RANDOM-1.example.org"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlLog "Create Profile $profile"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --keyusageextensions \"keyUsageCritical,keyUsageDigitalSignature,keyUsageNonRepudiation,keyUsageKeyEncipherment,keyUsageDataEncipherment,keyUsageEncipherOnly,keyUsageDecipherOnly\" \
                --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Add Profile $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out"
        rlLog "Verify by creating a server cert using the profile $profile"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:$subject_name \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Identifier: Key Usage: - 2.5.29.15" "$cert_out"
        rlAssertGrep "Encipher Only" "$cert_out"
        rlAssertGrep "Decipher Only" "$cert_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_profile_mod-0013: Modify server profile which adds CRL extension with URL https://pki.example.org/fullCRL"
        local subject_name="foobar$RANDOM-1.example.org"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --crlextension \"https://pki.example.org/fullCRL\" \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Create Profile xml which adds CRL Extension"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update Profile $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlLog "Verify by creating server cert using $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:$subject_name \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Distribution Point: \[URIName: https://pki.example.org/fullCRL\]" "$cert_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0014: Modify server profile to add SubjectAlt Name Extension having DNSName foobar.example.org"
        local subject_name="foobar$RANDOM-1.example.org"
        local profile="caServerCert$RANDOM"
        local profile_name="Manual Custom PKI Server $RANDOM Certificate Enrollment"
        rlRun "python -m PkiLib.pkiprofilecli --new server --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --altType DNSName \
                --altPattern www.foobar.example.org \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Create Profile xml which adds DNSName foobar.example.org to subjectAltName."
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update profile $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlLog "Verify by creating server cert using $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:$subject_name \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0 
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "DNSName: www.foobar.example.org" "$cert_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0015: Modify CA profile to add Netscape Extensions nsCertSSLCA, nsCertEmailCA"
        local subject_name="FooBar CA1"
        local profile="caCACert$RANDOM"
        local profile_name="FooBar CA1 Enrollment Profile"
        rlRun "python -m PkiLib.pkiprofilecli --new ca --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --netscapeextensions \"nsCertCritical,nsCertSSLCA,nsCertEmailCA\" \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Modify Profile with Netscape Certificate Extensions"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 0 "Update Profile $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlLog "Enable $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out 2>&1"
        rlAssertGrep "Enabled profile \"$profile\"" "$ca_profile_out"
        rlLog "Verify by creating a CA cert using profile $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$subject_name\" \
                subject_uid:\
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Basic Constraints - 2.5.29.19" "$cert_out"
        rlAssertGrep "Is CA: yes" "$cert_out"        
        rlAssertGrep "Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1" "$cert_out"
        rlAssertGrep "Secure Email CA" "$cert_out"
        rlAssertGrep "SSL CA" "$cert_out"
        rlPhaseEnd
        
        rlPhaseStartTest "pki_ca_profile_mod-0016: Modify CA profile to add CRL extension with URL https://pki.example.org/fullCRL"
        local subject_name="FooBar CA2"
        local profile="caCACert$RANDOM"
        local profile_name="FooBar CA2 Enrollment Profile"
        rlRun "python -m PkiLib.pkiprofilecli --new ca --profileId $profile --profilename \"$profile_name\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"        
        rlRun "python -m PkiLib.pkiprofilecli \
                --editprofile $TmpDir/$profile-test.xml \
                --crlextension \"https://pki.example.org/fullCRL\" \
                --outputfile $TmpDir/$profile-mod.xml" 0 "Add Profile with Netscape Certificate Extensions"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Update Profile $profile with profile changes"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-enable $profile > $ca_profile_out" 0 "Enable profile $profile"
        rlLog "Verify by creating a CA cert using the profile $profilename"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
                algo:rsa \
                key_size:2048 \
                subject_cn:\"$subject_name\" \
                subject_uid: \
                subject_email: \
                subject_ou: \
                subject_o: \
                subject_c: \
                archive:false \
                req_profile:$profile \
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info" 0
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local cert_subject=$(cat $cert_info | grep cert_subject | cut -d- -f2)
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --pretty > $cert_out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$cert_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_out"
        rlAssertGrep "Subject: $cert_subject" "$cert_out"
        rlAssertGrep "Status: VALID" "$cert_out"
        rlAssertGrep "Basic Constraints - 2.5.29.19" "$cert_out"
        rlAssertGrep "Is CA: yes" "$cert_out"
        rlAssertGrep "Distribution Point: \[URIName: https://pki.example.org/fullCRL\]" "$cert_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0017: Modifying Profile xml using admin cert should pass"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml" 
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"        
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0018: Adding Profile xml using agent cert should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_agent_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1
        rlAssertGrep "ForbiddenException: Authorization Error" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0019: Adding Profile xml using Revoked Admin cert should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $revoked_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1        
        rlAssertGrep "PKIException: Unauthorized" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0020: Adding Profile xml using Revoked Agent cert should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $revoked_agent_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1
        rlAssertGrep "PKIException: Unauthorized" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0021: Adding Profile xml using Expired Agent cert should fail"
        local cur_date=$(date -u)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_agent_cert | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $expired_agent_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1        
        rlAssertGrep "ProcessingException: Unable to invoke request" "$ca_profile_out"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0022: Adding Profile xml using Expired Admin cert should fail"
        local cur_date=$(date -u)
        local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_admin_cert | grep "Not After" | awk -F ": " '{print $2}')
        rlLog "Current Date/Time: $(date)"
        rlLog "Current Date/Time: before modifying using chrony $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Move system to $end_date + 1 day ahead"
        rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $expired_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1
        rlAssertGrep "ProcessingException: Unable to invoke request" "$ca_profile_out"
        rlLog "Set the date back to its original date & time"
        rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Current Date/Time after setting system date back using chrony $(date)"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0023: Adding Profile xml using Audit cert should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_audit_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1        
        rlAssertGrep "ForbiddenException: Authorization Error" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0024: Adding Profile xml using Operator cert should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n $valid_operator_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1
        rlAssertGrep "ForbiddenException: Authorization Error" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartSetup "Create a Normal User with No Privileges and add cert"
        local pki_user="idm1_user_$rand"
        local pki_user_fullName="Idm1 User $rand"
        local pki_pwd="Secret123"
        local profile=caUserCert
        rlLog "Create user $pki_user"
        rlRun "pki -d $CERTDB_DIR \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert \
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
                target_host:$tmp_ca_host \
                protocol: \
                port:$tmp_ca_port \
                cert_db_dir:$CERTDB_DIR \
                cert_db_pwd:$CERTDB_DIR_PASSWORD \
                certdb_nick:$valid_agent_cert \
                cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        rlLog "Get the $pki_user cert in a output file"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show $cert_serialNumber --encoded --output $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/pki-cert-show.out"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlLog "Add the $pki_user cert to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -c $TEMP_NSS_DB_PWD \
                -n "$pki_user" client-cert-import \
                --cert $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki-client-cert.out"
        rlAssertGrep "Imported certificate \"$pki_user\"" "$TEMP_NSS_DB/pki-client-cert.out"
        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"casigningcert\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"
        rlRun "pki -d $CERTDB_DIR \
                -h $tmp_ca_host \
                -p $tmp_ca_port \
                -n $valid_admin_cert \
                -c $CERTDB_DIR_PASSWORD \
                -t ca user-cert-add $pki_user \
                --input $TEMP_NSS_DB/$pki_user-out.pem 1> $TEMP_NSS_DB/pki_user_cert_add.out" 0 "Cert is added to the user $pki_user"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0025: Adding Profile xml using Normal cert should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -n $pki_user \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1
        rlAssertGrep "ForbiddenException: Authorization Error" "$ca_profile_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_profile_mod-0026: Executing pki ca-profile-add using https URI using Admin Cert"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -U https://$tmp_ca_host:$target_secure_port \
                -n $valid_admin_cert \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out" 0 "Modified Profile $profile"
        rlAssertGrep "Modified profile $profile" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0027: Adding Profile xml using Normal user authencation should fail"
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"   
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -u $pki_user \
                -w $pki_pwd \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1 "Modify Profile using $pki_user cert"
        rlAssertGrep "ForbiddenException: Authentication method not allowed" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_profile_mod-0028: Adding Profile xml  using invalid user authentication should fail"
        local invalid_pki_user=test1
        local invalid_pki_user_pwd=Secret123
        local profile="caUserCert$RANDOM"
        local profilename="$profile Enrollment Profile"
        rlLog "Create a new user profile for modification"
        rlRun "python -m PkiLib.pkiprofilecli --new user --profileId $profile --profilename \"$profilename\" --outputfile $TmpDir/$profile-test.xml"
        rlRun "pki -h $tmp_ca_host -p $tmp_ca_port -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert ca-profile-add $TmpDir/$profile-test.xml > $ca_profile_out"
        rlAssertGrep "Added profile $profile" "$ca_profile_out"
        rlRun "python -m PkiLib.pkiprofilecli \
            --editprofile $TmpDir/$profile-test.xml \
            --notBefore 5 \
            --notAfter 5 \
            --validfor 15 \
            --maxvalidity 30  \
            --outputfile $TmpDir/$profile-mod.xml"
        rlLog "Modify $profile"
        rlRun "pki -h $tmp_ca_host \
                -p $tmp_ca_port \
                -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -u $invalid_pki_user \
                -w $invalid_pki_user_pwd \
                ca-profile-mod $TmpDir/$profile-mod.xml > $ca_profile_out 2>&1" 255,1 "Modify Profile using $pki_user cert"
        rlAssertGrep "PKIException: Unauthorized" "$ca_profile_out"
        rlPhaseEnd

        rlPhaseStartCleanup "pki ca-profile-mod cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
