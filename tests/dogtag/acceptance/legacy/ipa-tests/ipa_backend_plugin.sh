#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ipa-tests/ipa_backend_plugin.sh
#   Description: IPA Backend Plugin
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

# Include tests
. ./acceptance/quickinstall/rhds-install.sh

run_ipa_backend_plugin()
{
        local cs_Type=$1
        local cs_Role=$2

	# Creating Temporary Directory for ca-admin-acl tests
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
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
        local sub_ca_ldap_port=1839
        local sub_ca_http_port=15080
        local sub_ca_https_port=15443
        local sub_ca_ajp_port=15009
        local sub_ca_tomcat_port=15005
        local subca_instance_name=pki-example-$RANDOM
        local SUBCA_SERVER_ROOT=/var/lib/pki/$subca_instance_name/ca
        local admin_cert_nickname="PKI Administrator for example.org"
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="Secret123"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_https_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$(eval echo \$${cs_Role})

       	rlPhaseStartSetup "Setup a Subordinate CA for pki cert-revoke"
        local install_info=$TmpDir/install_info
        rlLog "Setting up a Subordinate CA instance $subca_instance_name"
        rlRun "rhcs_install_ipaca $subca_instance_name \
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

	rlPhaseStartSetup "Preparation steps to generate Certificate request"
        rlLog "In create_cert"
        rlLog "Get the cert in a output file"
        rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/ca-cert-show.out"
        rlAssertGrep "Certificate \"0x1\"" "$TEMP_NSS_DB/ca-cert-show.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $target_port \
                -c $TEMP_NSS_DB_PWD \
                -n \"casigningcert\" client-cert-import \
                --ca-cert $TEMP_NSS_DB/ca_cert.pem 1> $TEMP_NSS_DB/pki-ca-cert.out"
        rlAssertGrep "Imported certificate \"casigningcert\"" "$TEMP_NSS_DB/pki-ca-cert.out"
	rlLog "Step-2: ipa certificate request for creating sslget client cert"
        rlLog "Generating temporary certificate"
	local ipa_cn="IPA-Subsystem-Certificate"
        rlRun "generate_new_cert \
		tmp_nss_db:$TEMP_NSS_DB \
		tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
                myreq_type:pkcs10 \
		algo:rsa \
		key_size:2048 \
		subject_cn:$ipa_cn \
		subject_uid: \
                subject_email: \
		subject_ou:pki-ipa \
		subject_o:redhat \
		subject_c: \
		archive:false \
                req_profile:caServerCert \
		target_host:$target_host \
		protocol: \
		port:$sub_ca_http_port \
		cert_db_dir:$TEMP_NSS_DB \
                cert_db_pwd:$TEMP_NSS_DB_PWD \
		certdb_nick:\"$admin_cert_nickname\" \
		cert_info:$cert_info"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
	rlLog "cert_serialNumber=$cert_serialNumber"
	rlRun "pki -h $target_host -p $sub_ca_http_port cert-show $cert_serialNumber --encoded --output  $TEMP_NSS_DB/$ipa_cn\.pem 1> $TEMP_NSS_DB/cert-show.out"
        rlAssertGrep "Certificate \"$cert_serialNumber\"" "$TEMP_NSS_DB/cert-show.out"
        rlRun "pki -d $TEMP_NSS_DB \
                -h $target_host \
                -p $sub_ca_http_port \
                -c $TEMP_NSS_DB_PWD \
                -n $ipa_cn client-cert-import \
                --cert $TEMP_NSS_DB/$ipa_cn\.pem 1> $TEMP_NSS_DB/pki-cert.out"
        rlAssertGrep "Imported certificate \"$ipa_cn\"" "$TEMP_NSS_DB/pki-cert.out"
	rlLog "Step-3: Generate freeIPA1 user and Import $ipa_cn cert"
        local test_agent_user="freeIPA1"
        local agent_user_fullName="free IPA1 Admin User"
        local test_agent_pwd="Secret123"
        rlLog "Create user with Admin Privileges only"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $target_host \
                -p $sub_ca_http_port \
                -n \"$admin_cert_nickname\"  \
                user-add $test_agent_user  \
                --fullName \"$agent_user_fullName\" \
                --password $test_agent_pwd" 0 "Create $agent_user_fullName"
        rlLog "Add user to Certificate Manager Agents Group"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $target_host \
                -p $sub_ca_http_port \
                -n \"$admin_cert_nickname\" \
                group-member-add \"Certificate Manager Agents\" $test_agent_user" 0 "Add $agent_user_fullName to Certificate Manager Agents"
        rlRun "pki -d $TEMP_NSS_DB \
                -c $TEMP_NSS_DB_PWD \
                -h $target_host \
                -p $sub_ca_http_port \
                -n \"$admin_cert_nickname\" \
                group-member-add \"Registration Manager Agents\" $test_agent_user" 0 "Add $agent_user_fullName to Registration Manager Agents"
	rlRun "pki -d $TEMP_NSS_DB \
		-c $TEMP_NSS_DB_PWD \
		-h $target_host \
		-p $sub_ca_http_port \
		-n \"$admin_cert_nickname\" \
		user-cert-add $test_agent_user --input $TEMP_NSS_DB/$ipa_cn\.pem > $TEMP_NSS_DB/cert-add.out" 0 "Import cert to $test_agent_user user"
	rlLog "Disable nonce"
	disable_ca_nonce $subca_instance_name
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-001: test is for requesting a ipa certificate"
	echo $TEMP_NSS_DB_PWD >> $TEMP_NSS_DB/certdb_pwd_file
	local request_type=pkcs10
	local request_key_type=rsa
	local request_key_size=2048
	local ipa_profile="caIPAserviceCert"
	local sslget_output=$TEMP_NSS_DB/sslget1.out
	rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa1-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa1-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa1-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa1-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
	local profile_request="/ca/ee/ca/profileSubmit"
	local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
	rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
	local serialNo=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
	local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
	local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
	rlLog "serialNo: $serialNo"
	rlLog "RequestID: $RequestId"
	if [ "$serialNo" == "" ]; then
		rlFail "Serial Number not found"
	else
		rlPass "Certificate request successfull approved"
	fi
	if [ "$RequestId" == "" ]; then

		rlFail "Requestid Number not found"
	else
		rlPass "Certificate Request successfull Submitted"
	fi
	rlPhaseEnd


	rlPhaseStartTest "ipa_legacy_test-002: This test is for requesting a ipa certificate when request signing cert is not provided."
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
	local encoded_request=""
	local sslget_output=$TEMP_NSS_DB/sslget2.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget with no cert request"
	local error=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Error")
	if [ "$error" == "Invalid Request" ]; then
		rlPass "Invalid Request"
	else
		rlFail "sslget failed with not a valid error"
	fi
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-003: This test is for requesting a ipa certificate when an invalid cert request is provided"
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
	local encoded_request="$rand"
	local sslget_output=$TEMP_NSS_DB/sslget3.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget with no cert request"
	local error=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Error")
	if [ "$error" == "Invalid Request" ]; then
		rlPass "sslget failed with eror: $error"
	else
		rlFail "sslget failed with not a valid error"
	fi
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-004: This test is for requesting a ipa certificate when request type is crmf"
        local ipa_cn="IPA-Subsystem-Certificate"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local ipa_profile="caIPAserviceCert"
        local sslget_output=$TEMP_NSS_DB/sslget4.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa2-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa2-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa2-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa2-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=crmf&xmlOutput=true&cert_request="
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serialNo=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-005: This test is for requesting a ipa certificate when request type is not provided"
        local ipa_cn="IPA-Subsystem-Certificate"
        local request_type=crmf
        local request_key_type=rsa
        local request_key_size=2048
        local ipa_profile="caIPAserviceCert"
        local sslget_output=$TEMP_NSS_DB/sslget5.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa3-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa3-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa3-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa3-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=&xmlOutput=true&cert_request="
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
	local error=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Error")
        if [ "$error" == "Unknown Certificate Request Type " ]; then
                rlPass "ssl get failed with error: $error"
        else
                rlFail "sslget failed with not a valid error"
        fi
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-006: This test is for requesting a ipa certificate when xmloutput set to false"
        local ipa_cn="IPA-Subsystem-Certificate"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local ipa_profile="caIPAserviceCert"
        local sslget_output=$TEMP_NSS_DB/sslget6.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa4-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa4-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa4-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa4-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=false&cert_request="
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
	requestid=$(cat -v $sslget_output | grep requestList.requestId | awk -F\" '{print $2}')
	cert_b64=$(cat -v $sslget_output | grep outputList.outputVal | grep "BEGIN CERTIFICATE" | awk -F \" '{print $2}')
	if [ $requestid == "" ]; then
		rlFail "Request not submitted"
	else
		rlPass "Request successfull submitted, requestid: $requestid"
	fi
	if [ $cert_b64 == "" ]; then
		rlFail "Request not approved"
	else
		rlPass "Request approved Successfully"
	fi
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-007: This test is for requesting a ipa certificate when xmloutput does not have any value"
        local ipa_cn="IPA-Subsystem-Certificate"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local ipa_profile="caIPAserviceCert"
        local sslget_output=$TEMP_NSS_DB/sslget7.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa5-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa5-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa5-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa5-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=&cert_request="
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        requestid=$(cat -v $sslget_output | grep requestList.requestId | awk -F\" '{print $2}')
        cert_b64=$(cat -v $sslget_output | grep outputList.outputVal | grep "BEGIN CERTIFICATE" | awk -F \" '{print $2}')
        if [ $requestid == "" ]; then
                rlFail "Request not submitted"
        else
                rlPass "Request successfull submitted, requestid: $requestid"
        fi
        if [ $cert_b64 == "" ]; then
                rlFail "Request not approved"
        else
                rlPass "Request approved Successfully"
        fi
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-008: This test is to get certificate when serial number is provided"
        local ipa_cn="IPA-Subsystem-Certificate"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local ipa_profile="caIPAserviceCert"
        local sslget_output=$TEMP_NSS_DB/sslget8-0.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa6-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa6-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa6-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa6-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
	local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved, requestid: $RequestId"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
	local profile_request="/ca/ee/ca/displayBySerial"
	local request_info="serialNumber=0x$serial_number"
	local sslget_output=$TEMP_NSS_DB/sslget8-1.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
	rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	local base64=$(cat -v $sslget_output | grep header.certChainBase64 | awk -F \" '{print $2}')
	if [ $base64 == "" ]; then
		rlFail "sslget failed to get certificate details"
	else
		rlPass "sslget was successful in getting certificate details"
		rlLog "Certificate Base64: $base64"
	fi
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-009: This test is to get certificate when serial number provided does not exist in cs"
        local ipa_cn="IPA-Subsystem-Certificate"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local ipa_profile="caIPAserviceCert"
        local sslget_output=$TEMP_NSS_DB/sslget9-0.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa7-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa7-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa7-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa7-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved, requestid: $RequestId"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
	local serial_number=$RANDOM$RANDOM
        local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=0x$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget9-1.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.unexpectedError = \"Certificate serial number 0x$serial_number not found\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0010: This test is to get certificate when serial number is not provided"
	local serial_number=""
        local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget10.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Certificate Serial number is not set or invalid.\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0011: This test is to get certificate when certificate is not created through ipa."
	rlLog "Generate Cert approved by $admin_cert_nickname"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser"
        local usercn="fooUser"
        local phone="1234"
	local admin_out="$TmpDir/admin.out"
        local usermail="fooUser@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$TEMP_NSS_DB"
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"$usercn\" \
                subject_uid:$userid \
                subject_email:$usermail \
                subject_ou:IDM \
                subject_organization:RedHat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/user-request.pem \
                cert_subject_file:$TEMP_NSS_DB/user-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/user-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=$cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/user-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/user-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/user-encoded-request.pem)\" \
                    -k \"https://$target_host:$sub_ca_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/user-encoded-request.pem)\" \
                    -k \"https://$target_host:$sub_ca_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
        rlLog "Approve $request_id using $valid_agent_cert"
	local Second=`date +'%S' -d now`
        local Minute=`date +'%M' -d now`
        local Hour=`date +'%H' -d now`
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local Year=`date +'%Y' -d now`
        local start_year=$Year
        let end_year=$Year+1
        local end_day="1"
        local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
        local notAfter="$end_year-$Month-$end_day $Hour:$Minute:$Second"
        rlLog "curl --cacert $TEMP_NSS_DB/ca_cert.pem \
                    --dump-header $admin_out \
                     -E \"$admin_cert_nickname\":$TEMP_NSS_DB_PWD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$target_host:$sub_ca_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $TEMP_NSS_DB/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E \"$admin_cert_nickname\":$TEMP_NSS_DB_PWD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$target_host:$sub_ca_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget8-1.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        local base64=$(cat -v $sslget_output | grep header.certChainBase64 | awk -F \" '{print $2}')
        if [ $base64 == "" ]; then
                rlFail "sslget failed to get certificate details"
        else
                rlPass "sslget was successful in getting certificate details"
                rlLog "Certificate Base64: $base64"
        fi
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0012: This test is for get certificate request on a revoked ipa certificate"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget12-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa12-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa12-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa12-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa12-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serial_number" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
	rlLog "Revoke ipa certificate"
	local sslget_output=$TEMP_NSS_DB/sslget12-2.out
	local profile_request="/ca/agent/ca/doRevoke"
	local revocation_reason=0
	local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
	rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
	rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
	rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "header.error = null" "$sslget_output"
	rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
	local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=0x$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget12-3.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        local base64=$(cat -v $sslget_output | grep header.certChainBase64 | awk -F \" '{print $2}')
        if [ "$base64" == "" ]; then
                rlFail "sslget failed to get certificate details"
        else
                rlPass "sslget was successful in getting certificate details"
                rlLog "Certificate Base64: $base64"
        fi
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0013: This test is to check certificate request status"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget13-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa13-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa13-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa13-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa13-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
	local sslget_output=$TEMP_NSS_DB/sslget13-2.out
	local profile_request="/ca/ee/ca/checkRequest"
	local request_info="requestId=$RequestId"
	rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
	rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
	rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "header.requestId = \"$RequestId\"" "$sslget_output"
	rlAssertGrep "header.status = \"complete\"" "$sslget_output"
	rlAssertGrep "record.serialNumber=\"$serial_number\"" "$sslget_output"
	rlPhaseEnd


	rlPhaseStartTest "ipa_legacy_test-0014: This test is for check certificate status request on a revoked ipa certificate"
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget14-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa14-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa14-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa14-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa14-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serial_number" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget14-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=0
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=0x$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget14-3.out
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        local base64=$(cat -v $sslget_output | grep header.certChainBase64 | awk -F \" '{print $2}')
	if [ "$base64" == "" ]; then
                rlFail "sslget failed to get certificate details"
        else
                rlPass "sslget was successful in getting certificate details"
                rlLog "Certificate Base64: $base64"
        fi
	local sslget_output=$TEMP_NSS_DB/sslget14-4.out
        local profile_request="/ca/ee/ca/checkRequest"
        local request_info="requestId=$RequestId"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.requestId = \"$RequestId\"" "$sslget_output"
        rlAssertGrep "header.status = \"complete\"" "$sslget_output"
        rlAssertGrep "record.serialNumber=\"$serial_number\"" "$sslget_output"
	rlPhaseEnd


	rlPhaseStartTest "ipa_legacy_test-0015: This test is to check certificate request status when request id provided does not exist"
	local RequestId=999999999
	local sslget_output=$TEMP_NSS_DB/sslget15.out
        local profile_request="/ca/ee/ca/checkRequest"
        local request_info="requestId=$RequestId"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.unexpectedError = \"Request ID $RequestId was not found in the request queue.\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0016: This test is to check certificate request status when request id provided are junk characters"
        local RequestId="jëmbëdhãøàe-ré1ürkçå"
        local sslget_output=$TEMP_NSS_DB/sslget16.out
        local profile_request="/ca/ee/ca/checkRequest"
        local request_info="requestId=$RequestId"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Get details of request"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.unexpectedError = \"Invalid number format: $RequestId\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0016: This test is for revoking an ipa certificate with reason 0-unspecified"
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget16-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa16-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa16-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa16-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa16-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget16-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=0
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0017: This test is for revoking an ipa certificate with reason 1-Key compromise"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget17-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa17-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa17-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa17-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa17-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget17-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=1
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0018: This test is for revoking an ipa certificate with reason 2-ca compromise"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget18-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa18-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa18-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa18-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa18-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget18-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=2
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0019: This test is for revoking an ipa certificate with reason 3-affiliation changed"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget19-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa19-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa19-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa19-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa19-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget19-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=3
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0020: This test is for revoking an ipa certificate with reason 4-superseded."
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget20-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa20-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa20-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa20-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa20-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget20-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=4
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0021: This test is for revoking an ipa certificate with reason 5-cessation of operation"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget21-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa21-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa21-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa21-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa21-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget21-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=5
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0022: This test is for revoking an ipa certificate with reason 6-certificate hold"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget22-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa22-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa22-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa22-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa22-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget22-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=6
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlPhaseEnd


	rlPhaseStartTest "ipa_legacy_test-0023: This test is for revoking an ipa certificate when serial number does not exist in cs db"
	local serial_number="0xEEEEEEEEE"
	local sslget_output=$TEMP_NSS_DB/sslget23.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=0
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Attempt to revoke non-existent certificate(s).\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0024: This test is for revoking an ipa certificate when serial number is not provided"
	local serial_number=""
        local sslget_output=$TEMP_NSS_DB/sslget24.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=0
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Attempt to revoke non-existent certificate(s).\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0025: This test is for revoking an ipa certificate when serial number has junk characters"
        local serial_number="jëmbëdhãøàe-ré1ürkçå"
        local sslget_output=$TEMP_NSS_DB/sslget25.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=0
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Attempt to revoke non-existent certificate(s).\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0026: This test is for revoking an ipa certificate with reason 0-unspecified"
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget26-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa26-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa26-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa26-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa26-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget26-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=""
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Invalid number format.\"" "$sslget_output"
        rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0027: This test is for revoke an ipa certificate with reason certificate hold and unrevoke the certificate."
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget27-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa27-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa27-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa27-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa27-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget27-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=6
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
	rlLog "Unrevoke $serial_number Certificate"
	local sslget_output=$TEMP_NSS_DB/sslget27-3.out
	local crlIssuingPoint="MasterCRL"
        local signatureAlgorithm="SHA512withRSA"
        local test_out=updatecrl.out
	local admin_out=$TEMP_NSS_DB/admin.out
        rlRun "export SSL_DIR=$TEMP_NSS_DB"
        rlLog "curl --cacert $TEMP_NSS_DB/ca_cert.pem --dump-header $admin_out -E \"$ipa_cn\":$TEMP_NSS_DB_PWD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$target_host:$sub_ca_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlRun "curl --cacert $TEMP_NSS_DB/ca_cert.pem --dump-header $admin_out -E \"$ipa_cn\":$TEMP_NSS_DB_PWD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$target_host:$sub_ca_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlUpdate = \"Scheduled\"" "$TmpDir/$test_out"
	local profile_request="/ca/agent/ca/doUnrevoke"
	local request_info="serialNumber=0x$serial_number"
	rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
	rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "header.unrevoked = \"yes\"" "$sslget_output"
	rlAssertGrep "header.serialNumber = \"$0xserial_number\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0028: This test is for revoked cert off hold for an ipa certificate when revoked reason is not 6-certificateHold"
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=2048
        local sslget_output=$TEMP_NSS_DB/sslget28-1.out
        rlLog "Create a new certificate request of type $request_type with key size $request_key_size"
        rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:\"IPA-Cert-$RANDOM\" \
                subject_uid: \
                subject_email: \
                subject_ou:pki-ipa \
                subject_organization:redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/freeipa28-request.pem \
                cert_subject_file:$TEMP_NSS_DB/freeipa28-subject.out" 0 "Create $request_type request"
        local cert_requestdn=$(cat $TEMP_NSS_DB/freeipa28-subject.out | grep Request_DN | cut -d ":" -f2)
        local encoded_request=$(cat $TEMP_NSS_DB/freeipa28-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());')
        local profile_request="/ca/ee/ca/profileSubmit"
        local request_info="profileId=caIPAserviceCert&cert_request_type=pkcs10&xmlOutput=true&cert_request="
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info$encoded_request\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Submit request using sslget for approval"
        local serial_number=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/serialno")
        local RequestId=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/Id")
        local base64=$(cat $sslget_output | grep ^"<?xml" | xmlstarlet sel -t -v "/XMLResponse/Requests/Request/b64")
        rlLog "serialNo: $serialNo"
        rlLog "RequestID: $RequestId"
        if [ "$serialNo" == "" ]; then
                rlFail "Serial Number not found"
        else
                rlPass "Certificate request successfull approved"
        fi
        if [ "$RequestId" == "" ]; then

                rlFail "Requestid Number not found"
        else
                rlPass "Certificate Request successfull Submitted"
        fi
        rlLog "Revoke ipa certificate"
        local sslget_output=$TEMP_NSS_DB/sslget28-2.out
        local profile_request="/ca/agent/ca/doRevoke"
        local revocation_reason=0
        local request_info="op=revoke&revocationReason=$revocation_reason&revokeAll=(certRecordId%3D0x$serial_number)&totalRecordCount=1"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Revoke Certificate $serial_number"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.error = null" "$sslget_output"
        rlAssertGrep "header.revoked = \"yes\"" "$sslget_output"
        rlLog "Unrevoke $serial_number Certificate"
        local sslget_output=$TEMP_NSS_DB/sslget28-3.out
        local profile_request="/ca/agent/ca/doUnrevoke"
        local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "header.unrevoked = \"no\"" "$sslget_output"
	rlAssertGrep "header.error = \"One or more certificates could not be unrevoked\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0029: This test is for revoked cert off hold for an ipa certificate when serial number provided does not exist in cs db."
        rlLog "Unrevoke Certificate which does not exist"
	local serial_number="0xEEEEEEE"
        local sslget_output=$TEMP_NSS_DB/sslget29.out
        local profile_request="/ca/agent/ca/doUnrevoke"
        local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Record not found\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0030: This test is for revoked cert off hold for an ipa certificate when serial number is not provided."
	local serial_number=""
        local sslget_output=$TEMP_NSS_DB/sslget30.out
        local profile_request="/ca/agent/ca/doUnrevoke"
        local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Invalid number format\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0031: This test is for revoked cert off hold for an ipa certificate when serial number is junk characters."
	local serial_number="jëmbëdhãøàe-ré1ürkçå"
        local sslget_output=$TEMP_NSS_DB/sslget31.out
        local profile_request="/ca/agent/ca/doUnrevoke"
        local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Invalid number format\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartTest "ipa_legacy_test-0032: This test is to get certificate when serial number is non existent - agent interface"
	local serial_number="0xEEFFDD"
	local profile_Request="/ca/agent/ca/displayBySerial"
	local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $TEMP_NSS_DB -w $TEMP_NSS_DB/certdb_pwd_file -n \"$ipa_cn\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$sub_ca_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
	rlAssertGrep "fixed.errorDetails = \"Record not found\"" "$sslget_output"
	rlPhaseEnd

	rlPhaseStartSetup "ipa_legacy_tests cleanup"
	rlLog "Destroy pki instance $subca_instance_name"
	rlRun "pkidestroy -s CA -i $subca_instance_name > $TmpDir/ca-uninstall.out 2>&1" 0
	rlAssertGrep "Uninstallation complete" "$TmpDir/ca-uninstall.out"
	rlLog "Remove DS instance"
	rlRun "remove-ds.pl -i slapd-$subca_instance_name > $TmpDir/dsuninstall.out 2>&1"
	rlAssertGrep "Instance slapd-$subca_instance_name removed" "$TmpDir/dsuninstall.out"
	rlPhaseEnd

	rlPhaseStartSetup "Deleting Temporary Directory"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
rhcs_install_ipaca()
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
        local admin_cert_nickname="PKI Administrator for example.org"
        local CA_ADMIN_PASSWORD=$(eval echo \$${CA_INST}\_ADMIN_PASSWORD)
        local CA_ADMIN_USER=$(eval echo \$${CA_INST}\_ADMIN_USER)
        local CA_SECURITY_DOMAIN_PASSWORD=$(eval echo \$${CA_INST}\_SECURITY_DOMAIN_PASSWORD)
        local CA_CLIENT_PKCS12_PASSWORD=$(eval echo \$${CA_INST}\_CLIENT_PKCS12_PASSWORD)
        local valid_admin_user_password=$CA_INST\_adminV_password

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
        exp_message2="example.org"
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
        echo -e "$CA_CLIENT_PKCS12_PASSWORD" > $SUBCA_WORK_DIR/pwfile
        rlRun "importP12FileNew $SUBCA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $SUBCA_CERTDB_DIR $CA_CLIENT_PKCS12_PASSWORD $admin_cert_nickname"
        return 0
}
