#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca_tests/ocsp/ca-ee-ocsp.sh
#   Description: CA Admin ee ocsp tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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
. /opt/rhqa_pki/pki-auth-plugin-lib.sh

run_ca-ee-ocsp_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for ca-agent-crls tests
        rlPhaseStartSetup "pki_console_internaldb Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
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
        local valid_admin_cert=$CA_INST\_adminV
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local cert_info="$TmpDir/cert_info"
	local SSL_DIR=$CERTDB_DIR
	local valid_admin_user=$CA_INST\_adminV
        local valid_admin_user_password=$CA_INST\_adminV_password

	rlPhaseStartTest "pki_ca_ee_ocsp_verify_good_cert-001:CA - EE Interface - Verify ocsp status of good certificate"
	local test_out="$TmpDir/admin_out_good_cert"
	local ocspRequest_out="$TmpDir/ocspRequest_out"
	rlLog "Verify ocsp status of good certificate"
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlLog "Generate a user cert"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Test User\" subject_uid:testuser subject_email:testuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$tmp_ca_host protocol: port:$target_unsecure_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$valid_agent_cert\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
	rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
	rlLog "Executing java -cp"
	rlLog "java -cp $CLASSPATH ca_ee_ocspRequest ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_unsecure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $valid_decimal_crmf_serialNumber -debug true > $test_out 2>&1"
	rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_unsecure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $valid_decimal_crmf_serialNumber -debug true > $test_out 2>&1"
	rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$test_out"
	rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$test_out"
	rlAssertGrep "CertStatus=Good" "$test_out"
	rlAssertGrep "SerialNumber=$valid_decimal_crmf_serialNumber" "$test_out"
	rlAssertGrep "SUCCESS" "$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_ee_ocsp_verify_revoked_cert-002:CA - EE Interface - Verify ocsp status of revoked certificate"
        local test_out="$TmpDir/admin_out_revoked_cert"
        rlLog "Verify ocsp status of revoked certificate"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Generate a user cert and revoke the cert"
        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Test User\" subject_uid:testuser subject_email:testuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$tmp_ca_host protocol: port:$target_unsecure_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$valid_agent_cert\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	rlRun "pki -d $CERTDB_DIR/ \
                           -n \"$valid_agent_cert\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $tmp_ca_host \
                           -p $target_unsecure_port \
                            cert-revoke $valid_crmf_serialNumber --force"
        rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_unsecure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $valid_decimal_crmf_serialNumber -debug true > $test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_unsecure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $valid_decimal_crmf_serialNumber -debug true > $test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$test_out"
        rlAssertGrep "CertStatus=Revoked" "$test_out"
        rlAssertGrep "SerialNumber=$valid_decimal_crmf_serialNumber" "$test_out"
        rlAssertGrep "SUCCESS" "$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_ee_ocsp_verify_unknown_cert-003:CA - EE Interface - Verify ocsp status of unknown certificate"
        local test_out="$TmpDir/admin_out_unknown_cert"
	local cert_show_out="$TmpDir/cert_show_out"
        rlLog "Verify ocsp status of unknown certificate"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
	while true
	do
		invalid_serial_number=75
		rlRun "pki -h $tmp_ca_host -p $target_unsecure_port cert-show $invalid_serial_number > $cert_show_out 2>&1" 0,255
		RETVAL=$?
		if [ $RETVAL -eq 255 ]; then
			break
		fi
		invalid_serial_number=$((invalid_serial_number+1))
	done
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_unsecure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $invalid_serial_number -debug true > $test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_unsecure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $invalid_serial_number -debug true > $test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$test_out"
        rlAssertGrep "CertStatus=Unknown" "$test_out"
	rlAssertGrep "SerialNumber=$invalid_serial_number" "$test_out"
	rlAssertGrep "SUCCESS" "$test_out"
        rlPhaseEnd

	rlPhaseStartSetup "pki_console_crlip_cleanup"
	#Delete temporary directory
	rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}

process_curl_output()
{
	output_file=$1
	sed -i "s/\&/\n&/g" $output_file
        sed -i "s/+//g"  $output_file
        sed -i "s/^&//g" $output_file
        sed -i "s/%3A/":"/g" $output_file
        sed -i "s/%3B/":"/g" $output_file
}
