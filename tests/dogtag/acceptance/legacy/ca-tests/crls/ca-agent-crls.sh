#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca_tests/crls/ca-agent-crls.sh
#   Description: CA Agent CRL tests
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

run_agent-ca-crls_tests()
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
        local valid_audit_cert=$CA_INST\_auditV
        local valid_operator_cert=$CA_INST\_operatorV
        local valid_admin_cert=$CA_INST\_adminV
	local cert_find_info="$TmpDir/cert_find_info"
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
	local SSL_DIR=$CERTDB_DIR
	local valid_admin_user=$CA_INST\_adminV
        local valid_admin_user_password=$CA_INST\_adminV_password

	rlPhaseStartTest "pki_ca_agent_display_crl_entire_crl-001:CA - Agent Interface - Display Master CRL with entire CRL display type"
	local test_out="$TmpDir/admin_out_displaycrl_entireCRL"
	header_001="$TmpDir/ca_crls_001.txt"
	crl_ip="MasterCRL"
	crl_display_type="entireCRL"
	rlLog "Display Master CRL with entire CRL display type"
	rlRun "export SSL_DIR=$CERTDB_DIR"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_001 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=$crl_ip&pageStart=1&crlDisplayType=$crl_display_type\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_001"
	rlAssertGrep "header.crlIssuingPoint = \"$crl_ip\"" "$test_out"
	rlAssertGrep "header.crlDisplayType = \"$crl_display_type\"" "$test_out"
	rlAssertGrep "Version:" "$test_out"
	rlAssertGrep "Signature Algorithm:" "$test_out"
	rlAssertGrep "Issuer:" "$test_out"
	rlAssertGrep "Signature:" "$test_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_agent_display_crl_cached_crl-002:CA - Agent Interface - Display a newly added CRL with cached CRL display type"
        local test_out="$TmpDir/admin_out_displaycrl_cachedCRL"
	header_002="$TmpDir/ca_crls_002.txt"
        crl_ip="testcrl"
        crl_display_type="cachedCRL"
	rlLog "Add a new CRL issuing point"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_002 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=crlIPs&RS_ID=$crl_ip&id=$crl_ip&description=$crl_ip&enable=true&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin > $test_out" 0 "Add crl issuing point"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_002"
        rlLog " Display a newly added CRL with cached CRL display type"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_002 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=$crl_ip&pageStart=1&crlDisplayType=$crl_display_type\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_002"
        rlAssertGrep "header.crlIssuingPoint = \"$crl_ip\"" "$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crl_display_type\"" "$test_out"
        rlAssertGrep "Signature Algorithm:" "$test_out"
        rlAssertGrep "Issuer:" "$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_agent_display_crl_crl_header-003:CA - Agent Interface - Display a CRL with CRL header display type"
        local test_out="$TmpDir/admin_out_displaycrl_CRLHeader"
	header_003="$TmpDir/ca_crls_003.txt"
        crl_display_type="crlHeader"
        rlLog " Display a CRL with CRL Header display type"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_003 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=$crl_ip&pageStart=1&crlDisplayType=$crl_display_type\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_003"
        rlAssertGrep "header.crlIssuingPoint = \"$crl_ip\"" "$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crl_display_type\"" "$test_out"
	rlAssertGrep "Version:" "$test_out"
        rlAssertGrep "Signature Algorithm:" "$test_out"
        rlAssertGrep "Issuer:" "$test_out"
        rlAssertGrep "Signature:" "$test_out"
        rlPhaseEnd
4
	rlPhaseStartTest "pki_ca_agent_display_crl_base64-004:CA - Agent Interface - Display a CRL with base64 encoded display type"
        local test_out="$TmpDir/admin_out_displaycrl_base64"
	header_004="$TmpDir/ca_crls_004.txt"
       crl_display_type="base64Encoded"
        rlLog " Display a CRL with base64 encoded display type"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_004 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=$crl_ip&pageStart=1&crlDisplayType=$crl_display_type\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_004"
        rlAssertGrep "header.crlIssuingPoint = \"$crl_ip\"" "$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crl_display_type\"" "$test_out"
	rlAssertGrep "BEGIN CERTIFICATE REVOCATION LIST" "$test_out"
	rlAssertGrep "END CERTIFICATE REVOCATION LIST" "$test_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_agent_update_crl-005:CA - Agent Interface - Update CRL"
        local test_out="$TmpDir/admin_out_updatecrl"
	header_005="$TmpDir/ca_crls_005.txt"
	local waitForUpdate="true"
	local signatureAlgorithm="SHA256withRSA"
	local crlNumber="1"
	local crl_display_type="entireCRL"
        rlLog " Display CRL and note the CRL number"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_005 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=$crl_ip&pageStart=1&crlDisplayType=$crl_display_type\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
	rlAssertGrep "header.crlNumber = \"$crlNumber\"" "$test_out"
	rlLog "Update CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_005 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"crlIssuingPoint=$crl_ip&waitForUpdate=$waitForUpdate&signatureAlgorithm=$signatureAlgorithm&\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
	crlNumber=$((crlNumber + 1))
	rlLog " Display CRL to verify the updated CRL number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_005 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=$crl_ip&pageStart=1&crlDisplayType=$crl_display_type\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "header.crlNumber = \"$crlNumber\"" "$test_out"

        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_005 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=crlIPs&RS_ID=$crl_ip&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $test_out" 0 "Delete crl issuing point"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_agent_update_ds-006:CA - Agent Interface - Update DS"
        local test_out="$TmpDir/admin_out_updateds"
	header_006="$TmpDir/ca_crls_006.txt"
	local dn_pattern="uid=\$subj.cn,ou=people,$(eval echo \$${CA_INST}_DB_SUFFIX)"
	local ldap_host=`hostname`
        local ldap_port=$(eval echo \$${CA_INST}_LDAP_PORT)
        local ldap_bind=$LDAP_ROOTDN
        local ldap_bind_pwd=$LDAP_ROOTDNPWD
        local ldap_secure="false"
        local ldap_prompt="CA LDAP Publishing"
        local ldap_authtype="BasicAuth"
        rlLog "Edit LDAP ca cert mapper"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RULENAME=LdapCaCertMap&createCAEntry=true&implName=LdapCaSimpleMap&dnPattern=$dn_pattern&RD_ID=LdapCaCertMap&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $test_out" 0 "Edit LdapCaCertMapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlLog "Edit LDAP user cert mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RULENAME=LdapUserCertMap&implName=LdapSimpleMap&dnPattern=$dn_pattern&RD_ID=LdapUserCertMap&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $test_out" 0 "Edit LdapUserCertMapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlLog "Edit LDAP crl mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RULENAME=LdapCrlMap&implName=LdapCaSimpleMap&dnPattern=$dn_pattern&RD_ID=LdapCrlMap&createCAEntry=true&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $test_out" 0 "Edit LdapCrlMapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"

	rlLog "Enable Publishing with Basic Auth"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_PROCESS&OP_SCOPE=ldap&RD_ID=RD_ID_CONFIG&publishingEnable=true&enable=true&ldapconn.host=$ldap_host&ldapconn.port=$ldap_port&ldapconn.secureConn=$ldap_secure&ldapauth.bindPWPrompt=$ldap_prompt&ldapauth.bindDN=$ldap_bind&directoryManagerPwd=$ldap_bind_pwd&ldapconn.version=3&ldapauth.authtype=$ldap_authtype&ldapauth.clientCertNickname=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $test_out" 0 "Enable Publishing with Basic Auth"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlLog "Save LDAP auth config"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=ldap&RD_ID=RD_ID_CONFIG&publishingEnable=true&enable=true&ldapconn.host=$ldap_host&ldapconn.port=$ldap_port&ldapconn.secureConn=$ldap_secure&ldapauth.bindPWPrompt=$ldap_prompt&ldapauth.bindDN=$ldap_bind&directoryManagerPwd=$ldap_bind_pwd&ldapconn.version=3&ldapauth.authtype=$ldap_authtype&ldapauth.clientCertNickname=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $test_out" 0 "Save Ldap auth config"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	
	rlLog "Generate a user cert and revoke the cert"
	rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Test User\" subject_uid:testuser subject_email:testuser@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$tmp_ca_host protocol: port:$target_unsecure_port cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$valid_agent_cert\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	rlLog "Display CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_006 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=MasterCRL&pageStart=1&crlDisplayType=entireCRL\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlAssertNotGrep "Serial Number: $valid_crmf_serialNumber" "$test_out"
	rlRun "pki -d $CERTDB_DIR/ \
                           -n \"$valid_agent_cert\" \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $tmp_ca_host \
                           -p $target_unsecure_port \
                            cert-revoke $valid_crmf_serialNumber --force"

	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_006 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"expiredTo=&updateCRL=yes&validFrom=&expiredFrom=&validTo=&revokedTo=&revokedFrom=&\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateDir > /tmp/updateds"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlLog "Update CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_006 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"crlIssuingPoint=MasterCRL&signatureAlgorithm=$signatureAlgorithm&\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/updateCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
		--dump-header  $header_006 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -d \"pageSize=50&crlIssuingPoint=MasterCRL&pageStart=1&crlDisplayType=entireCRL\"  \
                https://$tmp_ca_host:$target_secure_port/ca/agent/ca/displayCRL > $test_out"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	local STRIP_HEX=$(echo $valid_crmf_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
	valid_serial="0x$CONV_UPP_VAL"
	rlAssertGrep "Serial Number: $valid_serial" "$test_out"
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
