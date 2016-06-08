#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/subca_tests/subca-ad-authplugins.sh
#   Description: SUBCA Admin Auth Plugin tests
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

run_admin-subca-authplugin_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for ca-admin-acl tests
        rlPhaseStartSetup "pki_console_authplugin Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
	if [ $cs_Role="MASTER" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
        local target_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local tmp_ca_admin=$SUBCA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_admin_cert=$SUBCA_INST\_adminV
	local valid_admin_user=$SUBCA_INST\_adminV
        local valid_admin_user_password=$SUBCA_INST\_adminV_password

	rlPhaseStartTest "pki_console_authplugin_subca-001:SUBCA - Admin Interface - list all auth plugin"
	header_001="$TmpDir/subca_auth_001.txt"
	rlLog "List all auth plugins"
	local authlist=(raCertAuth AgentCertAuth SSLclientCertAuth flatFileAuth TokenAuth challengeAuthMgr certUserDBAuthMgr CMCAuth sslClientCertAuthMgr passwdUserDBAuthMgr)
	admin_out="$TmpDir/admin_out_listauthplugin"
	rlLog "curl --capath "$CERTDB_DIR" \
                --dump-header $header_001 \
                --basic --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
	rlRun "curl --capath "$CERTDB_DIR" \
		--dump-header $header_001 \
		--basic --user "$valid_admin_user:$valid_admin_user_password" \
		-d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "List all auth plugins"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_001"
	for i in ${authlist[@]}; do
		rlAssertGrep "$i" "$admin_out"	
	done
	rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-002:SUBCA - Admin Interface - view auth plugin"
        local plugin_id="AgentCertAuth"
	header_002="$TmpDir/subca_auth_002.txt"
	admin_out="$TmpDir/admin_out_viewauthplugin"
        rlLog "View auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_002 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_002 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "View auth plugin $plugin_id"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_002"
	rlAssertGrep "implName=AgentCertAuth" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-003:SUBCA - Admin Interface - Add agentcertauth auth plugin"
        local plugin_id="plug$RANDOM"
	header_003="$TmpDir/ca_auth_003.txt"
	admin_out="$TmpDir/admin_out_addagentcertplug"
        rlLog "Add auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_003 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=AgentCertAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_003 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=AgentCertAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Add auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_003"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_003 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "List all auth plugins"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_003"
	rlAssertGrep "$plugin_id" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-004:SUBCA - Admin Interface - Add cmccertauth plugin"
        local plugin_id="plug$RANDOM"
	header_004="$TmpDir/subca_auth_004.txt"
	admin_out="$TmpDir/admin_out_addcmccertauth"
        rlLog "Add auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_004 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=CMCAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_004 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=CMCAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Add cmccert auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_004"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_004 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "List all auth plugins"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_004"
        rlAssertGrep "$plugin_id" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-005:SUBCA - Admin Interface - Add uidpwddirauth plugin"
	header_005="$TmpDir/ca_auth_005.txt"
        local plugin_id="plug$RANDOM"
	local OP_TYPE="OP_ADD"
	local LDAP_HOST=`hostname`
	local LDAP_DN_PATTERN="UID=test,OU=people,O=netscapecertificateserver"
	local LDAP_STR_ATTR="mail"
	local LDAP_MAX_CONNS="10"
	local LDAP_MIN_CONNS="2"
	local LDAP_SEC_CONN="false"
	local LDAP_BYTE_ATTR="mail"
	admin_out="$TmpDir/admin_out_adduidpwddirauth"
        rlLog "Add uidpwddirauth auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_005 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_005 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Add uidpwddirauth auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_005 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_005 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "List all auth plugins"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "$plugin_id" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-006:SUBCA - Admin Interface - edit uidpwddirauth plugin"
	local OP_TYPE="OP_MODIFY"
	header_006="$TmpDir/subca_auth_006.txt"
	local LDAP_BYTE_ATTR="uid"
	admin_out="$TmpDir/admin_out_edituidpwddirauth"
        rlLog "Add auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_006 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Edit uidpwddirauth auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_006 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Verify uidpwddirauth auth plugin $plugin_id modification"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlAssertGrep "ldapByteAttributes=$LDAP_BYTE_ATTR" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-007:SUBCA - Admin Interface - Add uidpwdpindirauth plugin"
	header_007="$TmpDir/subca_auth_007.txt"
        local plugin_id="plug$RANDOM"
        local OP_TYPE="OP_ADD"
	local LDAP_BYTE_ATTR="mail"
	local LDAP_PIN_ATTR="pin"
	admin_out="$TmpDir/admin_out_adduidpwdpinddirauth"
        rlLog "Add uidpwdpindirauth auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_007 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdPinDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&pinAttr=$LDAP_PIN_ATTR&ldap.ldapauth.clientCertNickname=&ldap.ldapauth.bindDN=$LDAP_ROOTDN&removePin=false&ldap.ldapauth.authtype=BasicAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdPinDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&pinAttr=$LDAP_PIN_ATTR&ldap.ldapauth.clientCertNickname=&ldap.ldapauth.bindDN=$LDAP_ROOTDN&removePin=false&ldap.ldapauth.authtype=BasicAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Add uidpwdpindirauth auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_007 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "List all auth plugins"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
        rlAssertGrep "$plugin_id" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-008:SUBCA - Admin Interface - edit uidpwdpindirauth plugin"
	header_008="$TmpDir/subca_auth_008.txt"
        local OP_TYPE="OP_MODIFY"
	local LDAP_BYTE_ATTR="uid"
	admin_out="$TmpDir/admin_out_edituidpwdpindirauth"
        rlLog "Add auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_008 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdPinDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&pinAttr=$LDAP_PIN_ATTR&ldap.ldapauth.clientCertNickname=&ldap.ldapauth.bindDN=$LDAP_ROOTDN&removePin=false&ldap.ldapauth.authtype=BasicAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_008 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdPinDirAuth&RULENAME=$plugin_id&ldap.ldapconn.host=$LDAP_HOST&dnpattern=$LDAP_DN_PATTERN&ldapStringAttributes=$LDAP_STR_ATTR&ldap.ldapconn.version=3&ldap.ldapconn.port=$ROOTCA_LDAP_PORT&ldap.maxConns=$LDAP_MAX_CONNS&ldap.basedn=$ROOTCA_DB_SUFFIX&ldap.minConns=$LDAP_MIN_CONNS&ldap.ldapconn.secureConn=$LDAP_SEC_CONN&ldapByteAttributes=$LDAP_BYTE_ATTR&pinAttr=$LDAP_PIN_ATTR&ldap.ldapauth.clientCertNickname=&ldap.ldapauth.bindDN=$LDAP_ROOTDN&removePin=false&ldap.ldapauth.authtype=BasicAuth&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Edit uidpwdpindirauth auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_008 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_008 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Verify UidPwdPinDirAuth auth plugin $plugin_id modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlAssertGrep "ldapByteAttributes=$LDAP_BYTE_ATTR" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_authplugin_subca-011:SUBCA - Admin Interface - Delete auth plugin"
        local OP_TYPE="OP_DELETE"
	header_011="$TmpDir/subca_auth_011.txt"
	admin_out="$TmpDir/admin_out_deleteauthplugin"
        rlLog "Delete auth plugin $plugin_id"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_011 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_011 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=$OP_TYPE&OP_SCOPE=instance&RS_ID=$plugin_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "Delete auth plugin $plugin_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
	rlLog "curl --capath "$CERTDB_DIR" --basic \
                --dump-header  $header_011 \
                --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_011 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=instance&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/auths >> $admin_out" 0 "List all auth plugins"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlAssertNotGrep "$plugin_id" "$admin_out"
        rlPhaseEnd

	rlPhaseStartSetup "pki_console_acl-cleanup"
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
