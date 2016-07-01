#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/subca_tests/publishing/subca-ad-publishing.sh
#   Description: SUBCA publishing tests
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

run_admin-subca-publishing_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for ca-admin-internaldb tests
        rlPhaseStartSetup "pki_console_internaldb Temporary Directory"
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
	local ldap_host=`hostname`
        local ldap_port=$(eval echo \$${SUBCA_INST}_LDAP_PORT)
        local ldap_bind=$(eval echo \$${SUBCA_INST}_LDAP_ROOTDN)
	local ldap_bind_pwd=$(eval echo \$${SUBCA_INST}_LDAP_ROOTDNPWD)
	local ldap_secure="false"
	local ldap_prompt="CA LDAP Publishing"
	local ldap_authtype="BasicAuth"
	local valid_admin_user=$SUBCA_INST\_adminV
        local valid_admin_user_password=$SUBCA_INST\_adminV_password

	rlPhaseStartTest "pki_console_enable_publishing_subca-001:SUBCA - Admin Interface - Enable Publishing"
	header_001="$TmpDir/subca_pub_001.txt"
	local admin_out="$TmpDir/admin_out_enablepub"
	rlLog "Enable Publishing"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_001 \
		--user "$valid_admin_user:$valid_admin_user_password" \
		-d \"OP_TYPE=OP_PROCESS&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&publishingEnable=true&enable=true&ldapconn.host=$ldap_host&ldapconn.port=$ldap_port&ldapConn.secureConn=$ldap_secure&ldapauth.bindPWPrompt=$ldap_prompt&ldapauth.bindDN=$ldap_bind&directoryManagerPwd=$ldap_bind_pwd&ldapconn.version=3&ldapauth.authtype=$ldap_authtype&ldapauth.clientCertNickname=&\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Enable Publishing"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_001"
	rlAssertGrep "Success" "$admin_out"
	rlAssertNotGrep "Failure" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_read_publishing_config_subca-002:SUBCA - Admin Interface - Read Publishing config"
	header_002="$TmpDir/subca_pub_002.txt"
        local admin_out="$TmpDir/admin_out_readpubconf"
        rlLog "Read Publishing Config"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_002 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&publishingEnable=&enable=&ldapconn.host=&ldapconn.port=&ldapConn.secureConn=&ldapauth.bindPWPrompt=&ldapauth.bindDN=&directoryManagerPwd=&ldapconn.version=&ldapauth.authtype=&ldapauth.clientCertNickname=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read Publishing Config"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_002"
	ldapbindpromptout=$(echo $ldap_prompt | tr -d ' ')
	rlAssertGrep "ldapconn.host=$ldap_host" "$admin_out"
	rlAssertGrep "ldapconn.port=$ldap_port" "$admin_out"
	rlAssertGrep "ldapConn.secureConn=$ldap_secure" "$admin_out"
	rlAssertGrep "ldapauth.bindPWPrompt=$ldapbindpromptout" "$admin_out"
	rlAssertGrep "ldapauth.bindDN=cn%3DDSManager" "$admin_out"
	rlAssertGrep "directoryManagerPwd=" "$admin_out"
	rlAssertGrep "ldapconn.version=3" "$admin_out"
	rlAssertGrep "ldapauth.authtype=$ldap_authtype" "$admin_out"
	rlAssertGrep "ldapauth.clientCertNickname=" "$admin_out"
	rlAssertGrep "publishingEnable=true" "$admin_out"
	rlAssertGrep "enable=true" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_list_all_mappers_subca-003:SUBCA - Admin Interface - List all mappers"
	header_003="$TmpDir/subca_pub_003.txt"
        local admin_out="$TmpDir/admin_out_listmappers"
        rlLog "List all mappers"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_003 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=mapperRules&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "List all mappers"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_003"
	rlAssertGrep "LdapCaCertMap=LdapCaSimpleMap:visible" "$admin_out"
	rlAssertGrep "LdapUserCertMap=LdapSimpleMap:visible" "$admin_out"
	rlAssertGrep "NoMap=NoMap:visible" "$admin_out"
	rlAssertGrep "LdapCrlMap=LdapCaSimpleMap:visible" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_list_all_mapper_plugins_subca-004:SUBCA - Admin Interface - List all mapper plugins"
        local admin_out="$TmpDir/admin_out_listmapperplugin"
	header_004="$TmpDir/subca_pub_004.txt"
        rlLog "List all mapper plugin"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_004 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=mapperImpls&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "List all mapper plugins"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_004"
	rlAssertGrep "LdapEnhancedMap=com.netscape.cms.publish.mappers.LdapEnhancedMap%2CLdapEnhancedMap" "$admin_out"
	rlAssertGrep "LdapSubjAttrMap=com.netscape.cms.publish.mappers.LdapCertSubjMap%2CLdapCertSubjMap" "$admin_out"
	rlAssertGrep "NoMap=com.netscape.cms.publish.mappers.NoMap%2CNoMap" "$admin_out"
	rlAssertGrep "LdapSimpleMap=com.netscape.cms.publish.mappers.LdapSimpleMap%2CLdapSimpleMap" "$admin_out"
	rlAssertGrep "LdapCaSimpleMap=com.netscape.cms.publish.mappers.LdapCaSimpleMap%2CLdapCaSimpleMap" "$admin_out"
	rlAssertGrep "LdapDNExactMap=com.netscape.cms.publish.mappers.LdapCertExactMap%2CLdapCertExactMap" "$admin_out"
	rlAssertGrep "LdapDNCompsMap=com.netscape.cms.publish.mappers.LdapCertCompsMap%2CLdapCertCompsMap" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_read_mapper_rule_subca-005:SUBCA - Admin Interface - Read a mapper rule"
        local admin_out="$TmpDir/admin_out_readmaprule"
	header_005="$TmpDir/subca_pub_005.txt"
	searchrule="LdapUserCertMap"
        rlLog "Read a mapper rule"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_005 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$searchrule&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
	rlAssertGrep "implName=LdapSimpleMap" "$admin_out"
	rlAssertGrep "dnPattern=" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_mapper_subca-006:SUBCA - Admin Interface - Add CA ldap mapper"
        local admin_out="$TmpDir/admin_out_addmapper"
	header_006="$TmpDir/subca_pub_006.txt"
        mapper_id="pub07"
 	dn_pattern="uid=\$req.HTTP_PARAMS.uid,ou=\$subj.ou,o=\$subj.o"
	create_v2_ca_entry="false"
	create_ca_entry="true"
	mapper="LdapCaSimpleMap"
        rlLog "Add a ldap mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=LdapCaSimpleMap&dnPattern=$dn_pattern&CAEntryV2=$create_v2_ca_entry&createCAEntry=$create_ca_entry&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add a ldap mapper"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" \
		--dump-header  $header_006 \
		--basic --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlAssertGrep "implName=$mapper" "$admin_out"
	dnpattern1=$(echo $dn_pattern | sed -e 's/=/%3D/g' -e 's/,/%2C/g' -e 's/$req//g' -e 's/$subj//g')
	rlAssertGrep "dnPattern=$dnpattern1" "$admin_out"
	rlAssertGrep "createCAEntry=$create_ca_entry" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_ldap_mapper_subca-007:SUBCA - Admin Interface - Edit CA ldap mapper"
        local admin_out="$TmpDir/admin_out_editmapper"
	header_007="$TmpDir/subca_pub_007.txt"
        dn_pattern="uid=\$req.HTTP_PARAMS.uid,ou=\$subj.ou,o=netscapecertificateserver"
        rlLog "Edit a ldap mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=LdapCaSimpleMap&dnPattern=$dn_pattern&CAEntryV2=$create_v2_ca_entry&createCAEntry=$create_ca_entry&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Edit a ldap mapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlAssertGrep "netscapecertificateserver" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete mapper rule $mapper_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_dn_comps_mapper_subca-008:SUBCA - Admin Interface - Add ldap dn comps mapper"
        local admin_out="$TmpDir/admin_out_addldapdncomps"
	header_008="$TmpDir/subca_pub_008.txt"
        mapper_id="pub09"
	filter_comps="mail"
	dn_comps="uid"
	base_dn="o=redhat-ldapdncompsmap"
        mapper="LdapDNCompsMap"
        rlLog "Add ldap dn comps mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_008 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&filterComps=$filter_comps&dnComps=$dn_comps&baseDN=$base_dn&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap dn comps mapper"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
	rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_008 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
	rlAssertGrep "implName=$mapper" "$admin_out"
	basedn1=$(echo $base_dn | sed 's/=/%3D/g')
	rlAssertGrep "baseDN=$basedn1" "$admin_out"
	rlAssertGrep "dnComps=$dn_comps" "$admin_out"
	rlAssertGrep "filterComps=$filter_comps" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_ldap_dn_comps_mapper_subca-009:SUBCA - Admin Interface - Edit ldap dn comps mapper"
        local admin_out="$TmpDir/admin_out_editldapdncomps"
	header_009="$TmpDir/subca_pub_009.txt"
        base_dn="o=redhat-ldapdncompsmap-edit"
        rlLog "Edit ldap dn comps mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_009 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&filterComps=$filter_comps&dnComps=$dn_comps&baseDN=$base_dn&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap dn comps mapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_009 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "redhat-ldapdncompsmap-edit" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_009 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete mapper rule $mapper_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_dn_exact_mapper_subca-010:SUBCA - Admin Interface - Add ldap dn exact mapper"
        local admin_out="$TmpDir/admin_out_addldapdnexact"
	header_010="$TmpDir/subca_pub_010.txt"
        mapper_id="pub11"
        mapper="LdapDNExactMap"
        rlLog "Add ldap dn exact mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_010 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap dn exact mapper"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_010 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
	rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_010 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete mapper rule $mapper_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_enhanced_mapper_subca-011:SUBCA - Admin Interface - Add ldap enhanced mapper"
        local admin_out="$TmpDir/admin_out_addldapenhanced"
	header_011="$TmpDir/subca_pub_011.txt"
        mapper_id="pub12"
        mapper="LdapEnhancedMap"
	dn_pattern="uid=\$req.HTTP_PARAMS.uid,ou=\$subj.ou,o=netscapecertificateserver"
	attr_pattern="\$req.HTTP_PARAMS.csrRequestorEmail"
	attr_num="1"
	create_entry="true"
	attr_name="mail"
        rlLog "Add ldap enhanced mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_011 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&dnPattern=$dn_pattern&attrPattern0=$attr_pattern&attrNum=$attr_num&createEntry=$create_entry&attrName0=$attr_name&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap enhanced mapper"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_011 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
	rlAssertGrep "implName=$mapper" "$admin_out"
	dnpattern1=$(echo $dn_pattern | sed -e 's/=/%3D/g' -e 's/,/%2C/g' -e 's/$req//g' -e 's/$subj//g')
	rlAssertGrep "dnPattern=$dnpattern1" "$admin_out"
	rlAssertGrep "createEntry=$create_entry" "$admin_out"
	rlAssertGrep "attrNum=$attr_num" "$admin_out"
	rlAssertGrep "attrName0=$attr_name" "$admin_out"
	attrpattern1=$(echo $attr_pattern | sed 's/$req//g')
	rlAssertGrep "attrPattern0=$attrpattern1" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_ldap_enhanced_mapper_subca-012:SUBCA - Admin Interface - Edit ldap enhanced mapper"
        local admin_out="$TmpDir/admin_out_editldapenhanced"
	header_012="$TmpDir/subca_pub_012.txt"
        dn_pattern="uid=\$req.HTTP_PARAMS.uid,ou=\$subj.ou,o=netscapecertificateserver-e"
        rlLog "Edit ldap enhanced mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_012 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&dnPattern=$dn_pattern&attrPattern0=$attr_pattern&attrNum=$attr_num&createEntry=$create_entry&attrName0=$attrName&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Edit ldap enhanced mapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_012 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlAssertGrep "netscapecertificateserver-e" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_012 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete mapper rule $mapper_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_add_ldap_simple_mapper_subca-013:SUBCA - Admin Interface - Add ldap simple mapper"
	header_013="$TmpDir/subca_pub_013.txt"
        local admin_out="$TmpDir/admin_out_addldapsimple"
        mapper_id="pub14"
        mapper="LdapSimpleMap"
        dn_pattern="uid=\$req.HTTP_PARAMS.uid,ou=\$subj.ou,o=netscapecertificateserver"
        rlLog "Add ldap simple mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_013 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&dnPattern=$dn_pattern&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap simple mapper"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_013 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
	rlAssertGrep "implName=$mapper" "$admin_out"
	dnpattern1=$(echo $dn_pattern | sed -e 's/=/%3D/g' -e 's/,/%2C/g' -e 's/$req//g' -e 's/$subj//g')
	rlAssertGrep "dnPattern=$dnpattern1" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_ldap_simple_mapper_subca-014:SUBCA - Admin Interface - Edit ldap simple mapper"
        local admin_out="$TmpDir/admin_out_editldapsimple"
	header_014="$TmpDir/subca_pub_014.txt"
        mapper_id="pub14"
        dn_pattern="uid=\$req.HTTP_PARAMS.uid,ou=\$subj.ou,o=netscapecertificateserver-e"
        rlLog "Edit ldap simple mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_014 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&dnPattern=$dn_pattern&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Edit ldap simple mapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_014"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_014 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_014"
        rlAssertGrep "netscapecertificateserver-e" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_014 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete mapper rule $mapper_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_014"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_add_ldap_subj_attr_mapper_subca-015:SUBCA - Admin Interface - Add ldap subj attr mapper"
        local admin_out="$TmpDir/admin_out_addldapsubjattr"
	header_015="$TmpDir/subca_pub_015.txt"
        mapper_id="pub16"
        mapper="LdapSubjAttrMap"
        search_base="o=redhat"
	cert_subj_name_attr="certSubjectName"
        rlLog "Add ldap subj attr mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_015 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&searchBase=$search_base&certSubjNameAttr=$cert_subj_name_attr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap subj attr mapper"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_015"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_015 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_015"
	rlAssertGrep "implName=$mapper" "$admin_out"
	rlAssertGrep "certSubjNameAttr=$cert_subj_name_attr" "$admin_out"
	searchbase1=$(echo $search_base | sed 's/=/%3D/g')
	rlAssertGrep "searchBase=$searchbase1" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_ldap_subj_attr_mapper_subca-016:SUBCA - Admin Interface - Edit ldap subj attr mapper"
        local admin_out="$TmpDir/admin_out_editldapsubjattr"
	header_016="$TmpDir/subca_pub_016.txt"
        search_base="o=redhat-subjattr"
        rlLog "Edit ldap subj attr mapper"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_016 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&searchBase=$search_base&certSubjNameAttr=$cert_subj_name_attr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Edit ldap subj attr mapper"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_016"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_016 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_016"
        rlAssertGrep "redhat-subjattr" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_016 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete mapper rule $mapper_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_016"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_no_map_subca-017:SUBCA - Admin Interface - Add ldap no map"
        local admin_out="$TmpDir/admin_out_addldapnomap"
	header_017="$TmpDir/subca_pub_017.txt"
        mapper_id="pub18"
        mapper="NoMap"
        rlLog "Add ldap no map"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_017 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=mapperRules&RS_ID=$mapper_id&RULENAME=$mapper_id&implName=$mapper&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap no map"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_017"
	rlAssertGrep "implName=$mapper" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_read_ldap_no_map_subca-018:SUBCA - Admin Interface - Read ldap no map"
        local admin_out="$TmpDir/admin_out_readldapnomap"
	header_018="$TmpDir/subca_pub_018.txt"
        rlLog "Add ldap no map"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_018 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read ldap no map"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_018"
	rlAssertGrep "implName=$mapper" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_delete_ldap_no_map_subca-019:SUBCA - Admin Interface - Delete ldap no map"
        local admin_out="$TmpDir/admin_out_deleteldapnomap"
	header_019="$TmpDir/subca_pub_019.txt"
        rlLog "Delete ldap no map"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_019 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Delete ldap no map"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_019"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_019 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=mapperRules&RS_ID=$mapper_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read ldap no map"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_019"
	rlAssertNotGrep "$mapper" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_file_based_publisher_subca-020:SUBCA - Admin Interface - Add file based publisher"
        local admin_out="$TmpDir/admin_out_addfilebasedpub"
	header_020="$TmpDir/subca_pub_020.txt"
        pub_id="pub24"
        mapper="FileBasedPublisher"
	file_b64="true"
	file_dir="/tmp"
	file_der="true"
        rlLog "Add file based publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_020 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&Filename.b64=$file_b64&directory=$file_dir&Filename.der=$file_der&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add file based publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_020"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_020 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_020"
	rlAssertGrep "implName=$mapper" "$admin_out"
	filedir1=$(echo $file_dir | sed 's/\//%2F/g')
	rlAssertGrep "directory=$filedir1" "$admin_out"
	rlAssertGrep "Filename.der=$file_der" "$admin_out"
	rlAssertGrep "Filename.b64=$file_b64" "$admin_out"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_edit_file_based_publisher_subca-021:SUBCA - Admin Interface - Edit file based publisher"
        local admin_out="$TmpDir/admin_out_editfilebasedpub"
	header_021="$TmpDir/subca_pub_021.txt"
        file_dir="/usr"
        rlLog "Add file based publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_021 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&Filename.b64=$file_b64&directory=$file_dir&Filename.der=$file_der&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add file based publisher"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_021"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_021 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_021"
	filedir1=$(echo $file_dir | sed 's/\//%2F/g')
	rlAssertGrep "directory=$filedir1" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_021 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_021"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_cacert_publisher_subca-022:SUBCA - Admin Interface - Add Ldap cacert publisher"
        local admin_out="$TmpDir/admin_out_addldapcacertpub"
	header_022="$TmpDir/subca_pub_022.txt"
        pub_id="pub26"
        mapper="LdapCaCertPublisher"
	caObjectClass="certificationAuthority"
	caCertAttr="caCertificate;binary"
        rlLog "Add ldap ca cert publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_022 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&caObjectClass=$caObjectClass&caCertAttr=$caCertAttr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add Ldap ca cert publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_022"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_022 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_022"
	rlAssertGrep "implName=$mapper" "$admin_out"
	certAttr1=$(echo $caCertAttr | sed 's/;/:/g')
	rlAssertGrep "caCertAttr=$certAttr1" "$admin_out"
	rlAssertGrep "caObjectClass=$caObjectClass" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_022 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_022"
        rlPhaseEnd
	
	rlPhaseStartTest "pki_console_add_ldap_certificate_pair_publisher_subca-023:SUBCA - Admin Interface - Add Ldap certificate pair publisher"
        local admin_out="$TmpDir/admin_out_addldapcertpairpub"
	header_023="$TmpDir/subca_pub_023.txt"
        pub_id="pub27"
        mapper="LdapCertificatePairPublisher"
	caObjectClass="certificationAuthority"
	crossCertPairAttr="crossCertificatePair;binary"
        rlLog "Add ldap certificate pair publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_023 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&caObjectClass=$caObjectClass&crossCertPairAttr=$crossCertPairAttr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add Ldap certificate pair publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_023"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		 --dump-header  $header_023 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_023"
	rlAssertGrep "implName=$mapper" "$admin_out"
	crossCertPairAttr1=$(echo $crossCertPairAttr | sed 's/;/:/g')
	rlAssertGrep "crossCertPairAttr=$crossCertPairAttr1" "$admin_out"
	rlAssertGrep "caObjectClass=$caObjectClass" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_023 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_023"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_crl_publisher_subca-024:SUBCA - Admin Interface - Add Ldap crl publisher"
        local admin_out="$TmpDir/admin_out_addldapcrlpub"
	header_024="$TmpDir/subca_pub_024.txt"
        pub_id="pub28"
        mapper="LdapCrlPublisher"
        crlAttr="certificateRevocationList;binary"
        rlLog "Add ldap crl publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_024 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&crlAttr=$crlAttr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap crl publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_024"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_024 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_024"
	rlAssertGrep "implName=$mapper" "$admin_out"
	crlAttr1=$(echo $crlAttr | sed 's/;/:/g')
	rlAssertGrep "crlAttr=$crlAttr1" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_024 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_024"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_delta_crl_publisher_subca-025:SUBCA - Admin Interface - Add Ldap delta crl publisher"
        local admin_out="$TmpDir/admin_out_addldapdeltacrlpub"
	header_025="$TmpDir/subca_pub_025.txt"
        pub_id="pub29"
        mapper="LdapDeltaCrlPublisher"
        crlAttr="certificateRevocationList;binary"
        rlLog "Add ldap delta crl publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_025 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&crlAttr=$crlAttr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap delta crl publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_025"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_025 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_025"
	rlAssertGrep "implName=$mapper" "$admin_out"
	crlAttr1=$(echo $crlAttr | sed 's/;/:/g')
        rlAssertGrep "crlAttr=$crlAttr1" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_025 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_025"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ldap_user_cert_publisher_subca-026:SUBCA - Admin Interface - Add Ldap user cert publisher"
        local admin_out="$TmpDir/admin_out_addldapusercertpub"
	header_026="$TmpDir/subca_pub_026.txt"
        pub_id="pub30"
        mapper="LdapUserCertPublisher"
        certAttr="userCertificate;binary"
        rlLog "Add ldap user cert publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_026 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&certAttr=$certAttr&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ldap user cert publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_026"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_026 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_026"
	rlAssertGrep "implName=$mapper" "$admin_out"
	certAttr1=$(echo $certAttr | sed 's/;/:/g')
        rlAssertGrep "certAttr=$certAttr1" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_026 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_026"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_ocsp_publisher_subca-027:SUBCA - Admin Interface - Add ocsp publisher"
        local admin_out="$TmpDir/admin_out_addocsppub"
	header_027="$TmpDir/subca_pub_027.txt"
        pub_id="pub31"
        mapper="OCSPPublisher"
	ocsp_host="somehost"
	ocsp_port="1234"
        rlLog "Add ocsp publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_027 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&host=$ocsp_host&port=$ocsp_port&path=/ocsp/addCRL&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add ocsp publisher"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_027"
        rlAssertGrep "implName=$mapper" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_027 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_027"
	rlAssertGrep "implName=$mapper" "$admin_out"
	rlAssertGrep "host=$ocsp_host" "$admin_out"
	rlAssertGrep "port=$ocsp_port" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_ocsp_publisher_subca-028:SUBCA - Admin Interface - Edit ocsp publisher"
        local admin_out="$TmpDir/admin_out_editocsppub"
	header_028="$TmpDir/subca_pub_028.txt"
        ocsp_host="somehost.redhat.com"
        rlLog "Edit ocsp publisher"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_028 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=publisherRules&RS_ID=$pub_id&RULENAME=$pub_id&implName=$mapper&host=$ocsp_host&port=$ocsp_port&path=/ocsp/addCRL&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Edit ocsp publisher"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_028"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_028 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_028"
        rlAssertGrep "host=$ocsp_host" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_delete_publisher_subca-029:SUBCA - Admin Interface - Delete publisher"
        local admin_out="$TmpDir/admin_out_deletepub"
	header_029="$TmpDir/subca_pub_029.txt"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_029 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publisher $pub_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_029"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_029 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=publisherRules&RS_ID=$pub_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read a mapper rule"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_029"
	rlAssertNotGrep "implName=$mapper" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_list_all_publishing_rules_subca-030:SUBCA - Admin Interface - List all publishing rules"
        local admin_out="$TmpDir/admin_out_listpubrules"
	header_030="$TmpDir/subca_pub_030.txt"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_030 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=ruleRules&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "List all publishing rules"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_030"
	rlAssertGrep "LdapXCertRule" "$admin_out"
	rlAssertGrep "LdapCaCertRule" "$admin_out"
	rlAssertGrep "LdapUserCertRule" "$admin_out"
	rlAssertGrep "LdapCrlRule" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_publishing_rule_type_certs_subca-031:SUBCA - Admin Interface - Add publishing rule - type certs"
        local admin_out="$TmpDir/admin_out_addpubrulecerts"
	header_031="$TmpDir/subca_pub_031.txt"
        rule_id="rule35"
        rule_predicate="HTTP_PARAMS.certType==client"
	rule_enable="true"
	rule_type="certs"
	rule_publisher="LdapUserCertPublisher"
	rule_mapper="LdapUserCertMap"
        rlLog "Add publishing rule - type certs"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_031 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=ruleRules&RS_ID=$rule_id&RULENAME=$rule_id&implName=Rule&predicate=$rule_predicate&enable=$rule_enable&type=$rule_type&publisher=$rule_publisher&mapper=$rule_mapper&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add publishing rule - type certs"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_031"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_031 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read publishing rule $rule_id"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_031"
	rlAssertGrep "implName=Rule" "$admin_out"
	rlAssertGrep "type=$rule_type" "$admin_out"
	rule_predict1=$(echo $rule_predict | sed 's/=/%3D/g')
	rlAssertGrep "predicate=$rule_predict1" "$admin_out"
	rlAssertGrep "enable=$rule_enable" "$admin_out"
	rlAssertGrep "mapper=$rule_mapper" "$admin_out"
	rlAssertGrep "publisher=$rule_publisher" "$admin_out"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_031 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publishing rule $rule_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_031"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_publishing_rule_type_cacert_subca-032:SUBCA - Admin Interface - Add publishing rule - type cacert"
        local admin_out="$TmpDir/admin_out_addpubrulecacert"
	header_032="$TmpDir/subca_pub_032.txt"
        rule_id="rule36"
        rule_predicate="HTTP_PARAMS.certType==ca"
        rule_enable="true"
        rule_type="cacert"
        rule_publisher="LdapCaCertPublisher"
        rule_mapper="LdapCaCertMap"
        rlLog "Add publishing rule - type cacert"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_032 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=ruleRules&RS_ID=$rule_id&RULENAME=$rule_id&implName=Rule&predicate=$rule_predicate&enable=$rule_enable&type=$rule_type&publisher=$rule_publisher&mapper=$rule_mapper&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add publishing rule - type cacert"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_032"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_032 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read publishing rule $rule_id"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_032"
        rlAssertGrep "implName=Rule" "$admin_out"
        rlAssertGrep "type=$rule_type" "$admin_out"
        rule_predict1=$(echo $rule_predict | sed 's/=/%3D/g')
        rlAssertGrep "predicate=$rule_predict1" "$admin_out"
        rlAssertGrep "enable=$rule_enable" "$admin_out"
        rlAssertGrep "mapper=$rule_mapper" "$admin_out"
        rlAssertGrep "publisher=$rule_publisher" "$admin_out"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_032 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher >> $admin_out" 0 "Delete publishing rule $rule_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_032"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_add_publishing_rule_type_crl_subca-033:SUBCA - Admin Interface - Add publishing rule - type crl"
        local admin_out="$TmpDir/admin_out_addpubrulecrl"
	header_033="$TmpDir/subca_pub_033.txt"
        rule_id="rule37"
        rule_predicate="issuingPointId==MasterCRL"
        rule_enable="true"
        rule_type="crl"
        rule_publisher="LdapCrlPublisher"
        rule_mapper="LdapCrlMap"
        rlLog "Add publishing rule - type cacert"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_033 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_ADD&OP_SCOPE=ruleRules&RS_ID=$rule_id&RULENAME=$rule_id&implName=Rule&predicate=$rule_predicate&enable=$rule_enable&type=$rule_type&publisher=$rule_publisher&mapper=$rule_mapper&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Add publishing rule - type crl"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_033 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read publishing rule $rule_id"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
        rlAssertGrep "implName=Rule" "$admin_out"
        rlAssertGrep "type=$rule_type" "$admin_out"
        rule_predict1=$(echo $rule_predict | sed 's/=/%3D/g')
        rlAssertGrep "predicate=$rule_predict1" "$admin_out"
        rlAssertGrep "enable=$rule_enable" "$admin_out"
        rlAssertGrep "mapper=$rule_mapper" "$admin_out"
        rlAssertGrep "publisher=$rule_publisher" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_read_publishing_rule_subca-034:SUBCA - Admin Interface - Read publishing rule"
        local admin_out="$TmpDir/admin_out_readpubrule"
	header_034="$TmpDir/subca_pub_034.txt"
	rlLog "Read publishing rule"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_034 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read publishing rule $rule_id"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_034"
        rlAssertGrep "implName=Rule" "$admin_out"
        rlAssertGrep "type=$rule_type" "$admin_out"
        rule_predict1=$(echo $rule_predict | sed 's/=/%3D/g')
        rlAssertGrep "predicate=$rule_predict1" "$admin_out"
        rlAssertGrep "enable=$rule_enable" "$admin_out"
        rlAssertGrep "mapper=$rule_mapper" "$admin_out"
        rlAssertGrep "publisher=$rule_publisher" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_delete_publishing_rule_subca-035:SUBCA - Admin Interface - Delete publishing rule"
        local admin_out="$TmpDir/admin_out_deletepubrule"
	header_035="$TmpDir/subca_pub_035.txt"
	rlLog "Delete publishing rule"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_035 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Delete publishing rule $rule_id"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
	
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_035 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=ruleRules&RS_ID=$rule_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Read publishing rule $rule_id"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
	rlAssertNotGrep "implName=Rule" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_disable_publishing_subca-036:SUBCA - Admin Interface - Disable Publishing"
        local admin_out="$TmpDir/admin_out_disablepub"
	header_036="$TmpDir/subca_pub_036.txt"
        rlLog "Disable Publishing"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_036 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_PROCESS&OP_SCOPE=ldap&RS_ID=RS_ID_CONFIG&publishingEnable=false&enable=false&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/capublisher > $admin_out" 0 "Disable Publishing"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "stopped=Publishingisstopped." "$admin_out"
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
