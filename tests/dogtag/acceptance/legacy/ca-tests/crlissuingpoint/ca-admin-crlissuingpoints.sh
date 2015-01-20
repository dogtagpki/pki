#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/ca_tests/crlissuingpoints/ca-admin-crlissuingpoints.sh
#   Description: CA Admin CRL Issuing Point tests
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

run_admin-ca-crlissuingpoints_tests()
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
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_admin_cert=$CA_INST\_adminV
	local crl_ip_id="crl02"
	local crl_ip_desc="testdescription"
	local crl_ip_enable="true"
	local valid_admin_user=$CA_INST\_adminV
        local valid_admin_user_password=$CA_INST\_adminV_password

	rlPhaseStartTest "pki_console_add_crl_issuing_point-001:CA - Admin Interface - add crl issuing point"
	local admin_out="$TmpDir/admin_out_addcrlip"
	header_001="$TmpDir/ca_cip_001.txt"
	rlLog "Add crl issuing point"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_001 \
		--user "$valid_admin_user:$valid_admin_user_password" \
		-d \"OP_TYPE=OP_ADD&OP_SCOPE=crlIPs&RS_ID=$crl_ip_id&id=$crl_ip_id&description=$crl_ip_desc&enable=$crl_ip_enable&\" \
		-k https://$tmp_ca_host:$target_secure_port/ca/caadmin > $admin_out" 0 "Add crl issuing point"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_001"
	rlAssertGrep "id=$crl_ip_id" "$admin_out"
	rlAssertGrep "description=$crl_ip_desc" "$admin_out"
	rlAssertGrep "enable=$crl_ip_enable" "$admin_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_crl_issuing_point-002:CA - Admin Interface - edit crl issuing point"
	local admin_out="$TmpDir/admin_out_edit_crlip"
	header_002="$TmpDir/ca_cip_002.txt"
	crl_ip_desc="testdescriptionmodified"
        rlLog "Edit crl issuing point"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_002 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlIPs&RS_ID=$crl_ip_id&id=$crl_ip_id&description=$crl_ip_desc&enable=$crl_ip_enable&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit crl issuing point"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_002"
        rlAssertGrep "id=$crl_ip_id" "$admin_out"
        rlAssertGrep "description=$crl_ip_desc" "$admin_out"
        rlAssertGrep "enable=$crl_ip_enable" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_list_all_crl_issuing_point-003:CA - Admin Interface - List all crl issuing point"
	local admin_out="$TmpDir/admin_out_list_crlip"
	header_003="$TmpDir/ca_cip_003.txt"
        rlLog "List all crl issuing point"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_003 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=crlIPs&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "List crl issuing points"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_003"
	rlAssertGrep "$crl_ip_id=$crl_ip_desc" "$admin_out"
	rlAssertGrep "$crl_ip_id.enable=$crl_ip_enable" "$admin_out"
        rlAssertGrep "MasterCRL" "$admin_out"
	rlAssertGrep "MasterCRL.enable=true" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_read_crl_update_info-004:CA - Admin Interface - Read CRL update info"
	local admin_out="$TmpDir/admin_out_read_crl_update_info"
	header_004="$TmpDir/ca_cip_004.txt"
        rlLog "Read CRL update info"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_004 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crl&RS_ID=$crl_ip_id&enableCRLUpdates=&updateSchema=&extendedNextUpdate=&alwaysUpdate=&enableDailyUpdates=&dailyUpdates=&enableUpdateInterval=&autoUpdateInterval=&nextUpdateGracePeriod=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Read CRL Update info"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_004"
	rlAssertGrep "enableCRLUpdates=true" "$admin_out"
	rlAssertGrep "updateSchema=1" "$admin_out"
	rlAssertGrep "extendedNextUpdate=true" "$admin_out"
	rlAssertGrep "alwaysUpdate=false" "$admin_out"
	rlAssertGrep "enableDailyUpdates=false" "$admin_out"
	rlAssertGrep "dailyUpdates=3:45" "$admin_out"
	rlAssertGrep "enableUpdateInterval=true" "$admin_out"
	rlAssertGrep "autoUpdateInterval=240" "$admin_out"
	rlAssertGrep "nextUpdateGracePeriod=0" "$admin_out"
	rlAssertGrep "defaultSigningAlgorithm=SHA512withRSA" "$admin_out"
	rlAssertGrep "allSigningAlgorithms=SHA1withRSA:SHA256withRSA:SHA512withRSA:MD5withRSA:MD2withRSA" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_read_crl_cache_info-005:CA - Admin Interface - Read CRL cache info"
	header_005="$TmpDir/ca_cip_005.txt"
	local admin_out="$TmpDir/admin_out_read_crl_cache_info"
        rlLog "Read CRL cache info"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_005 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crl&RS_ID=$crl_ip_id&enableCRLCache=&cacheUpdateInterval=&enableCacheRecovery=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Read CRL Cache info"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
	rlAssertGrep "enableCRLCache=true" "$admin_out"
	rlAssertGrep "cacheUpdateInterval=15" "$admin_out"
	rlAssertGrep "enableCacheRecovery=true" "$admin_out"
	rlAssertGrep "defaultSigningAlgorithm=SHA512withRSA" "$admin_out"
	rlAssertGrep "allSigningAlgorithms=SHA1withRSA:SHA256withRSA:SHA512withRSA:MD5withRSA:MD2withRSA" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_read_crl_format_info-006:CA - Admin Interface - Read CRL format info"
	header_006="$TmpDir/ca_cip_006.txt"
	local admin_out="$TmpDir/admin_out_read_crl_format_info"
        rlLog "Read CRL format info"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_006 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crl&RS_ID=$crl_ip_id&allowExtensions=&signingAlgorithm=&includeExpiredCerts=&caCertsOnly=&profileCertsOnly=&profileList=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Read CRL format info"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
	rlAssertGrep "allowExtensions=true" "$admin_out"
	rlAssertGrep "signingAlgorithm=SHA256withRSA" "$admin_out"
	rlAssertGrep "includeExpiredCerts=false" "$admin_out"
	rlAssertGrep "caCertsOnly=false" "$admin_out"
	rlAssertGrep "profileCertsOnly=" "$admin_out"
	rlAssertGrep "profileList=" "$admin_out"
	rlAssertGrep "defaultSigningAlgorithm=SHA512withRSA" "$admin_out"
	rlAssertGrep "allSigningAlgorithms=SHA1withRSA:SHA256withRSA:SHA512withRSA:MD5withRSA:MD2withRSA" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_crl_update_info-007:CA - Admin Interface - Edit CRL update info"
	header_007="$TmpDir/ca_cip_007.txt"
	local admin_out="$TmpDir/admin_out_edit_crl_update_info"
	enable_crl_update="true"
	update_schema="1"
	extended_next_update="true"
	always_update="false"
	enable_daily_updates="false"
	daily_update_time="3:45"
	enable_update_interval="true"
	auto_update_interval="240"
	next_update_grace_period="1"
        rlLog "Edit CRL update info"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crl&RS_ID=$crl_ip_id&enableCRLUpdates=$enable_crl_update&updateSchema=$update_schema&extendedNextUpdate=$extended_next_update&alwaysUpdate=$always_update&enableDailyUpdates=$enable_daily_updates&dailyUpdates=$daily_update_time&enableUpdateInterval=$enable_update_interval&autoUpdateInterval=$auto_update_interval&nextUpdateGracePeriod=$next_update_grace_period&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit CRL Update info"
	rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_007 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crl&RS_ID=$crl_ip_id&enableCRLUpdates=&updateSchema=&extendedNextUpdate=&alwaysUpdate=&enableDailyUpdates=&dailyUpdates=&enableUpdateInterval=&autoUpdateInterval=&nextUpdateGracePeriod=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Read CRL Update info"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlAssertGrep "enableCRLUpdates=$enable_crl_update" "$admin_out"
        rlAssertGrep "updateSchema=$update_schema" "$admin_out"
        rlAssertGrep "extendedNextUpdate=$extended_next_update" "$admin_out"
        rlAssertGrep "alwaysUpdate=$always_update" "$admin_out"
        rlAssertGrep "enableDailyUpdates=$enable_daily_updates" "$admin_out"
        rlAssertGrep "dailyUpdates=$daily_update_time" "$admin_out"
        rlAssertGrep "enableUpdateInterval=$enable_update_interval" "$admin_out"
        rlAssertGrep "autoUpdateInterval=$auto_update_interval" "$admin_out"
        rlAssertGrep "nextUpdateGracePeriod=$next_update_grace_period" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_crl_cache_info-008:CA - Admin Interface - Edit CRL cache info"
	header_008="$TmpDir/ca_cip_008.txt"
        local admin_out="$TmpDir/admin_out_edit_crl_cache_info"
	enable_crl_cache="true"
	cache_update_interval="15"
	enable_cache_recovery="true"
        rlLog "Edit CRL cache info"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_008 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crl&RS_ID=$crl_ip_id&enableCRLCache=$enable_crl_cache&cacheUpdateInterval=$cache_update_interval&enableCacheRecovery=$enable_cache_recovery&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit CRL Cache info"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_008 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crl&RS_ID=$crl_ip_id&enableCRLCache=&cacheUpdateInterval=&enableCacheRecovery=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Read CRL Cache info"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlAssertGrep "enableCRLCache=$enable_crl_cache" "$admin_out"
        rlAssertGrep "cacheUpdateInterval=$cache_update_interval" "$admin_out"
        rlAssertGrep "enableCacheRecovery=$enable_cache_recovery" "$admin_out"
        rlAssertGrep "defaultSigningAlgorithm=SHA512withRSA" "$admin_out"
        rlAssertGrep "allSigningAlgorithms=SHA1withRSA:SHA256withRSA:SHA512withRSA:MD5withRSA:MD2withRSA" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_crl_format_info-009:CA - Admin Interface - Edit CRL format info"
	header_009="$TmpDir/ca_cip_009.txt"
        local admin_out="$TmpDir/admin_out_edit_crl_format_info"
	allow_extensions="true"
	include_expired_certs="false"
	ca_certs_only="false"
	profile_certs_only="true"
	profile_list="caUserCert"
	signing_algorithm="SHA256withRSA"
        rlLog "Edit CRL format info"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_009 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crl&RS_ID=$crl_ip_id&allowExtensions=$allow_extensions&signingAlgorithm=$signing_algorithm&includeExpiredCerts=$include_expired_certs&caCertsOnly=$ca_certs_only&profileCertsOnly=$profile_certs_only&profileList=$profile_list&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit CRL Format info"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_009 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crl&RS_ID=$crl_ip_id&allowExtensions=&signingAlgorithm=&includeExpiredCerts=&caCertsOnly=&profileCertsOnly=&profileList=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Read CRL format info"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "allowExtensions=$allow_extensions" "$admin_out"
        rlAssertGrep "signingAlgorithm=$signing_algorithm" "$admin_out"
        rlAssertGrep "includeExpiredCerts=$include_expired_certs" "$admin_out"
        rlAssertGrep "caCertsOnly=$ca_certs_only" "$admin_out"
        rlAssertGrep "profileCertsOnly=$profile_certs_only" "$admin_out"
        rlAssertGrep "profileList=$profile_list" "$admin_out"
        rlAssertGrep "defaultSigningAlgorithm=SHA512withRSA" "$admin_out"
        rlAssertGrep "allSigningAlgorithms=SHA1withRSA:SHA256withRSA:SHA512withRSA:MD5withRSA:MD2withRSA" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_list_all_crl_extensions-010:CA - Admin Interface - List all crl extensions"
	header_010="$TmpDir/ca_cip_010.txt"
        local admin_out="$TmpDir/admin_out_list_crl_extension"
        rlLog "List all crl extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_010 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=crlExtsRules&RS_ID=$crl_ip_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "List all crl extensions"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
	rlAssertGrep "AuthorityInformationAccess=AuthorityInformationAccess:visible:disabled" "$admin_out"
	rlAssertGrep "AuthorityKeyIdentifier=AuthorityKeyIdentifier:visible:enabled" "$admin_out"
	rlAssertGrep "CRLNumber=CRLNumber:visible:enabled" "$admin_out"
	rlAssertGrep "CRLReason=CRLReason:visible:enabled" "$admin_out"
	rlAssertGrep "DeltaCRLIndicator=DeltaCRLIndicator:visible:disabled" "$admin_out"
	rlAssertGrep "FreshestCRL=FreshestCRL:visible:disabled" "$admin_out"
	rlAssertGrep "InvalidityDate=InvalidityDate:visible:enabled" "$admin_out"
	rlAssertGrep "IssuerAlternativeName=IssuerAlternativeName:visible:disabled" "$admin_out"
	rlAssertGrep "IssuingDistributionPoint=IssuingDistributionPoint:visible:disabled" "$admin_out"
        rlPhaseEnd


        rlPhaseStartTest "pki_console_edit_crl_reason_extension-011:CA - Admin Interface - Edit crl reason extension"
	header_011="$TmpDir/ca_cip_011.txt"
        local admin_out="$TmpDir/admin_out_edit_crl_reason_extension"
        crl_reason_enable="true"
        crl_reason_status="enabled"
        crl_reason_critical="false"
        rlLog "Edit crl reason extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_011 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=CRLReason&id=$crl_ip_id&implName=CMSCRLReasonExtension&enable=$crl_reason_enable&critical=$crl_reason_critical&RULENAME=CRLReason&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit crl reason extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_011 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=crlExtsRules&RS_ID=$crl_ip_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "List all crl extensions"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlAssertGrep "CRLReason=CRLReason:visible:$crl_reason_status" "$admin_out"
	rlLog "https://fedorahosted.org/pki/ticket/1189"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_edit_delta_crl_extension-012:CA - Admin Interface - Edit delta crl extension"
	header_012="$TmpDir/ca_cip_012.txt"
        local admin_out="$TmpDir/admin_out_edit_delta_crl_extension"
        delta_crl_enable="true"
        delta_crl_critical="false"
        rlLog "Edit delta crl extension"
        rlRun "curl --capath "$CERTDB_DIR" \
		--dump-header  $header_012 \
		--basic --user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=DeltaCRLIndicator&id=$crl_ip_id&implName=CMSDeltaCRLIndicatorExtension&enable=$delta_crl_enable&critical=$delta_crl_critical&RULENAME=DeltaCRLIndicator&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit delta crl extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_012 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=DeltaCRLIndicator&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlAssertGrep "enable=$delta_crl_enable" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_edit_issuer_alternative_name_extension-013:CA - Admin Interface - Edit issuer alternative name extension"
	header_013="$TmpDir/ca_cip_013.txt"
        local admin_out="$TmpDir/admin_out_edit_issuer_alternative_name_extension"
        ian_enable="true"
        ian_critical="false"
        ian_name="http://www.redhat.com"
        ian_name_type="URI"
        rlLog "Edit Issuer Alternative Name extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_013 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=IssuerAlternativeName&implName=CMSIssuerAlternativeNameExtension&id=$crl_ip_id&enable=$ian_enable&critical=$ian_critical&RULENAME=IssuerAlternativeName&numNames=1&name0=$ian_name&nameType0=$ian_name_type&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit Issuer Alternative name extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_013 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=IssuerAlternativeName&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlAssertGrep "enable=$ian_enable" "$admin_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_console_edit_invalidity_date_extension-014:CA - Admin Interface - Edit invalidity date extension"
	header_014="$TmpDir/ca_cip_014.txt"
        local admin_out="$TmpDir/admin_out_edit_invalidity_date_extension"
        inv_date_enable="true"
        inv_date_critical="false"
        rlLog "Edit invalidity date extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_014 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=InvalidityDate&implName=CMSInvalidityDateExtension&id=$crl_ip_id&enable=$inv_date_enable&critical=$inv_date_critical&RULENAME=InvalidityDate&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit Invalidity Date extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_014"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_014 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=InvalidityDate&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_014"
        rlAssertGrep "enable=$inv_date_enable" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_authority_key_identifier_extension-015:CA - Admin Interface - Edit authority key identifier extension"
	header_015="$TmpDir/ca_cip_015.txt"
        local admin_out="$TmpDir/admin_out_edit_authority_key_identifier_extension"
        aki_enable="true"
        aki_critical="false"
        rlLog "Edit authority key identifier extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_015 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=AuthorityKeyIdentifier&implName=CMSAuthorityKeyIdentifierExtension&id=$crl_ip_id&enable=$aki_enable&critical=$aki_critical&RULENAME=AuthorityKeyIdentifier&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit Authority Key Identifier extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_015"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_015 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=AuthorityKeyIdentifier&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_015"
        rlAssertGrep "enable=$aki_enable" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_freshest_crl_extension-016:CA - Admin Interface - Edit freshest crl extension"
	header_016="$TmpDir/ca_cip_016.txt"
        local admin_out="$TmpDir/admin_out_edit_freshest_crl_extension"
        fcrl_enable="true"
        fcrl_critical="false"
	fcrl_name="http://www.redhat.com"
	fcrl_name_type="URI"
        rlLog "Edit freshest crl extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_016 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=FreshestCRL&implName=CMSFreshestCRLExtension&id=$crl_ip_id&enable=$fcrl_enable&critical=$fcrl_critical&RULENAME=FreshestCRL&numPoints=1&point0=$fcrl_name&pointType0=$fcrl_name_type&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit Freshest CRL extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_016"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_016 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=FreshestCRL&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_016"
        rlAssertGrep "enable=$fcrl_enable" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_crl_number_extension-017:CA - Admin Interface - Edit CRL number extension"
	header_017="$TmpDir/ca_cip_017.txt"
        local admin_out="$TmpDir/admin_out_edit_crl_number_extension"
        cnum_enable="true"
        cnum_critical="false"
        rlLog "Edit CRL number extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_017 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=CRLNumber&implName=CMSCRLNumberExtension&id=$crl_ip_id&enable=$cnum_enable&critical=$cnum_critical&RULENAME=CRLNumber&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit CRL Number extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_017"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_017 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=CRLNumber&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_017"
        rlAssertGrep "enable=$cnum_enable" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_edit_issuing_distribution_point_extension-018:CA - Admin Interface - Edit Issuing Distribution Point extension"
	header_018="$TmpDir/ca_cip_018.txt"
        local admin_out="$TmpDir/admin_out_issuing_dp_extension"
        idp_enable="true"
        idp_critical="false"
	idp_point_name="http://www.redhat.com"
	idp_point_type="URI"
	idp_only_ca_certs="true"
	idp_indirect_crl="true"
	idp_reasons="keyCompromise\,certificateHold"
	idp_only_user_certs="true"
        rlLog "Edit Issuing Distribution Point extension"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_018 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_MODIFY&OP_SCOPE=crlExtsRules&RS_ID=IssuingDistributionPoint&implName=CMSIssuingDistributionPointExtension&id=$crl_ip_id&enable=$idp_enable&critical=$idp_critical&RULENAME=IssuingDistributionPoint&pointType=$idp_point_type&onlyContainsCACerts=$idp_only_ca_certs&pointName=$idp_point_name&onlySomeReasons=$idp_reasons&indirectCRL=$idp_indirect_crl&onlyContainsUserCerts=$idp_only_user_certs&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Edit CRL Number extension"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_018"
	rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_018 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_READ&OP_SCOPE=crlExtsRules&RS_ID=IssuingDistributionPoint&$crl_ip_id=&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Verify Modification"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_018"
        rlAssertGrep "enable=$idp_enable" "$admin_out"
        rlPhaseEnd

	rlPhaseStartTest "pki_console_delete_crl_issuing_point-019:CA - Admin Interface - delete crl issuing point"
	header_019="$TmpDir/ca_cip_019.txt"
        local admin_out="$TmpDir/admin_out_deletecrl"
        rlLog "Delete crl issuing point"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_019 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_DELETE&OP_SCOPE=crlIPs&RS_ID=$crl_ip_id&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "Delete crl issuing point"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_019"
        rlRun "curl --capath "$CERTDB_DIR" --basic \
		--dump-header  $header_019 \
		--user "$valid_admin_user:$valid_admin_user_password" \
                -d \"OP_TYPE=OP_SEARCH&OP_SCOPE=crlIPs&\" \
                -k https://$tmp_ca_host:$target_secure_port/ca/caadmin >> $admin_out" 0 "List crl issuing points"
        rlRun "process_curl_output $admin_out" 0 "Process curl output file"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_019"
        rlAssertNotGrep "$crl_ip_id" "$admin_out"
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
