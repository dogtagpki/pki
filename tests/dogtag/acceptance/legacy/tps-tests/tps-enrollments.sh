#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/tps-tests/tps-enrollments.sh
#   Description: TPS Enrollment tests
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

run_tps-enrollment_tests()
{
        local cs_Type=$1
        local cs_Role=$2
        
	# Creating Temporary Directory for tps-enrollments tests
        rlPhaseStartSetup "pki_tps_enrollments Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Local Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local TPS_INST=$(cat $TmpDir/topo_file | grep MY_TPS | cut -d= -f2)
        local target_unsecure_port=$(eval echo \$${TPS_INST}_UNSECURE_PORT)
        local target_secure_port=$(eval echo \$${TPS_INST}_SECURE_PORT)
        local tmp_ca_admin=$CA_INST\_adminV
	local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_tps_host=$(eval echo \$${cs_Role})
        local valid_admin_cert=$TPS_INST\_adminV
	local valid_agent_cert=$TPS_INST\_agentV
	local valid_admin1_cert=$TPS_INST\_admin1V
        local valid_agent1_cert=$TPS_INST\_agent1V
	local valid_admin_user=$TPS_INST\_adminV
        local valid_admin_user_password=$TPS_INST\_adminV_password

	rlPhaseStartTest "pki_tps_enrollments-001: Add an LDAP user and enroll a token using tpsclient"
        ldap_user_num=001
        change_type="add"
        passwd="redhat"
        local tps_out="$TmpDir/admin_out_tpsenroll001"
        local cuid="10000000000000000001"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers001.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers001.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers001.ldif | grep uid: | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll001.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll001.test
        /usr/bin/tpsclient < $TmpDir/enroll001.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-002: Pin reset a token using tpsclient"
        local tps_out="$TmpDir/admin_out_tpsenroll002"
        local cuid="10000000000000000001"
        rlLog "gen_pin_reset_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/pinreset002.test"
        gen_pin_reset_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/pinreset002.test
        /usr/bin/tpsclient < $TmpDir/pinreset002.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_reset_pin' Success" "$tps_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-003: Format a token using tpsclient"
        local tps_out="$TmpDir/admin_out_tpsenroll003"
        local cuid="10000000000000000001"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format003.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format003.test
        /usr/bin/tpsclient < $TmpDir/format003.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	#Cleanup
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
	rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

        #### TPS audit logging is not functional yet. https://fedorahosted.org/pki/ticket/1006 and https://fedorahosted.org/pki/ticket/1007	
	
	rlPhaseStartTest "pki_tps_enrollments-004: Perform 50 enrollments"
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 50 > $TmpDir/ldapusers004.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers004.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 51 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="3000000000000000000$i"
        else
                cuid="300000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers004.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done
         i=1
        while [ $i -lt 51 ]; do
                if [ $i -lt 10 ]; then
                        cuid="3000000000000000000$i"
                else
                        cuid="300000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
	#Cleanup
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-005: Edit the key size property of userKey profile - BZ 1192232"
        header_005="$TmpDir/header005"
        local tps_out="$TmpDir/admin_out_tpsenroll0053"
        local cuid="10000000000000000053"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers005.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers005.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers005.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0053.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0053.test
        /usr/bin/tpsclient < $TmpDir/enroll0053.test > $tps_out 2>&1
        rlRun "sleep 10"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Verify the certs on the token. Implement that after https://fedorahosted.org/pki/ticket/1164 is fixed
        #rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        #serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        #for j in ${serial[@]}; do
        #        rlLog "$j"
        #        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
        #        rlAssertGrep "1024 bits" "$TmpDir/keysizecheck.out"
        #        rlAssertNotGrep "2048 bits" "$TmpDir/keysizecheck.out"
        #done
        rlRun "curl --dump-header  $header_005 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate005"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1192232"
        # Remove the below when bug 1192232 is fixed
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=enable > $TmpDir/changestate005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile005"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile005" 0 "Download user key profile to a file"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile005
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile005
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile005 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize005"
	rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlRun "curl --dump-header  $header_005 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/verifykeysize005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048" "$TmpDir/verifykeysize005"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048" "$TmpDir/verifykeysize005"
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=enable > $TmpDir/changestate005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/changestate005"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format005.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format005.test
        /usr/bin/tpsclient < $TmpDir/format005.test > $tps_out 2>&1

        rlRun "sleep 10"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlLog "gen_enroll_data_file  $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0053.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0053.test
        /usr/bin/tpsclient < $TmpDir/enroll0053.test > $tps_out 2>&1
        rlRun "sleep 10"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

         #Verify the certs on the token to check if the key size changes have been applied
        #rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        #serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        #for j in ${serial[@]}; do
        #        rlLog "$j"
        #        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
        #        rlAssertGrep "2048 bits" "$TmpDir/keysizecheck.out"
        #        rlAssertNotGrep "1024 bits" "$TmpDir/keysizecheck.out"
        #done
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format005.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format005.test
        /usr/bin/tpsclient < $TmpDir/format005.test > $tps_out 2>&1
        rlRun "sleep 10"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "<Status>Disabled</Status>" "$TmpDir/changestate005"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile005
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile005
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile005 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlRun "curl --dump-header  $header_005 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/verifykeysize005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024" "$TmpDir/verifykeysize005"
        rlRun "curl --dump-header  $header_005 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=enable > $TmpDir/changestate005"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_005"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/changestate005"

        /usr/bin/tpsclient < $TmpDir/enroll0053.test > $tps_out 2>&1
        rlRun "sleep 10"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

         #Verify the certs on the token to check if the key size changes have been applied
        #rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        #serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        #for j in ${serial[@]}; do
        #        rlLog "$j"
        #        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
        #        rlAssertGrep "1024 bits" "$TmpDir/keysizecheck.out"
        #        rlAssertNotGrep "2048 bits" "$TmpDir/keysizecheck.out"
        #done
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format005.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format005.test
        /usr/bin/tpsclient < $TmpDir/format005.test > $tps_out 2>&1
        rlRun "sleep 10"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-006: Admin cannot edit userKey profile unless Agent disables the profile"
        header_006="$TmpDir/header006"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of userKey Profile is Enabled"
        rlRun "curl --dump-header  $header_006 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate006"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate006"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile006"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile006" 0 "Download user key profile to a file"
        rlLog "Edit the userKey Profile xml file by changing the encryption key keySize and update the profile. This should fail."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile006
        rlLog "curl --dump-header  $header_006 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile006 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey"
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile006 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize006"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 403 Forbidden" "$header_006"
        rlAssertGrep "Unable to update profile userKey" "$TmpDir/changekeysize006"
        rlLog "Agent disables the profile userKey"
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate006"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlLog "Edit userKey profile - key size of encryption key 1024-2048"
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile006 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize006"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize006"
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate006"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlRun "curl --dump-header  $header_006 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate006"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048" "$TmpDir/currentstate006"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate006"
                #Revert back the changes
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate006"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile006
        rlLog "curl --dump-header  $header_006 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                       -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile006 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey"
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile006 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize006"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize006"
        rlRun "curl --dump-header  $header_006 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate006"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlRun "curl --dump-header  $header_006 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate006"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_006"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024" "$TmpDir/currentstate006"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate006"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-007: Enrollment fails when profile is disabled - BZ 1192232"
        header_007="$TmpDir/header007"
        local tps_out="$TmpDir/admin_out_tpsenroll0054"
        local cuid="10000000000000000054"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of userKey Profile is Enabled and disable it."
        rlRun "curl --dump-header  $header_007 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate007"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate007"
	rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1192232"
        # Remove the below when bug 1192232 is fixed
        rlRun "curl --dump-header  $header_007 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=enable > $TmpDir/changestate007"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_007"

	rlLog "Disable the userKey profile"
	rlRun "curl --dump-header  $header_007 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate007"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlAssertGrep "<Status>Disabled</Status>" "$TmpDir/changestate007"
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers007.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers007.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers007.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0054.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0054.test
        /usr/bin/tpsclient < $TmpDir/enroll0054.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format007.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format007.test
        /usr/bin/tpsclient < $TmpDir/format007.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        #Revert back the change
        rlRun "curl --dump-header  $header_007 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=enable > $TmpDir/changestate007"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_007"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd


	rlPhaseStartTest "pki_tps_enrollments-008: Agent approves the profile changes made by Admin"
        header_008="$TmpDir/header008"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Check the status of userKey Profile is Enabled"
        rlRun "curl --dump-header  $header_008 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate008"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate008"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile008"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile008" 0 "Download user key profile to a file"
        rlLog "Agent disables the profile userKey"
        rlRun "curl --dump-header  $header_008 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate008"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Edit the userKey Profile xml file by changing the encryption key and signing key keySize and update the profile."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile008
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile008
        rlLog "Edit userKey profile - key size of encryption key 1024-2048 and the verify the state of the profile is pending approval"
        rlRun "curl --dump-header  $header_008 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile008 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize008"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize008"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Agent user approve and enable the profile"
	rlRun "curl --dump-header  $header_008 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate008"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlRun "curl --dump-header  $header_008 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate008"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048" "$TmpDir/currentstate008"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048" "$TmpDir/currentstate008"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate008"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"

        #Revert back the changes
        rlRun "curl --dump-header  $header_008 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate008"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile008
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile008
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "curl --dump-header  $header_008 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                       -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile008 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey"
        rlRun "curl --dump-header  $header_008 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile008 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize008"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
	rlRun "curl --dump-header  $header_008 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate008"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlRun "curl --dump-header  $header_008 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate008"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_008"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024" "$TmpDir/currentstate008"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024" "$TmpDir/currentstate008"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate008"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-009: Enrollment fails when profile is in Pending_Approval state"
        header_009="$TmpDir/header009"
        local tps_out="$TmpDir/admin_out_tpsenroll0055"
        local cuid="10000000000000000055"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of userKey Profile is Enabled and disable it."
        rlRun "curl --dump-header  $header_009 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate009"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate009"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile009"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile009" 0 "Download user key profile to a file"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlRun "curl --dump-header  $header_009 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate009"
                rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlLog "Edit the userKey Profile xml file by changing the encryption key and signing key keySize and update the profile."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile009
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile009
        rlLog "Edit userKey profile - key size of encryption key 1024-2048 and the verify the state of the profile is pending approval"
        rlRun "curl --dump-header  $header_009 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile009 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize009"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize009"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers009.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers009.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers009.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0055.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0055.test
        /usr/bin/tpsclient < $TmpDir/enroll0055.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "Approve the profile changes"
        rlRun "curl --dump-header  $header_009 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                -X POST \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/currentstate009"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlRun "curl --dump-header  $header_009 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate009"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048" "$TmpDir/currentstate009"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048" "$TmpDir/currentstate009"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate009"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"

        /usr/bin/tpsclient < $TmpDir/enroll0055.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Verify the certs on the token to check if the key size changes have been applied
        #rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        #serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        #for j in ${serial[@]}; do
        #        rlLog "$j"
        #        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
        #        rlAssertGrep "2048 bits" "$TmpDir/keysizecheck.out"
        #        rlAssertNotGrep "1024 bits" "$TmpDir/keysizecheck.out"
        #done

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format009.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format009.test
        /usr/bin/tpsclient < $TmpDir/format009.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Revert back the change
        rlRun "curl --dump-header  $header_009 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate009"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile009
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile009
        rlLog "Edit userKey profile - key size of encryption key 1024-2048 and the verify the state of the profile is pending approval"
        rlRun "curl --dump-header  $header_009 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile009 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize009"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize009"
        rlRun "curl --dump-header  $header_009 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate009"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlRun "curl --dump-header  $header_009 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
               -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate009"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_009"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024" "$TmpDir/currentstate009"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024" "$TmpDir/currentstate009"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate009"
        /usr/bin/tpsclient < $TmpDir/enroll0055.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        #Verify the certs on the token to check if the key size changes have been reverted      
        #rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        #numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        #serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        #for j in ${serial[@]}; do
        #        rlLog "$j"
        #        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
        #        rlAssertGrep "1024 bits" "$TmpDir/keysizecheck.out"
        #        rlAssertNotGrep "2048 bits" "$TmpDir/keysizecheck.out"
        #done

        /usr/bin/tpsclient < $TmpDir/format009.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-010: Create a new profile using the properties of userKey profile and agent approves"
        header_010="$TmpDir/header010"
        local tps_out="$TmpDir/admin_out_tpsenroll0056"
        local cuid="10000000000000000056"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of userKey Profile is Enabled."
        rlRun "curl --dump-header  $header_010 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate010"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate010"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile010"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile010" 0 "Download user key profile to a file"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Disable the userKey profile"
        rlRun "curl --dump-header  $header_010 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate010"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        rlLog "Delete the userKey profile"
        rlRun "curl --dump-header  $header_010 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize010"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_010"
        rlLog "Verify the profile userKey has been deleted"
        rlRun "curl --dump-header $header_010 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate010"
        rlAssertGrep "HTTP/1.1 404 Not Found" "$header_010"
        rlLog "Set the keySize to 2048 in the saved userKey profile xml file"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile010
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile010
        rlLog "Create a profile with the name userKey"
        rlRun "curl --dump-header  $header_010 \
                       -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X POST \
                        --data @$TmpDir/userkey-profile010 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles > $TmpDir/changekeysize010"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 201 Created" "$header_010"
        rlLog "Verify the userKey profile has been created"
        rlRun "curl --dump-header  $header_010 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate010"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        rlLog "Enable the profile before attempting enrollment"
        rlRun "curl --dump-header  $header_010 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=enable > $TmpDir/changestate010"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        rlLog "Enroll and format a token using tpsclient"
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers010.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers010.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers009.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0056.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0056.test
        /usr/bin/tpsclient < $TmpDir/enroll0056.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Verify the certs on the token to check if the key size changes have been reverted      
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        for j in ${serial[@]}; do
                rlLog "$j"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
                rlAssertGrep "2048 bits" "$TmpDir/keysizecheck.out"
                rlAssertNotGrep "1024 bits" "$TmpDir/keysizecheck.out"
        done

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format010.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format010.test
        /usr/bin/tpsclient < $TmpDir/format010.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Edit the keySize back to 1024"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile010
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile010
        rlLog "Disable the profile before editing it"

        rlRun "curl --dump-header  $header_010 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate010"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"

        rlRun "curl --dump-header  $header_010 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile010 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize010"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"

        rlLog "Approve the changes made to the profile"

        rlRun "curl --dump-header  $header_010 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate010"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_010"
        /usr/bin/tpsclient < $TmpDir/enroll0056.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Verify the certs on the token to check if the key size changes have been reverted      
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        for j in ${serial[@]}; do
                rlLog "$j"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
                rlAssertGrep "1024 bits" "$TmpDir/keysizecheck.out"
                rlAssertNotGrep "2048 bits" "$TmpDir/keysizecheck.out"
        done

        /usr/bin/tpsclient < $TmpDir/format010.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd
		

	rlPhaseStartTest "pki_tps_enrollments-011: Create a new profile userKey when userKey profile already exists"
        header_011="$TmpDir/header011"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of userKey Profile is Enabled."
        rlRun "curl --dump-header  $header_011 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate011"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile011"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile011" 0 "Download user key profile to a file"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Disable the userKey profile"
        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlLog "Set the keySize to 2048 in the saved userKey profile xml file"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile011
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile011
        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile011 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize011"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlLog "Approve the changes made to the profile"

        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlRun "curl --dump-header  $header_011 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate011"
        rlLog "Create a profile with the name userKey"
        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X POST \
                        --data @$TmpDir/userkey-profile011 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles > $TmpDir/changekeysize011"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 409 Conflict" "$header_011"

        # Revert back the changes

        rlLog "Disable the userKey profile"
        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlLog "Set the keySize to 2048 in the saved userKey profile xml file"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile011
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile011
        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile011 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize011"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlLog "Approve the changes made to the profile"

        rlRun "curl --dump-header  $header_011 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlRun "curl --dump-header  $header_011 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate011"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_011"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate011"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-012: Profile is not enabled if it is rejected by agent after modification to profile"
        header_012="$TmpDir/header012"
        local tps_out="$TmpDir/admin_out_tpsenroll0057"
        local cuid="10000000000000000057"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of userKey Profile is Enabled."
        rlRun "curl --dump-header  $header_012 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate012"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate012"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile012"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile012" 0 "Download user key profile to a file"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"

        rlLog "Disable the userKey profile"
        rlRun "curl --dump-header  $header_012 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate012"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlLog "Set the keySize to 2048 in the saved userKey profile xml file"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile012
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile012
        rlRun "curl --dump-header  $header_012 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile012 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize012"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"

        rlLog "Reject the changes made to the profile"

        rlRun "curl --dump-header  $header_012 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=reject > $TmpDir/changestate012"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"

        rlRun "curl --dump-header  $header_012 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate012"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlAssertGrep "<Status>Disabled</Status>" "$TmpDir/currentstate012"

        #Revert the changes back

        rlLog "Set the keySize to 1024 in the saved userKey profile xml file"
                sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile012
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile012
        rlRun "curl --dump-header  $header_012 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile012 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize012"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"

        rlLog "Approve the changes made to the profile"

        rlRun "curl --dump-header  $header_012 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate012"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlRun "curl --dump-header  $header_012 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate012"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_012"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate012"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers010.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers010.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers009.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0057.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0057.test
        /usr/bin/tpsclient < $TmpDir/enroll0057.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        #Verify the certs on the token to check if the key size changes have been reverted      
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        for j in ${serial[@]}; do
                rlLog "$j"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j --pretty > $TmpDir/keysizecheck.out"
                rlAssertGrep "1024 bits" "$TmpDir/keysizecheck.out"
                rlAssertNotGrep "2048 bits" "$TmpDir/keysizecheck.out"
        done
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format012.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format012.test
        /usr/bin/tpsclient < $TmpDir/format012.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	 ### TPS subsystem connection is not working. https://bugzilla.redhat.com/show_bug.cgi?id=1194050. 2 tests skipped.

        rlPhaseStartTest "pki_tps_enrollments-013: Edit the mapping order of enrollment profile mapper - BZ 1192232"
        header_013="$TmpDir/header013"
        local tps_out="$TmpDir/admin_out_tpsenroll0058"
        local cuid="10000000000000000058"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Review the mapping order of enroll profile mapping"
        rlRun "curl --dump-header  $header_013 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver > $TmpDir/currentstate013"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlAssertGrep "<Property name=\"tokenProfileResolver.enrollMappingResolver.mapping.order\">0,1,2" "$TmpDir/currentstate013"
        rlAssertGrep "<Status>Enabled" "$TmpDir/currentstate013"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1192232"
	# Remove the below when bug 1192232 is fixed
        rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=enable > $TmpDir/changestate013"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
                rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=disable > $TmpDir/changestate013"
                rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlLog "Download enroll mapping profile"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-mapping-show enrollMappingResolver --output $TmpDir/enroll-profile-mapping013"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-mapping-show enrollMappingResolver --output $TmpDir/enroll-profile-mapping013" 0 "Download enroll profile mapping to a file"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profile_Mappings.enrollMappingResolver.timestamp | cut -d= -f2)"

        rlLog "Set the enroll profile mapping order property to 2,0,1"
        sed -i -e "s/<Property name=\"tokenProfileResolver.enrollMappingResolver.mapping.order\">0,1,2/<Property name=\"tokenProfileResolver.enrollMappingResolver.mapping.order\">2,0,1/g" $TmpDir/enroll-profile-mapping013
        rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/enroll-profile-mapping013 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver > $TmpDir/changeorder013"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=enable > $TmpDir/changestate013"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlAssertGrep "<Status>Enabled" "$TmpDir/changestate013"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profile_Mappings.enrollMappingResolver.timestamp | cut -d= -f2)"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers013.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers013.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers013.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0058.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0058.test
        /usr/bin/tpsclient < $TmpDir/enroll0058.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format013.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format013.test
        /usr/bin/tpsclient < $TmpDir/format013.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        #Revert back the change
        rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=disable > $TmpDir/changestate013"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"

        sed -i -e "s/<Property name=\"tokenProfileResolver.enrollMappingResolver.mapping.order\">2,0,1/<Property name=\"tokenProfileResolver.enrollMappingResolver.mapping.order\">0,1,2/g" $TmpDir/enroll-profile-mapping013
        rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/enroll-profile-mapping013 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver > $TmpDir/changeorder013"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"

        rlRun "curl --dump-header  $header_013 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=enable > $TmpDir/changestate013"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_013"
        rlAssertGrep "<Status>Enabled" "$TmpDir/changestate013"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profile_Mappings.enrollMappingResolver.timestamp | cut -d= -f2)"

        /usr/bin/tpsclient < $TmpDir/enroll0058.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        /usr/bin/tpsclient < $TmpDir/format013.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-014: Delete the existing enroll mapping profile and add a new one"
        header_014="$TmpDir/header014"
        local tps_out="$TmpDir/admin_out_tpsenroll0059"
        local cuid="10000000000000000059"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Review the mapping order of enroll profile mapping"
        rlRun "curl --dump-header  $header_014 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver > $TmpDir/currentstate014"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_014"
        rlAssertGrep "<Status>Enabled" "$TmpDir/currentstate014"
        rlRun "curl --dump-header  $header_014 \
                    -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                    -X POST \
                    -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=disable > $TmpDir/changestate014"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_014"

        rlLog "Download enroll mapping profile"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-mapping-show enrollMappingResolver --output $TmpDir/enroll-profile-mapping014"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-mapping-show enrollMappingResolver --output $TmpDir/enroll-profile-mapping014" 0 "Download enroll profile mapping to a file"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profile_Mappings.enrollMappingResolver.timestamp | cut -d= -f2)"
        rlRun "curl --dump-header  $header_014 \
                    -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                    -X DELETE \
                    -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver > $TmpDir/deletemapping014"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_014"
        rlAssertNotGrep "enrollMappingResolver" "$TmpDir/deletemapping014"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers014.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers014.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers014.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0059.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0059.test
        /usr/bin/tpsclient < $TmpDir/enroll0059.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format014.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format014.test
        /usr/bin/tpsclient < $TmpDir/format014.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Create a new enroll profile mapping using the downloaded file"
        rlRun "curl --dump-header  $header_014 \
                       -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X POST \
                        --data @$TmpDir/enroll-profile-mapping014 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings > $TmpDir/addenrollmapping014"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 201 Created" "$header_014"
        rlAssertGrep "enrollMappingResolver" "$TmpDir/addenrollmapping014"

        rlRun "curl --dump-header  $header_014 \
                    -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                    -X POST \
                    -k https://$tmp_tps_host:$target_secure_port/tps/rest/profile-mappings/enrollMappingResolver?action=enable > $TmpDir/changestate014"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_014"

        /usr/bin/tpsclient < $TmpDir/enroll0059.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        /usr/bin/tpsclient < $TmpDir/format014.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-015: TPS process shutdown when the audit log (disk) is full - PKI ticket 1006"
        header_015="$TmpDir/header015"
        local tps_out="$TmpDir/admin_out_tpsenroll0060"
        local cuid="10000000000000000060"
        partition_created="false"
        new_mount_dir="/tps-audit-logs"
        #Create 2M ram-disk for the audit logs
        rlRun "mkdir $new_mount_dir"
        rlRun "mount -t tmpfs -o size=2M,mode=0755 tmpfs $new_mount_dir"
        rlRun "chown pkiuser:pkiuser $new_mount_dir"
        # Add appropriate selinux context to the partition:
        semanage_loc="/usr/sbin/semanage"
        rlRun "$semanage_loc fcontext -a -t pki_tomcat_log_t $new_mount_dir"
        rlRun "restorecon -vR $new_mount_dir"
        partition_created="true"

        if [ $partition_created = "true" ]; then
                #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak015"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s,log.instance.SignedAudit.fileName=.*,log.instance.SignedAudit.fileName=$new_mount_dir/tps-audit.log,g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf
                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Check and delete audit failure message from error log
                #no error log file

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
                passwd="redhat"
                rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers015.ldif"
                rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers015.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
                ldap_user=$(cat $TmpDir/ldapusers015.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

                rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format015.test"
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format015.test
                /usr/bin/tpsclient < $TmpDir/format015.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0060.test"
                gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0060.test
                /usr/bin/tpsclient < $TmpDir/enroll0060.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

                #Fill the disk
                rlRun "dd if=/dev/zero of=$new_mount_dir/bigfile bs=10K count=117"
#change ownership of the file
                rlRun "chown pkiuser: $new_mount_dir/bigfile"

                /usr/bin/tpsclient < $TmpDir/format015.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                /usr/bin/tpsclient < $TmpDir/format015.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                /usr/bin/tpsclient < $TmpDir/format015.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                /usr/bin/tpsclient < $TmpDir/enroll0060.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

                #Remove this when the bug is fixed
                /usr/bin/tpsclient < $TmpDir/format015.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                #Check the error log for message for failure to write to audit log
                rlFail "No Audit log messages - https://fedorahosted.org/pki/ticket/1006 and https://fedorahosted.org/pki/ticket/1007"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

                # restore CS.cfg
                rlRun "cp $tps_conf_bak $tps_conf"
		rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
                #Cleanup partition
                rlRun "umount $new_mount_dir"
                rlRun "rm -rf $new_mount_dir"
		rlRun "rm -rf $tps_conf_bak"

        fi
	rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-016: TPS process shutdown when the signed audit log (disk) is full - PKI ticket 1006"
        header_016="$TmpDir/header016"
        local tps_out="$TmpDir/admin_out_tpsenroll0061"
        local cuid="10000000000000000061"
        partition_created="false"
        new_mount_dir="/tps-audit-log1"
        #Create 2M ram-disk for the audit logs
        rlRun "mkdir $new_mount_dir"
        rlRun "mount -t tmpfs -o size=2M,mode=0755 tmpfs $new_mount_dir"
        rlRun "chown pkiuser:pkiuser $new_mount_dir"
        # Add appropriate selinux context to the partition:
        semanage_loc="/usr/sbin/semanage"
        rlRun "$semanage_loc fcontext -a -t pki_tomcat_log_t $new_mount_dir"
        rlRun "restorecon -vR $new_mount_dir"
        partition_created="true"

        if [ $partition_created = "true" ]; then
                #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak016"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s,log.instance.SignedAudit.fileName=.*,log.instance.SignedAudit.fileName=$new_mount_dir/tps-audit.log,g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.signedAuditCertNickname=.*/log.instance.SignedAudit.signedAuditCertNickname=$(eval echo \$${TPS_INST}_AUDIT_SIGNING_CERT_NICKNAME)/g" $tps_conf
                rlLog "$(cat $tps_conf | grep log.instance.SignedAudit.fileName)"
                rlLog "$(cat $tps_conf | grep log.instance.SignedAudit.logSigning)"
                rlLog "$(cat $tps_conf | grep log.instance.SignedAudit.signedAuditCertNickname)"
                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Check and delete audit failure message from error log
                #no error log file

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
                passwd="redhat"
                rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers016.ldif"
                rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers016.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
                ldap_user=$(cat $TmpDir/ldapusers016.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

                rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format016.test"
		gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format016.test
                /usr/bin/tpsclient < $TmpDir/format016.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0061.test"
                gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0061.test
                /usr/bin/tpsclient < $TmpDir/enroll0061.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

                #Fill the disk
                rlRun "dd if=/dev/zero of=$new_mount_dir/bigfile bs=10K count=117"
                #change ownership of the file
                rlRun "chown pkiuser: $new_mount_dir/bigfile"

                /usr/bin/tpsclient < $TmpDir/format016.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                /usr/bin/tpsclient < $TmpDir/format016.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                /usr/bin/tpsclient < $TmpDir/format016.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                /usr/bin/tpsclient < $TmpDir/enroll0061.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

                #Remove this when the bug is fixed
                /usr/bin/tpsclient < $TmpDir/format016.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

                #Check the error log for message for failure to write to audit log
                rlFail "No Audit log messages - https://fedorahosted.org/pki/ticket/1006 and https://fedorahosted.org/pki/ticket/1007"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

                # restore CS.cfg
                rlRun "cp $tps_conf_bak $tps_conf"
                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
                #Cleanup partition
                rlRun "umount $new_mount_dir"
                rlRun "rm -rf $new_mount_dir"
                rlRun "rm -rf $tps_conf_bak"

        fi
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-017: Audit messages are flushed to the log file for every given flush interval - PKI ticket 1006"
        header_017="$TmpDir/header017"
        local tps_out="$TmpDir/admin_out_tpsenroll0062"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak017"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=4096/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf
                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"
                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers017.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers017.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers017.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        rlLog "$i"
        done

        #Wait for flush interval
        rlRun "sleep 5"

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-018: Audit messages are flushed to the log file for every given flush interval when the flush interval is longer - PKI ticket 1006"
        header_018="$TmpDir/header018"
        local tps_out="$TmpDir/admin_out_tpsenroll0063"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak018"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=8192/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=123/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf
                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers018.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers018.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers018.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done
        #Wait for flush interval
        rlRun "sleep 123"

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-019: Audit messages are flushed to the log file for every given flush interval when the flush interval is 0 - PKI ticket 1006"
        header_019="$TmpDir/header019"
        local tps_out="$TmpDir/admin_out_tpsenroll0064"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak019"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=512/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=0/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf
                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers019.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers019.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers019.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done


        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd



        rlPhaseStartTest "pki_tps_enrollments-020: Audit messages are flushed to the log file for every given flush interval when file type is RollingLog - PKI ticket 1006"
        header_020="$TmpDir/header020"
        local tps_out="$TmpDir/admin_out_tpsenroll0065"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak020"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=4096/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers020.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers020.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers020.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done
        #Wait for flush interval
        rlRun "sleep 5"

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd


        rlPhaseStartTest "pki_tps_enrollments-021: Audit messages are flushed to the log file for every given flush interval when file type is RollingLog and longer flush interval - PKI ticket 1006"
        header_021="$TmpDir/header021"
        local tps_out="$TmpDir/admin_out_tpsenroll0066"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak021"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=8192/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=123/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers021.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers021.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers021.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 123"

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd



        rlPhaseStartTest "pki_tps_enrollments-022: Audit messages are flushed to the log file for every given flush interval when file type is RollingLog and flush interval is 0 - PKI ticket 1006"
        header_022="$TmpDir/header022"
        local tps_out="$TmpDir/admin_out_tpsenroll0067"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak022"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=512/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=0/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers022.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers022.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers022.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd



        rlPhaseStartTest "pki_tps_enrollments-023: Audit messages are flushed to the log file for every given flush interval when file type is RollingLog, buffer size is very small and flush interval is 5s - PKI ticket 1006"
        header_023="$TmpDir/header023"
        local tps_out="$TmpDir/admin_out_tpsenroll0068"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak023"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=512/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers023.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers023.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers023.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 5"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd



        rlPhaseStartTest "pki_tps_enrollments-024: Audit messages are flushed to the log file for every given flush interval when file type is RollingLog and buffer size is 0 - PKI ticket 1006"
        header_024="$TmpDir/header024"
        local tps_out="$TmpDir/admin_out_tpsenroll0069"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak024"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=0/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=false/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers024.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers024.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers024.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd



        rlPhaseStartTest "pki_tps_enrollments-025: Audit messages are flushed to the log file for every given flush interval when log signing is enabled - PKI ticket 1006"
        header_025="$TmpDir/header025"
        local tps_out="$TmpDir/admin_out_tpsenroll0070"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak025"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=4096/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers025.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers025.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers025.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 5"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd




        rlPhaseStartTest "pki_tps_enrollments-026: Audit messages are flushed to the log file for every given flush interval when log signing is enabled and flush interval is longer - PKI ticket 1006"
        header_026="$TmpDir/header026"
        local tps_out="$TmpDir/admin_out_tpsenroll0071"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak026"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=8192/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=123/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers026.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers026.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers026.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 123"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-027: Audit messages are flushed to the log file for every given flush interval when log signing is enabled and flush interval is 0 - PKI ticket 1006"
        header_027="$TmpDir/header027"
        local tps_out="$TmpDir/admin_out_tpsenroll0072"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak027"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=512/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.LogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=0/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers027.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers027.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers026.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done


        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-028: Audit messages are flushed to the log file for every given flush interval when log signing is enabled and RollingLogFile type - PKI ticket 1006"
        header_028="$TmpDir/header028"
        local tps_out="$TmpDir/admin_out_tpsenroll0073"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak028"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=4096/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers028.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers028.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers028.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 5"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-029: Audit messages are flushed to the log file for longer flush interval when log signing is enabled and RollingLogFile type - PKI ticket 1006"
        header_029="$TmpDir/header029"
        local tps_out="$TmpDir/admin_out_tpsenroll0074"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak029"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=8192/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=123/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers029.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers029.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers029.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1

        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done
        #Wait for flush interval
        rlRun "sleep 123"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-030: Audit messages are flushed to the log file when flush interval is 0 when log signing is enabled and RollingLogFile type - PKI ticket 1006"
        header_030="$TmpDir/header030"
        local tps_out="$TmpDir/admin_out_tpsenroll0075"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak030"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=512/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=0/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"
                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers030.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers030.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers030.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-031: Audit messages are flushed to the log file when flush interval is 5 when log signing is enabled, RollingLogFile type and buffer size is very small - PKI ticket 1006"
        header_031="$TmpDir/header031"
        local tps_out="$TmpDir/admin_out_tpsenroll0076"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak031"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=512/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers031.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers031.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers031.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 5"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-032: Audit messages are flushed to the log file when flush interval is 5 when log signing is enabled, RollingLogFile type and buffer size is 0 - PKI ticket 1006"
        header_032="$TmpDir/header032"
        local tps_out="$TmpDir/admin_out_tpsenroll0077"
        #Make tps CS.cfg audit log to write to the new partition
                tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
                tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak032"
                rlRun "cp $tps_conf $tps_conf_bak"
                sed -i -e "s/log.instance.SignedAudit.bufferSize=.*/log.instance.SignedAudit.bufferSize=0/g" $tps_conf
                sed -i -e "s/log.impl.file.class=.*/log.impl.file.class=com.netscape.cms.logging.RollingLogFile/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.flushInterval=.*/log.instance.SignedAudit.flushInterval=5/g" $tps_conf
                sed -i -e "s/log.instance.SignedAudit.logSigning=.*/log.instance.SignedAudit.logSigning=true/g" $tps_conf

                rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

                #Delete audit log file
                audit_log=$(cat $tps_conf | grep log.instance.SignedAudit.fileName | cut -d= -f2)
                #rlRun "rm -rf $audit_log"

                rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        i=1
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 4 > $TmpDir/ldapusers032.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers032.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        while [ $i -lt 5 ]; do
        local tps_out="$TmpDir/admin_out_tpsenroll00$i"
        if [ $i -lt 10 ]; then
                cuid="4000000000000000000$i"
        else
                cuid="400000000000000000$i"
        fi
        ldap_user=$(cat $TmpDir/ldapusers032.ldif | grep -x "uid: idmuser$i" | cut -d ':' -f2 | tr -d ' ')
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll00$i.test
        /usr/bin/tpsclient < $TmpDir/enroll00$i.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        i=$((i+1))
        done

        #Wait for flush interval
        rlRun "sleep 5"
        #Verify audit log for each enrollment. I am checking just one here because audit log does not have any messages. Change it for all users once the bug is fixed.
        rlAssertGrep "idmuser1" "$audit_log"
        rlLog "https://fedorahosted.org/pki/ticket/1006"
        rlLog "https://fedorahosted.org/pki/ticket/1007"
        i=1
        while [ $i -lt 5 ]; do
                if [ $i -lt 10 ]; then
                        cuid="4000000000000000000$i"
                else
                        cuid="400000000000000000$i"
                fi
                if [ $i -lt 10 ]; then
                        ldap_user="idmuser$i"
                else
                        ldap_user="idmuser$i"
                fi
                gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format00$i.test
                /usr/bin/tpsclient < $TmpDir/format00$i.test > $tps_out 2>&1
                rlRun "sleep 20"
                rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
		rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
                rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
                i=$((i+1))
        done
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        # restore CS.cfg
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-033: Edit the authenticator port - BZ 643446"
        header_033="$TmpDir/header033"
        local tps_out="$TmpDir/admin_out_tpsenroll0078"
        local cuid="10000000000000000078"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Review the authenticator 1"
        rlRun "curl --dump-header  $header_033 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1 > $TmpDir/currentstate033"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
        rlAssertGrep "<Property name=\"auths.instance.ldap1.ldap.ldapconn.port\">$(eval echo \$${TPS_INST}_LDAP_PORT)" "$TmpDir/currentstate033"
        rlAssertGrep "<Status>Enabled" "$TmpDir/currentstate033"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1192232"
	# Remove the below when bug 1192232 is fixed
        rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=enable > $TmpDir/changestate033"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"

                rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=disable > $TmpDir/changestate033"
                rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
        rlLog "Download authenticator 1"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-authenticator-show ldap1 --output $TmpDir/auth033"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-authenticator-show ldap1 --output $TmpDir/auth033" 0 "Download authenticator ldap1"

        rlLog "Set the authenticator port to 1234"
        sed -i -e "s/<Property name=\"auths.instance.ldap1.ldap.ldapconn.port\">$(eval echo \$${TPS_INST}_LDAP_PORT)/<Property name=\"auths.instance.ldap1.ldap.ldapconn.port\">1234/g" $TmpDir/auth033
        rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/auth033 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1 > $TmpDir/changeorder033"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
	#The server has to restarted because of https://bugzilla.redhat.com/show_bug.cgi?id=643446. Remove these lines once the bug is fixed. I am doing this because the further tests are failing if this not done.
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=enable > $TmpDir/changestate033"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
        rlAssertGrep "<Status>Enabled" "$TmpDir/changestate033"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers033.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers033.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers033.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0078.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0078.test
        /usr/bin/tpsclient < $TmpDir/enroll0078.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format033.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format033.test
        /usr/bin/tpsclient < $TmpDir/format033.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"
        #Revert back the change
        rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                       -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=disable > $TmpDir/changestate033"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"

        sed -i -e "s/<Property name=\"auths.instance.ldap1.ldap.ldapconn.port\">1234/<Property name=\"auths.instance.ldap1.ldap.ldapconn.port\">$(eval echo \$${TPS_INST}_LDAP_PORT)/g" $TmpDir/auth033
        rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/auth033 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1 > $TmpDir/changeorder033"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
	#The server has to restarted because of https://bugzilla.redhat.com/show_bug.cgi?id=643446. Remove these lines once the bug is fixed.
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "curl --dump-header  $header_033 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=enable > $TmpDir/changestate033"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_033"
        rlAssertGrep "<Status>Enabled" "$TmpDir/changestate033"

        /usr/bin/tpsclient < $TmpDir/enroll0078.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        /usr/bin/tpsclient < $TmpDir/format033.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-034: Delete authenticator"
        header_034="$TmpDir/header034"
        local tps_out="$TmpDir/admin_out_tpsenroll0079"
        local cuid="10000000000000000079"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Review the authenticator 1"
        rlRun "curl --dump-header  $header_034 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1 > $TmpDir/currentstate034"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_034"
        rlAssertGrep "<Status>Enabled" "$TmpDir/currentstate034"
                rlRun "curl --dump-header  $header_034 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=disable > $TmpDir/changestate034"
                rlAssertGrep "HTTP/1.1 200 OK" "$header_034"
        rlLog "Download authenticator 1"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-authenticator-show ldap1 --output $TmpDir/auth034"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-authenticator-show ldap1 --output $TmpDir/auth034" 0 "Download authenticator ldap1"

        rlRun "curl --dump-header  $header_034 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1 > $TmpDir/deleteauth034"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_034"
        rlAssertNotGrep "ldap1" "$TmpDir/deleteauth034"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers034.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers034.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers034.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0079.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0079.test
        /usr/bin/tpsclient < $TmpDir/enroll0079.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format034.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format034.test
        /usr/bin/tpsclient < $TmpDir/format034.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        rlLog "Create a new authenticator 1"
        rlRun "curl --dump-header  $header_034 \
                       -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X POST \
                        --data @$TmpDir/auth034 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators > $TmpDir/addauth034"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 201 Created" "$header_034"
        rlAssertGrep "ldap1" "$TmpDir/addauth034"

        rlRun "curl --dump-header  $header_034 \
                    -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                    -X POST \
                    -k https://$tmp_tps_host:$target_secure_port/tps/rest/authenticators/ldap1?action=enable > $TmpDir/changestate034"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_034"

        /usr/bin/tpsclient < $TmpDir/enroll0079.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        /usr/bin/tpsclient < $TmpDir/format034.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	#tps40 expects enrollment to fail when applet.delete_old is false but it is not so. Also seeing an internal server error during edit config param
        rlPhaseStartTest "pki_tps_enrollments-035: Edit general configuration - BZ 1195895"
        header_035="$TmpDir/header035"
        local tps_out="$TmpDir/admin_out_tpsenroll0080"
        local cuid="10000000000000000080"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Review general configuration"
        rlRun "curl --dump-header  $header_035 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/config > $TmpDir/config035"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
        rlAssertGrep "<Property name=\"applet.delete_old\">true" "$TmpDir/config035"
        rlLog "Download general config"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-config-show --output $TmpDir/config035"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-config-show --output $TmpDir/config035" 0 "Download general configuration"

        rlLog "Set applet.delete_old to false"
        sed -i -e "s/<Property name=\"applet.delete_old\">true/<Property name=\"applet.delete_old\">false/g" $TmpDir/config035
        rlRun "curl --dump-header  $header_035 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/config035 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/config > $TmpDir/changeapplet035"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
        rlAssertGrep "<Property name=\"applet.delete_old\">false" "$TmpDir/changeapplet035"
	rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1195895"
        rlRun "curl --dump-header  $header_035 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/config > $TmpDir/config035"

        rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
        rlAssertGrep "<Property name=\"applet.delete_old\">false" "$TmpDir/config035"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers035.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers035.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers035.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0080.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0080.test
        /usr/bin/tpsclient < $TmpDir/enroll0080.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format035.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format035.test
        /usr/bin/tpsclient < $TmpDir/format035.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"
        #Revert back the change

        sed -i -e "s/<Property name=\"applet.delete_old\">false/<Property name=\"applet.delete_old\">true/g" $TmpDir/config035

        rlRun "curl --dump-header  $header_035 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/config035 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/config > $TmpDir/changeapplet035"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
        rlAssertGrep "<Property name=\"applet.delete_old\">true" "$TmpDir/changeapplet035"

        rlRun "curl --dump-header  $header_035 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/config > $TmpDir/config035"

        rlAssertGrep "HTTP/1.1 200 OK" "$header_035"
        rlAssertGrep "<Property name=\"applet.delete_old\">true" "$TmpDir/config035"

        /usr/bin/tpsclient < $TmpDir/enroll0080.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        /usr/bin/tpsclient < $TmpDir/format035.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-036: Edit key recovery properties of userKey profile"
        header_036="$TmpDir/header036"
        local tps_out="$TmpDir/admin_out_tpsenroll0081"
        local cuid="10000000000000000081"
        local new_cuid="10000000000000000082"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Check the status of userKey Profile is Enabled"
        rlRun "curl --dump-header  $header_036 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate036"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate036"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">RecoverLast" "$TmpDir/currentstate036"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile036"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile036" 0 "Download user key profile to a file"
        rlLog "Agent disables the profile userKey"
        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate036"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Edit the userKey Profile xml file by changing the keyRecovery scheme param"
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">RecoverLast/<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">GenerateNewKeyandRecoverLast/g" $TmpDir/userkey-profile036
        rlLog "Edit userKey profile - changing the keyRecovery scheme param"
        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile036 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize036"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize036"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Agent user approve and enable the profile"
        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate036"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlRun "curl --dump-header  $header_036 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate036"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">GenerateNewKeyandRecoverLast" "$TmpDir/currentstate036"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate036"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
 passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers036.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers036.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        local ldap_user=$(cat $TmpDir/ldapusers036.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0081.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0081.test
        /usr/bin/tpsclient < $TmpDir/enroll0081.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token"
        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=DAMAGED > $TmpDir/changestate036"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlRun "curl --dump-header  $header_036 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate036"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "<Status>DAMAGED</Status>" "$TmpDir/currentstate036"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0082.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0082.test
        /usr/bin/tpsclient < $TmpDir/enroll0082.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Verify there are 2 encryption certs

        #rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep $cuid > $TmpDir/tokencert.out"
        #rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep $cuid > $TmpDir/tokencert.out"
        #numofentries=$(cat $TmpDir/tokencert.out | grep Token | wc -l)
        #rlLog "$numofentries"
        #if [ numofentries = 3 ]; then
        #        rlPass "The token has 3 certificates"
        #fi


        #Add Damaged to format transition to CS.cfg

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak036"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=0:0,0:4,4:0,1:0/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format036.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format036.test
        /usr/bin/tpsclient < $TmpDir/format036.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format036.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format036.test
        /usr/bin/tpsclient < $TmpDir/format036.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $new_cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""


        #Revert back the changes

        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate036"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"

        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">GenerateNewKeyandRecoverLast/<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">RecoverLast/g" $TmpDir/userkey-profile036
        rlLog "Edit userKey profile - changing the keyRecovery scheme param"
        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile036 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize036"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize036"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Agent user approve and enable the profile"
        rlRun "curl --dump-header  $header_036 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate036"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlRun "curl --dump-header  $header_036 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate036"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_036"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme\">RecoverLast" "$TmpDir/currentstate036"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate036"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"

        #Enroll a new token
        cuid="10000000000000000083"
        ldap_user=$(cat $TmpDir/ldapusers036.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0083.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0083.test
        /usr/bin/tpsclient < $TmpDir/enroll0083.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Verify there are 3 certs - Find the certs on a token when a token ID is provided, feature does not exist

        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep $cuid > $TmpDir/tokencert.out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep $cuid > $TmpDir/tokencert.out"
        numofentries=$(cat $TmpDir/tokencert.out | grep Token | wc -l)
        rlLog "$numofentries"
        if [ numofentries = 2 ]; then
                rlPass "Changes have been reverted successfully"
        fi

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format036.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format036.test
        /usr/bin/tpsclient < $TmpDir/format036.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-037: Edit the params that determine the cert revocation in tokenKey profile - BZ 1192232"
        header_037="$TmpDir/header037"
        local tps_out="$TmpDir/admin_out_tpsenroll0084"
        local cuid="10000000000000000084"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "Check the status of tokenKey Profile is Enabled"
        rlRun "curl --dump-header  $header_037 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey > $TmpDir/currentstate037"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlAssertGrep "<Property name=\"op.format.tokenKey.revokeCert\">true" "$TmpDir/currentstate037"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate037"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1192232"
        # Remove the below when bug 1192232 is fixed
        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey?action=enable > $TmpDir/changestate037"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"

        rlLog "Download tokenKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show tokenKey --output $TmpDir/tokenkey-profile037"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show tokenKey --output $TmpDir/tokenkey-profile037" 0 "Download user key profile to a file"
        rlLog "Agent disables the profile tokenKey"
        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey?action=disable > $TmpDir/changestate037"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlLog "Edit the tokenKey Profile xml file revokeCert property"
        sed -i -e "s/<Property name=\"op.format.tokenKey.revokeCert\">true/<Property name=\"op.format.tokenKey.revokeCert\">false/g" $TmpDir/tokenkey-profile037
        rlLog "Edit userKey profile - revokeCert parameter"
        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/tokenkey-profile037 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey > $TmpDir/changekeysize037"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize037"
        rlLog "Agent user approve and enable the profile"
        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey?action=approve > $TmpDir/changestate037"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlRun "curl --dump-header  $header_037 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey > $TmpDir/currentstate037"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlAssertGrep "<Property name=\"op.format.tokenKey.revokeCert\">false" "$TmpDir/currentstate037"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate037"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers037.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers037.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers037.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0084.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0084.test
        /usr/bin/tpsclient < $TmpDir/enroll0084.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #to check if there are encryption and signing certs - not complete
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format037.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format037.test
        /usr/bin/tpsclient < $TmpDir/format037.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-cert-find | grep -B2 $cuid > $TmpDir/tokencert.out"
        numofentries=$(cat $TmpDir/tokencert.out | grep Serial | wc -l)
        serial=$(cat $TmpDir/tokencert.out | grep 'Serial Number' | cut -d ':' -f2 |  tr -d ' ')
        for j in ${serial[@]}; do
                rlLog "$j"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $tmp_ca_admin -h $tmp_tps_host -p $target_unsecure_port cert-show $j > $TmpDir/keysizecheck.out"
                rlAssertGrep "Status: VALID" "$TmpDir/keysizecheck.out"
        done

        #Revert the changes

        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey?action=disable > $TmpDir/changestate037"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlLog "Edit the tokenKey Profile xml file revokeCert property"
        sed -i -e "s/<Property name=\"op.format.tokenKey.revokeCert\">false/<Property name=\"op.format.tokenKey.revokeCert\">true/g" $TmpDir/tokenkey-profile037
        rlLog "Edit userKey profile - revokeCert parameter"
        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/tokenkey-profile037 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey > $TmpDir/changekeysize037"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize037"
        rlLog "Agent user approve and enable the profile"
        rlRun "curl --dump-header  $header_037 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey?action=approve > $TmpDir/changestate037"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlRun "curl --dump-header  $header_037 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/tokenKey > $TmpDir/currentstate037"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_037"
        rlAssertGrep "<Property name=\"op.format.tokenKey.revokeCert\">true" "$TmpDir/currentstate037"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate037"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0084.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0084.test
        /usr/bin/tpsclient < $TmpDir/enroll0084.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format037.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format037.test
        /usr/bin/tpsclient < $TmpDir/format037.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""

        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-038: TPS operations.allowedTransitions - default configuration - Format an uninitialized token (0:0)"
        header_038="$TmpDir/header038"
        local tps_out="$TmpDir/admin_out_tpsenroll038"
        local cuid="10000000000000000085"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers038.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers038.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers038.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Format an uninitialized token"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format038.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format038.test
        /usr/bin/tpsclient < $TmpDir/format038.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlPhaseEnd



        rlPhaseStartTest "pki_tps_enrollments-039: TPS operations.allowedTransitions - default configuration - Enroll a formatted token (0:4)"
        local cuid="10000000000000000085"
        local tps_out="$TmpDir/admin_out_tpsenroll039"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test
        /usr/bin/tpsclient < $TmpDir/enroll0085.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format039.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format039.test
        /usr/bin/tpsclient < $TmpDir/format039.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-040: TPS operations.allowedTransitions - Mark the Enrolled token temporarily lost, format the token"
        local cuid="10000000000000000085"
        header_040="$TmpDir/header040"
        local tps_out="$TmpDir/admin_out_tpsenroll040"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test
        /usr/bin/tpsclient < $TmpDir/enroll0085.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_040 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate040"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_040"
        rlRun "curl --dump-header  $header_040 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate040"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_040"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate040"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format040.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format040.test
        /usr/bin/tpsclient < $TmpDir/format039.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        #Cleanup
        rlLog "Mark the token as found and then format"
        rlRun "curl --dump-header  $header_040 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=ACTIVE > $TmpDir/changestate040"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_040"
        rlRun "curl --dump-header  $header_040 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate040"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_040"
        rlAssertGrep "<Status>ACTIVE</Status>" "$TmpDir/currentstate040"

        /usr/bin/tpsclient < $TmpDir/format039.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-041: TPS operations.allowedTransitions - Mark the Enrolled token temporarily lost, enroll the token"
        local cuid="10000000000000000085"
        header_041="$TmpDir/header041"
        local tps_out="$TmpDir/admin_out_tpsenroll041"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test
        /usr/bin/tpsclient < $TmpDir/enroll0085.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_041 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate041"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_041"
        rlRun "curl --dump-header  $header_041 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate041"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_041"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate041"

        /usr/bin/tpsclient < $TmpDir/enroll0085.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup
        rlLog "Mark the token as found and then format"
        rlRun "curl --dump-header  $header_041 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=ACTIVE > $TmpDir/changestate041"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_041"
        rlRun "curl --dump-header  $header_041 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate041"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_041"
        rlAssertGrep "<Status>ACTIVE</Status>" "$TmpDir/currentstate041"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format41.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format041.test
        /usr/bin/tpsclient < $TmpDir/format041.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-042: TPS operations.allowedTransitions - Mark the Enrolled token temporarily lost, temp token issued, mark the temporary lost token to be permanently lost - format or enroll perm lost token"
        local cuid="10000000000000000085"
        local new_cuid="10000000000000000086"
        header_042="$TmpDir/header042"
        local tps_out="$TmpDir/admin_out_tpsenroll042"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0085.test
        /usr/bin/tpsclient < $TmpDir/enroll0085.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_042 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate042"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_042"
        rlRun "curl --dump-header  $header_042 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate042"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_042"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate042"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0086.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0086.test
        /usr/bin/tpsclient < $TmpDir/enroll0086.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Temporarily lost token is permanently lost"
        rlRun "curl --dump-header  $header_042 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST_PERM_LOST > $TmpDir/changestate042"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_042"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/changestate042"

        /usr/bin/tpsclient < $TmpDir/enroll0085.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format42.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format042.test
        /usr/bin/tpsclient < $TmpDir/format042.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_042 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken042"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_042"

        rlRun "curl --dump-header  $header_042 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken042"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_042"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken042"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format42.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format042.test
        /usr/bin/tpsclient < $TmpDir/format042.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-043: TPS operations.allowedTransitions - Mark the Enrolled token temporarily lost, temp token is not issued, mark the temporary lost token to be permanently lost - format or enroll perm lost token"
        local cuid="10000000000000000086"
        header_043="$TmpDir/header043"
        local tps_out="$TmpDir/admin_out_tpsenroll043"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0086.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0086.test
        /usr/bin/tpsclient < $TmpDir/enroll0086.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_043 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate043"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_043"
        rlRun "curl --dump-header  $header_043 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate043"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_043"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate043"


        rlLog "Change the state of the token - Temporarily lost token is permanently lost"
        rlRun "curl --dump-header  $header_043 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST_PERM_LOST > $TmpDir/changestate043"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_043"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/changestate043"

        /usr/bin/tpsclient < $TmpDir/enroll0086.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format43.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format043.test
        /usr/bin/tpsclient < $TmpDir/format043.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"
        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_043 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken043"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_043"

        rlRun "curl --dump-header  $header_043 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken043"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_043"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken043"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-044: TPS operations.allowedTransitions - Mark the Enrolled token temporarily lost, temp token is issued - format the temp token"
        local cuid="10000000000000000087"
        local new_cuid="10000000000000000088"
        header_044="$TmpDir/header044"
        local tps_out="$TmpDir/admin_out_tpsenroll044"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        #passwd="redhat"
        #rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers044.ldif"
        #rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers044.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        #ldap_user=$(cat $TmpDir/ldapusers044.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0087.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0087.test
        /usr/bin/tpsclient < $TmpDir/enroll0087.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_044 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate044"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_044"
        rlRun "curl --dump-header  $header_044 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate044"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_044"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate044"


        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0087.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0087.test
        /usr/bin/tpsclient < $TmpDir/enroll0087.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format44.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format044.test
        /usr/bin/tpsclient < $TmpDir/format044.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlLog "Delete temporarily lost token"
        rlRun "curl --dump-header  $header_044 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken044"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_044"

        rlRun "curl --dump-header  $header_044 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken044"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_044"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken044"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-045: TPS operations.allowedTransitions - Mark the Enrolled token temporarily lost, temp token issued, mark the temporary lost token to be permanently lost - format the temp token"
        local cuid="10000000000000000088"
        local new_cuid="10000000000000000089"
        header_045="$TmpDir/header045"
        local tps_out="$TmpDir/admin_out_tpsenroll045"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_045 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate045"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_045"
        rlRun "curl --dump-header  $header_045 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate045"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_045"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate045"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"


        rlLog "Change the state of the token - Temporarily lost token is permanently lost"
        rlRun "curl --dump-header  $header_045 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST_PERM_LOST > $TmpDir/changestate045"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_045"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/changestate045"

        rlLog "Format the temporary token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format45.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format045.test
        /usr/bin/tpsclient < $TmpDir/format045.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_045 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken045"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_045"

        rlRun "curl --dump-header  $header_045 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken045"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_045"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken045"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-046: TPS operations.allowedTransitions - Mark the Enrolled token permanently lost, format the token"
        local cuid="10000000000000000089"
        header_046="$TmpDir/header046"
        local tps_out="$TmpDir/admin_out_tpsenroll046"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to permanently lost"
        rlRun "curl --dump-header  $header_046 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=PERM_LOST > $TmpDir/changestate046"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_046"
        rlRun "curl --dump-header  $header_046 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate046"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_046"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/currentstate046"


        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format046.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format046.test
        /usr/bin/tpsclient < $TmpDir/format046.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_046 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken046"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_046"

        rlRun "curl --dump-header  $header_046 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken046"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_046"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken046"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-047: TPS operations.allowedTransitions - Mark the Enrolled token permanently lost, enroll the token"
        local cuid="10000000000000000089"
        header_047="$TmpDir/header047"
        local tps_out="$TmpDir/admin_out_tpsenroll047"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to permanently lost"
        rlRun "curl --dump-header  $header_047 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=PERM_LOST > $TmpDir/changestate047"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_047"
        rlRun "curl --dump-header  $header_047 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate047"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_047"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/currentstate047"


        rlLog "Enroll the token"
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_047 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken047"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_047"

        rlRun "curl --dump-header  $header_047 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken047"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_047"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken047"
        rlPhaseEnd



rlPhaseStartTest "pki_tps_enrollments-048: TPS operations.allowedTransitions - Mark the Enrolled token physically damaged, format the token"
        local cuid="10000000000000000089"
        header_048="$TmpDir/header048"
        local tps_out="$TmpDir/admin_out_tpsenroll048"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to physically damaged"
        rlRun "curl --dump-header  $header_048 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=DAMAGED > $TmpDir/changestate048"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_048"
        rlRun "curl --dump-header  $header_048 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate048"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_048"
        rlAssertGrep "<Status>DAMAGED</Status>" "$TmpDir/currentstate048"

        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format048.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format048.test
        /usr/bin/tpsclient < $TmpDir/format048.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete the damaged token"
        rlRun "curl --dump-header  $header_048 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken048"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_048"

        rlRun "curl --dump-header  $header_048 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken048"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_048"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken048"
        rlPhaseEnd


rlPhaseStartTest "pki_tps_enrollments-049: TPS operations.allowedTransitions - Mark the Enrolled token physically damaged, enroll the token"
        local cuid="10000000000000000089"
        header_049="$TmpDir/header049"
        local tps_out="$TmpDir/admin_out_tpsenroll049"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to physically damaged"
        rlRun "curl --dump-header  $header_049 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=DAMAGED > $TmpDir/changestate049"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_049"
        rlRun "curl --dump-header  $header_049 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate049"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_049"
        rlAssertGrep "<Status>DAMAGED</Status>" "$TmpDir/currentstate049"

        rlLog "Enroll the token"
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_049 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken049"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_049"

        rlRun "curl --dump-header  $header_049 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken049"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_049"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken049"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-050: TPS operations.allowedTransitions - Mark the Enrolled token terminated, format the token"
        local cuid="10000000000000000089"
        header_050="$TmpDir/header050"
        local tps_out="$TmpDir/admin_out_tpsenroll050"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to terminated"
        rlRun "curl --dump-header  $header_050 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TERMINATED > $TmpDir/changestate050"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_050"
        rlRun "curl --dump-header  $header_050 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate050"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_050"
        rlAssertGrep "<Status>TERMINATED</Status>" "$TmpDir/currentstate050"

        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format050.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format050.test
        /usr/bin/tpsclient < $TmpDir/format050.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete the terminated token"
        rlRun "curl --dump-header  $header_050 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken050"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_050"

        rlRun "curl --dump-header  $header_050 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken050"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_050"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken050"
        rlPhaseEnd


rlPhaseStartTest "pki_tps_enrollments-051: TPS operations.allowedTransitions - Mark the Enrolled token terminated, enroll the token"
        local cuid="10000000000000000089"
        header_051="$TmpDir/header051"
        local tps_out="$TmpDir/admin_out_tpsenroll051"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temrinated"
        rlRun "curl --dump-header  $header_051 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TERMINATED > $TmpDir/changestate051"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_051"
        rlRun "curl --dump-header  $header_051 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate051"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_051"
        rlAssertGrep "<Status>TERMINATED</Status>" "$TmpDir/currentstate051"

        rlLog "Enroll the token"
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete permanently lost token"
        rlRun "curl --dump-header  $header_051 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken051"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_051"

        rlRun "curl --dump-header  $header_051 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken051"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_051"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken051"
        rlPhaseEnd
        rlPhaseStartTest "pki_tps_enrollments-052: TPS operations.allowedTransitions - Mark the Enrolled token as physically damaged, temp token is issued"
        local cuid="10000000000000000088"
        local new_cuid="10000000000000000089"
        header_052="$TmpDir/header052"
        local tps_out="$TmpDir/admin_out_tpsenroll052"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to physically damaged"
        rlRun "curl --dump-header  $header_052 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=DAMAGED > $TmpDir/changestate052"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_052"
        rlRun "curl --dump-header  $header_052 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate052"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_052"
        rlAssertGrep "<Status>DAMAGED</Status>" "$TmpDir/currentstate052"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"


        #Cleanup
        rlLog "Format the temporary token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format52.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format052.test
        /usr/bin/tpsclient < $TmpDir/format052.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"


        rlLog "Delete the damaged token"
        rlRun "curl --dump-header  $header_052 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken052"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_052"

        rlRun "curl --dump-header  $header_052 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken052"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_052"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken052"
        rlPhaseEnd


rlPhaseStartTest "pki_tps_enrollments-053: TPS operations.allowedTransitions - Mark the Enrolled token as temporarily lost, temp token is issued, temporarily lost token is found"
        local cuid="10000000000000000088"
        local new_cuid="10000000000000000089"
        header_053="$TmpDir/header053"
        local tps_out="$TmpDir/admin_out_tpsenroll053"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_053 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate053"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_053"
        rlRun "curl --dump-header  $header_053 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate053"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_053"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate053"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        rlLog "Change the state of the token - Temp lost to temp lost token found"
        rlRun "curl --dump-header  $header_053 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=ACTIVE > $TmpDir/changestate053"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_053"
        rlRun "curl --dump-header  $header_053 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate053"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_053"
        rlAssertGrep "<Status>ACTIVE</Status>" "$TmpDir/currentstate053"

        #Cleanup
        rlLog "Format the original token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format53.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format053.test
        /usr/bin/tpsclient < $TmpDir/format053.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Format the temporary token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format53.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format053.test
        /usr/bin/tpsclient < $TmpDir/format053.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-054: TPS operations.allowedTransitions - Mark the Enrolled token as temporarily lost, no temp token is issued, temporarily lost token is found"
        local cuid="10000000000000000088"
        header_054="$TmpDir/header054"
        local tps_out="$TmpDir/admin_out_tpsenroll054"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_054 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate054"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_054"
        rlRun "curl --dump-header  $header_054 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate054"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_054"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate054"

        rlLog "Change the state of the token - Temp lost to temp lost token found"
        rlRun "curl --dump-header  $header_054 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=ACTIVE > $TmpDir/changestate054"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_054"
        rlRun "curl --dump-header  $header_054 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate054"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_054"
        rlAssertGrep "<Status>ACTIVE</Status>" "$TmpDir/currentstate054"

        #Cleanup
        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format54.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format054.test
        /usr/bin/tpsclient < $TmpDir/format054.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlPhaseEnd


rlPhaseStartTest "pki_tps_enrollments-055: TPS operations.allowedTransitions - Mark the Enrolled token as temporarily lost, temp token is issued, temporarily lost token is terminated"
        local cuid="10000000000000000088"
        local new_cuid="10000000000000000089"
        header_055="$TmpDir/header055"
        local tps_out="$TmpDir/admin_out_tpsenroll055"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_055 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate055"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_055"
        rlRun "curl --dump-header  $header_055 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate055"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_055"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate055"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Temp lost to terminated"
        rlRun "curl --dump-header  $header_055 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TERMINATED > $TmpDir/changestate055"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_055"
        rlRun "curl --dump-header  $header_055 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate055"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_055"
        rlAssertGrep "<Status>TERMINATED</Status>" "$TmpDir/currentstate055"

        #Cleanup

        rlLog "Format the temporary token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format55.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format055.test
        /usr/bin/tpsclient < $TmpDir/format055.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Delete the terminated token token"
        rlRun "curl --dump-header  $header_055 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken055"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_055"

        rlRun "curl --dump-header  $header_055 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken055"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_055"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken055"
        rlPhaseEnd



rlPhaseStartTest "pki_tps_enrollments-056: TPS operations.allowedTransitions - Mark the Enrolled token as temporarily lost, no temp token is issued, temporarily lost token is terminated"
        local cuid="10000000000000000088"
        header_056="$TmpDir/header056"
        local tps_out="$TmpDir/admin_out_tpsenroll056"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temporarily lost"
        rlRun "curl --dump-header  $header_056 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate056"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_056"
        rlRun "curl --dump-header  $header_056 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate056"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_056"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate056"

        rlLog "Change the state of the token - Temp lost to terminated"
        rlRun "curl --dump-header  $header_056 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TERMINATED > $TmpDir/changestate056"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_056"
        rlRun "curl --dump-header  $header_056 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate056"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_056"
        rlAssertGrep "<Status>TERMINATED</Status>" "$TmpDir/currentstate056"

        #Cleanup

        rlLog "Delete the terminated token token"
        rlRun "curl --dump-header  $header_056 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken056"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_056"

        rlRun "curl --dump-header  $header_056 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken056"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_056"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken056"

        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-057: TPS operations.allowedTransitions - none set"
        local cuid="10000000000000000088"
        header_057="$TmpDir/header057"
        local tps_out="$TmpDir/admin_out_tpsenroll0057"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlRun "curl --dump-header  $header_057 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken057"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_057"
	foundcuid=$(cat $TmpDir/showToken057 | grep $cuid)
        if [ -n "$foundcuid" ]; then
                rlLog "Delete the token"
        rlRun "curl --dump-header  $header_057 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken057"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_057"
        rlRun "curl --dump-header  $header_057 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken057"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_057"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken057"
        fi

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak057"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlLog "Format an uninitialized token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format057.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format057.test
        /usr/bin/tpsclient < $TmpDir/format057.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Format a formatted token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format057.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format057.test
        /usr/bin/tpsclient < $TmpDir/format057.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlPhaseEnd


rlPhaseStartTest "pki_tps_enrollments-058: TPS operations.allowedTransitions - Re-enroll a token - Failure"
        local cuid="10000000000000000088"
        header_058="$TmpDir/header058"
        local tps_out="$TmpDir/admin_out_tpsenroll058"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Re-enroll the above token to the same user"

        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup

        rlLog "Format the enrolled token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format58.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format058.test
        /usr/bin/tpsclient < $TmpDir/format058.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlPhaseEnd
rlPhaseStartTest "pki_tps_enrollments-059: TPS operations.allowedTransitions - Re-enroll a token - add transition 4:4 - Success"
        local cuid="10000000000000000088"
        header_059="$TmpDir/header059"
        local tps_out="$TmpDir/admin_out_tpsenroll059"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak059"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,4:4/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Re-enroll the above token to the same user"

        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Cleanup

        rlLog "Format the enrolled token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format59.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format059.test
        /usr/bin/tpsclient < $TmpDir/format059.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-060: TPS operations.allowedTransitions - Re-enroll a token - add transition 4:4 - RE_ENROLL=NO - Failure"
        local cuid="10000000000000000088"
        header_060="$TmpDir/header060"
        local tps_out="$TmpDir/admin_out_tpsenroll060"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak059"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,4:4/g" $tps_conf
        sed -i -e "s/^tokendb.defaultPolicy=RE_ENROLL=YES/tokendb.defaultPolicy=RE_ENROLL=NO/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rlLog "$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tokendb.defaultPolicy)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers060.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers060.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers060.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0088.test
        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Re-enroll the above token to the same user"

        /usr/bin/tpsclient < $TmpDir/enroll0088.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup

        rlLog "Format the enrolled token"
	rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format60.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format060.test
        /usr/bin/tpsclient < $TmpDir/format060.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-061: TPS operations.allowedTransitions - Mark the Enrolled token temp lost, format the token - Add transition 3:0"
        local cuid="10000000000000000089"
        header_061="$TmpDir/header061"
        local tps_out="$TmpDir/admin_out_tpsenroll061"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak061"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,3:0/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers060.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers060.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers060.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temp lost"
        rlRun "curl --dump-header  $header_061 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate061"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_061"
        rlRun "curl --dump-header  $header_061 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate061"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_061"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate061"
        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format061.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format061.test
        /usr/bin/tpsclient < $TmpDir/format061.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-062: TPS operations.allowedTransitions - Mark the Enrolled token temp lost, temp token issued, temp lost token is perm lost, format the perm lost token - Add transition 2:0"
        local cuid="10000000000000000089"
        local new_cuid="10000000000000000088"
        header_062="$TmpDir/header062"
        local tps_out="$TmpDir/admin_out_tpsenroll062"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak062"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,2:0/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers060.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers060.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers060.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temp lost"
        rlRun "curl --dump-header  $header_062 \
                -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate062"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_062"
        rlRun "curl --dump-header  $header_062 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate062"
        rlRun "sleep 5"
rlAssertGrep "HTTP/1.1 200 OK" "$header_062"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate062"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Temp lost to perm lost"
        rlRun "curl --dump-header  $header_062 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST_PERM_LOST > $TmpDir/changestate062"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_062"
        rlRun "curl --dump-header  $header_062 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate062"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_062"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/currentstate062"

        rlLog "Format the perm lost token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format062.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format062.test
        /usr/bin/tpsclient < $TmpDir/format062.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup

        rlLog "Format the temp token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format062.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format062.test
	/usr/bin/tpsclient < $TmpDir/format062.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"

	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-063: TPS operations.allowedTransitions - Mark the Enrolled token permanently lost, format the token - Add transition 2:0"
        local cuid="10000000000000000089"
        header_063="$TmpDir/header063"
        local tps_out="$TmpDir/admin_out_tpsenroll063"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak063"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,2:0/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers063.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers063.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers063.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to permanently lost"
        rlRun "curl --dump-header  $header_063 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=PERM_LOST > $TmpDir/changestate063"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_063"
        rlRun "curl --dump-header  $header_063 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate063"
        rlRun "sleep 5"
rlAssertGrep "HTTP/1.1 200 OK" "$header_063"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/currentstate063"

        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format063.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format063.test
        /usr/bin/tpsclient < $TmpDir/format063.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-064: TPS operations.allowedTransitions - Mark the Enrolled token physically damaged, format the token - Add transition 1:0"
        local cuid="10000000000000000089"
        header_064="$TmpDir/header064"
        local tps_out="$TmpDir/admin_out_tpsenroll064"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak064"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,1:0/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

         passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers064.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers064.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers064.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to permanently lost"
        rlRun "curl --dump-header  $header_064 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=DAMAGED > $TmpDir/changestate064"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_064"
        rlRun "curl --dump-header  $header_064 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate064"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_064"
        rlAssertGrep "<Status>DAMAGED</Status>" "$TmpDir/currentstate064"


        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format064.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format064.test
        /usr/bin/tpsclient < $TmpDir/format064.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-065: TPS operations.allowedTransitions - Mark the Enrolled token terminated, format the token - Add transition 6:0"
        local cuid="10000000000000000089"
        header_065="$TmpDir/header065"
        local tps_out="$TmpDir/admin_out_tpsenroll065"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak065"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,6:0/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers065.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers065.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers065.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to terminated"
        rlRun "curl --dump-header  $header_065 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TERMINATED > $TmpDir/changestate065"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_065"
        rlRun "curl --dump-header  $header_065 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate065"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_065"
        rlAssertGrep "<Status>TERMINATED</Status>" "$TmpDir/currentstate065"


        rlLog "Format the token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format065.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format065.test
        /usr/bin/tpsclient < $TmpDir/format065.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        #Cleanup
        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-066: TPS operations.allowedTransitions and tokendb.defaultPolicy - none set - BZ 1196278"
        local cuid="10000000000000000088"
        header_066="$TmpDir/header066"
        local tps_out="$TmpDir/admin_out_tpsenroll0066"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlRun "curl --dump-header  $header_066 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken066"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_066"
        foundcuid=$(cat $TmpDir/showToken066 | grep $cuid)
        if [ -n "$foundcuid" ]; then
                rlLog "Delete the token"
                rlRun "curl --dump-header  $header_066 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken066"
                rlAssertGrep "HTTP/1.1 204 No Content" "$header_066"
                rlRun "curl --dump-header  $header_066 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken066"
                rlAssertGrep "HTTP/1.1 200 OK" "$header_066"
                rlAssertNotGrep "$cuid" "$TmpDir/showToken066"
        fi

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak066"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=/g" $tps_conf
        sed -i -e "s/^tokendb.allowedTransitions=.*/tokendb.allowedTransitions=/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rlLog "Tokendb transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tokendb.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers066.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers066.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers066.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        rlLog "Format an uninitialized token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format066.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format066.test
        /usr/bin/tpsclient < $TmpDir/format066.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Format a formatted token"

        /usr/bin/tpsclient < $TmpDir/format066.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196278#c2"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
	#rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-067: TPS operations.allowedTransitions - Mark the Enrolled token terminated, enroll the token - Add transition 6:4 - BZ 1196278"
        local cuid="10000000000000000089"
        header_067="$TmpDir/header067"
        local tps_out="$TmpDir/admin_out_tpsenroll067"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak067"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,6:4/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers067.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers067.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers067.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        new_ldap_user=$(cat $TmpDir/ldapusers067.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to terminated"
        rlRun "curl --dump-header  $header_067 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TERMINATED > $TmpDir/changestate067"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_067"
        rlRun "curl --dump-header  $header_067 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate067"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_067"
        rlAssertGrep "<Status>TERMINATED</Status>" "$TmpDir/currentstate067"

        rlLog "Enroll a the token for the same user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "Enroll the token for a different user"
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196278"

        #Cleanup
        rlLog "Delete the terminated token token"
        rlRun "curl --dump-header  $header_067 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken067"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_067"

        rlRun "curl --dump-header  $header_067 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken067"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_067"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken067"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"

        new_ldap_user=$(cat $TmpDir/ldapusers067.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$new_ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-068: TPS operations.allowedTransitions - Mark the Enrolled token temp lost, enroll the token - Add transition 3:4 - BZ 1196308"
        local cuid="10000000000000000089"
        header_068="$TmpDir/header068"
        local tps_out="$TmpDir/admin_out_tpsenroll068"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak068"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,3:4/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers068.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers068.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers068.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        new_ldap_user=$(cat $TmpDir/ldapusers068.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temp lost"
        rlRun "curl --dump-header  $header_068 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate068"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_068"
        rlRun "curl --dump-header  $header_068 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate068"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_068"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate068"

        rlLog "Enroll the token for the same user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196308"

        rlLog "Enroll the token for a different user"
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete the terminated token token"
        rlRun "curl --dump-header  $header_068 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken068"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_068"

        rlRun "curl --dump-header  $header_068 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken068"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_068"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken068"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"

	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$new_ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-069: TPS operations.allowedTransitions - Mark the Enrolled token temp lost, temp token issued, temp lost token is perm lost, enroll the perm lost token - Add transition 2:4 - BZ 1196278"
        local cuid="10000000000000000089"
        local new_cuid="10000000000000000088"
        header_069="$TmpDir/header069"
        local tps_out="$TmpDir/admin_out_tpsenroll069"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak069"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,2:4/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers069.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers069.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers069.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        new_ldap_user=$(cat $TmpDir/ldapusers069.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to temp lost"
        rlRun "curl --dump-header  $header_069 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST > $TmpDir/changestate069"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_069"
        rlRun "curl --dump-header  $header_069 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate069"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_069"
        rlAssertGrep "<Status>TEMP_LOST</Status>" "$TmpDir/currentstate069"

        #Enroll a new token for the same user

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Temp lost to perm lost"
        rlRun "curl --dump-header  $header_069 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=TEMP_LOST_PERM_LOST > $TmpDir/changestate069"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_069"
        rlRun "curl --dump-header  $header_069 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate069"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_069"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/currentstate069"

        rlLog "Enroll the token for the same user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "Enroll the token for a different user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196278"

        #Cleanup

        rlLog "Format the temp token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format069.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $new_cuid $ldap_user $passwd $TmpDir/format069.test
        /usr/bin/tpsclient < $TmpDir/format069.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Delete the perm lost token token"
        rlRun "curl --dump-header  $header_069 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken069"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_069"

        rlRun "curl --dump-header  $header_069 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken069"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_069"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken069"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"

	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $new_cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$new_ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-070: TPS operations.allowedTransitions - Mark the Enrolled token physically damaged, enroll the token - Add transition 1:4 - BZ 1196278"
        local cuid="10000000000000000089"
        header_070="$TmpDir/header070"
        local tps_out="$TmpDir/admin_out_tpsenroll070"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak070"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,1:4/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers070.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers070.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers070.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        new_ldap_user=$(cat $TmpDir/ldapusers070.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to physically damaged"
        rlRun "curl --dump-header  $header_070 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=DAMAGED > $TmpDir/changestate070"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_070"
        rlRun "curl --dump-header  $header_070 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate070"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_070"
        rlAssertGrep "<Status>DAMAGED</Status>" "$TmpDir/currentstate070"

        rlLog "Enroll the token for the same user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        rlLog "Enroll the token for a different user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test"
	gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196278"

        #Cleanup
        rlLog "Delete the damaged token"
        rlRun "curl --dump-header  $header_070 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken070"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_070"

        rlRun "curl --dump-header  $header_070 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken070"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_070"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken070"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"

	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
	rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$new_ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-071: TPS operations.allowedTransitions - Mark the Enrolled token permanently lost, enroll the token - Add transition 2:4 - BZ 1196278"
        local cuid="10000000000000000089"
        header_071="$TmpDir/header071"
        local tps_out="$TmpDir/admin_out_tpsenroll071"
        rlRun "export SSL_DIR=$CERTDB_DIR"

        transitions=$(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak071"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=$transitions,2:4/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers071.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers071.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers071.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        new_ldap_user=$(cat $TmpDir/ldapusers071.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        rlLog "Change the state of the token - Enrolled to physically damaged"
        rlRun "curl --dump-header  $header_071 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid?status=PERM_LOST > $TmpDir/changestate071"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_071"
        rlRun "curl --dump-header  $header_071 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/currentstate071"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_071"
        rlAssertGrep "<Status>PERM_LOST</Status>" "$TmpDir/currentstate071"

        rlLog "Enroll the token for the same user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196278"

        rlLog "Enroll the token for a different user"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        #Cleanup
        rlLog "Delete the damaged token"
        rlRun "curl --dump-header  $header_071 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken071"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_071"

        rlRun "curl --dump-header  $header_071 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken071"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_071"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken071"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"

	rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$new_ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-072: Two Agent users approve the profile change at the same time"
        header_073="$TmpDir/header073"
        local tps_out="$TmpDir/admin_out_tpsenroll073"
        local cuid="10000000000000000073"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers073.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers073.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers073.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Check the status of userKey Profile is Enabled"
        rlRun "curl --dump-header  $header_073 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate073"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_073"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate073"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile073"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile073" 0 "Download user key profile to a file"
        rlLog "Agent disables the profile userKey"
        rlRun "curl --dump-header  $header_073 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate073"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_073"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Edit the userKey Profile xml file by changing the encryption key and signing key keySize and update the profile."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile073
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile073
        rlLog "Edit userKey profile - key size of encryption key 1024-2048 and the verify the state of the profile is pending approval"
        rlRun "curl --dump-header  $header_073 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile073 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize073"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_073"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize073"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Two Agent users approve and enable the profile"

        username="Valid_TPS_Agent"
        rlRun "pki -d $CERTDB_DIR \
                          -n \"$valid_admin_cert\" \
                          -c $CERTDB_DIR_PASSWORD \
                          -h $tmp_tps_host \
                          -t tps \
                          -p $target_unsecure_port \
                           user-add --fullName=\"$username\" $valid_agent1_cert" 0 "Add user $valid_agent1_cert to TPS"
        rlRun "pki -d $CERTDB_DIR \
                                   -n \"$valid_admin_cert\" \
                                   -c $CERTDB_DIR_PASSWORD \
                                   -h $tmp_tps_host \
                                   -t tps \
                                   -p $target_unsecure_port \
                                    group-member-add \"TPS Agents\" $valid_agent1_cert" \
                                    0 \
                                    "Add user $valid_agent1_cert to TPS Agents"
        local temp_file="$CERTDB_DIR/certrequest_001.xml"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"$tmp_ca_admin\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $tmp_tps_host \
                   -t ca \
                   -p $tmp_ca_port \
                   cert-request-profile-show caUserCert --output $temp_file" \
                   0 \
                   "Enrollment Template for Profile caUserCert"
        rlRun "generate_PKCS10 \"$CERTDB_DIR\"  \"$CERTDB_DIR_PASSWORD\" rsa 2048 \"$CERTDB_DIR/request_001.out\" \"CN=admin1V\" " 0 "generate PKCS10 certificate"
        rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $CERTDB_DIR/request_001.out"
        rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $CERTDB_DIR/request_001.out"
        rlRun "dos2unix $CERTDB_DIR/request_001.out"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v 'pkcs10' $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $CERTDB_DIR/request_001.out)\" $temp_file" 0 "adding certificate request"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v $valid_agent1_cert $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v $valid_agent1_cert@example.com $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v $username $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v Engineering $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v Example $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v US $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v $valid_agent1_cert $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v $valid_agent1_cert@example.com $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $temp_file"

        subsystem=ca
        rlLog "Executing: pki cert-request-submit  $temp_file"
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ${subsystem}-cert-request-submit $temp_file > $CERTDB_DIR/certrequest.out" 0 "Executing pki cert-request-submit"
        rlAssertGrep "Submitted certificate request" "$CERTDB_DIR/certrequest.out"
        rlAssertGrep "Request ID:" "$CERTDB_DIR/certrequest.out"
        rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequest.out"
        rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequest.out"
        local request_id=`cat $CERTDB_DIR/certrequest.out | grep "Request ID:" | awk '{print $3}'`
        rlLog "Request ID=$request_id"
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ${subsystem}-cert-request-show $request_id > $CERTDB_DIR/certrequestshow_001.out" 0 "Executing pki cert-request-show $request_id"
        rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestshow_001.out"
        rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestshow_001.out"
        rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequestshow_001.out"
        rlAssertGrep "Operation Result: success" "$CERTDB_DIR/certrequestshow_001.out"

        rlRun "pki -d $CERTDB_DIR \
                   -n \"$tmp_ca_agent\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $tmp_tps_host \
                   -t ca \
                   -p $tmp_ca_port \
                   cert-request-review $request_id --action=approve > $CERTDB_DIR/certapprove_001.out" \
                   0 \
                  "CA agent approve the cert"
        rlAssertGrep "Approved certificate request $request_id" "$CERTDB_DIR/certapprove_001.out"
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ca-cert-request-show $request_id > $CERTDB_DIR/certrequestapprovedshow_001.out" 0 "Executing pki cert-request-show $request_id"
        rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        rlAssertGrep "Status: complete" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        rlAssertGrep "Certificate ID:" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        local certificate_serial_number=`cat $CERTDB_DIR/certrequestapprovedshow_001.out | grep "Certificate ID:" | awk '{print $3}'`
        rlLog "Cerificate Serial Number=$certificate_serial_number"

        #Verify the certificate is valid
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ${subsystem}-cert-show  $certificate_serial_number --encoded > $CERTDB_DIR/certificate_show_001.out" 0 "Executing pki cert-show $certificate_serial_number"
        rlAssertGrep "Subject: UID=$valid_agent1_cert,E=$valid_agent1_cert@example.com,CN=$username,OU=Engineering,O=Example,C=US" "$CERTDB_DIR/certificate_show_001.out"
        rlAssertGrep "Status: VALID" "$CERTDB_DIR/certificate_show_001.out"

        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $CERTDB_DIR/certificate_show_001.out > $CERTDB_DIR/validcert_001.pem"
        rlRun "certutil -d $CERTDB_DIR -A -n $valid_agent1_cert -i $CERTDB_DIR/validcert_001.pem  -t "u,u,u""
        rlRun "pki -d $CERTDB_DIR/ \
                   -n \"$valid_admin_cert\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $tmp_tps_host \
                   -t tps \
                   -p $target_unsecure_port \
                   user-cert-add $valid_agent1_cert --input $CERTDB_DIR/validcert_001.pem  > $CERTDB_DIR/useraddcert_001.out" \
                   0 \
                  "Cert is added to the user $valid_agent1_cert"

        echo "$valid_agent1_cert" > $TmpDir/commands073
        echo "$valid_agent_cert" >> $TmpDir/commands073
        rlRun "sleep 5"
        rlRun "cat $TmpDir/commands073 | xargs -n2 -I % curl --dump-header  $header_073 -E \"%:$CERTDB_DIR_PASSWORD\" -X POST -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/xargs-result073" 0 "Two agents approves the profile change"
        rlAssertGrep "Enabled" "$TmpDir/xargs-result073"
        rlAssertGrep "Invalid action: approve" "$TmpDir/xargs-result073"
	rlRun "sleep 10"
        rlLog "Enroll a token"
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0073.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0073.test
        /usr/bin/tpsclient < $TmpDir/enroll0073.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Revert the changes

        rlRun "curl --dump-header  $header_073 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate073"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_073"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Edit the userKey Profile xml file by changing the encryption key and signing key keySize and update the profile."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile073
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile073
        rlLog "Edit userKey profile - key size of encryption key 1024-2048 and the verify the state of the profile is pending approval"
        rlRun "curl --dump-header  $header_073 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile073 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize073"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_073"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize073"

        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Approve as an agent user"
        rlRun "curl --dump-header  $header_073 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate073"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_073"

        rlLog "Format a token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format073.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format073.test
        /usr/bin/tpsclient < $TmpDir/format073.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
        rlRun "pki -d $CERTDB_DIR \
                          -n \"$valid_admin_cert\" \
                          -c $CERTDB_DIR_PASSWORD \
                          -h $tmp_tps_host \
                          -t tps \
                          -p $target_unsecure_port \
                           user-del $valid_agent1_cert" 0 "Delete user $valid_agent1_cert"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

        rlPhaseStartTest "pki_tps_enrollments-073: Two Admin users edit the same params at the same time"
        header_074="$TmpDir/header074"
        local tps_out="$TmpDir/admin_out_tpsenroll074"
        local cuid="10000000000000000074"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 1 > $TmpDir/ldapusers074.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers074.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers074.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Check the status of userKey Profile is Enabled"
        rlRun "curl --dump-header  $header_074 \
                -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/currentstate074"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_074"
        rlAssertGrep "<Status>Enabled</Status>" "$TmpDir/currentstate074"
        rlLog "Download userKey profile properties"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile074"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_cert -h $tmp_tps_host -p $target_unsecure_port tps-profile-show userKey --output $TmpDir/userkey-profile074" 0 "Download user key profile to a file"
        rlLog "Agent disables the profile userKey"
        rlRun "curl --dump-header  $header_074 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate074"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_074"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Edit the userKey Profile xml file by changing the encryption key and signing key keySize and update the profile."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/g" $TmpDir/userkey-profile074
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/g" $TmpDir/userkey-profile074
        rlLog "Edit userKey profile - by two admin users"

        username="Valid_TPS_Admin"
        rlRun "pki -d $CERTDB_DIR \
                          -n \"$valid_admin_cert\" \
                          -c $CERTDB_DIR_PASSWORD \
                          -h $tmp_tps_host \
                          -t tps \
                          -p $target_unsecure_port \
                           user-add --fullName=\"$username\" $valid_admin1_cert" 0 "Add user $valid_admin1_cert to TPS"
        rlRun "pki -d $CERTDB_DIR \
                                   -n \"$valid_admin_cert\" \
                                   -c $CERTDB_DIR_PASSWORD \
                                   -h $tmp_tps_host \
                                   -t tps \
                                   -p $target_unsecure_port \
                                    group-member-add \"Administrators\" $valid_admin1_cert" \
                                    0 \
                                    "Add user $valid_admin1_cert to Administrators"
        local temp_file="$CERTDB_DIR/certrequest_001.xml"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"$tmp_ca_admin\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $tmp_tps_host \
                   -t ca \
                   -p $tmp_ca_port \
                   cert-request-profile-show caUserCert --output $temp_file" \
                   0 \
                   "Enrollment Template for Profile caUserCert"
        rlRun "generate_PKCS10 \"$CERTDB_DIR\"  \"$CERTDB_DIR_PASSWORD\" rsa 2048 \"$CERTDB_DIR/request_001.out\" \"CN=admin1V\" " 0 "generate PKCS10 certificate"
        rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $CERTDB_DIR/request_001.out"
        rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $CERTDB_DIR/request_001.out"
        rlRun "dos2unix $CERTDB_DIR/request_001.out"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v 'pkcs10' $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $CERTDB_DIR/request_001.out)\" $temp_file" 0 "adding certificate request"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v $valid_admin1_cert $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v $valid_admin1_cert@example.com $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v $username $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v Engineering $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v Example $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v US $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v $valid_admin1_cert $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v $valid_admin1_cert@example.com $temp_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $temp_file"
        subsystem=ca
        rlLog "Executing: pki cert-request-submit  $temp_file"
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ${subsystem}-cert-request-submit $temp_file > $CERTDB_DIR/certrequest.out" 0 "Executing pki cert-request-submit"
        rlAssertGrep "Submitted certificate request" "$CERTDB_DIR/certrequest.out"
        rlAssertGrep "Request ID:" "$CERTDB_DIR/certrequest.out"
        rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequest.out"
        rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequest.out"
        local request_id=`cat $CERTDB_DIR/certrequest.out | grep "Request ID:" | awk '{print $3}'`
        rlLog "Request ID=$request_id"
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ${subsystem}-cert-request-show $request_id > $CERTDB_DIR/certrequestshow_001.out" 0 "Executing pki cert-request-show $request_id"
        rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestshow_001.out"
        rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestshow_001.out"
        rlAssertGrep "Status: pending" "$CERTDB_DIR/certrequestshow_001.out"
        rlAssertGrep "Operation Result: success" "$CERTDB_DIR/certrequestshow_001.out"

        rlRun "pki -d $CERTDB_DIR \
                   -n \"$tmp_ca_agent\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $tmp_tps_host \
                   -t ca \
                   -p $tmp_ca_port \
                   cert-request-review $request_id --action=approve > $CERTDB_DIR/certapprove_001.out" \
                   0 \
                  "CA agent approve the cert"
        rlAssertGrep "Approved certificate request $request_id" "$CERTDB_DIR/certapprove_001.out"
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ca-cert-request-show $request_id > $CERTDB_DIR/certrequestapprovedshow_001.out" 0 "Executing pki cert-request-show $request_id"
        rlAssertGrep "Request ID: $request_id" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        rlAssertGrep "Type: enrollment" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        rlAssertGrep "Status: complete" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        rlAssertGrep "Certificate ID:" "$CERTDB_DIR/certrequestapprovedshow_001.out"
        local certificate_serial_number=`cat $CERTDB_DIR/certrequestapprovedshow_001.out | grep "Certificate ID:" | awk '{print $3}'`
        rlLog "Cerificate Serial Number=$certificate_serial_number"

        #Verify the certificate is valid
        rlRun "pki -p $tmp_ca_port -h $tmp_tps_host ${subsystem}-cert-show  $certificate_serial_number --encoded > $CERTDB_DIR/certificate_show_001.out" 0 "Executing pki cert-show $certificate_serial_number"
        rlAssertGrep "Subject: UID=$valid_admin1_cert,E=$valid_admin1_cert@example.com,CN=$username,OU=Engineering,O=Example,C=US" "$CERTDB_DIR/certificate_show_001.out"
        rlAssertGrep "Status: VALID" "$CERTDB_DIR/certificate_show_001.out"

        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $CERTDB_DIR/certificate_show_001.out > $CERTDB_DIR/validcert_001.pem"
        rlRun "certutil -d $CERTDB_DIR -A -n $valid_admin1_cert -i $CERTDB_DIR/validcert_001.pem  -t "u,u,u""
        rlRun "pki -d $CERTDB_DIR/ \
                   -n \"$valid_admin_cert\" \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $tmp_tps_host \
                   -t tps \
                   -p $target_unsecure_port \
                   user-cert-add $valid_admin1_cert --input $CERTDB_DIR/validcert_001.pem  > $CERTDB_DIR/useraddcert_001.out" \
                   0 \
                  "Cert is added to the user $valid_admin1_cert"


        echo "$valid_admin1_cert" > $TmpDir/commands074
        echo "$valid_admin_cert" >> $TmpDir/commands074
        rlRun "sleep 5"
        rlRun "cat $TmpDir/commands074 | xargs -n2 -I % curl --dump-header  $header_074 -E \"%:$CERTDB_DIR_PASSWORD\" -H \"Content-Type: application/xml\" -X PATCH --data @$TmpDir/userkey-profile074 -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/xargs-result074" 0 "Two admin users edit the profile"
        rlAssertGrep "Unable to update profile userKey" "$TmpDir/xargs-result074"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048" "$TmpDir/xargs-result074"
        rlAssertGrep "<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048" "$TmpDir/xargs-result074"
        rlAssertGrep "Pending_Approval" "$TmpDir/xargs-result074"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Agent approves the profile userKey"
        rlRun "curl --dump-header  $header_074 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate074"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_074"
        rlAssertGrep "Enabled" "$TmpDir/changestate074"
	rlRun "sleep 10"
        rlLog "Enroll a token"
        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0074.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0074.test
        /usr/bin/tpsclient < $TmpDir/enroll0074.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"

        #Revert the changes

        rlRun "curl --dump-header  $header_074 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=disable > $TmpDir/changestate074"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_074"
        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Edit the userKey Profile xml file by changing the encryption key and signing key keySize and update the profile."
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.encryption.keySize\">1024/g" $TmpDir/userkey-profile074
        sed -i -e "s/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">2048/<Property name=\"op.enroll.userKey.keyGen.signing.keySize\">1024/g" $TmpDir/userkey-profile074
        rlLog "Edit userKey profile - key size of encryption key 1024-2048 and the verify the state of the profile is pending approval"
        rlRun "curl --dump-header  $header_074 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -H \"Content-Type: application/xml\" \
                        -X PATCH \
                        --data @$TmpDir/userkey-profile074 \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey > $TmpDir/changekeysize074"
        rlRun "sleep 5"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_074"
        rlAssertGrep "<Status>Pending_Approval</Status>" "$TmpDir/changekeysize074"

        rlLog "Timestamp is $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep config.Profiles.userKey.timestamp | cut -d= -f2)"
        rlLog "Approve as an agent user"
        rlRun "curl --dump-header  $header_074 \
                        -E \"$valid_agent_cert:$CERTDB_DIR_PASSWORD\" \
                        -X POST \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/profiles/userKey?action=approve > $TmpDir/changestate074"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_074"

        rlLog "Format a token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format074.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format074.test
        /usr/bin/tpsclient < $TmpDir/format074.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"
	rlRun "pki -d $CERTDB_DIR \
                          -n \"$valid_admin_cert\" \
                          -c $CERTDB_DIR_PASSWORD \
                          -h $tmp_tps_host \
                          -t tps \
                          -p $target_unsecure_port \
                           user-del $valid_admin1_cert"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd

	rlPhaseStartTest "pki_tps_enrollments-074: TPS operations.allowedTransitions - random junk value - BZ 1196278"
        local cuid="10000000000000000088"
        header_072="$TmpDir/header072"
        local tps_out="$TmpDir/admin_out_tpsenroll0072"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlRun "curl --dump-header  $header_072 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken072"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_072"
        foundcuid=$(cat $TmpDir/showToken072 | grep $cuid)
        if [ -n "$foundcuid" ]; then
                rlLog "Delete the token"
        rlRun "curl --dump-header  $header_072 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -X DELETE \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens/$cuid > $TmpDir/deleteToken072"
        rlAssertGrep "HTTP/1.1 204 No Content" "$header_072"
        rlRun "curl --dump-header  $header_072 \
                        -E \"$valid_admin_cert:$CERTDB_DIR_PASSWORD\" \
                        -k https://$tmp_tps_host:$target_secure_port/tps/rest/tokens > $TmpDir/showToken072"
        rlAssertGrep "HTTP/1.1 200 OK" "$header_072"
        rlAssertNotGrep "$cuid" "$TmpDir/showToken072"
        fi

        tps_conf="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg"
        tps_conf_bak="/var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg.bak072"
        rlRun "cp $tps_conf $tps_conf_bak"
        sed -i -e "s/^tps.operations.allowedTransitions=.*/tps.operations.allowedTransitions=junk\$^@123&/g" $tps_conf
        rlLog "TPS transitions: $(cat /var/lib/pki/$(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)/tps/conf/CS.cfg | grep ^tps.operations.allowedTransitions | cut -d= -f2)"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        passwd="redhat"
        rlRun "create_dir_user $(eval echo \$${TPS_INST}_DB_SUFFIX) 2 > $TmpDir/ldapusers072.ldif"
        rlRun "ldapadd -x -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -f $TmpDir/ldapusers072.ldif > $TmpDir/ldapadd.out" 0 "Add test users for Directory-Authenticated Enrollment"
        ldap_user=$(cat $TmpDir/ldapusers072.ldif | grep -x "uid: idmuser1" | cut -d ':' -f2 | tr -d ' ')
        new_ldap_user=$(cat $TmpDir/ldapusers072.ldif | grep -x "uid: idmuser2" | cut -d ':' -f2 | tr -d ' ')

        rlLog "Format an uninitialized token"
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format072.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format072.test
        /usr/bin/tpsclient < $TmpDir/format072.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlLog "Format a formatted token"

        /usr/bin/tpsclient < $TmpDir/format072.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Failure" "$tps_out"

        rlLog "Enroll a formatted token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0089.test
        /usr/bin/tpsclient < $TmpDir/enroll0089.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Failure" "$tps_out"

        cuid="10000000000000000090"

        rlLog "Enroll an uninitialized token"

        rlLog "gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/enroll0090.test"
        gen_enroll_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/enroll0090.test
        /usr/bin/tpsclient < $TmpDir/enroll0090.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_enroll' Success" "$tps_out"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1196278"

        #Cleanup
        rlLog "gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $new_ldap_user $passwd $TmpDir/format072.test"
        gen_format_data_file $tmp_tps_host $target_unsecure_port $cuid $ldap_user $passwd $TmpDir/format072.test
        /usr/bin/tpsclient < $TmpDir/format072.test > $tps_out 2>&1
        rlRun "sleep 20"
        rlAssertGrep "Operation 'ra_format' Success" "$tps_out"

        rlRun "cp $tps_conf_bak $tps_conf"
        rhcs_stop_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)

        rhcs_start_instance $(eval echo \$${TPS_INST}_TOMCAT_INSTANCE_NAME)
        rlRun "rm -rf $tps_conf_bak"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n $valid_admin_user -h $tmp_tps_host -p $target_unsecure_port tps-token-del $cuid" 0 "Delete token"
	rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$new_ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"uid=$ldap_user,ou=People,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlRun "ldapdelete -x -h $tmp_tps_host -p $(eval echo \$${TPS_INST}_LDAP_PORT) -D \"$LDAP_ROOTDN\" -w $LDAP_ROOTDNPWD \"cn=idmusers,ou=Groups,$(eval echo \$${TPS_INST}_DB_SUFFIX)\""
        rlPhaseEnd


	rlPhaseStartSetup "pki_console_acl-cleanup"
	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
