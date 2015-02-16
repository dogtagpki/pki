#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy-tests/ca-tests/renewal
#   Description: PKI CA certificate renewal of Directory Authenticated user certificates
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki commands needs to be tested:
#  /ca/ee/ca/ProfileSubmit profile caDirUserRenewal
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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
#
# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

run_pki-legacy-ca-renew_dir_auth_user_cert_tests()
{
	local subsystemType=$1
        local csRole=$2

        # Creating Temporary Directory for pki ca-renew-dir-auth-user-cert
        rlPhaseStartSetup "pki ca renew directory auth user cert - Temporary Directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	        rlRun "pushd $TmpDir"
        	rlRun "export SSL_DIR=$CERTDB_DIR"
		#Forward the clock 40 days to test grace period
		forward_system_clock 40
        rlPhaseEnd

        # Local Variables
        get_topo_stack $csRole $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local ca_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local ca_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local ca_host=$(eval echo \$${csRole})
        local valid_agent_user=$CA_INST\_agentV
        local valid_agent_user_password=$CA_INST\_agentV_password
        local valid_admin_user=$CA_INST\_adminV
        local valid_admin_user_password=$CA_INST\_adminV_password
        local valid_audit_user=$CA_INST\_auditV
        local valid_audit_user_password=$CA_INST\_auditV_password
        local valid_operator_user=$CA_INST\_operatorV
        local valid_operator_user_password=$CA_INST\_operatorV_password
        local valid_agent_cert=$CA_INST\_agentV
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local ca_admin_user=$(eval echo \$${CA_INST}_ADMIN_USER)
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local ca_db_suffix=$(eval echo \$${CA_INST}_DB_SUFFIX)
	local ldap_conn_port=$(eval echo \$${CA_INST}_LDAP_PORT)
	local ldap_rootdn=$(eval echo $LDAP_ROOTDN)
	local ldap_rootdn_password=$(eval echo $LDAP_ROOTDNPWD)
	disable_ca_nonce $tomcat_name

        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-001: Renew a directory user cert that expire in the renew grace period"
		#Change caDirUserCert.cfg profile to have cert validity range to be 20 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=20"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_001_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_001_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend1$rand
		local ldap_user_password=rend1password
		cat > $TmpDir/adduser1.ldif << adduser1.ldif_EOF

version: 1

 entry-id: 101
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser1.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser1.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_001_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_001_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_001_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_001_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_001_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_001_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_001_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_001_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_001_005.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-002: Renew a directory user cert that expired and in the renew grace period"
		#set system clock 20 days older
		reverse_system_clock 20

		#Change caDirUserCert.cfg profile to have cert validity range to be 10 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=10"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_002_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_002_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend2$rand
		local ldap_user_password=rend2password
		cat > $TmpDir/adduser2.ldif << adduser2.ldif_EOF

version: 1

 entry-id: 102
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser2.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser2.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_002_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_002_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_002_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Set System Clock back to today
		forward_system_clock 20

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_002_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_002_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_002_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_002_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_002_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_002_005.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-003: Renew a directory user cert thats going to expire after the renew grace period BZ1182353"
		#Change caDirUserCert.cfg profile to have cert validity range to be 31 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=31"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_003_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_003_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend3$rand
		local ldap_user_password=rend3password
		cat > $TmpDir/adduser3.ldif << adduser3.ldif_EOF

version: 1

 entry-id: 103
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser3.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser3.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_003_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_003_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_003_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string
		if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_003_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_003_004.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_dir_auth_usercert_003_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_005.txt \
                            -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_003_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_003_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_003_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-004: Renew a directory user cert that expired and outside the renew grace period BZ1182353"
		#set system clock 34 days older
		reverse_system_clock 34

		#Change caDirUserCert.cfg profile to have cert validity range to be 3 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=3"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_004_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_004_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend2$rand
		local ldap_user_password=rend4password
		cat > $TmpDir/adduser4.ldif << adduser4.ldif_EOF

version: 1

 entry-id: 104
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser4.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser4.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_004_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_004_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_004_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Set System Clock back to today
		forward_system_clock 34

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_004_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_004_004.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_dir_auth_usercert_004_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_004_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_004_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_004_005.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-005: Renew a directory user cert when userid is not provided"
		#Change caDirUserCert.cfg profile to have cert validity range to be 20 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=20"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                            -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_005_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_005_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend5$rand
		local ldap_user_password=rend5password
		cat > $TmpDir/adduser5.ldif << adduser5.ldif_EOF

version: 1

 entry-id: 105
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser5.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser5.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_005_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_005_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_005_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_004.txt \
                             -d \"profileId=$renew_profile_id&uid= &pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_004.txt \
                             -d \"profileId=$renew_profile_id&uid= &pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_005_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_005_004.txt"
                rlAssertGrep "Invalid Credential" "$TmpDir/ca_renew_dir_auth_usercert_005_004_2.txt"

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_005_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_005_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_005_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-006: Renew a directory user cert when certificate is a non directory usercert"
		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_006_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_006_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local userid=rend6$rand
                local password=password$userid
		cat > $TmpDir/adduser6.ldif << adduser6.ldif_EOF

version: 1

 entry-id: 106
dn: uid=$userid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $userid
cn: Posix User1
sn: User1
homeDirectory: /home/$userid
loginshell: /bin/bash
userPassword: $password
adduser6.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser6.ldif" 0

		#user certificate enrollment using profile caUserCert
                local fullname=$userid
                local email="$userid@mail_domain.com"
                local phone="1234"
                local state="CA"

                #Create a certificate request
                local profile_id="caUserCert"
                local request_type="crmf"
                local request_key_size=2048
                local request_key_type="rsa"

                rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$userid \
                subject_uid:$userid \
                subject_email:$email \
                subject_ou:IDM \
                subject_organization:Redhat \
                subject_country:US \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
                rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$userid&sn_e=$userid&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$email&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_006_002_2.txt" 0 "Submit Certificate request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_006_002.txt"
                local request_id=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_006_002_2.txt | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
		rlLog "requestid=$request_id"

                #Approve certificate request
                #10 days validity for the certs
                local Second=`date +'%S' -d now`
                local Minute=`date +'%M' -d now`
                local Hour=`date +'%H' -d now`
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local start_year=$Year
                local end_year=$(date -d '+10 days' '+%Y')
                local end_month=$(date -d '+10 days' '+%m')
                local end_day=$(date -d '+10 days'  '+%d')
                local notBefore="$start_year-$Month-$Day $Hour:$Minute:$Second"
                local notAfter="$end_year-$end_month-$end_day $Hour:$Minute:$Second"
                local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                local cert_ext_subjAltNames="RFC822Name: "
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_003.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"requestId=$request_id&op=approve&submit=submit&name=UID=$userid&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/ca_renew_dir_auth_usercert_006_003_2.txt" 0 "Submit Certificate approve request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_006_003.txt"
                local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_006_003_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"	
		
		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$userid&pwd=$password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$userid&pwd=$password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_006_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_006_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_006_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

                #Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_006_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_006_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_006_005.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-007: Renew a directory user cert when userid is a long string"
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_007_001.txt \
                             -d \"profileId=$renew_profile_id&uid=rend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11user&pwd=rend7password&renewal=true&serial_num=2\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_007_001.txt \
                             -d \"profileId=$renew_profile_id&uid=rend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11user&pwd=rend7password&renewal=true&serial_num=2\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_007_001_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_007_001.txt"
                rlAssertGrep "Cannot load UserDirEnrollment" "$TmpDir/ca_renew_dir_auth_usercert_007_001_2.txt"
	rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-008: Renew a directory user cert when userpassword is a long string"
                local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_008_001.txt \
                             -d \"profileId=$renew_profile_id&uid=rend8&pwd=rend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11user&renewal=true&serial_num=2\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_008_001.txt \
                             -d \"profileId=$renew_profile_id&uid=rend8&pwd=rend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11userrend11user&renewal=true&serial_num=2\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_008_001_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_008_001.txt"
                rlAssertGrep "Cannot load UserDirEnrollment" "$TmpDir/ca_renew_dir_auth_usercert_008_001_2.txt"
        rlPhaseEnd
	
        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-009: Renew a directory user cert when serial number field has a very long string"
		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_009_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_009_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_009_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_009_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend9$rand
		local ldap_user_password=rend9password
		cat > $TmpDir/adduser1.ldif << adduser1.ldif_EOF

version: 1

 entry-id: 109
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser1.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser1.ldif" 0

                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_009_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=12341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_009_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=12341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_009_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_009_004.txt"
                rlAssertGrep "Record not found" "$TmpDir/ca_renew_dir_auth_usercert_009_004_2.txt"

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_009_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_009_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_009_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_009_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-010: Renew a directory user cert when grace period graceBefore value is a negative number"
		#Change grace period graceBefore value to a negative number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=-10"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 20 days
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=20"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_010_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_010_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend10$rand
		local ldap_user_password=rend10password
		cat > $TmpDir/adduser10.ldif << adduser10.ldif_EOF

version: 1

 entry-id: 110
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser10.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser10.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_010_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_010_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_010_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_010_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_010_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_010_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_010_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_010_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_010_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-011: Renew a directory user cert when grace period graceBefore value is a smaller number"
		#Change grace period graceBefore value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=1"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 1 day
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=1"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                            -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_011_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_011_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend11$rand
		local ldap_user_password=rend11password
		cat > $TmpDir/adduser11.ldif << adduser11.ldif_EOF

version: 1

 entry-id: 111
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser11.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser11.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_011_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_011_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_011_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_011_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_011_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_011_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_011_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_011_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_011_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-012: Renew a directory user cert outside renew grace period when grace period graceBefore value is a smaller number BZ1182353"
		#Change grace period graceBefore value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=1"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 10 days
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=10"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_012_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_012_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend12$rand
		local ldap_user_password=rend12password
		cat > $TmpDir/adduser12.ldif << adduser12.ldif_EOF

version: 1

 entry-id: 112
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser12.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser12.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_012_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_012_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_012_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_012_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_012_004.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_dir_auth_usercert_012_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_012_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_012_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_012_005.txt"
        rlPhaseEnd

        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-013: Renew a directory user cert when grace period graceBefore value is a bigger number"
		#Change grace period graceBefore value to a bigger number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=360"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 1 day
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=359"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_013_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_013_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend13$rand
		local ldap_user_password=rend13password
		cat > $TmpDir/adduser13.ldif << adduser13.ldif_EOF

version: 1

 entry-id: 113
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser13.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser13.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_013_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_013_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_013_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_013_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_013_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_013_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_013_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_013_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_013_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-014: Renew a directory user cert outside renew grace period when grace period graceBefore value is a bigger number BZ1182353"
		#Change grace period graceBefore value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceBefore=360"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 362 days
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=362"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_014_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_014_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend14$rand
		local ldap_user_password=rend14password
		cat > $TmpDir/adduser14.ldif << adduser14.ldif_EOF

version: 1

 entry-id: 114
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser14.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser14.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_014_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_014_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_014_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi


		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_014_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_014_004.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_dir_auth_usercert_014_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Change grace period graceBefore value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_014_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_014_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_014_005.txt"
        rlPhaseEnd

	
        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-015: Renew a directory user cert when grace period graceAfter value is a smaller number"
		#set system clock 34 days older
                reverse_system_clock 34

		#Change grace period graceAfter value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=2"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 33 days
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=33"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_015_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_015_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend15$rand
		local ldap_user_password=rend15password
		cat > $TmpDir/adduser15.ldif << adduser15.ldif_EOF

version: 1

 entry-id: 115
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser15.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser15.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_015_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_015_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_015_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Set System Clock back to today
                forward_system_clock 34

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_015_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_015_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_015_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_015_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_015_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_015_005.txt"
        rlPhaseEnd

	
        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-016: Renew a directory user cert outside renew grace period when grace period graceAfter value is a smaller number BZ1182353"
		#set system clock 34 days older
                reverse_system_clock 34

		#Change grace period graceAfter value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=2"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 31 days
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=31"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_016_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_016_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend16$rand
		local ldap_user_password=rend16password
		cat > $TmpDir/adduser16.ldif << adduser16.ldif_EOF

version: 1

 entry-id: 116
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser16.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser16.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_016_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_016_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_016_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Set System Clock back to today
                forward_system_clock 34

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_016_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_016_004.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_dir_auth_usercert_016_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_016_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_016_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_016_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-017: Renew a directory user cert when grace period graceAfter value is a bigger number"
		#set system clock 37 days older
                reverse_system_clock 37

		#Change grace period graceAfter value to a bigger number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=360"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 1 day
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=1"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_017_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_017_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend17$rand
		local ldap_user_password=rend17password
		cat > $TmpDir/adduser17.ldif << adduser17.ldif_EOF

version: 1

 entry-id: 117
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser17.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser17.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_017_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_017_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_017_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Set System Clock back to today
                forward_system_clock 37

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string2 $search_string2
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_017_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_017_004.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_017_004_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
                rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi

		#Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_017_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_017_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_017_005.txt"
        rlPhaseEnd


        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-018: Renew a directory user cert outside renew grace period when grace period graceAfter value is a bigger number BZ1182353"
		#set system clock 37 days older
                reverse_system_clock 37

		#Change grace period graceAfter value to a smaller number
                local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
                local search_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=30"
                local replace_string1="policyset.userCertSet.10.constraint.params.renewal.graceAfter=35"
                replace_string_in_a_file $profile_file $search_string1 $replace_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi	

		#Change caDirUserCert.cfg profile to have cert validity range to be 1 day
		local search_string2="policyset.userCertSet.2.default.params.range=180"
		local replace_string2="policyset.userCertSet.2.default.params.range=1"
		replace_string_in_a_file $profile_file $search_string2 $replace_string2
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_018_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_018_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend18$rand
		local ldap_user_password=rend18password
		cat > $TmpDir/adduser18.ldif << adduser18.ldif_EOF

version: 1

 entry-id: 118
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser18.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser18.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_018_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_018_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_018_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Set System Clock back to today
                forward_system_clock 37

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file  $replace_string2 $search_string2 
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                serial_number_in_decimal=$((${serial_number}))
                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_018_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_018_004.txt"
                rlAssertGrep "Request Rejected - Outside of Renewal Grace Period" "$TmpDir/ca_renew_dir_auth_usercert_018_004_2.txt"
		rlLog "BZ1182353 - https://bugzilla.redhat.com/show_bug.cgi?id=1182353"

		#Change grace period graceAfter value to original value 30
                replace_string_in_a_file $profile_file $replace_string1 $search_string1
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_018_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_018_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_018_005.txt"
        rlPhaseEnd

	
        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-019: Renew a revoked directory user cert that epires in renew grace period - manually approved by a valid agent"
		#Change caDirUserCert.cfg profile to have cert validity range to be 20 days
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=20"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_019_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_019_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend19$rand
		local ldap_user_password=rend19password
		cat > $TmpDir/adduser19.ldif << adduser19.ldif_EOF

version: 1

 entry-id: 119
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser19.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser19.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_019_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_019_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_019_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
		
		#Revoke the cert
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local invalidity_time=$(($(date +%s%N)/1000000))
                serial_number_in_decimal=$((${serial_number}))
                serial_number_only=${serial_number:2:$serial_length}
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/ca_renew_dir_auth_usercert_019_004_2.txt" 0 "Submit Certificate Revoke request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_019_004.txt"
                rlAssertGrep "revoked = \"yes\"" "$TmpDir/ca_renew_dir_auth_usercert_019_004_2.txt"

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string 
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_019_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_019_004.txt"
                rlAssertGrep "Cannot renew a revoked certificate" "$TmpDir/ca_renew_dir_auth_usercert_019_004_2.txt"

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_019_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_019_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_019_005.txt"
        rlPhaseEnd

	
        rlPhaseStartTest "pki_ca_renew_dir_auth_usercert-020: Renew a revoked expired directory user cert"
		#set system clock 37 days older
                reverse_system_clock 37

		#Change caDirUserCert.cfg profile to have cert validity range to be 1 day
		local profile_file="/var/lib/pki/$tomcat_name/ca/profiles/ca/caDirUserCert.cfg"
		local search_string="policyset.userCertSet.2.default.params.range=180"
		local replace_string="policyset.userCertSet.2.default.params.range=20"
		replace_string_in_a_file $profile_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $profile_file
        	        rhcs_stop_instance $tomcat_name
	                rhcs_start_instance $tomcat_name
		fi

		# setup uidpwddirauth authentication plugin
		local plugin_id="UserDirEnrollment"
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_1.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=$plugin_id&implName=UidPwdDirAuth&RULENAME=UserDirEnrollment&ldap.ldapconn.host=$ca_host&dnpattern=UID=!attr.uid,OU=people,$ca_db_suffix&ldapStringAttributes=mail&ldap.ldapconn.version=3&ldap.ldapconn.port=$ldap_conn_port&ldap.maxConns=5&ldap.basedn=$ca_db_suffix&ldap.minConns=2&ldap.ldapconn.secureConn=false&ldapByteAttributes=mail\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_020_2.txt" 
		rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_020_1.txt"
	
		#Add ldap user
        	local rand=$RANDOM
		local ldap_uid=rend20$rand
		local ldap_user_password=rend20password
		cat > $TmpDir/adduser20.ldif << adduser20.ldif_EOF

version: 1

 entry-id: 120
dn: uid=$ldap_uid,ou=People,$ca_db_suffix
passwordGraceUserTime: 0
modifiersName: cn=Directory manager
uidNumber: 1001
gidNumber: 1001
objectClass: top
objectClass: person
objectClass: posixAccount
uid: $ldap_uid
cn: Posix User1
sn: User1
homeDirectory: /home/$ldap_uid
loginshell: /bin/bash
userPassword: $ldap_user_password
adduser20.ldif_EOF
		
		rlRun "/usr/bin/ldapmodify -a -x -h $ca_host -p $ldap_conn_port -D  \"$ldap_rootdn\" -w $ldap_rootdn_password -c -f $TmpDir/adduser20.ldif" 0

		#userdir enrollment using profile
		local profile_id="caDirUserCert"
		local request_type="crmf"
		local request_key_size=1024
		local request_key_type="rsa"

		rlRun "create_new_cert_request \
                tmp_nss_db:$TEMP_NSS_DB \
                tmp_nss_db_password:$TEMP_NSS_DB_PWD \
                request_type:$request_type \
                request_algo:$request_key_type \
                request_size:$request_key_size \
                subject_cn:$ldap_uid \
                subject_uid:$ldap_uid \
                subject_email: \
                subject_ou:  \
                subject_organization:  \
                subject_country:  \
                subject_archive:false \
                cert_request_file:$TEMP_NSS_DB/$rand-request.pem \
                cert_subject_file:$TEMP_NSS_DB/$rand-subject.out"
		rlRun "cat $TEMP_NSS_DB/$rand-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/$rand-encoded-request.pem"

		#userdir enrollment using profile
		rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
		rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_002.txt \
                             -d \"profileId=$profile_id&cert_request_type=$request_type&uid=$ldap_uid&pwd=$ldap_user_password&cert_request=$(cat -v $TEMP_NSS_DB/$rand-encoded-request.pem)\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_020_002_2.txt" 0 "Submit Certificate directory user enrollment request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_020_002.txt"
		local serial_number=$(cat -v  $TmpDir/ca_renew_dir_auth_usercert_020_002_2.txt | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
		rlLog "serial_number=$serial_number"

		#Verify length of the serial number
                serial_length=${#serial_number}
                if [ $serial_length -le 0 ] ; then
                        rlFail "Certificate Serial Number is invalid : $serial_number"
                fi
	
		#Revoke the cert
                local Day=`date +'%d' -d now`
                local Month=`date +'%m' -d now`
                local Year=`date +'%Y' -d now`
                local invalidity_time=$(($(date +%s%N)/1000000))
                serial_number_in_decimal=$((${serial_number}))
                serial_number_only=${serial_number:2:$serial_length}
                rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\""
                rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_004.txt \
                             -E $valid_agent_cert:$CERTDB_DIR_PASSWORD \
                             -d \"op=doRevoke&submit=submit&serialNumber=$serial_number_only&$serial_number_only=on&revocationReason=0&revokeAll=%28%7C%28certRecordId%3D$serial_number_in_decimal%29%29&invalidityDate=$invalidity_time&day=$Day&month=$Month&year=$Year&totalRecordCount=1&verifiedRecordCount=1&templateType=RevocationSuccess&csrRequestorComments=revokecerttest\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/ca_renew_dir_auth_usercert_020_004_2.txt" 0 "Submit Certificate Revoke request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_020_004.txt"
                rlAssertGrep "revoked = \"yes\"" "$TmpDir/ca_renew_dir_auth_usercert_020_004_2.txt"
	
		#Set System Clock back to today
                forward_system_clock 37

		#Change caDirUserCert.cfg profile to have cert validity range default 180 days.
                replace_string_in_a_file $profile_file $replace_string $search_string
                if [ $? -eq 0 ] ; then
                        chown pkiuser:pkiuser $profile_file
                        rhcs_stop_instance $tomcat_name
                        rhcs_start_instance $tomcat_name
                fi

                #Submit Renew certificate request
		local renew_profile_id="caDirUserRenewal"
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_004.txt \
                             -d \"profileId=$renew_profile_id&uid=$ldap_uid&pwd=$ldap_user_password&renewal=true&serial_num=$serial_number_in_decimal\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/ca_renew_dir_auth_usercert_020_004_2.txt" 0 "Submit Certificate renew request"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_020_004.txt"
                rlAssertGrep "Cannot renew a revoked certificate" "$TmpDir/ca_renew_dir_auth_usercert_020_004_2.txt"

		#Cleanup: Delete uidpwddirauth authentication plugin
                rlLog "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\""
                rlRun "curl --basic \
                            --dump-header  $TmpDir/ca_renew_dir_auth_usercert_020_005.txt \
                             -u $valid_admin_user:$valid_admin_user_password \
                             -d \"OP_TYPE=OP_DELETE&OP_SCOPE=instance&RS_ID=$plugin_id\" \
                             -k \"https://$ca_host:$ca_secure_port/ca/auths\" > $TmpDir/ca_renew_dir_auth_usercert_020_005_2.txt"
                rlAssertGrep "HTTP/1.1 200 OK" "$TmpDir/ca_renew_dir_auth_usercert_020_005.txt"
        rlPhaseEnd

	rlPhaseStartTest "pki_ca_renew_dir_auth_usercert_cleanup: Enable nonce and delete temporary directory"
		#set system clock 40 days older, backto today's datetime
		reverse_system_clock 40
		rlLog "tomcat name=$tomcat_name"
                enable_ca_nonce $tomcat_name
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
