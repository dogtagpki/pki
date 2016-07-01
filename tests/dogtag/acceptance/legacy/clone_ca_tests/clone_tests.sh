#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy/clone_ca_tests/clone_tests.sh
#   Description: CA Clone tests
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

clone_legacy_ca_tests()
{
	local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for clone ca tests
        rlPhaseStartSetup "Create Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

	#local variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
	local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local CA_agentV=$CA_INST\_agentV
        local CA_auditV=$CA_INST\_auditV
        local CA_operatorV=$CA_INST\_operatorV
        local CA_adminV=$CA_INST\_adminV
        local CA_agentR=$CA_INST\_agentR
        local CA_adminR=$CA_INST\_adminR
        local CA_adminE=$CA_INST\_adminE
        local CA_agentE=$CA_INST\_agentE
        local invalid_serialNumber=$RANDOM
        local invalid_hex_serialNumber=0x$(echo "ibase=16;$invalid_serialNumber"|bc)
	local TEMP_NSS_DB="$TmpDir/nssdb"
	local TEMP_NSS_DB_PWD="Secret123"
	local target_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local masterca_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local target_host=$(eval echo \$${cs_Role})
	local cert_show_out="$TmpDir/cert_show.out"
	local root_ca_ldap_port=$(eval echo \$${CA_INST}_LDAP_PORT)
	local root_ca_admin_user=$(eval echo \$${CA_INST}_ADMIN_USER)
	local root_ca_security_domain_password=$(eval echo \$${CA_INST}_SECURITY_DOMAIN_PASSWORD)
	local root_ca_security_domain=$(eval echo \$${CA_INST}_DOMAIN)
	local root_ca_db_suffix=$(eval echo \$${CA_INST}_DB_SUFFIX)
	local root_ca_ldap_instance_name=$(eval echo \$${CA_INST}_LDAP_INSTANCE_NAME)

	rlPhaseStartSetup "Preparation to Master CA before clones are configured"

	#"In the CS.cfg file for the master CA, enable the master CA to monitor replication database changes by adding the ca.listenToCloneModifications parameter:"
	rlLog "Enable the master CA to monitor replication database changes"
	CURRENT_MASTERCA_CONFIG_FILE=$ROOTCA_SERVER_ROOT/conf/CS.cfg
	BACKUP_MASTERCA_CONFIG_FILE=$ROOTCA_SERVER_ROOT/conf/CS.cfg.backupfile

	rlLog "Stop $tomcat_name instance"
	rhcs_stop_instance $tomcat_name

	rlLog "Take backup of existing CS.cfg"
	rlRun "/usr/bin/cp $CURRENT_MASTERCA_CONFIG_FILE $BACKUP_MASTERCA_CONFIG_FILE" 0 "Backup current cs.cfg"

	search_string1="ca.listenToCloneModifications"
	replace_string1="ca.listenToCloneModifications=true"

	check_val_exists1=$(cat $CURRENT_MASTERCA_CONFIG_FILE | grep $search_string1)
	if [ "$check_val_exists1" == "" ]; then
		rlLog "Append $replace_string1 value to $tomcat_name CS.cfg"
		echo "$replace_string1" >> $CURRENT_MASTERCA_CONFIG_FILE

	elif [ "$check_val_exists1" == "ca.listenToCloneModifications=true" ]; then
		rlLog "Master is already configured to track clone modifications"
	else
		rlLog "Replace $search_string1 with $replace_string1"
		rlRun "sed -i s/"$search_string1"/"$replace_string1"/ $CURRENT_MASTERCA_CONFIG_FILE" 0
		RETVAL=$?
		if [ $RETVAL != 0 ]; then
			rlLog "Could not modify value of $search_string1"
			return 1
		fi
	fi
	rlLog "Start $tomcat_name instance"
	rhcs_start_instance $tomcat_name
	rlLog "Disable nonce"
	disable_ca_nonce $tomcat_name
	rlPhaseEnd

	rlPhaseStartSetup "clone_ca_tests: Setup clonecatest-tp1"
	local clone_ca1_ldap_port=1839
	local clone_ca1_http_port=29444
	local clone_ca1_https_port=29443
	local clone_ca1_ajp_port=29449
	local clone_ca1_tomcat_port=29445
	local clone_ca1_instance_name="clonecatest-tp1"
	local clone_ca1_server_root=/var/lib/$clone_ca1_instance_name/ca
	local clone_ca1_admin_cert_nickname="clonecatest-tp1-admin"
	local clone_ca1_install_info=$TmpDir/$clone_ca1_instance_name-install.info
	local clone_ca1_install_cfg=$TmpDir/$clone_ca1_instance_name-install.inf
	local clone_ca1_instance_out=$TmpDir/$clone_ca1_instance_name-create.out
	local clone_ca1_admin_cert_location=$TmpDir/$clone_ca1_instance_name/clone_ca1_admin_cert.p12

	rhcs_install_prep_disableFirewall

	for i in {$clone_ca1_ldap_port $clone_ca1_http_port $clone_ca1_https_port $clone_ca1_ajp_port $clone_ca1_tomcat_port}
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
	rlRun "rhds_install $clone_ca1_ldap_port $clone_ca1_instance_name \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0 "Installing RHDS instance for CLONE CA install"

	rlLog "Creating CLONE CA Instance"
	echo -e "[DEFAULT]" >> $clone_ca1_install_cfg
	echo -e "pki_instance_name=$clone_ca1_instance_name" >> $clone_ca1_install_cfg
	echo -e "pki_https_port=$clone_ca1_https_port" >> $clone_ca1_install_cfg
	echo -e "pki_http_port=$clone_ca1_http_port" >> $clone_ca1_install_cfg
	echo -e "pki_ajp_port=$clone_ca1_ajp_port" >> $clone_ca1_install_cfg
	echo -e "pki_tomcat_server_port=$clone_ca1_tomcat_port" >> $clone_ca1_install_cfg
	echo -e "pki_user=pkiuser" >> $clone_ca1_install_cfg
	echo -e "pki_group=pkiuser" >> $clone_ca1_install_cfg
	echo -e "pki_audit_group=pkiaudit" >> $clone_ca1_install_cfg
	echo -e "pki_token_name=Internal" >> $clone_ca1_install_cfg
	echo -e "pki_token_password=Secret123" >> $clone_ca1_install_cfg
	echo -e "pki_client_pkcs12_password=Secret123" >> $clone_ca1_install_cfg
	echo -e "pki_admin_password=Secret123" >> $clone_ca1_install_cfg
	echo -e "pki_ds_password=Secret123" >> $clone_ca1_install_cfg
	echo -e "pki_clone=True" >> $clone_ca1_install_cfg
	echo -e "pki_clone_pkcs12_password=Secret123" >> $clone_ca1_install_cfg
	echo -e "pki_clone_pkcs12_path=$CLIENT_PKCS12_DIR/ca_backup_keys.p12" >> $clone_ca1_install_cfg
	echo -e "pki_clone_replication_master_port=$root_ca_ldap_port" >> $clone_ca1_install_cfg
	echo -e "pki_clone_replication_clone_port=$clone_ca1_ldap_port" >> $clone_ca1_install_cfg
	echo -e "pki_clone_repicate_schema=$REPLICATE_SCHEMA" >> $clone_ca1_install_cfg
	echo -e "pki_clone_replication_security=$REPLICATION_SEC" >> $clone_ca1_install_cfg
	echo -e "pki_clone_uri=https://$(eval echo \$${cs_Role}):$masterca_secure_port" >> $clone_ca1_install_cfg
	echo -e "pki_client_database_dir=/tmp/dummydir1" >> $clone_ca1_install_cfg
	echo -e "pki_client_database_password=Secret123"  >> $clone_ca1_install_cfg
	echo -e "pki_client_dir=$TmpDir/$clone_ca1_instance_name" >> $clone_ca1_install_cfg
	echo -e "[CA]" >> $clone_ca1_install_cfg
	echo -e "pki_admin_name=caadmin" >> $clone_ca1_install_cfg
	echo -e "pki_admin_uid=caadmin" >> $clone_ca1_install_cfg
	echo -e "pki_admin_email=root@localhost" >> $clone_ca1_install_cfg
	echo -e "pki_admin_dualkey=True" >> $clone_ca1_install_cfg
	echo -e "pki_admin_key_size=2048" >> $clone_ca1_install_cfg
	echo -e "pki_admin_key_type=rsa" >> $clone_ca1_install_cfg
	echo -e "pki_admin_subject_dn=CN=$clone_ca1_admin_cert_nickname,O=redhat" >> $clone_ca1_install_cfg
	echo -e "pki_admin_nickname=$clone_ca1_admin_cert_nickname" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_key_type=rsa" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_key_size=2048" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_key_algorithm=SHA512withRSA" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_signing_algorithm=SHA512withRSA" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_token=Internal" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_nickname=Server-Cert cert-pki-$clone_ca1_instance_name" >> $clone_ca1_install_cfg
	echo -e "pki_ssl_server_subject_dn=cn=$(hostname),O=redhat" >> $clone_ca1_install_cfg
	echo -e "pki_client_admin_cert_p12=$clone_ca1_admin_cert_location" >> $clone_ca1_install_cfg
	echo -e "pki_security_domain_hostname=$(eval echo \$${cs_Role})" >> $clone_ca1_install_cfg
	echo -e "pki_security_domain_https_port=$masterca_secure_port" >> $clone_ca1_install_cfg
	echo -e "pki_security_domain_user=$root_ca_admin_user" >> $clone_ca1_install_cfg
	echo -e "pki_security_domain_password=$root_ca_security_domain_password" >> $clone_ca1_install_cfg
	echo -e "pki_security_domain_name=$root_ca_security_domain" >> $clone_ca1_install_cfg
	echo -e "pki_ds_hostname=$(hostname)" >> $clone_ca1_install_cfg
	echo -e "pki_ds_ldap_port=$clone_ca1_ldap_port" >> $clone_ca1_install_cfg
	echo -e "pki_ds_bind_dn=cn=Directory Manager" >> $clone_ca1_install_cfg
	echo -e "pki_ds_password=Secret123" >> $clone_ca1_install_cfg
	echo -e "pki_ds_secure_connection=False" >> $clone_ca1_install_cfg
	echo -e "pki_ds_remove_data=True" >> $clone_ca1_install_cfg
	echo -e "pki_ds_base_dn=$root_ca_db_suffix" >> $clone_ca1_install_cfg
	echo -e "pki_ds_database=$root_ca_ldap_instance_name" >> $clone_ca1_install_cfg

	rlLog "EXECUTING: pkispawn -s CA -f $clone_ca1_install_cfg -v"
	rlRun "pkispawn -s CA -f $clone_ca1_install_cfg -v > $clone_ca1_install_info  2>&1"
	exp_message1="Administrator's username:             caadmin"
	rlAssertGrep "$exp_message1" "$clone_ca1_install_info"

	#  Edit the CS.cfg file for the clone. Certain parameters must be added to the clone configuration to disable caching
	# and generating CRLs

	CURRENT_CLONECA1_CONFIG_FILE=/var/lib/pki/$clone_ca1_instance_name/ca/conf/CS.cfg
	BACKUP_CLONECA1_CONFIG_FILE=/var/lib/pki/$clone_ca1_instance_name/ca/conf/CS.cfg.backup
	rlLog "Stop $clone_ca1_instance_name instance"
	rhcs_stop_instance $clone_ca1_instance_name

	rlLog "Take backup of existing CS.cfg"
	rlRun "/usr/bin/cp $CURRENT_CLONECA1_CONFIG_FILE $BACKUP_CLONECA1_CONFIG_FILE" 0 "Backup current cs.cfg"

	search_string1="ca.crl.MasterCRL.enableCRLUpdates=true"
	replace_string1="ca.crl.MasterCRL.enableCRLUpdates=false"
	search_string2="ca.crl.MasterCRL.enableCRLCache=true"
	replace_string2="ca.crl.MasterCRL.enableCRLCache=false"
	search_string3="master.ca.agent.host="
	replace_string3="master.ca.agent.host=$tmp_ca_host"
	search_string4="master.ca.agent.port="
	replace_string4="master.ca.agent.port=$masterca_secure_port"

	check_val_exists1=$(cat $CURRENT_CLONECA1_CONFIG_FILE | grep $search_string1)
	if [ "$check_val_exists1" == "" ]; then
		rlLog "Append $replace_string1 value to $clone_ca1_instance_name CS.cfg"
		echo "$replace_string1" >> $CURRENT_CLONECA1_CONFIG_FILE
	else
		rlLog "Replace $search_string1 with $replace_string1"
		rlRun "sed -i s/"$search_string1"/"$replace_string1"/ $CURRENT_CLONECA1_CONFIG_FILE" 0
		RETVAL=$?
		if [ $RETVAL != 0 ]; then
			rlLog "Could not modify value of $search_string1"
			return 1
		fi
	fi
	check_val_exists2=$(cat $CURRENT_CLONECA1_CONFIG_FILE | grep $search_string2)
	if [ "$check_val_exists2" == "" ]; then
                rlLog "Append $replace_string2 value to $clone_ca1_instance_name CS.cfg"
                echo "$replace_string2" >> $CURRENT_CLONECA1_CONFIG_FILE
        else
                rlLog "Replace $search_string2 with $replace_string2"
                rlRun "sed -i s/"$search_string2"/"$replace_string2"/ $CURRENT_CLONECA1_CONFIG_FILE" 0
                RETVAL=$?
                if [ $RETVAL != 0 ]; then
                        rlLog "Could not modify value of $search_string2"
                        return 1
                fi
        fi
	check_val_exists3=$(cat $CURRENT_CLONECA1_CONFIG_FILE | grep $search_string3)
	if [ "$check_val_exists3" == "" ]; then
                rlLog "Append $replace_string3 value to $clone_ca1_instance_name CS.cfg"
                echo "$replace_string3" >> $CURRENT_CLONECA1_CONFIG_FILE
        else
                rlLog "Replace $search_string3 with $replace_string3"
                rlRun "sed -i s/"$search_string3"/"$replace_string3"/ $CURRENT_CLONECA1_CONFIG_FILE" 0
                RETVAL=$?
                if [ $RETVAL != 0 ]; then
                        rlLog "Could not modify value of $search_string3"
                        return 1
                fi
        fi
	check_val_exists4=$(cat $CURRENT_CLONECA1_CONFIG_FILE | grep $search_string4)
	if [ "$check_val_exists4" == "" ]; then
                rlLog "Append $replace_string4 value to $clone_ca1_instance_name CS.cfg"
                echo "$replace_string4" >> $CURRENT_CLONECA1_CONFIG_FILE
        else
                rlLog "Replace $search_string4 with $replace_string4"
                rlRun "sed -i s/"$search_string4"/"$replace_string4"/ $CURRENT_CLONECA1_CONFIG_FILE" 0
                RETVAL=$?
                if [ $RETVAL != 0 ]; then
                        rlLog "Could not modify value of $search_string4"
                        return 1
                fi
        fi
	rlLog "Start $clone_ca1_instance_name instance"
	rhcs_start_instance $clone_ca1_instance_name

	rlLog "Disable Nonce"
	disable_ca_nonce $clone_ca1_instance_name
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-001: Enroll cert on master and search requestid and serialNumber on clone"
		# (1) user cert enrollment using master CA instance.
		# (2) Search for the requestId in Clone CA's agent page.
		# (3) approve this request id using master CA.
		# (4) Search for the serial number in Clone CA's agent page
	# (1) user cert enrollment using master CA instance.
	local admin_out=$TmpDir/admin.out
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) Search for the requestId in Clone CA's agent page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$useid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	# (3) approve this request id using master CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (4) Search for the serial number in Clone CA's agent page
	rlLog "serial_number=$serial_number"
        local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget.out
        rlRun "/usr/bin/sslget -d $CERTDB_DIR -p $CERTDB_DIR_PASSWORD -n \"$CA_agentV\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$clone_ca1_https_port\" > $sslget_output 2>&1" 0 "Verify certificate from clone CA"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        local base64=$(cat -v $sslget_output | grep header.pkcs7ChainBase64 | awk -F \" '{print $2}')
        if [ $base64 == "" ]; then
                rlFail "sslget failed to get certificate details"
        else
                rlPass "sslget was successful in getting certificate details"
                rlLog "Certificate Base64: $base64"
        fi
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-002: Enroll cert on clone and search requestid and serialNumber on master"
		# (1) user cert enrollment using clone CA instance.
	        # (2) Search for the requestId in Master CA's agent page.
        	# (3) approve this request id using clone CA.
	        # (4) Search for the serial number in Master CA's agent page

	# (1) user cert enrollment using clone CA instance.
	local admin_out=$TmpDir/admin.out
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) Search for the requestId in Master CA's Agent Page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$useid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	# (3) approve this request id using Clone CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlLog "serial_number=$serial_number"
	rlLog "sleep 10"
	rlRun "sleep 10"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (4) Search for the serial number in Master CA's agent page
	rlLog "serial_number=$serial_number"
        local profile_request="/ca/ee/ca/displayBySerial"
        local request_info="serialNumber=$serial_number"
        local sslget_output=$TEMP_NSS_DB/sslget.out
        rlRun "/usr/bin/sslget -d $CERTDB_DIR -p $CERTDB_DIR_PASSWORD -n \"$CA_agentV\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$masterca_secure_port\" > $sslget_output 2>&1" 0 "Verify certificate from clone CA"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        local base64=$(cat -v $sslget_output | grep header.pkcs7ChainBase64 | awk -F \" '{print $2}')
        if [ $base64 == "" ]; then
                rlFail "sslget failed to get certificate details"
        else
                rlPass "sslget was successful in getting certificate details"
                rlLog "Certificate Base64: $base64"
        fi
	rlPhaseEnd


	rlPhaseStartTest "clone_ca_test-003: Enroll cert on Master CA, Reject it on clone CA,  and search request id on clone"
		# (1) user cert enrollment using master CA instance.
	        # (2) Search for the requestId in Clone CA's agent page.
        	# (3) Reject this request id using master CA.
	        # (4) Search for the requestId in Clone CA's agent page

	# (1) user cert enrollment using Master CA instance.
	local admin_out=$TmpDir/admin.out
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) Search for the requestId in Master Clone's Agent Page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	# (3) Reject this request id using Master CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=reject&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=reject&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"rejected\"" "$TmpDir/$test_out"
	# (4) Search for the Request Id in clone CA's agent page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-004: Enroll cert on Clone CA, Reject it on clone CA,  and search request id on Master"
		# (1) user cert enrollment using clone CA instance.
	        # (2) Search for the requestId in master CA's agent page.
        	# (3) Reject this request id using clone CA.
	        # (4) Search for the requestId in master CA's agent page

	# (1) user cert enrollment using Clone CA instance.
	local admin_out=$TmpDir/admin.out
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	rlLog "sleep 10"
	rlRun "sleep 10"
	# (2) Search for the requestId in clone CA Agent Page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlLog "sleep 10"
	rlRun "sleep 10"
	# (3) Reject this request id on Clone CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=reject&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=reject&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"rejected\"" "$TmpDir/$test_out"
	# (4) Search for the Request Id in Master CA agent page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlPhaseEnd


	rlPhaseStartTest "clone_ca_test-005: Enroll cert on Master CA, Cancel it on Master CA,  and search request id on clone"
		# (1) user cert enrollment using master CA instance.
	        # (2) Search for the requestId in Clone CA's agent page.
        	# (3) Cancel this request id using master CA.
	        # (4) Search for the requestId in Clone CA's agent page

	# (1) user cert enrollment using Master CA instance.
	local admin_out=$TmpDir/admin.out
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) Search for the requestId in Master Clone's Agent Page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	# (3) Cancel this request id using Master CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=cancel&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=cancel&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"canceled\"" "$TmpDir/$test_out"
	# (4) Search for the Request Id in clone CA's agent page
	rlLog "View certificate request details in clone CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-006: Enroll cert on Clone CA, Cancel it on clone CA,  and search request id on Master"
		# (1) user cert enrollment using clone CA instance.
	        # (2) Search for the requestId in master CA's agent page.
        	# (3) Reject this request id using clone CA.
	        # (4) Search for the requestId in master CA's agent page

	# (1) user cert enrollment using Clone CA instance.
	local admin_out=$TmpDir/admin.out
	local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) Search for the requestId in master CA Agent Page
	rlLog "View certificate request details in Master CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlLog "sleep 10"
	rlRun "sleep 10"
	# (3) Cancel this request id on Clone CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=cancel&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=cancel&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
	rlAssertGrep "requestType=\"enrollment\"" "$TmpDir/$test_out"
        rlAssertGrep "profileId=\"caUserCert\"" "$TmpDir/$test_out"
        rlAssertGrep "requestId=\"$request_id\"" "$TmpDir/$test_out"
        rlAssertGrep "errorCode=\"0\"" "$TmpDir/$test_out"
        rlAssertGrep "requestStatus=\"canceled\"" "$TmpDir/$test_out"
	# (4) Search for the Request Id in Master CA agent page
	rlLog "sleep 10"
	rlRun "sleep 10"
	rlLog "View certificate request details in Master CA's agent page"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileReview\" > $TmpDir/$test_out"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "defList.defVal=\"RSA - 1.2.840.113549.1.1.1\"" "$TmpDir/$test_out"
        rlAssertGrep "defList.defVal=\"$cert_ext_exKeyUsageOIDs\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$userid\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usercn\"" "$TmpDir/$test_out"
        rlAssertGrep "inputList.inputVal=\"$usermail\"" "$TmpDir/$test_out"
        rlAssertGrep "profileName=\"Manual User Dual-Use Certificate Enrollment\"" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-007: Enroll cert on Master CA, approve, Revoke the cert on Master CA and search cert on clone, status should be revoked"
		# (1) user cert enrollment using master CA instance.
	        # (2) approve this request id using master CA.
        	# (3) Revoke this certificate from master CA.
	        # (4) Search for this certificate from clone CA, status should be revoked.

	# (1) user cert enrollment using master CA instance.
	local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using master CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
	local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (3) Revoke this certificate from master CA
	local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local CONV_LOW_VAL=${STRIP_HEX,,}
        serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="0"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	# (4) Search for the serial number in Clone CA
	rlLog "Sleep for 10 seconds for clone to get synced"
	rlRun "sleep 10"
	rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $clone_ca1_http_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $clone_ca1_http_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$TmpDir/$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$TmpDir/$test_out"
        rlAssertGrep "CertStatus=Revoked" "$TmpDir/$test_out"
        rlAssertGrep "SerialNumber=$decimal_serial_number" "$TmpDir/$test_out"
        rlAssertGrep "SUCCESS" "$TmpDir/$test_out"
	rlPhaseEnd


	rlPhaseStartTest "clone_ca_test-008: Enroll cert on Clone CA, approve, Revoke the cert on clone CA and search cert on master, status should be revoked"
		# (1) user cert enrollment using clone CA .
	        # (2) approve this request id using clone CA.
        	# (3) Revoke this certificate from clone CA.
	        # (4) Search for this certificate from Master CA, status should be revoked.

	# (1) user cert enrollment using clone CA.
	local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using clone CA.
	rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
	rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
	local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
	if [ "$serial_number" == "" ]; then
		rlFail "Certificate request did not approve"
	fi
	# (3) Revoke this certificate from clone CA
	local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local CONV_LOW_VAL=${STRIP_HEX,,}
        serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="0"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	# (4) Search for the serial number in Master CA
	rlLog "Sleep for 10 seconds for clone to get synced"
	rlRun "sleep 10"
	rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$TmpDir/$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$TmpDir/$test_out"
        rlAssertGrep "CertStatus=Revoked" "$TmpDir/$test_out"
        rlAssertGrep "SerialNumber=$decimal_serial_number" "$TmpDir/$test_out"
        rlAssertGrep "SUCCESS" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-009: Enroll cert on Master CA, approve, and take cert on Hold, take cert of hold from clone CA, status from master ca should be valid"
		# (1) user cert enrollment using master CA instance.
	        # (2) approve this request id using master CA.
        	# (3) Take cert on hold from master CA.
	        # (4) Search for this certificate from clone CA, status should be revoked.
        	# (5) Take cert off hold from clone CA.
	        # (6) Search for this certificate from master CA, status should be valid
	# (1) user cert enrollment using master CA instance.
        local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using master CA.
        rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
        local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (3) Revoke this certificate from master CA
        local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local CONV_LOW_VAL=${STRIP_HEX,,}
        serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="6"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	# (4) Search for this certificate from clone CA, status should be revoked.
        rlLog "Sleep for 10 seconds for clone to get synced"
        rlRun "sleep 10"
        rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $clone_ca1_http_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $clone_ca1_http_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$TmpDir/$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$TmpDir/$test_out"
        rlAssertGrep "CertStatus=Revoked" "$TmpDir/$test_out"
        rlAssertGrep "SerialNumber=$decimal_serial_number" "$TmpDir/$test_out"
        rlAssertGrep "SUCCESS" "$TmpDir/$test_out"
	#(5) Take cert off hold from clone CA
	local profile_request="/ca/agent/ca/doUnrevoke"
        local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $CERTDB_DIR -p $CERTDB_DIR_PASSWORD -n \"$CA_agentV\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$clone_ca1_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $CERTDB_DIR -p $CERTDB_DIR_PASSWORD -n \"$CA_agentV\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$clone_ca1_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.unrevoked = \"yes\"" "$sslget_output"
        rlAssertGrep "header.serialNumber = \"$serial_number\"" "$sslget_output"
	# (6) Search for this certificate from master CA, status should be valid
	rlLog "Sleep for 10 seconds for master to get synced"
	rlRun "sleep 10"
	rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $target_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$TmpDir/$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$TmpDir/$test_out"
        rlAssertGrep "CertStatus=Good" "$TmpDir/$test_out"
        rlAssertGrep "SerialNumber=$decimal_serial_number" "$TmpDir/$test_out"
        rlAssertGrep "SUCCESS" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-0011: Enroll cert on clone CA, approve, and take cert on Hold, take cert of hold from master CA, status from master and clone ca should be valid"
		# (1) user cert enrollment using clone CA.
	        # (2) approve this request id using clone CA.
        	# (3) Take cert on hold from clone CA.
	        # (4) Search for this certificate from master CA, status should be revoked.
        	# (5) Take cert off hold from master CA.
	        # (6) Search for this certificate from clone CA, status should be valid

	# (1) user cert enrollment using clone CA.
        local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using clone CA.
        rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
        local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (3) Revoke this certificate from clone CA
        local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local CONV_LOW_VAL=${STRIP_HEX,,}
        serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="6"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	# (4) Search for this certificate from master CA, status should be revoked
        rlLog "Sleep for 10 seconds for clone to get synced"
        rlRun "sleep 10"
        rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $masterca_secure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $masterca_secure_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$TmpDir/$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$TmpDir/$test_out"
        rlAssertGrep "CertStatus=Revoked" "$TmpDir/$test_out"
        rlAssertGrep "SerialNumber=$decimal_serial_number" "$TmpDir/$test_out"
        rlAssertGrep "SUCCESS" "$TmpDir/$test_out"
	#(5) Take cert off hold from master CA.
	local profile_request="/ca/agent/ca/doUnrevoke"
        local request_info="serialNumber=$serial_number"
        rlLog "/usr/bin/sslget -d $CERTDB_DIR -p $CERTDB_DIR_PASSWORD -n \"$CA_agentV\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$clone_ca1_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlRun "/usr/bin/sslget -d $CERTDB_DIR -p $CERTDB_DIR_PASSWORD -n \"$CA_agentV\" -e \"$request_info\" -v -r \"$profile_request\" \"$target_host\":\"$clone_ca1_https_port\" > $sslget_output 2>&1" 0 "Un Revoke Certificate"
        rlAssertGrep "TTP/1.1 200 OK" "$sslget_output"
        rlAssertGrep "header.unrevoked = \"yes\"" "$sslget_output"
        rlAssertGrep "header.serialNumber = \"$serial_number\"" "$sslget_output"
	# (6) Search for this certificate from clone CA, status should be valid
	rlLog "Sleep for 10 seconds for master to get synced"
	rlRun "sleep 10"
	rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
        rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
        rlLog "Executing java -cp"
        rlLog "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $clone_ca1_http_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlRun "java -cp $CLASSPATH ca_ee_ocspRequest -ca_hostname $tmp_ca_host -ca_ee_port $clone_ca1_http_port -client_certdb_dir $CERTDB_DIR -client_certdb_pwd $CERTDB_DIR_PASSWORD -ca_cert_nickname $(eval echo \$${CA_INST}_SIGNING_NICKNAME) -serial_number $decimal_serial_number -debug true > $TmpDir/$test_out 2>&1"
        rlAssertGrep "RESPONSE STATUS:  HTTP/1.1 200 OK" "$TmpDir/$test_out"
        rlAssertGrep "RESPONSE HEADER:  Content-Type: application/ocsp-response" "$TmpDir/$test_out"
        rlAssertGrep "CertStatus=Good" "$TmpDir/$test_out"
        rlAssertGrep "SerialNumber=$decimal_serial_number" "$TmpDir/$test_out"
        rlAssertGrep "SUCCESS" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-0011: Verify CA clone displays updated CRL on clone CA with enrollment and revokcation on Master CA"
	# (1) user cert enrollment using master CA instance.
	# (2) approve this request id using master CA
	# (3) Revoke this cert from master CA.
	# (4) Update RevocationList in master CA.
	# (5) Display RevocationList in clone CA, should have the revoked cert.
	# (6) Display RevocationList in master CA, should have the revoked cert.

	# (1) user cert enrollment using master CA instance
	local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using master CA.
        rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
        local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (3) Revoke this cert from master CA
	local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local CONV_LOW_VAL=${STRIP_HEX,,}
        serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="6"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	# (4) Update RevocationList in master CA.
	local crlIssuingPoint="MasterCRL"
        local signatureAlgorithm="SHA512withRSA"
        local test_out=updatecrl.out
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlUpdate = \"Scheduled\"" "$TmpDir/$test_out"
	#(5) Display RevocationList in clone CA, should have the revoked cert
	rlLog "Display Entire CRL"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='entireCRL'
        local pageStart='1'
        local pageSize='50'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$masterca_ecure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"
	rlAssertGrep "Serial Number: $serial_number" "$TmpDir/$test_out"
	#Update RevocationList in clone CA.
        local crlIssuingPoint="MasterCRL"
        local signatureAlgorithm="SHA512withRSA"
        local test_out=updatecrl.out
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
	#(6) Display RevocationList in master CA, should have the revoked cert
	rlLog "Display Entire CRL"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='entireCRL'
        local pageStart='1'
        local pageSize='50'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"
        rlAssertGrep "Serial Number: $serial_number" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-0012: Verify CA clone displays updated CRL on Master CA with enrollment and revokcation on Clone CA"
	# (1) user cert enrollment using clone CA.
	# (2) approve this request id using clone CA
	# (3) Revoke this cert from clone CA.
	# (4) Update RevocationList in clone CA.
	# (5) Display RevocationList in master CA, should have the revoked cert.
	# (6) Display RevocationList in clone CA, should have the revoked cert.

	# (1) user cert enrollment using clone CA
	local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using clone CA.
        rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
        local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
	rlLog "sleep 10 seconds for master to get updated"
	rlRun "sleep 10"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"
	# (3) Revoke this cert from clone CA
	local STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        local serial=$STRIP_HEX
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local CONV_LOW_VAL=${STRIP_HEX,,}
        serial_number_array+=(0x$CONV_LOW_VAL)
        local decimal_serial_number=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
        local Day=`date +'%d' -d now`
        local Month=`date +'%m' -d now`
        local revocationReason="6"
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
           --dump-header  $admin_out \
           -E $CA_agentV:$CERTDB_DIR_PASSWORD \
           -d \"$serial=on&day=0&month=$Month&year=0&revocationReason=$revocationReason&csrRequestorComments=&submit=Submit&op=doRevoke&templateType=RevocationSuccess&serialNumber=$serial&revokeAll=(|(certRecordId=$decimal_serial_number))&totalRecordCount=1&verifiedRecordCount=1&invalidityDate=0\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/doRevoke\" > $TmpDir/$test_out" 0 "Revoke cert with serial Number $serial_number"
        rlAssertGrep "header.revoked = \"yes\"" "$TmpDir/$test_out"
        rlAssertGrep "header.error = null" "$TmpDir/$test_out"
	rlLog "Sleep for 10 seconds"
	rlRun "sleep 10"
	# (4) Update RevocationList in clone CA.
	local crlIssuingPoint="MasterCRL"
        local signatureAlgorithm="SHA512withRSA"
        local test_out=updatecrl.out
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
	rlLog "sleep for 10s for master to get updated"
	rlRun "sleep 10"
	#(5) Display RevocationList in clone CA, should have the revoked cert
	rlLog "Display Entire CRL"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='entireCRL'
        local pageStart='1'
        local pageSize='150'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"
	rlAssertGrep "$serial_number" "$TmpDir/$test_out"
	#Update RevocationList in master CA.
        local crlIssuingPoint="MasterCRL"
        local signatureAlgorithm="SHA512withRSA"
        local test_out=updatecrl.out
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem --dump-header $admin_out -E $CA_agentV:$CERTDB_DIR_PASSWORD -d \"crlIssuingPoint=$crlIssuingPoint&signatureAlgorithm=$signatureAlgorithm\" -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/updateCRL\" > $TmpDir/$test_out" 0 "Update CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlUpdate = \"Scheduled\"" "$TmpDir/$test_out"
	rlLog "Sleep for 10 seconds"
	rlRun "sleep 10"
	#(6) Display RevocationList in master CA, should have the revoked cert
	rlLog "Display Entire CRL"
        local crlIssuingPoint='MasterCRL'
        local crlDisplayType='entireCRL'
        local pageStart='1'
        local pageSize='150'
        local test_out=$crlDisplayType
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out"
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem \
                --dump-header  $admin_out \
                -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                -d \"crlIssuingPoint=$crlIssuingPoint&crlDisplayType=$crlDisplayType&pageStart=$pageStart&pageSize=$pageSize\" -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/displayCRL\" > $TmpDir/$test_out" 0 "Display cached CRL"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertGrep "header.crlIssuingPoint = \"$crlIssuingPoint\"" "$TmpDir/$test_out"
        rlAssertGrep "header.crlDisplayType = \"$crlDisplayType\"" "$TmpDir/$test_out"
        rlAssertGrep "$serial_number" "$TmpDir/$test_out"
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-0013: Shutdown Clone instance. Master CA instance should work just fine"
	# (1) Shutdown Clone instance.
        # (2) user cert enrollment using master CA instance.
        # (3) approve this request id using master CA.

	# (1) Shutdown Clone instance.
	rlLog "Shutdown clone instance $clone_ca1_instance_name"
	rhcs_stop_instance $clone_ca1_instance_name

	 # (1) user cert enrollment using master CA instance
        local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using master CA.
        rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$masterca_secure_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$masterca_secure_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
        local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlRun "verify_cert \"$serial_number\" \"$cert_requestdn\"" 0 "Verify cert"

	rlLog "Start clone instance $clone_ca1_instance_name"
        rhcs_start_instance $clone_ca1_instance_name
	rlPhaseEnd

	rlPhaseStartTest "clone_ca_test-0013: Shutdown Master CA instance. Clone CA instance should work just fine"
		# (1) Shutdown master CA instance.
        	# (2) user cert enrollment using clone CA instance.
	        # (3) approve this request id using clone CA.

	# (1) Shutdown Master CA instance.
        rlLog "Shutdown Master CA instance $tomcat_name"
        rhcs_stop_instance $tomcat_name

	# (1) user cert enrollment using clone CA
        local admin_out=$TmpDir/admin.out
        local request_type=pkcs10
        local request_key_type=rsa
        local request_key_size=1024
        local profile=caUserCert
        local cert_ext_exKeyUsageOIDs="1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
        local userid="fooUser-$RANDOM"
        local usercn="$userid"
        local phone="1234"
        local usermail="$userid@example.org"
        local test_out=ca-$profile-test.txt
        rlRun "export SSL_DIR=$CERTDB_DIR"
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
                cert_request_file:$TEMP_NSS_DB/cert-request.pem \
                cert_subject_file:$TEMP_NSS_DB/cert-subject.out" 0 "Create $request_type request for $profile"
        local cert_requestdn=$(cat $TEMP_NSS_DB/cert-subject.out | grep Request_DN | cut -d ":" -f2)
        rlLog "cert_requestdn=cert_requestdn"
        rlRun "cat $TEMP_NSS_DB/cert-request.pem |  python -c 'import sys, urllib as ul; print ul.quote(sys.stdin.read());' >  $TEMP_NSS_DB/cert-encoded-request.pem"
        rlLog "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\""
        rlRun "curl --basic \
                    --dump-header  $admin_out \
                    -d \"profileId=$profile&cert_request_type=$request_type&sn_uid=$userid&sn_cn=$usercn&sn_e=$usermail&sn_ou=IDM&sn_o=Redhat&sn_C=US&requestor_email=$useremail&requestor_phone=$phone&cert_request=$(cat -v $TEMP_NSS_DB/cert-encoded-request.pem)\" \
                    -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/profileSubmit\" > $TmpDir/$test_out" 0 "Submit Certificate request to $profile"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        rlAssertNotGrep "Sorry, your request has been rejected" "$admin_out"
        local request_id=$(cat -v  $TmpDir/$test_out | grep 'requestList.requestId' |  awk -F '=\"' '{print $2}' | awk -F '\";' '{print $1}')
        rlLog "request_id=$request_id"
	# (2) approve this request id using clone CA.
        rlLog "Approve $request_id using $CA_agentV"
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
        rlLog "curl --cacert $CERTDB_DIR/ca_cert.pem \
                    --dump-header  $admin_out \
                     -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                     -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\""
        rlRun "curl --cacert $CERTDB_DIR/ca_cert.pem  \
                    --dump-header  $admin_out \
                    -E $CA_agentV:$CERTDB_DIR_PASSWORD \
                    -d \"requestId=$request_id&op=approve&submit=submit&name=$cert_requestdn&notBefore=$notBefore&notAfter=$notAfter&authInfoAccessCritical=false&authInfoAccessGeneralNames=&keyUsageCritical=true&keyUsageDigitalSignature=true&keyUsageNonRepudiation=true&keyUsageKeyEncipherment=true&keyUsageDataEncipherment=false&keyUsageKeyAgreement=false&keyUsageKeyCertSign=false&keyUsageCrlSign=false&keyUsageEncipherOnly=false&keyUsageDecipherOnly=false&exKeyUsageCritical=false&exKeyUsageOIDs=$cert_ext_exKeyUsageOIDs&&subjAltNameExtCritical=false&subjAltNames=$cert_ext_subjAltNames&signingAlg=SHA1withRSA&requestNotes=submittingcertfor$userid\" \
                     -k \"https://$tmp_ca_host:$clone_ca1_https_port/ca/agent/ca/profileProcess\" > $TmpDir/$test_out" 0 "Submit Certificare request"
        rlAssertGrep "HTTP/1.1 200 OK" "$admin_out"
        local serial_number=$(cat -v  $TmpDir/$test_out | tr '\\n' '\n' | grep 'Serial Number' |  awk -F 'Serial Number: ' '{print $2}')
        rlRun "curl --basic --dump-header $admin_out -d \"op=displayBySerial&serialNumber=$serial_number\" -k https://$tmp_ca_host:$clone_ca1_https_port/ca/ee/ca/displayBySerial 1> $TmpDir/cert.out"
        local certificate_base64=$(cat -v $TmpDir/cert.out | grep "header.certChainBase64 = "|awk -F \" '{print $2}' | sed '/^$/d' | sed 's/^\\n//'|sed -e 's/^/-----BEGIN CERTIFICATE-----/' | sed 's/$/-----END CERTIFICATE-----/' | sed 's/\\r\\n//g')
        rlLog "serial_number=$serial_number"
        rlLog "sleep 10 seconds for master to get updated"
        rlRun "sleep 10"
	STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        CONV_LOW_VAL=${STRIP_HEX,,}
        rlRun "pki -h $tmp_ca_host -p $clone_ca1_http_port cert-show $serial_number > $cert_show_out" 0 "Executing pki cert-show $serial_number"
        rlAssertGrep "Serial Number: 0x$CONV_LOW_VAL" "$cert_show_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"

	# (1) Start Master CA instance.
        rlLog "Start Master CA instance $tomcat_name"
        rhcs_start_instance $tomcat_name
	rlPhaseEnd

	rlPhaseStartSetup "clone_ca_tests cleanup"
        rlLog "Destroy pki instance $clone_ca1_instance_name"
        rlRun "pkidestroy -s CA -i $clone_ca1_instance_name > $TmpDir/clone-ca1-uninstall.out 2>&1" 0
        rlAssertGrep "Uninstallation complete" "$TmpDir/clone-ca1-uninstall.out"
        rlLog "Remove DS instance"
        rlRun "remove-ds.pl -i slapd-$clone_ca1_instance_name > $TmpDir/ds-clone1-uninstall.out 2>&1"
        rlAssertGrep "Instance slapd-$clone_ca1_instance_name removed" "$TmpDir/ds-clone1-uninstall.out"
        rlPhaseEnd

        rlPhaseStartSetup "Deleting Temporary Directory"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
}
verify_cert()
{
        local serial_number=$1
        local request_dn=$2
        STRIP_HEX=$(echo $serial_number | cut -dx -f2)
        CONV_LOW_VAL=${STRIP_HEX,,}
        rlRun "pki -h $tmp_ca_host -p $target_port cert-show $serial_number > $cert_show_out" 0 "Executing pki cert-show $serial_number"
        rlAssertGrep "Serial Number: 0x$CONV_LOW_VAL" "$cert_show_out"
        rlAssertGrep "Issuer: CN=PKI $CA_INST Signing Cert,O=redhat" "$cert_show_out"
        rlAssertGrep "Subject: $request_dn" "$cert_show_out"
        rlAssertGrep "Status: VALID" "$cert_show_out"
}
