#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   rhcs_install.sh of /CoreOS/dogtag/acceptance/quickinstall
#   Description: CS quickinstall acceptance tests for new install
#                functions.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following rhcs will be tested:
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com>
#  	     Saili Pandit <saipandi@redhat.com>
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

# ROLE=MASTER, CLONE1, SUBCA1, SUBCA2, CLONE2

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/rhcs-install-shared.sh
. /opt/rhqa_pki/env.sh

# Include tests
. ./acceptance/quickinstall/rhds-install.sh

#Copy rhcs-install-lib.sh to /opt/rhqa_pki/
        rm -f /opt/rhqa_pki/rhcs-install-lib.sh
        cp -a ./acceptance/quickinstall/rhcs-install-lib.sh /opt/rhqa_pki/.

###########################################################
#    	CA INSTALL TESTS				  #
###########################################################
rhcs_install_RootCA() {
    rlPhaseStartTest  "rhcs_install_ca - Install RHCS CA Server"
	local INSTANCECFG="/tmp/ca_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/ca_instance_create.out"
	local PKI_SECURITY_DOMAIN_USER=$ROOTCA_ADMIN_USER
        rlLog "$FUNCNAME"
	local SUBSYSTEM_NAME=ROOTCA
	rhcs_install_prep_disableFirewall

	#List RHDS packages
	rhcs_install_set_ldap_vars

	#Install and configure RHDS instance
	rlLog "Creating LDAP server Instance to configure CA"
	rlRun "rhds_install $ROOTCA_LDAP_PORT $ROOTCA_LDAP_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $ROOTCA_DB_SUFFIX $SUBSYSTEM_NAME"

	#Install CA
	rlLog "Creating CA Instance"
	        rlLog "Setting up Dogtag CA instance ............."
		echo "[DEFAULT]" > $INSTANCECFG
		echo "pki_instance_name=$ROOTCA_TOMCAT_INSTANCE_NAME" >> $INSTANCECFG
		echo "pki_https_port=$ROOTCA_SECURE_PORT" >> $INSTANCECFG	
		echo "pki_http_port=$ROOTCA_UNSECURE_PORT" >> $INSTANCECFG
		echo "pki_ajp_port=$ROOTCA_AJP_PORT" >> $INSTANCECFG
		echo "pki_tomcat_server_port=$ROOTCA_TOMCAT_SERVER_PORT" >> $INSTANCECFG
		echo "pki_user=$USER" >> $INSTANCECFG
		echo "pki_group=$GROUP" >> $INSTANCECFG
		echo "pki_audit_group=$GROUP_AUDIT" >> $INSTANCECFG
		echo "pki_token_name=$ROOTCA_TOKEN_NAME" >> $INSTANCECFG
		echo "pki_token_password=$ROOTCA_TOKEN_PASSWORD" >> $INSTANCECFG
		echo "pki_client_pkcs12_password=$ROOTCA_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
		echo "pki_admin_password=$ROOTCA_ADMIN_PASSWORD" >> $INSTANCECFG

		echo "[CA]" >> $INSTANCECFG

		echo "pki_ca_signing_key_type=$ROOTCA_KEY_TYPE" >> $INSTANCECFG
		echo "pki_ca_signing_key_size=$ROOTCA_KEY_SIZE" >> $INSTANCECFG
		echo "pki_ca_signing_key_algorithm=$ROOTCA_SIGNING_KEY_ALGORITHM" >> $INSTANCECFG
		echo "pki_ca_signing_signing_algorithm=$ROOTCA_SIGNING_SIGNING_ALGORITHM" >> $INSTANCECFG
		echo "pki_ca_signing_token=$ROOTCA_SIGNING_TOKEN" >> $INSTANCECFG
		echo "pki_ca_signing_nickname=$ROOTCA_SIGNING_NICKNAME" >> $INSTANCECFG
		echo "pki_ca_signing_subject_dn=$ROOTCA_SIGNING_CERT_SUBJECT_NAME" >> $INSTANCECFG
		echo "pki_ocsp_signing_key_type=$ROOTCA_OCSP_SIGNING_KEY_TYPE" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_size=$ROOTCA_OCSP_SIGNING_KEY_SIZE" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_algorithm=$ROOTCA_OCSP_SIGNING_KEY_ALGORITHM" >> $INSTANCECFG
                echo "pki_ocsp_signing_signing_algorithm=$ROOTCA_OCSP_SIGNING_SIGNING_ALGORITHM" >> $INSTANCECFG
                echo "pki_ocsp_signing_token=$ROOTCA_OCSP_SIGNING_TOKEN" >> $INSTANCECFG
                echo "pki_ocsp_signing_nickname=$ROOTCA_OCSP_SIGNING_NICKNAME" >> $INSTANCECFG
                echo "pki_ocsp_signing_subject_dn=$ROOTCA_OCSP_SIGNING_CERT_SUBJECT_NAME" >> $INSTANCECFG
		echo "pki_audit_signing_key_type=$ROOTCA_AUDIT_SIGNING_KEY_TYPE" >> $INSTANCECFG
                echo "pki_audit_signing_key_size=$ROOTCA_AUDIT_SIGNING_KEY_SIZE" >> $INSTANCECFG
                echo "pki_audit_signing_key_algorithm=$ROOTCA_AUDIT_SIGNING_KEY_ALGORITHM" >> $INSTANCECFG
                echo "pki_audit_signing_signing_algorithm=$ROOTCA_AUDIT_SIGNING_SIGNING_ALGORITHM" >> $INSTANCECFG
                echo "pki_audit_signing_token=$ROOTCA_AUDIT_SIGNING_TOKEN" >> $INSTANCECFG
                echo "pki_audit_signing_nickname=$ROOTCA_AUDIT_SIGNING_NICKNAME" >> $INSTANCECFG
                echo "pki_audit_signing_subject_dn=$ROOTCA_AUDIT_SIGNING_CERT_SUBJECT_NAME" >> $INSTANCECFG
  		echo "pki_ssl_server_key_type=$ROOTCA_SSL_SERVER_KEY_TYPE" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$ROOTCA_SSL_SERVER_KEY_SIZE" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$ROOTCA_SSL_SERVER_KEY_ALGORITHM" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$ROOTCA_SSL_SERVER_SIGNING_ALGORITHM" >> $INSTANCECFG
                echo "pki_ssl_server_token=$ROOTCA_SSL_SERVER_TOKEN" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$ROOTCA_SSL_SERVER_NICKNAME" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$ROOTCA_SSL_SERVER_CERT_SUBJECT_NAME" >> $INSTANCECFG
		echo "pki_subsystem_key_type=$ROOTCA_SUBSYSTEM_KEY_TYPE" >> $INSTANCECFG
                echo "pki_subsystem_key_size=$ROOTCA_SUBYSTEM_KEY_SIZE" >> $INSTANCECFG
                echo "pki_subsystem_key_algorithm=$ROOTCA_SUBSYSTEM_KEY_ALGORITHM" >> $INSTANCECFG
                echo "pki_subsystem_signing_algorithm=$ROOTCA_SUBSYSTEM_SIGNING_ALGORITHM" >> $INSTANCECFG
                echo "pki_subsystem_token=$ROOTCA_SUBSYSTEM_TOKEN" >> $INSTANCECFG
                echo "pki_subsystem_nickname=$ROOTCA_SUBSYTEM_NICKNAME" >> $INSTANCECFG
                echo "pki_subsystem_subject_dn=$ROOTCA_SUBSYSTEM_CERT_SUBJECT_NAME" >> $INSTANCECFG
		echo "pki_admin_name=$ROOTCA_ADMIN_USER" >> $INSTANCECFG
		echo "pki_admin_uid=$ROOTCA_ADMIN_USER" >> $INSTANCECFG
		echo "pki_admin_email=$ROOTCA_ADMIN_EMAIL" >> $INSTANCECFG
		echo "pki_admin_dualkey=$ROOTCA_ADMIN_DUAL_KEY" >> $INSTANCECFG
		echo "pki_admin_key_size=$ROOTCA_ADMIN_KEY_SIZE" >> $INSTANCECFG
		echo "pki_admin_key_type=$ROOTCA_ADMIN_KEY_TYPE" >> $INSTANCECFG
		echo "pki_admin_subject_dn=$ROOTCA_ADMIN_CERT_SUBJECT_NAME" >> $INSTANCECFG
		echo "pki_admin_nickname=$ROOTCA_ADMIN_CERT_NICKNAME" >> $INSTANCECFG
		echo "pki_import_admin_cert=$ROOTCA_ADMIN_IMPORT_CERT" >> $INSTANCECFG
		echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
		echo "pki_client_admin_cert_p12=$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12" >> $INSTANCECFG
		echo "pki_backup_keys=$ROOTCA_BACKUP" >> $INSTANCECFG
		echo "pki_backup_password=$ROOTCA_BACKUP_PASSWORD" >> $INSTANCECFG
		echo "pki_client_database_dir=$ROOTCA_CERTDB_DIR" >> $INSTANCECFG
		echo "pki_client_database_password=$ROOTCA_CERTDB_DIR_PASSWORD" >> $INSTANCECFG 
		echo "pki_client_database_purge=$CLIENT_DB_PURGE" >> $INSTANCECFG
		echo "pki_security_domain_hostname=$(hostname)" >> $INSTANCECFG
		echo "pki_security_domain_https_port=$ROOTCA_SECURE_PORT" >> $INSTANCECFG
		echo "pki_security_domain_user=$ROOTCA_ADMIN_USER" >> $INSTANCECFG
		echo "pki_security_domain_password=$ROOTCA_SECURITY_DOMAIN_PASSWORD" >> $INSTANCECFG
		echo "pki_security_domain_name=$(hostname -d)" >> $INSTANCECFG
		echo "pki_ds_hostname=$LDAP_HOSTNAME" >> $INSTANCECFG
		echo "pki_ds_ldap_port=$ROOTCA_LDAP_PORT" >> $INSTANCECFG
		echo "pki_ds_bind_dn=$LDAP_ROOTDN" >> $INSTANCECFG
		echo "pki_ds_password=$LDAP_ROOTDNPWD" >> $INSTANCECFG
		echo "pki_ds_secure_connection=$SECURE_CONN" >> $INSTANCECFG
		echo "pki_ds_remove_data=$REMOVE_DATA" >> $INSTANCECFG
		echo "pki_ds_base_dn=$ROOTCA_DB_SUFFIX" >> $INSTANCECFG
		echo "pki_ds_database=$ROOTCA_LDAP_INSTANCE_NAME" >> $INSTANCECFG
		echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
		echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
		echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
		echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
		echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
		echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG

                ROOTCA_DOMAIN=`hostname -d`
		echo "export ROOTCA_DOMAIN=$ROOTCA_DOMAIN" >> /opt/rhqa_pki/env.sh
		cat $INSTANCECFG
		rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
		rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
		rlRun "cat $INSTANCE_CREATE_OUT"
		exp_message1="Administrator's username:             $ROOTCA_ADMIN_USER"
		rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
		exp_message1_1="Administrator's PKCS #12 file:"
		rlAssertGrep "$exp_message1_1" "$INSTANCE_CREATE_OUT"
		exp_message2="$ROOTCA_DOMAIN"
		rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
		exp_message3_1="To check the status of the subsystem:"
		rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
		exp_message3_2="systemctl status pki-tomcatd@$ROOTCA_TOMCAT_INSTANCE_NAME.service"
		rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
		exp_message4_1="To restart the subsystem:"
		rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
		exp_message4_2=" systemctl restart pki-tomcatd@$ROOTCA_TOMCAT_INSTANCE_NAME.service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
		exp_message5="The URL for the subsystem is:"
		rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
		exp_message5_1="https://$(hostname):$ROOTCA_SECURE_PORT/ca"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                echo "export ROOTCA_SERVER_ROOT=/var/lib/pki/$ROOTCA_TOMCAT_INSTANCE_NAME/ca" >> /opt/rhqa_pki/env.sh
		mkdir -p $CLIENT_PKCS12_DIR
		mv /var/lib/pki/$ROOTCA_TOMCAT_INSTANCE_NAME/alias/ca_backup_keys.p12 $CLIENT_PKCS12_DIR

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/ROOTCA_instance_status.txt 2>&1"
		exp_result1="$ROOTCA_TOMCAT_INSTANCE_NAME\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$ROOTCA_SECURE_PORT/ca/services"
                if [ $(grep $exp_result1 /tmp/ROOTCA_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/ROOTCA_instance_status.txt | wc -l) -gt 0 ]; then
                        rlLog " ROOTCA instance created successfully"
                        sed -i s/^ROOTCA_INSTANCE_CREATED_STATUS=False/ROOTCA_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export ROOTCA_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}

###########################################################
#    		KRA INSTALL TESTS			  #
###########################################################
rhcs_install_kra() {
     rlPhaseStartTest "rhcs_install_kra - Install RHCS KRA Server"
        rlLog "$FUNCNAME"
        local INSTANCECFG="/tmp/kra_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/kra_instance_create.out"
	local number=$1
        local master_hostname=$2
        local CA=$3

	local PKI_SECURITY_DOMAIN_PORT=$(eval echo \$${CA}_SECURE_PORT)
	local PKI_SECURITY_DOMAIN_USER=$(eval echo \$${CA}_ADMIN_USER)
        rhcs_install_prep_disableFirewall
	local SUBSYSTEM_NAME=$(echo KRA${number})
	local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
	local INSTANCE_NAME=$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME)
        $(check_instance $INSTANCE_NAME)
        local retval=$?
        rlLog "retval=$retval"
        if [[ "${retval}" -eq 0 ]]; then
                IMPORT_ADMIN_CERT_NONCA=True
        else
                IMPORT_ADMIN_CERT_NONCA=False
        fi

	#Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure KRA"
        rlRun "rhds_install $(eval echo \$KRA${number}_LDAP_PORT) $(eval echo \$KRA${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$KRA${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for KRA install"

        #Install KRA
        rlLog "Creating KRA Instance"
                rlLog "Setting up Dogtag KRA instance ............."
		echo "[DEFAULT]" > $INSTANCECFG
		echo "pki_instance_name=$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_https_port=$(eval echo \$KRA${number}_SECURE_PORT)" >> $INSTANCECFG	
		echo "pki_http_port=$(eval echo \$KRA${number}_UNSECURE_PORT)" >> $INSTANCECFG
		echo "pki_ajp_port=$(eval echo \$KRA${number}_AJP_PORT)" >> $INSTANCECFG
		echo "pki_tomcat_server_port=$(eval echo \$KRA${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
		echo "pki_user=$USER" >> $INSTANCECFG
		echo "pki_group=$GROUP" >> $INSTANCECFG
		echo "pki_audit_group=$GROUP_AUDIT" >> $INSTANCECFG
		echo "pki_token_name=$ROOTCA_TOKEN_NAME" >> $INSTANCECFG
		echo "pki_token_password=$ROOTCA_TOKEN_PASSWORD" >> $INSTANCECFG
		echo "pki_client_pkcs12_password=$(eval echo \$KRA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
		echo "pki_admin_password=$(eval echo \$KRA${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
                echo "[KRA]" >> $INSTANCECFG
                echo "pki_subsystem_key_type=$(eval echo \$KRA${number}_SUBSYSTEM_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_subsystem_key_size=$(eval echo \$KRA${number}_SUBYSTEM_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_subsystem_key_algorithm=$(eval echo \$KRA${number}_SUBSYSTEM_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_signing_algorithm=$(eval echo \$KRA${number}_SUBSYSTEM_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_token=$(eval echo \$KRA${number}_SUBSYSTEM_TOKEN )" >> $INSTANCECFG
                echo "pki_subsystem_nickname=$(eval echo \$KRA${number}_SUBSYTEM_NICKNAME)" >> $INSTANCECFG
                echo "pki_subsystem_subject_dn=$(eval echo \$KRA${number}_SUBSYSTEM_SUBJECT_DN)" >> $INSTANCECFG
		echo "pki_storage_key_type=$(eval echo \$KRA${number}_STORAGE_KEY_TYPE)" >> $INSTANCECFG
		echo "pki_storage_key_size=$(eval echo \$KRA${number}_STORAGE_KEY_SIZE)" >> $INSTANCECFG
		echo "pki_storage_key_algorithm=$(eval echo \$KRA${number}_STORAGE_KEY_ALGORITHM)" >> $INSTANCECFG
		echo "pki_storage_signing_algorithm=$(eval echo \$KRA${number}_STORAGE_SIGNING_ALGORITHM)" >> $INSTANCECFG
		echo "pki_storage_token=$(eval echo \$KRA${number}_STORAGE_TOKEN)" >> $INSTANCECFG
		echo "pki_storage_nickname=$(eval echo \$KRA${number}_STORAGE_NICKNAME)" >> $INSTANCECFG
 		echo "pki_storage_subject_dn=$(eval echo \$KRA${number}_STORAGE_SUBJECT_DN)" >> $INSTANCECFG
		echo "pki_transport_key_type=$(eval echo \$KRA${number}_TRANSPORT_KEY_TYPE)" >> $INSTANCECFG
		echo "pki_transport_key_size=$(eval echo \$KRA${number}_TRANSPORT_KEY_SIZE)" >> $INSTANCECFG
		echo "pki_transport_key_algorithm=$(eval echo \$KRA${number}_TRANSPORT_KEY_ALGORITHM)" >> $INSTANCECFG
		echo "pki_transport_signing_algorithm=$(eval echo \$KRA${number}_TRANSPORT_SIGNING_ALGORITHM)" >> $INSTANCECFG
		echo "pki_transport_token=$(eval echo \$KRA${number}_TRANSPORT_TOKEN)" >> $INSTANCECFG
		echo "pki_transport_nickname=$(eval echo \$KRA${number}_TRANSPORT_NICKNAME)" >> $INSTANCECFG 
		echo "pki_transport_subject_dn=$(eval echo \$KRA${number}_TRANSPORT_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_audit_signing_key_type=$(eval echo \$KRA${number}_AUDIT_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_size=$(eval echo \$KRA${number}_AUDIT_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_algorithm=$(eval echo \$KRA${number}_AUDIT_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_signing_algorithm=$(eval echo \$KRA${number}_AUDIT_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_token=$(eval echo \$KRA${number}_AUDIT_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_audit_signing_nickname=$(eval echo \$KRA${number}_AUDIT_SIGNING_NICKNAME)" >> $INSTANCECFG
                echo "pki_audit_signing_subject_dn=$(eval echo \$KRA${number}_AUDIT_SIGNING_SUBJECT_DN)" >> $INSTANCECFG
	 	echo "pki_ssl_server_key_type=$(eval echo \$KRA${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$KRA${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$KRA${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$KRA${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$KRA${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$KRA${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$KRA${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_admin_name=$(eval echo \$KRA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$KRA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$KRA${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$KRA${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$KRA${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$KRA${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$KRA${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$KRA${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$IMPORT_ADMIN_CERT_NONCA" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$KRA${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
		echo "pki_issuing_ca_hostname=$master_hostname" >> $INSTANCECFG
		echo "pki_issuing_ca_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_issuing_ca_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_backup_keys=$(eval echo \$${CA}_BACKUP)" >> $INSTANCECFG
		echo "pki_backup_password=$(eval echo \$KRA${number}_BACKUP_PASSWORD)" >> $INSTANCECFG
		echo "pki_client_database_dir=$(eval echo \$${CA}_CERTDB_DIR)" >> $INSTANCECFG
		echo "pki_client_database_password=$(eval echo \$${CA}_CERTDB_DIR_PASSWORD)" >> $INSTANCECFG 
		echo "pki_client_database_purge=$CLIENT_DB_PURGE" >> $INSTANCECFG
		echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
		echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
		echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
		echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
		echo "pki_ds_hostname=$LDAP_HOSTNAME" >> $INSTANCECFG
		echo "pki_ds_ldap_port=$(eval echo \$KRA${number}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_ds_bind_dn=$LDAP_ROOTDN" >> $INSTANCECFG
		echo "pki_ds_password=$LDAP_ROOTDNPWD" >> $INSTANCECFG
		echo "pki_ds_secure_connection=$SECURE_CONN" >> $INSTANCECFG
		echo "pki_ds_remove_data=$REMOVE_DATA" >> $INSTANCECFG
		echo "pki_ds_base_dn =$(eval echo \$KRA${number}_DB_SUFFIX)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$KRA${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
		echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
		echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
		echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
		echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
		echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG
                cat $INSTANCECFG
                
		rlLog "EXECUTING: pkispawn -s KRA -f $INSTANCECFG -v "
                rlRun "pkispawn -s KRA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
		exp_message1="Administrator's username:             $(eval echo \$KRA${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message4="To check the status of the subsystem:"
                rlAssertGrep "$exp_message4" "$INSTANCE_CREATE_OUT"
                exp_message5="systemctl status pki-tomcatd@$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message6="To restart the subsystem:"
                rlAssertGrep "$exp_message6" "$INSTANCE_CREATE_OUT"
                exp_message7=" systemctl restart pki-tomcatd@$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message7" "$INSTANCE_CREATE_OUT"
                exp_message8="The URL for the subsystem is:"
                rlAssertGrep "$exp_message8" "$INSTANCE_CREATE_OUT"
		exp_message8_1="https://$(hostname):$(eval echo \$KRA${number}_SECURE_PORT)/kra"
                rlAssertGrep "$exp_message8_1" "$INSTANCE_CREATE_OUT"
		#echo "export KRA_SERVER_ROOT=/var/lib/pki/$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME)/kra" >> /opt/rhqa_pki/env.sh
		mkdir -p $CLIENT_PKCS12_DIR
		mv /var/lib/pki/$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME)/alias/kra_backup_keys.p12 $CLIENT_PKCS12_DIR

		#Update Instance creation status to env.sh
                rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/KRA${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$KRA${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$KRA${number}_SECURE_PORT)/kra/services"
                if [ $(grep $exp_result1 /tmp/KRA${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/KRA${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "KRA${number} instance creation successful"
                        sed -i s/^KRA${number}_INSTANCE_CREATED_STATUS=False/KRA${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export KRA${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}

###########################################################
#              OCSP INSTALL TESTS                         #
###########################################################
rhcs_install_ocsp() {
    rlPhaseStartTest "rhcs_install_ocsp - Install RHCS OCSP Server"
        rlLog "$FUNCNAME"
        local INSTANCECFG="/tmp/ocsp_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/ocsp_instance_create.out"
	local SUBSYSTEM_NAME=$(echo OCSP${number})
        rhcs_install_prep_disableFirewall

	local number=$1
        local master_hostname=$2
        local CA=$3
	local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
	local INSTANCE_NAME=$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME)
        $(check_instance $INSTANCE_NAME)
        local retval=$?
        rlLog "retval=$retval"
        if [[ "${retval}" -eq 0 ]]; then
                IMPORT_ADMIN_CERT_NONCA=True
        else
                IMPORT_ADMIN_CERT_NONCA=False
        fi
        local PKI_SECURITY_DOMAIN_PORT=$(eval echo \$${CA}_SECURE_PORT)
        local PKI_SECURITY_DOMAIN_USER=$(eval echo \$${CA}_ADMIN_USER)
	#Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure OCSP"
        rlRun "rhds_install $(eval echo \$OCSP${number}_LDAP_PORT) $(eval echo \$OCSP${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$OCSP${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for OCSP install"

        #Install OCSP
        rlLog "Creating OCSP Instance"
                rlLog "Setting up Dogtag OCSP instance ............."
   		echo "[DEFAULT]" > $INSTANCECFG
		echo "pki_instance_name=$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_https_port=$(eval echo \$OCSP${number}_SECURE_PORT)" >> $INSTANCECFG	
		echo "pki_http_port=$(eval echo \$OCSP${number}_UNSECURE_PORT)" >> $INSTANCECFG
		echo "pki_ajp_port=$(eval echo \$OCSP${number}_AJP_PORT)" >> $INSTANCECFG
		echo "pki_tomcat_server_port=$(eval echo \$OCSP${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
		echo "pki_user=$USER" >> $INSTANCECFG
		echo "pki_group=$GROUP" >> $INSTANCECFG
		echo "pki_audit_group=$GROUP_AUDIT" >> $INSTANCECFG
		echo "pki_token_name=$ROOTCA_TOKEN_NAME" >> $INSTANCECFG
		echo "pki_token_password=$ROOTCA_TOKEN_PASSWORD" >> $INSTANCECFG
		echo "pki_client_pkcs12_password=$(eval echo \$OCSP${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
		echo "pki_admin_password=$(eval echo \$OCSP${number}_ADMIN_PASSWORD)" >> $INSTANCECFG

                echo "[OCSP]" >> $INSTANCECFG

		echo "pki_ocsp_signing_key_type=$(eval echo \$OCSP${number}_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_size=$(eval echo \$OCSP${number}_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_algorithm=$(eval echo \$OCSP${number}_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
		echo "pki_ocsp_signing_signing_algorithm=$(eval echo \$OCSP${number}_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ocsp_signing_token=$(eval echo \$OCSP${number}_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_ocsp_signing_nickname=$(eval echo \$OCSP${number}_SIGNING_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_ocsp_signing_subject_dn=$(eval echo \$OCSP${number}_SIGNING_SUBJECT_DN)" >> $INSTANCECFG
  		echo "pki_subsystem_key_type=$(eval echo \$OCSP${number}_SUBSYSTEM_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_subsystem_key_size=$(eval echo \$OCSP${number}_SUBSYSTEM_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_subsystem_key_algorithm=$(eval echo \$OCSP${number}_SUBSYSTEM_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_signing_algorithm=$(eval echo \$OCSP${number}_SUBSYSTEM_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_token=$(eval echo \$OCSP${number}_SUBSYSTEM_TOKEN)" >> $INSTANCECFG
                echo "pki_subsystem_nickname=$(eval echo \$OCSP${number}_SUBSYSTEM_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_subsystem_subject_dn=$(eval echo \$OCSP${number}_SUBSYSTEM_SUBJECT_DN)" >> $INSTANCECFG
  		echo "pki_audit_signing_key_type=$(eval echo \$OCSP${number}_AUDIT_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_size=$(eval echo \$OCSP${number}_AUDIT_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_algorithm=$(eval echo \$OCSP${number}_AUDIT_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_signing_algorithm=$(eval echo \$OCSP${number}_AUDIT_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_token=$(eval echo \$OCSP${number}_AUDIT_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_audit_signing_nickname=$(eval echo \$OCSP${number}_AUDIT_SIGNING_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_audit_signing_subject_dn=$(eval echo \$OCSP${number}_AUDIT_SIGNING_SUBJECT_DN)" >> $INSTANCECFG
		echo "pki_ssl_server_key_type=$(eval echo \$OCSP${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$OCSP${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$OCSP${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$OCSP${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$OCSP${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$OCSP${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$OCSP${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
		echo "pki_admin_name=$(eval echo \$OCSP${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$OCSP${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$OCSP${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$OCSP${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$OCSP${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$OCSP${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$OCSP${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$OCSP${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$IMPORT_ADMIN_CERT_NONCA" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$OCSP${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
                echo "pki_issuing_ca_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_issuing_ca_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_issuing_ca_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_backup_keys=$(eval echo \$${CA}_BACKUP)" >> $INSTANCECFG
		echo "pki_backup_password=$(eval echo \$OCSP${number}_BACKUP_PASSWORD)" >> $INSTANCECFG
		echo "pki_client_database_dir=$(eval echo \$${CA}_CERTDB_DIR)" >> $INSTANCECFG
		echo "pki_client_database_password=$(eval echo \$${CA}_CERTDB_DIR_PASSWORD)" >> $INSTANCECFG 
		echo "pki_client_database_purge=$CLIENT_DB_PURGE" >> $INSTANCECFG
		echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
		echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
		echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
		echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
		echo "pki_ds_hostname=$LDAP_HOSTNAME"  >> $INSTANCECFG
		echo "pki_ds_ldap_port=$(eval echo \$OCSP${number}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_ds_bind_dn=$LDAP_ROOTDN" >> $INSTANCECFG
		echo "pki_ds_password=$LDAP_ROOTDNPWD" >> $INSTANCECFG
		echo "pki_ds_secure_connection=$SECURE_CONN" >> $INSTANCECFG
		echo "pki_ds_remove_data=$REMOVE_DATA" >> $INSTANCECFG
		echo "pki_ds_base_dn =$(eval echo \$OCSP${number}_DB_SUFFIX)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$OCSP${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
		echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
		echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
		echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
		echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
		echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG        
		cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s OCSP -f $INSTANCECFG -v "
                rlRun "pkispawn -s OCSP -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
		exp_message1="Administrator's username:             $(eval echo \$OCSP${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
		exp_message5_1="https://$(hostname):$(eval echo \$OCSP${number}_SECURE_PORT)/ocsp"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
#		echo "export OCSP_SERVER_ROOT=/var/lib/pki/$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME)/ocsp" >> /opt/rhqa_pki/env.sh
		mkdir -p $CLIENT_PKCS12_DIR
		mv /var/lib/pki/$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME)/alias/ocsp_backup_keys.p12 $CLIENT_PKCS12_DIR
	
		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/OCSP${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$OCSP${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$OCSP${number}_SECURE_PORT)/ocsp/services"
                if [ $(grep $exp_result1 /tmp/OCSP${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/OCSP${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "OCSP${number} instance creation successful"
                        sed -i s/^OCSP${number}_INSTANCE_CREATED_STATUS=False/OCSP${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export OCSP${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}
###########################################################
#              TKS INSTALL TESTS                         #
###########################################################
rhcs_install_tks() {
    rlPhaseStartTest "rhcs_install_tks - Install RHCS TKS Server"
        rlLog "$FUNCNAME"
	local number=$1
        local master_hostname=$2
        local CA=$3
        local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
	local INSTANCE_NAME=$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)
        $(check_instance $INSTANCE_NAME)
        local retval=$?
        rlLog "retval=$retval"
        if [[ "${retval}" -eq 0 ]]; then
                IMPORT_ADMIN_CERT_NONCA=True
        else
                IMPORT_ADMIN_CERT_NONCA=False
        fi
        local PKI_SECURITY_DOMAIN_USER=$(eval echo \$${CA}_ADMIN_USER)
        local PKI_SECURITY_DOMAIN_PORT=$(eval echo \$${CA}_SECURE_PORT)
        local INSTANCECFG="/tmp/tks_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/tks_instance_create.out"
	local SUBSYSTEM_NAME=$(echo TKS${number})
        rhcs_install_prep_disableFirewall
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure TKS"
        rlRun "rhds_install $(eval echo \$TKS${number}_LDAP_PORT) $(eval echo \$TKS${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$TKS${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for TKS install"
        #Install TKS
        rlLog "Creating TKS Instance"
                rlLog "Setting up Dogtag TKS instance ............."
    		echo "[DEFAULT]" > $INSTANCECFG
		echo "pki_instance_name=$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_https_port=$(eval echo \$TKS${number}_SECURE_PORT)" >> $INSTANCECFG	
		echo "pki_http_port=$(eval echo \$TKS${number}_UNSECURE_PORT)" >> $INSTANCECFG
		echo "pki_ajp_port=$(eval echo \$TKS${number}_AJP_PORT)" >> $INSTANCECFG
		echo "pki_tomcat_server_port=$(eval echo \$TKS${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
		echo "pki_user=$USER" >> $INSTANCECFG
		echo "pki_group=$GROUP" >> $INSTANCECFG
		echo "pki_audit_group=$GROUP_AUDIT" >> $INSTANCECFG
		echo "pki_token_name=$ROOTCA_TOKEN_NAME" >> $INSTANCECFG
		echo "pki_token_password=$ROOTCA_TOKEN_PASSWORD" >> $INSTANCECFG
		echo "pki_client_pkcs12_password=$(eval echo \$TKS${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
		echo "pki_admin_password=$(eval echo \$TKS${number}_ADMIN_PASSWORD)" >> $INSTANCECFG

                echo "[TKS]" >> $INSTANCECFG

                echo "pki_subsytem_key_type=$(eval echo \$TKS${number}_SUBSYSTEM_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_subsystem_key_size=$(eval echo \$TKS${number}_SUBSYSTEM_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_subsystem_key_algorithm=$(eval echo \$TKS${number}_SUBSYSTEM_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_signing_algorithm=$(eval echo \$TKS${number}_SUBSYSTEM_SIGNING_ALGORITHM)" >> $INSTANCECFG                
                echo "pki_subsystem_token=$(eval echo \$TKS${number}_SUBSYSTEM_TOKEN )" >> $INSTANCECFG
                echo "pki_subsystem_nickname=$(eval echo \$TKS${number}_SUBSYSTEM_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_subsystem_subject_dn=$(eval echo \$TKS${number}_SUBSYSTEM_SUBJECT_DN)" >> $INSTANCECFG
 		echo "pki_audit_signing_key_type=$(eval echo \$TKS${number}_AUDIT_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_size=$(eval echo \$TKS${number}_AUDIT_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_algorithm=$(eval echo \$TKS${number}_AUDIT_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_signing_algorithm=$(eval echo \$TKS${number}_AUDIT_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_token=$(eval echo \$TKS${number}_AUDIT_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_audit_signing_nickname=$(eval echo \$TKS${number}_AUDIT_SIGNING_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_audit_signing_subject_dn=$(eval echo \$TKS${number}_AUDIT_SIGNING_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_ssl_server_key_type=$(eval echo \$TKS${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$TKS${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$TKS${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$TKS${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$TKS${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$TKS${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$TKS${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG

		echo "pki_admin_name=$(eval echo \$TKS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$TKS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$TKS${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$TKS${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$TKS${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$TKS${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$TKS${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$TKS${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$IMPORT_ADMIN_CERT_NONCA" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$TKS${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
                echo "pki_issuing_ca_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_issuing_ca_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_issuing_ca_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_backup_keys=$(eval echo \$${CA}_BACKUP)" >> $INSTANCECFG
		echo "pki_backup_password=$(eval echo \$TKS${number}_BACKUP_PASSWORD)" >> $INSTANCECFG
		echo "pki_client_database_dir=$(eval echo \$${CA}_CERTDB_DIR)" >> $INSTANCECFG
		echo "pki_client_database_password=$(eval echo \$${CA}_CERTDB_DIR_PASSWORD)" >> $INSTANCECFG 
		echo "pki_client_database_purge=$CLIENT_DB_PURGE" >> $INSTANCECFG
		echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
		echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
		echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
		echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
		echo "pki_ds_hostname=$LDAP_HOSTNAME" >> $INSTANCECFG
		echo "pki_ds_ldap_port=$(eval echo \$TKS${number}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_ds_bind_dn=$LDAP_ROOTDN" >> $INSTANCECFG
		echo "pki_ds_password=$LDAP_ROOTDNPWD" >> $INSTANCECFG
		echo "pki_ds_secure_connection=$SECURE_CONN" >> $INSTANCECFG
		echo "pki_ds_remove_data=$REMOVE_DATA" >> $INSTANCECFG
		echo "pki_ds_base_dn =$(eval echo \$TKS${number}_DB_SUFFIX)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$TKS${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
		echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
		echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
		echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
		echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
		echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG        
		cat $INSTANCECFG

		rlLog "EXECUTING: pkispawn -s TKS -f $INSTANCECFG -v "
                rlRun "pkispawn -s TKS -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $(eval echo \$TKS${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$TKS${number}_SECURE_PORT)/tks"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
               # echo "export TKS_SERVER_ROOT=/var/lib/pki/$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)/tks" >> /opt/rhqa_pki/env.sh
		mkdir -p $CLIENT_PKCS12_DIR
		mv /var/lib/pki/$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)/alias/tks_backup_keys.p12 $CLIENT_PKCS12_DIR

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/TKS${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$TKS${number}_SECURE_PORT)/ocsp/services"
                if [ $(grep $exp_result1 /tmp/TKS${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/TKS${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "TKS${number} instance creation successful"
                        sed -i s/^TKS${number}_INSTANCE_CREATED_STATUS=False/TKS${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export TKS${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}

###########################################################
#              TPS INSTALL TESTS                         #
###########################################################
rhcs_install_tps() {
    rlPhaseStartTest "rhcs_install_tps - Install RHCS TPS Server"
        rlLog "$FUNCNAME"
	local number=$1
        local master_hostname=$2
        local CA=$3
        local KRA=$4
        local TKS=$5
        local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
        local PKI_SECURITY_DOMAIN_USER=$(eval echo \$${CA}_ADMIN_USER)
        local PKI_SECURITY_DOMAIN_PORT=$(eval echo \$${CA}_SECURE_PORT)
        local INSTANCECFG="/tmp/tps_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/tps_instance_create.out"
        local SUBSYSTEM_NAME=$(echo TPS${number})
	local INSTANCE_NAME=$(eval echo \$TPS${number}_TOMCAT_INSTANCE_NAME)
        $(check_instance $INSTANCE_NAME)
        local retval=$?
        rlLog "retval=$retval"
        if [[ "${retval}" -eq 0 ]]; then
                IMPORT_ADMIN_CERT_NONCA=True
        else
                IMPORT_ADMIN_CERT_NONCA=False
        fi
        rhcs_install_prep_disableFirewall
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure TPS"
        rlRun "rhds_install $(eval echo \$TPS${number}_LDAP_PORT) $(eval echo \$TPS${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$TPS${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for TPS install"
        #Install TPS
        rlLog "Creating TPS Instance"
                rlLog "Setting up Dogtag TPS instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$TPS${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$TPS${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$TPS${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$TPS${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$TPS${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$USER" >> $INSTANCECFG
                echo "pki_group=$GROUP" >> $INSTANCECFG
                echo "pki_audit_group=$GROUP_AUDIT" >> $INSTANCECFG
                echo "pki_token_name=$ROOTCA_TOKEN_NAME" >> $INSTANCECFG
                echo "pki_token_password=$ROOTCA_TOKEN_PASSWORD" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$TPS${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_admin_password=$(eval echo \$TPS${number}_ADMIN_PASSWORD)" >> $INSTANCECFG

                echo "[TPS]" >> $INSTANCECFG

                echo "pki_subsytem_key_type=$(eval echo \$TPS${number}_SUBSYSTEM_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_subsystem_key_size=$(eval echo \$TPS${number}_SUBSYSTEM_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_subsystem_key_algorithm=$(eval echo \$TPS${number}_SUBSYSTEM_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_signing_algorithm=$(eval echo \$TPS${number}_SUBSYSTEM_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_token=$(eval echo \$TPS${number}_SUBSYSTEM_TOKEN )" >> $INSTANCECFG
                echo "pki_subsystem_nickname=$(eval echo \$TPS${number}_SUBSYSTEM_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_subsystem_subject_dn=$(eval echo \$TPS${number}_SUBSYSTEM_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_audit_signing_key_type=$(eval echo \$TPS${number}_AUDIT_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_size=$(eval echo \$TPS${number}_AUDIT_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_algorithm=$(eval echo \$TPS${number}_AUDIT_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_signing_algorithm=$(eval echo \$TPS${number}_AUDIT_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_token=$(eval echo \$TPS${number}_AUDIT_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_audit_signing_nickname=$(eval echo \$TPS${number}_AUDIT_SIGNING_CERT_NICKNAME)" >> $INSTANCECFG
		echo "pki_audit_signing_subject_dn=$(eval echo \$TPS${number}_AUDIT_SIGNING_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_ssl_server_key_type=$(eval echo \$TPS${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$TPS${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$TPS${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$TPS${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$TPS${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$TPS${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$TPS${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG

                echo "pki_admin_name=$(eval echo \$TPS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$TPS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$TPS${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$TPS${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$TPS${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$TPS${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$TPS${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$TPS${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$IMPORT_ADMIN_CERT_NONCA" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$TPS${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
                echo "pki_issuing_ca_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_issuing_ca_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_issuing_ca_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_ca_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_enable_server_side_keygen=$(eval echo \$TPS${number}_SERVER_KEYGEN)" >> $INSTANCECFG
		echo "pki_kra_uri=https://$master_hostname:$(eval echo \$${KRA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_tks_uri=https://$master_hostname:$(eval echo \$${TKS}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_authdb_hostname=$(eval echo \$TPS${number}_AUTHDB_HOST)" >> $INSTANCECFG
		echo "pki_authdb_port=$(eval echo \$TPS${number}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_authdb_basedn=$(eval echo \$TPS${number}_DB_SUFFIX)" >> $INSTANCECFG
                echo "pki_backup_keys=$(eval echo \$${CA}_BACKUP)" >> $INSTANCECFG
                echo "pki_backup_password=$(eval echo \$TPS${number}_BACKUP_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_database_dir=$(eval echo \$${CA}_CERTDB_DIR)" >> $INSTANCECFG
                echo "pki_client_database_password=$(eval echo \$${CA}_CERTDB_DIR_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_database_purge=$CLIENT_DB_PURGE" >> $INSTANCECFG
                echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
                echo "pki_ds_hostname=$LDAP_HOSTNAME" >> $INSTANCECFG
                echo "pki_ds_ldap_port=$(eval echo \$TPS${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_ds_bind_dn=$LDAP_ROOTDN" >> $INSTANCECFG
                echo "pki_ds_password=$LDAP_ROOTDNPWD" >> $INSTANCECFG
                echo "pki_ds_secure_connection=$SECURE_CONN" >> $INSTANCECFG
                echo "pki_ds_remove_data=$REMOVE_DATA" >> $INSTANCECFG
                echo "pki_ds_base_dn =$(eval echo \$TPS${number}_DB_SUFFIX)" >> $INSTANCECFG
                echo "pki_ds_database=$(eval echo \$TPS${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
                echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
                echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
                echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
                echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
                echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s TPS -f $INSTANCECFG -v "
                rlRun "pkispawn -s TPS -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
		tps_pkispawn_retval=$?
                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $(eval echo \$TPS${number}_ADMIN_USER)"
		rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$TPS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$TPS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$TPS${number}_SECURE_PORT)/tps"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
               # echo "export TKS_SERVER_ROOT=/var/lib/pki/$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)/tks" >> /opt/rhqa_pki/env.sh
                mkdir -p $CLIENT_PKCS12_DIR
                mv /var/lib/pki/$(eval echo \$TPS${number}_TOMCAT_INSTANCE_NAME)/alias/tps_backup_keys.p12 $CLIENT_PKCS12_DIR

#		#Update Instance creation status to env.sh
#		rlLog "Executing: pkidaemon status tomcat"
#		rlRun "pkidaemon status tomcat >  /tmp/TPS${number}_instance_status.txt 2>&1"
#		exp_result1="$(eval echo \$TPS${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
#                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$TPS${number}_SECURE_PORT)/services"
#                if [ $(grep $exp_result1 /tmp/TPS${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/TPS${number}_instance_status.txt | wc -l) -gt 0 ] ; then
#                        rlLog "TPS${number} instance creation successful"
#                        sed -i s/^TPS${number}_INSTANCE_CREATED_STATUS=False/TPS${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
#                        rlRun "export TPS${number}_INSTANCE_CREATED_STATUS=TRUE"
#                fi
		# BZ 1188331 pkidaemon status tomcat does not list TPS subsystem details
                #Because of this bug above code to Update Instance creation status to env.sh does not give correct results, when BZ is fixed un-comment above lines and remove Temp Workaround.
                #Temp Workaround is:
                if [ $tps_pkispawn_retval -eq 0 ] ; then
                        rlLog "TPS${number} instance creation successful"
                        sed -i s/^TPS${number}_INSTANCE_CREATED_STATUS=False/TPS${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export TPS${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}

rhcs_install_prep_disableFirewall() 
{
	rlRun "systemctl stop firewalld"
}

###################CLONE CA##############################################
#########################################################################

rhcs_install_cloneCA()
{
     rlPhaseStartTest  "rhcs_install_clone_ca - Install RHCS CLONE CA Server BZ1165864"
	rlLog "Failing due to: https://bugzilla.redhat.com/show_bug.cgi?id=1165864"
        local INSTANCECFG="/tmp/cloneca_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/cloneca_instance_create.out"
        rlLog "$FUNCNAME"
        rhcs_install_prep_disableFirewall
	local number=$1
	local master_hostname=$2
	local CA=$3
	local SUBSYSTEM_NAME=$(echo CloneCA${number})
	local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)

        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
	rlRun "mkdir /tmp/dummydir"
        rlRun "rhds_install $(eval echo \$CLONE_CA${number}_LDAP_PORT) $(eval echo \$CLONE_CA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $(eval echo \$${CA}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install"

        #Install CA
        rlLog "Creating CLONE CA Instance"
                rlLog "Setting up Dogtag CLONE CA instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$CLONE_CA${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$CLONE_CA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$CLONE_CA${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$CLONE_CA${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$CLONE_CA${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$(eval echo \$CLONE${number}_USER)" >> $INSTANCECFG
                echo "pki_group=$(eval echo \$CLONE${number}_GROUP)" >> $INSTANCECFG
                echo "pki_audit_group=$(eval echo \$CLONE${number}_GROUP_AUDIT)" >> $INSTANCECFG
                echo "pki_token_name=$(eval echo \$CLONE_CA${number}_TOKEN_NAME)" >> $INSTANCECFG
                echo "pki_token_password=$(eval echo \$CLONE_CA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$CLONE_CA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_admin_password=$(eval echo \$CLONE_CA${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
		echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
		echo "pki_clone=True" >> $INSTANCECFG
		echo "pki_clone_pkcs12_password=$(eval echo \$CLONE_CA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
		echo "pki_clone_pkcs12_path=$CLIENT_PKCS12_DIR/ca_backup_keys.p12" >> $INSTANCECFG
		echo "pki_clone_replication_master_port=$(eval echo \$${CA}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_clone_replication_clone_port=$(eval echo \$CLONE_CA${number}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_clone_repicate_schema=$REPLICATE_SCHEMA" >> $INSTANCECFG
		echo "pki_clone_replication_security=$REPLICATION_SEC" >> $INSTANCECFG
		echo "pki_clone_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_client_database_dir=/tmp/dummydir" >> $INSTANCECFG
                echo "pki_client_database_password=$ROOTCA_CERTDB_DIR_PASSWORD" >> $INSTANCECFG
		echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
		echo "[CA]" >> $INSTANCECFG

  		echo "pki_admin_name=$(eval echo \$CLONE_CA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$CLONE_CA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$CLONE_CA${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$CLONE_CA${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$CLONE_CA${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$CLONE_CA${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$CLONE_CA${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$CLONE_CA${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG

                echo "pki_ssl_server_key_type=$(eval echo \$CLONE_CA${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$CLONE_CA${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$CLONE_CA${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$CLONE_CA${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$CLONE_CA${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$CLONE_CA${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$CLONE_CA${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
		echo "pki_import_admin_cert=$(eval echo \$CLONE_CA${number}_ADMIN_IMPORT_CERT)" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$CLONE_CA${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
		echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
		echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
		echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
		echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
		echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
		echo "pki_ds_hostname=$(hostname)" >> $INSTANCECFG
		echo "pki_ds_ldap_port=$(eval echo \$CLONE_CA${number}_LDAP_PORT)" >> $INSTANCECFG
		echo "pki_ds_bind_dn=$(eval echo \$CLONE${number}_LDAP_ROOTDN)" >> $INSTANCECFG
		echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
		echo "pki_ds_secure_connection=$(eval echo \$CLONE_CA${number}_SECURE_CONN)" >> $INSTANCECFG
		echo "pki_ds_remove_data=$(eval echo \$CLONE_CA${number}_REMOVE_DATA)" >> $INSTANCECFG
		echo "pki_ds_base_dn=$(eval echo \$${CA}_DB_SUFFIX)" >> $INSTANCECFG
 		echo "pki_ds_database=$(eval echo \$${CA}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
		HOSTNAME_CLONE=`hostname`
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
                rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                rlRun "cat $INSTANCE_CREATE_OUT"
                exp_message1="Administrator's username:             $(eval echo \$CLONE_CA${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message2="$DOMAIN"
                rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$CLONE_CA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$CLONE_CA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$HOSTNAME_CLONE:$(eval echo \$CLONE_CA${number}_SECURE_PORT)/ca"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                #echo "export CA_SERVER_ROOT=/var/lib/pki/$(eval echo \$CLONE_CA${number}_TOMCAT_INSTANCE_NAME)/ca" >> /opt/rhqa_pki/env.sh
	
		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/CLONE_CA${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$CLONE_CA${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$CLONE_CA${number}_SECURE_PORT)/services"
                if [ $(grep $exp_result1 /tmp/CLONE_CA${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/CLONE_CA${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "CLONE_CA${number} instance creation successful"
                        sed -i s/^CLONE_CA${number}_INSTANCE_CREATED_STATUS=False/CLONE_CA${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export CLONE_CA${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd

}

rhcs_install_SubCA(){

     rlPhaseStartTest  "rhcs_install_subca - Install RHCS eval echo SUBCA Server"
        local INSTANCECFG="/tmp/subca_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/subca_instance_create.out"
        rlLog "$FUNCNAME"
        local DOMAIN='hostname -d'
        rhcs_install_prep_disableFirewall

        #Install and configure RHDS instance 
	local number=$1
        local master_hostname=$2
        local CA=$3
	local SUBSYSTEM_NAME=$(echo SubCA${number})
	local SUBCA${number}_DOMAIN=`hostname -d`
	rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $(eval echo \$SUBCA${number}_LDAP_PORT) $(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$SUBCA${number}_LDAP_ROOTDN)\" $(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD) $(eval echo \$SUBCA${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install"
	#Install eval echo $(eval echo $SUBCA${number} INSTANCE
                rlLog "Setting up Dogtag SUBCA instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$SUBCA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$SUBCA${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$SUBCA${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$SUBCA${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$(eval echo \$SUBCA${number}_USER)" >> $INSTANCECFG
                echo "pki_group=$(eval echo \$SUBCA${number}_GROUP)" >> $INSTANCECFG
                echo "pki_audit_group=$(eval echo \$SUBCA${number}_GROUP_AUDIT)" >> $INSTANCECFG
                echo "pki_token_name=$(eval echo \$SUBCA${number}_TOKEN_NAME)" >> $INSTANCECFG
                echo "pki_token_password=$(eval echo \$SUBCA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$SUBCA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_admin_password=$(eval echo \$SUBCA${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
     		echo "pki_ds_password=$(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG   
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
		echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG

                echo "[CA]" >> $INSTANCECFG

		echo "pki_subordinate=True" >> $INSTANCECFG
		echo "pki_admin_name=$(eval echo \$SUBCA${number}_ADMIN_USER)" >> $INSTANCECFG
		echo "pki_issuing_ca=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$SUBCA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$SUBCA${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$SUBCA${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$SUBCA${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$SUBCA${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$SUBCA${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$SUBCA${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$(eval echo \$SUBCA${number}_ADMIN_IMPORT_CERT)" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$SUBCA${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
                echo "pki_subsystem_key_type=$(eval echo \$SUBCA${number}_SUBSYSTEM_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_subsystem_key_size=$(eval echo \$SUBCA${number}_SUBYSTEM_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_subsystem_key_algorithm=$(eval echo \$SUBCA${number}_SUBSYSTEM_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_signing_algorithm=$(eval echo \$SUBCA${number}_SUBSYSTEM_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_subsystem_token=$(eval echo \$SUBCA${number}_SUBSYSTEM_TOKEN)" >> $INSTANCECFG
                echo "pki_subsystem_nickname=$(eval echo \$SUBCA${number}_SUBSYTEM_NICKNAME)" >> $INSTANCECFG
                echo "pki_subsystem_subject_dn=$(eval echo \$SUBCA${number}_SUBSYSTEM_SUBJECT_DN)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_ca_signing_key_type=$(eval echo \$SUBCA${number}_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ca_signing_key_size=$(eval echo \$SUBCA${number}_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ca_signing_key_algorithm=$(eval echo \$SUBCA${number}_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ca_signing_signing_algorithm=$(eval echo \$SUBCA${number}_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ca_signing_token=$(eval echo \$SUBCA${number}_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_ca_signing_nickname=$(eval echo \$SUBCA${number}_SIGNING_NICKNAME)" >> $INSTANCECFG
                echo "pki_ca_signing_subject_dn=$(eval echo \$SUBCA${number}_SIGNING_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_type=$(eval echo \$SUBCA${number}_OCSP_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_size=$(eval echo \$SUBCA${number}_OCSP_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ocsp_signing_key_algorithm=$(eval echo \$SUBCA${number}_OCSP_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ocsp_signing_signing_algorithm=$(eval echo \$SUBCA${number}_OCSP_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ocsp_signing_token=$(eval echo \$SUBCA${number}_OCSP_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_ocsp_signing_nickname=$(eval echo \$SUBCA${number}_OCSP_SIGNING_NICKNAME)" >> $INSTANCECFG
                echo "pki_ocsp_signing_subject_dn=$(eval echo \$SUBCA${number}_OCSP_SIGNING_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_audit_signing_key_type=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_size=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_audit_signing_key_algorithm=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_signing_algorithm=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_audit_signing_token=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_TOKEN)" >> $INSTANCECFG
                echo "pki_audit_signing_nickname=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_NICKNAME)" >> $INSTANCECFG
                echo "pki_audit_signing_subject_dn=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_ssl_server_key_type=$(eval echo \$SUBCA${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$SUBCA${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$SUBCA${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$SUBCA${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$SUBCA${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$SUBCA${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
		echo "pki_ssl_server_subject_dn=$(eval echo \$SUBCA${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_subordinate_security_domain_name=$(eval echo \$SUBCA${number}_DOMAIN)" >> $INSTANCECFG
		echo "pki_subordinate_create_new_security_domain=True" >> $INSTANCECFG
                echo "pki_ds_hostname=$(eval echo \$SUBCA${number}_DS_HOSTNAME)" >> $INSTANCECFG
                echo "pki_ds_ldap_port=$(eval echo \$SUBCA${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_ds_bind_dn=$(eval echo \$SUBCA${number}_LDAP_ROOTDN)" >> $INSTANCECFG
                echo "pki_ds_password=$(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
                echo "pki_ds_secure_connection=$(eval echo \$SUBCA${number}_SECURE_CONN)" >> $INSTANCECFG
                echo "pki_ds_remove_data=$(eval echo \$SUBCA${number}_REMOVE_DATA)" >> $INSTANCECFG
                echo "pki_ds_base_dn=$(eval echo \$SUBCA${number}_DB_SUFFIX)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
		echo "pki_backup_keys=$(eval echo \$SUBCA${number}_BACKUP)" >> $INSTANCECFG
                echo "pki_backup_password=$(eval echo \$SUBCA${number}_BACKUP_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_database_dir=$(eval echo \$SUBCA${number}_CERTDB_DIR)" >> $INSTANCECFG
                echo "pki_client_database_password=$(eval echo \$SUBCA${number}_CERTDB_DIR_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_database_purge=$(eval echo \$SUBCA${number}_CLIENT_DB_PURGE)" >> $INSTANCECFG
 		echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
                echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
                echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
                echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
                echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
                echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG
                echo "export SUBCA${number}_DOMAIN=$(eval echo \$SUBCA${number}_DOMAIN)" >> /opt/rhqa_pki/env.sh
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
                rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                rlRun "cat $INSTANCE_CREATE_OUT"
                exp_message1="Administrator's username:             $(eval echo \$SUBCA${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message1_1="Administrator's PKCS #12 file:"
                rlAssertGrep "$exp_message1_1" "$INSTANCE_CREATE_OUT"
                exp_message2="$(eval echo \$SUBCA${number}_DOMAIN)"
                rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$SUBCA${number}_SECURE_PORT)/ca"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                #echo "export CA_SERVER_ROOT=/var/lib/pki/$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)/ca" >> /opt/rhqa_pki/env.sh
		mkdir -p $CLIENT_PKCS12_DIR
                mv /var/lib/pki/$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)/alias/ca_backup_keys.p12 $CLIENT_PKCS12_DIR

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/SUBCA${number}_instance_status.txt 2>&1"
		exp_result1="$SUBCA${number}_TOMCAT_INSTANCE_NAME\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$SUBCA${number}_SECURE_PORT/ca/services"
                if [ $(grep $exp_result1 /tmp/SUBCA${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/SUBCA${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "SUBCA${number} instance created successfully"
                        sed -i s/^SUBCA${number}_INSTANCE_CREATED_STATUS=False/SUBCA${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export SUBCA${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}


rhcs_install_cloneKRA(){

     rlPhaseStartTest  "rhcs_install_clonekra_only - Install RHCS CLONE KRA Server BZ1165864"
	rlLog "Failing due to: https://bugzilla.redhat.com/show_bug.cgi?id=1165864"
        local INSTANCECFG="/tmp/clonekra_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/clonekra_instance_create.out"
        rlLog "$FUNCNAME"
        rhcs_install_prep_disableFirewall
	local number=$1
        local master_hostname=$2
        local CA=$3
	local MASTER_KRA=$4
	local SUBSYSTEM_NAME=$(echo CloneKRA${number})
        local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $(eval echo \$CLONE_KRA${number}_LDAP_PORT) $(eval echo \$CLONE_KRA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $(eval echo \$${MASTER_KRA}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install"

        #Install KRA CLONE
        rlLog "Creating CLONE KRA Instance"
                rlLog "Setting up Dogtag CLONE KRA instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$CLONE_KRA${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$CLONE_KRA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$CLONE_KRA${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$CLONE_KRA${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$CLONE_KRA${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$(eval echo \$CLONE${number}_USER)" >> $INSTANCECFG
                echo "pki_group=$(eval echo \$CLONE${number}_GROUP)" >> $INSTANCECFG
                echo "pki_audit_group=$(eval echo \$CLONE${number}_GROUP_AUDIT)" >> $INSTANCECFG
                echo "pki_token_name=$(eval echo \$CLONE_CA${number}_TOKEN_NAME)" >> $INSTANCECFG
                echo "pki_token_password=$(eval echo \$CLONE_CA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$CLONE_CA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
             	echo "pki_issuing_ca=https://$(hostname):$(eval echo \$CLONE_CA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
                echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
   		echo "pki_admin_password=$(eval echo \$CLONE_CA${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_clone_replication_master_port=$(eval echo \$${MASTER_KRA}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_clone_replication_clone_port=$(eval echo \$CLONE_KRA${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_clone_replication_security=$REPLICATION_SEC" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
		echo "pki_client_database_dir=/tmp/dummydir" >> $INSTANCECFG
                echo "pki_client_database_password=$ROOTCA_CERTDB_DIR_PASSWORD" >> $INSTANCECFG

                echo "[KRA]" >> $INSTANCECFG

                echo "pki_clone_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_clone_repicate_schema=$REPLICATE_SCHEMA" >> $INSTANCECFG
                echo "pki_clone_pkcs12_path=$CLIENT_PKCS12_DIR/kra_backup_keys.p12" >> $INSTANCECFG
                echo "pki_clone_pkcs12_password=$(eval echo \$${MASTER_KRA}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_clone=True" >> $INSTANCECFG
                echo "pki_admin_name=$(eval echo \$CLONE_KRA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$CLONE_KRA${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$CLONE_KRA${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$CLONE_KRA${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$CLONE_KRA${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$CLONE_KRA${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$CLONE_KRA${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$CLONE_KRA${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
		echo "pki_ssl_server_key_type=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$CLONE_KRA${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$CLONE_ADMIN_IMPORT_CERT" >> $INSTANCECFG
 		echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$${MASTER_KRA}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
                echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
                echo "pki_ds_hostname=$(hostname)" >> $INSTANCECFG
                echo "pki_ds_ldap_port=$(eval echo \$CLONE_KRA${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_ds_bind_dn=$(eval echo \$CLONE${number}_LDAP_ROOTDN)" >> $INSTANCECFG
                echo "pki_ds_secure_connection=$(eval echo \$CLONE_KRA${number}_SECURE_CONN)" >> $INSTANCECFG
                echo "pki_ds_remove_data=$(eval echo \$CLONE_KRA${number}_REMOVE_DATA)" >> $INSTANCECFG
                echo "pki_ds_base_dn=$(eval echo \$${MASTER_KRA}_DB_SUFFIX)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$${MASTER_KRA}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
 		cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s KRA -f $INSTANCECFG -v "
                rlRun "pkispawn -s KRA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $(eval echo \$CLONE_KRA${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message4="To check the status of the subsystem:"
                rlAssertGrep "$exp_message4" "$INSTANCE_CREATE_OUT"
                exp_message5="systemctl status pki-tomcatd@$(eval echo \$CLONE_KRA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message6="To restart the subsystem:"
                rlAssertGrep "$exp_message6" "$INSTANCE_CREATE_OUT"
                exp_message7=" systemctl restart pki-tomcatd@$(eval echo \$CLONE_KRA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message7" "$INSTANCE_CREATE_OUT"
                exp_message8="The URL for the subsystem is:"
                rlAssertGrep "$exp_message8" "$INSTANCE_CREATE_OUT"
                exp_message8_1="https://$master_hostname:$(eval echo \$CLONE_KRA${number}_SECURE_PORT)/kra"
                rlAssertGrep "$exp_message8_1" "$INSTANCE_CREATE_OUT"
#                echo "export KRA_SERVER_ROOT=/var/lib/pki/$(eval echo \$CLONE_KRA{number}_TOMCAT_INSTANCE_NAME)/kra" >> /opt/rhqa_pki/env.sh

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/CLONE_KRA${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$CLONE_KRA${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$CLONE_KRA${number}_SECURE_PORT)/services"
                if [ $(grep $exp_result1 /tmp/CLONE_KRA${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/CLONE_KRA${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "CLONE_KRA${number} instance creation successful"
                        sed -i s/^CLONE_KRA${number}_INSTANCE_CREATED_STATUS=False/CLONE_KRA${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export CLONE_KRA${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd
}


rhcs_install_cloneOCSP(){

     rlPhaseStartTest  "rhcs_install_CLONEOCSP_only - Install RHCS CLONE OCSP SERVER - Ticket 1058"
        local INSTANCECFG="/tmp/cloneocsp_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/cloneocsp_instance_create.out"
        rlLog "$FUNCNAME"
        local DOMAIN='hostname -d'
        rhcs_install_prep_disableFirewall
	local number=$1
        local master_hostname=$2
        local CA=$3
	local MASTER_OCSP=$4
	local SUBSYSTEM_NAME=$(echo CloneOCSP${number})
	local DOMAIN=$master_hostname | cut -d. -f2-
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
	rlLog "$SUBSYSTEM_NAME"
        rlRun "rhds_install $(eval echo \$CLONE_OCSP${number}_LDAP_PORT) $(eval echo \$CLONE_OCSP${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $(eval echo \$${MASTER_OCSP}_DB_SUFFIX) $SUBSYSTEM_NAME > /tmp/ocspclone.out 2>&1" 0 "Installing RHDS instance for CLONE CA install"

        #Install OCSP CLONE
        rlLog "Creating CLONE OCSP Instance"
                rlLog "Setting up Dogtag OCSP instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$CLONE_OCSP${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$CLONE_OCSP${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$CLONE_OCSP${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$CLONE_OCSP${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$CLONE_OCSP${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$(eval echo \$CLONE${number}_USER)" >> $INSTANCECFG
                echo "pki_group=$(eval echo \$CLONE${number}_GROUP)" >> $INSTANCECFG
                echo "pki_audit_group=$(eval echo \$CLONE${number}_GROUP_AUDIT)" >> $INSTANCECFG
                echo "pki_token_name=$(eval echo \$CLONE_CA${number}_TOKEN_NAME)" >> $INSTANCECFG
                echo "pki_token_password=$(eval echo \$CLONE_CA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$CLONE_CA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_clone=True" >> $INSTANCECFG
                echo "pki_clone_pkcs12_password=$(eval echo \$${MASTER_OCSP}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_clone_pkcs12_path=$CLIENT_PKCS12_DIR/ocsp_backup_keys.p12" >> $INSTANCECFG
                echo "pki_clone_replication_master_port=$(eval echo \$${MASTER_OCSP}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_clone_replication_clone_port=$(eval echo \$CLONE_OCSP${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_clone_repicate_schema=$REPLICATE_SCHEMA" >> $INSTANCECFG
                echo "pki_clone_replication_security=$REPLICATION_SEC" >> $INSTANCECFG
                echo "pki_clone_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
		echo "pki_issuing_ca=https://$(hostname):$(eval echo \$CLONE_CA${number}_SECURE_PORT)" >> $INSTANCECFG
		#echo "pki_client_database_dir=/tmp/dummydir" >> $INSTANCECFG
                #echo "pki_client_database_password=$ROOTCA_CERTDB_DIR_PASSWORD" >> $INSTANCECFG

                echo "[OCSP]" >> $INSTANCECFG
                
                echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
                echo "pki_admin_name=$(eval echo \$CLONE_OCSP${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$CLONE_OCSP${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$CLONE_OCSP${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$CLONE_OCSP${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$CLONE_OCSP${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$CLONE_OCSP${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$CLONE_OCSP${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$CLONE_OCSP${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
		echo "pki_ssl_server_key_type=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$CLONE_OCSP${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$CLONE_ADMIN_IMPORT_CERT" >> $INSTANCECFG
                echo "pki_admin_password=$(eval echo \$CLONE_OCSP${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
		echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$CLONE_OCSP${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
                echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
                echo "pki_ds_hostname=$(hostname)" >> $INSTANCECFG
                echo "pki_ds_ldap_port=$(eval echo \$CLONE_OCSP${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_ds_bind_dn=$(eval echo \$CLONE${number}_LDAP_ROOTDN)" >> $INSTANCECFG
                echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
                echo "pki_ds_secure_connection=$(eval echo \$CLONE_OCSP${number}_SECURE_CONN)" >> $INSTANCECFG
                echo "pki_ds_remove_data=$(eval echo \$CLONE_OCSP${number}_REMOVE_DATA)" >> $INSTANCECFG
                echo "pki_ds_base_dn=$(eval echo \$${MASTER_OCSP}_DB_SUFFIX)" >> $INSTANCECFG
		echo "pki_ds_database=$(eval echo \$${MASTER_OCSP}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s OCSP -f $INSTANCECFG -v "
                rlRun "pkispawn -s OCSP -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $(eval echo \$CLONE_OCSP${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$CLONE_OCSP${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$CLONE_OCSP${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$BEAKERCLONE:$(eval echo \$CLONE_OCSP${number}_SECURE_PORT)/ocsp"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                #echo "export OCSP_SERVER_ROOT=/var/lib/pki/$(eval echo \$CLONE_OCSP${number}_TOMCAT_INSTANCE_NAME)/ocsp" >> /opt/rhqa_pki/env.sh
		rlLog "https://fedorahosted.org/pki/ticket/1058"

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/CLONE_OCSP${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$CLONE_OCSP${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$CLONE_OCSP${number}_SECURE_PORT)/services"
                if [ $(grep $exp_result1 /tmp/CLONE_OCSP${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/CLONE_OCSP${number}_instance_status.txt | wc -l) -gt 0 ] ; then
                        rlLog "CLONE_OCSP${number} instance creation successful"
                        sed -i s/^CLONE_OCSP${number}_INSTANCE_CREATED_STATUS=False/CLONE_OCSP${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export CLONE_OCSP${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
     rlPhaseEnd

}

rhcs_install_cloneTKS(){

     rlPhaseStartTest  "rhcs_install_clonetks_only - Install RHCS CLONE TKS Server BZ1165864"
	rlLog "Failing due to: https://bugzilla.redhat.com/show_bug.cgi?id=1165864"
        local INSTANCECFG="/tmp/clonetks_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/clonetks_instance_create.out"
        rlLog "$FUNCNAME"
        local DOMAIN='hostname -d'
        rhcs_install_prep_disableFirewall
	local number=$1
        local master_hostname=$2
        local CA=$3
	local SUBSYSTEM_NAME=$(echo CloneTKS${number})
	local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $(eval echo \$CLONE_TKS${number}_LDAP_PORT) $(eval echo \$CLONE_TKS${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $TKS1_DB_SUFFIX $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE TKS install"

        #Install CLONE TKS 
        rlLog "Creating CLONE TKS Instance"
                rlLog "Setting up Dogtag TKS CLONE Instance"
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$CLONE_TKS${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$CLONE_TKS${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$CLONE_TKS${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$CLONE_TKS${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$CLONE_TKS${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$(eval echo \$CLONE${number}_USER)" >> $INSTANCECFG
                echo "pki_group=$(eval echo \$CLONE${number}_GROUP)" >> $INSTANCECFG
                echo "pki_audit_group=$(eval echo \$CLONE${number}_GROUP_AUDIT)" >> $INSTANCECFG
                echo "pki_token_name=$(eval echo \$CLONE_CA${number}_TOKEN_NAME)" >> $INSTANCECFG
                echo "pki_token_password=$(eval echo \$CLONE_CA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$CLONE_CA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
            	echo "pki_issuing_ca=https://$(hostname):$(eval echo \$CLONE_CA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_clone=True" >> $INSTANCECFG
		echo "pki_clone_pkcs12_password=$TKS1_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_clone_pkcs12_path=$CLIENT_PKCS12_DIR/tks_backup_keys.p12" >> $INSTANCECFG
                echo "pki_clone_replication_master_port=$TKS1_LDAP_PORT" >> $INSTANCECFG
                echo "pki_clone_replication_clone_port=$(eval echo \$CLONE_TKS${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_clone_repicate_schema=$REPLICATE_SCHEMA" >> $INSTANCECFG
                echo "pki_clone_replication_security=$REPLICATION_SEC" >> $INSTANCECFG
                echo "pki_clone_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
                echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
		echo "pki_admin_password=$(eval echo \$CLONE_TKS${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
		echo "pki_client_database_dir=/tmp/dummydir" >> $INSTANCECFG
                echo "pki_client_database_password=$ROOTCA_CERTDB_DIR_PASSWORD" >> $INSTANCECFG

                echo "[TKS]" >> $INSTANCECFG

                echo "pki_admin_name=$(eval echo \$CLONE_TKS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$CLONE_TKS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$CLONE_TKS${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$CLONE_TKS${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$CLONE_TKS${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$CLONE_TKS${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$CLONE_TKS${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$CLONE_TKS${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
		echo "pki_ssl_server_key_type=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$CLONE_TKS${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
 		echo "pki_import_admin_cert=$CLONE_ADMIN_IMPORT_CERT" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$TKS1_ADMIN_CERT_NICKNAME.p12" >> $INSTANCECFG
                echo "pki_ds_hostname=$(hostname)" >> $INSTANCECFG
                echo "pki_ds_ldap_port=$(eval echo \$CLONE_TKS${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_ds_bind_dn=$(eval echo \$CLONE${number}_LDAP_ROOTDN)" >> $INSTANCECFG
                echo "pki_ds_secure_connection=$(eval echo \$CLONE_TKS${number}_SECURE_CONN)" >> $INSTANCECFG
                echo "pki_ds_remove_data=$(eval echo \$CLONE_TKS${number}_REMOVE_DATA)" >> $INSTANCECFG
                echo "pki_ds_base_dn=$TKS1_DB_SUFFIX" >> $INSTANCECFG
		echo "pki_ds_database=$TKS1_LDAP_INSTANCE_NAME" >> $INSTANCECFG
		cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s TKS -f $INSTANCECFG -v "
                rlRun "pkispawn -s TKS -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $(eval echo \$CLONE_TKS${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$CLONE_TKS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$CLONE_TKS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$CLONE_TKS${number}_SECURE_PORT)/tks"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/CLONE_TKS${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$CLONE_TKS${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$CLONE_TKS${number}_SECURE_PORT)/services"
                if [ $(grep $exp_result1 /tmp/CLONE_TKS${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/CLONE_TKS${number}_instance_status.txt | wc -l) -gt 0 ]; then
                        rlLog "CLONE_TKS${number} instance creation successful"
                        sed -i s/^CLONE_TKS${number}_INSTANCE_CREATED_STATUS=False/CLONE_TKS${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export CLONE_TKS${number}_INSTANCE_CREATED_STATUS=TRUE"
                fi
	rlPhaseEnd
}

rhcs_install_cloneTPS(){

     rlPhaseStartTest  "rhcs_install_clonetps_only - Install RHCS CLONE TPS Server BZ1190184"
        rlLog "Failing due to: https://bugzilla.redhat.com/show_bug.cgi?id=1190184"
        local INSTANCECFG="/tmp/clonetps_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/clonetps_instance_create.out"
        rlLog "$FUNCNAME"
        local DOMAIN='hostname -d'
        rhcs_install_prep_disableFirewall
        local number=$1
        local master_hostname=$2
        local CA=$3
	local KRA=$4
	local TKS=$5
        local SUBSYSTEM_NAME=$(echo CloneTPS${number})
        local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $(eval echo \$CLONE_TPS${number}_LDAP_PORT) $(eval echo \$CLONE_TPS${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $TPS1_DB_SUFFIX $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE TPS install"

        #Install CLONE TPS
        rlLog "Creating CLONE TPS Instance"
                rlLog "Setting up Dogtag TPS CLONE Instance"
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_instance_name=$(eval echo \$CLONE_TPS${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
                echo "pki_https_port=$(eval echo \$CLONE_TPS${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_http_port=$(eval echo \$CLONE_TPS${number}_UNSECURE_PORT)" >> $INSTANCECFG
                echo "pki_ajp_port=$(eval echo \$CLONE_TPS${number}_AJP_PORT)" >> $INSTANCECFG
                echo "pki_tomcat_server_port=$(eval echo \$CLONE_TPS${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
                echo "pki_user=$(eval echo \$CLONE${number}_USER)" >> $INSTANCECFG
                echo "pki_group=$(eval echo \$CLONE${number}_GROUP)" >> $INSTANCECFG
                echo "pki_audit_group=$(eval echo \$CLONE${number}_GROUP_AUDIT)" >> $INSTANCECFG
                echo "pki_token_name=$(eval echo \$CLONE_CA${number}_TOKEN_NAME)" >> $INSTANCECFG
                echo "pki_token_password=$(eval echo \$CLONE_CA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
                echo "pki_client_pkcs12_password=$(eval echo \$CLONE_CA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
                echo "pki_issuing_ca=https://$(hostname):$(eval echo \$CLONE_CA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_clone=True" >> $INSTANCECFG
                echo "pki_clone_pkcs12_password=$TPS1_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_clone_pkcs12_path=$CLIENT_PKCS12_DIR/tks_backup_keys.p12" >> $INSTANCECFG
                echo "pki_clone_replication_master_port=$TPS1_LDAP_PORT" >> $INSTANCECFG
                echo "pki_clone_replication_clone_port=$(eval echo \$CLONE_TPS${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_clone_repicate_schema=$REPLICATE_SCHEMA" >> $INSTANCECFG
                echo "pki_clone_replication_security=$REPLICATION_SEC" >> $INSTANCECFG
                echo "pki_clone_uri=https://$master_hostname:$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
                echo "pki_ds_password=$(eval echo \$CLONE${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
                echo "pki_admin_password=$(eval echo \$CLONE_TPS${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
                echo "pki_security_domain_https_port=$(eval echo \$${CA}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_security_domain_user=$(eval echo \$${CA}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_security_domain_password=$(eval echo \$${CA}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
                echo "pki_security_domain_name=$DOMAIN" >> $INSTANCECFG
		echo "pki_client_database_dir=/tmp/dummydir" >> $INSTANCECFG
                echo "pki_client_database_password=$ROOTCA_CERTDB_DIR_PASSWORD" >> $INSTANCECFG

                echo "[TPS]" >> $INSTANCECFG
		echo "pki_admin_name=$(eval echo \$CLONE_TPS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_uid=$(eval echo \$CLONE_TPS${number}_ADMIN_USER)" >> $INSTANCECFG
                echo "pki_admin_email=$(eval echo \$CLONE_TPS${number}_ADMIN_EMAIL)" >> $INSTANCECFG
                echo "pki_admin_dualkey=$(eval echo \$CLONE_TPS${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
                echo "pki_admin_key_size=$(eval echo \$CLONE_TPS${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_admin_key_type=$(eval echo \$CLONE_TPS${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_admin_subject_dn=$(eval echo \$CLONE_TPS${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
                echo "pki_admin_nickname=$(eval echo \$CLONE_TPS${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_key_type=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_size=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
                echo "pki_ssl_server_key_algorithm=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_signing_algorithm=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
                echo "pki_ssl_server_token=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
                echo "pki_ssl_server_nickname=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
                echo "pki_ssl_server_subject_dn=$(eval echo \$CLONE_TPS${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
                echo "pki_import_admin_cert=$CLONE_ADMIN_IMPORT_CERT" >> $INSTANCECFG
                echo "pki_client_admin_cert_p12=$CLIENT_DIR/$TPS1_ADMIN_CERT_NICKNAME.p12" >> $INSTANCECFG
                echo "pki_ds_hostname=$(hostname)" >> $INSTANCECFG
                echo "pki_ds_ldap_port=$(eval echo \$CLONE_TPS${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_ds_bind_dn=$(eval echo \$CLONE${number}_LDAP_ROOTDN)" >> $INSTANCECFG
                echo "pki_ds_secure_connection=$(eval echo \$CLONE_TPS${number}_SECURE_CONN)" >> $INSTANCECFG
                echo "pki_ds_remove_data=$(eval echo \$CLONE_TPS${number}_REMOVE_DATA)" >> $INSTANCECFG
                echo "pki_ds_base_dn=$TPS1_DB_SUFFIX" >> $INSTANCECFG
                echo "pki_ds_database=$TPS1_LDAP_INSTANCE_NAME" >> $INSTANCECFG
		echo "pki_ca_uri=https://$(hostname):$(eval echo \$CLONE_CA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_enable_server_side_keygen=$(eval echo \$CLONE_TPS${number}_SERVER_KEYGEN)" >> $INSTANCECFG
                echo "pki_kra_uri=https://$(hostname):$(eval echo \$CLONE_KRA${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_tks_uri=https://$(hostname):$(eval echo \$CLONE_TKS${number}_SECURE_PORT)" >> $INSTANCECFG
                echo "pki_authdb_hostname=$(eval echo \$CLONE_TPS${number}_DS_HOSTNAME)" >> $INSTANCECFG
                echo "pki_authdb_port=$(eval echo \$CLONE_TPS${number}_LDAP_PORT)" >> $INSTANCECFG
                echo "pki_authdb_basedn=$(eval echo \$TPS${number}_DB_SUFFIX)" >> $INSTANCECFG
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s TPS -f $INSTANCECFG -v "
                rlRun "pkispawn -s TPS -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $(eval echo \$CLONE_TPS${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$CLONE_TPS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$CLONE_TPS${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$CLONE_TPS${number}_SECURE_PORT)/tks"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"

		#Update Instance creation status to env.sh
		rlLog "Executing: pkidaemon status tomcat"
		rlRun "pkidaemon status tomcat >  /tmp/CLONE_TPS${number}_instance_status.txt 2>&1"
		exp_result1="$(eval echo \$CLONE_TPS${number}_TOMCAT_INSTANCE_NAME)\sis\srunning"
                exp_result2="Secure\sAdmin\sURL\s\s\s\s=\shttps://$(hostname):$(eval echo \$CLONE_TPS${number}_SECURE_PORT)/services"
                if [ $(grep $exp_result1 /tmp/CLONE_TPS${number}_instance_status.txt | wc -l) -gt 0 ] && [ $(grep $exp_result2 /tmp/CLONE_TPS${number}_instance_status.txt | wc -l) -gt 0 ]; then
                        rlLog "CLONE_TPS${number} instance creation successful"
                        sed -i s/^CLONE_TPS${number}_INSTANCE_CREATED_STATUS=False/CLONE_TPS${number}_INSTANCE_CREATED_STATUS=TRUE/g  /opt/rhqa_pki/env.sh
                        rlRun "export CLONE_TPS${number}_INSTANCE_CREATED_STATUS=TRUE"

                fi
     rlPhaseEnd
}
###########################################################
#       CA SIGNED BY AN EXTERNAL CA TESTS                                  #
###########################################################
rhcs_install_CAwithExtCA() {
	rlLog "Creating a CA signed by ROOTCA"
	local INSTANCECFG="/tmp/subca_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/subca_instance_create.out"
        rlLog "$FUNCNAME"
        local DOMAIN='hostname -d'
        rhcs_install_prep_disableFirewall

        #Install and configure RHDS instance 
        local number=$1
	local csr=$2
	local admin_cert_location=$4
	local client_pkcs12_password=$5
	local admin_cert=$6
	local tmp_host=$7
        local SUBSYSTEM_NAME=$(echo SubCA${number})
        local SUBCA${number}_DOMAIN=`hostname -d`
	local cert_type=$3
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $(eval echo \$SUBCA${number}_LDAP_PORT) $(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$SUBCA${number}_LDAP_ROOTDN)\" $(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD) $(eval echo \$SUBCA${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install"
        #Install eval echo $(eval echo $SUBCA${number} INSTANCE
        rlLog "Setting up Dogtag SUBCA instance ............."
        echo "[DEFAULT]" > $INSTANCECFG
        echo "pki_instance_name=$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)" >> $INSTANCECFG
        echo "pki_https_port=$(eval echo \$SUBCA${number}_SECURE_PORT)" >> $INSTANCECFG
        echo "pki_http_port=$(eval echo \$SUBCA${number}_UNSECURE_PORT)" >> $INSTANCECFG
        echo "pki_ajp_port=$(eval echo \$SUBCA${number}_AJP_PORT)" >> $INSTANCECFG
        echo "pki_tomcat_server_port=$(eval echo \$SUBCA${number}_TOMCAT_SERVER_PORT)" >> $INSTANCECFG
        echo "pki_user=$(eval echo \$SUBCA${number}_USER)" >> $INSTANCECFG
        echo "pki_group=$(eval echo \$SUBCA${number}_GROUP)" >> $INSTANCECFG
        echo "pki_audit_group=$(eval echo \$SUBCA${number}_GROUP_AUDIT)" >> $INSTANCECFG
        echo "pki_token_name=$(eval echo \$SUBCA${number}_TOKEN_NAME)" >> $INSTANCECFG
        echo "pki_token_password=$(eval echo \$SUBCA${number}_TOKEN_PASSWORD)" >> $INSTANCECFG
        echo "pki_client_pkcs12_password=$(eval echo \$SUBCA${number}_CLIENT_PKCS12_PASSWORD)" >> $INSTANCECFG
        echo "pki_admin_password=$(eval echo \$SUBCA${number}_ADMIN_PASSWORD)" >> $INSTANCECFG
        echo "pki_ds_password=$(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
        echo "pki_client_dir=$CLIENT_DIR" >> $INSTANCECFG
        echo "pki_security_domain_hostname=$master_hostname" >> $INSTANCECFG
        echo "pki_security_domain_https_port=$(eval echo \$SUBCA${number}_SECURE_PORT)" >> $INSTANCECFG
        echo "pki_security_domain_user=$(eval echo \$SUBCA${number}_ADMIN_USER)" >> $INSTANCECFG
        echo "pki_security_domain_password=$(eval echo \$SUBCA${number}_SECURITY_DOMAIN_PASSWORD)" >> $INSTANCECFG
	echo "pki_security_domain_name=$(eval echo \$SUBCA${number}_DOMAIN)" >> $INSTANCECFG

        echo "[CA]" >> $INSTANCECFG

        echo "pki_external=True" >> $INSTANCECFG
        echo "pki_external_csr_path=$csr" >> $INSTANCECFG
        echo "pki_admin_name=$(eval echo \$SUBCA${number}_ADMIN_USER)" >> $INSTANCECFG
        echo "pki_admin_uid=$(eval echo \$SUBCA${number}_ADMIN_USER)" >> $INSTANCECFG
        echo "pki_admin_email=$(eval echo \$SUBCA${number}_ADMIN_EMAIL)" >> $INSTANCECFG
        echo "pki_admin_dualkey=$(eval echo \$SUBCA${number}_ADMIN_DUAL_KEY)" >> $INSTANCECFG
        echo "pki_admin_key_size=$(eval echo \$SUBCA${number}_ADMIN_KEY_SIZE)" >> $INSTANCECFG
        echo "pki_admin_key_type=$(eval echo \$SUBCA${number}_ADMIN_KEY_TYPE)" >> $INSTANCECFG
        echo "pki_admin_subject_dn=$(eval echo \$SUBCA${number}_ADMIN_SUBJECT_DN)" >> $INSTANCECFG
        echo "pki_admin_nickname=$(eval echo \$SUBCA${number}_ADMIN_CERT_NICKNAME)" >> $INSTANCECFG
        echo "pki_import_admin_cert=$(eval echo \$SUBCA${number}_ADMIN_IMPORT_CERT)" >> $INSTANCECFG
        echo "pki_client_admin_cert_p12=$CLIENT_DIR/$(eval echo \$SUBCA${number}_ADMIN_CERT_NICKNAME).p12" >> $INSTANCECFG
        echo "pki_subsystem_key_type=$(eval echo \$SUBCA${number}_SUBSYSTEM_KEY_TYPE)" >> $INSTANCECFG
        echo "pki_subsystem_key_size=$(eval echo \$SUBCA${number}_SUBYSTEM_KEY_SIZE)" >> $INSTANCECFG
        echo "pki_subsystem_key_algorithm=$(eval echo \$SUBCA${number}_SUBSYSTEM_KEY_ALGORITHM)" >> $INSTANCECFG
        echo "pki_subsystem_signing_algorithm=$(eval echo \$SUBCA${number}_SUBSYSTEM_SIGNING_ALGORITHM)" >> $INSTANCECFG
        echo "pki_subsystem_token=$(eval echo \$SUBCA${number}_SUBSYSTEM_TOKEN)" >> $INSTANCECFG
        echo "pki_subsystem_nickname=$(eval echo \$SUBCA${number}_SUBSYTEM_NICKNAME)" >> $INSTANCECFG
        echo "pki_subsystem_subject_dn=$(eval echo \$SUBCA${number}_SUBSYSTEM_SUBJECT_DN)" >> $INSTANCECFG
        echo "pki_ds_database=$(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
        echo "pki_ca_signing_key_type=$(eval echo \$SUBCA${number}_KEY_TYPE)" >> $INSTANCECFG
        echo "pki_ca_signing_key_size=$(eval echo \$SUBCA${number}_KEY_SIZE)" >> $INSTANCECFG
        echo "pki_ca_signing_key_algorithm=$(eval echo \$SUBCA${number}_SIGNING_ALGORITHM)" >> $INSTANCECFG
        echo "pki_ca_signing_signing_algorithm=$(eval echo \$SUBCA${number}_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
        echo "pki_ca_signing_token=$(eval echo \$SUBCA${number}_SIGNING_TOKEN)" >> $INSTANCECFG
        echo "pki_ca_signing_nickname=$(eval echo \$SUBCA${number}_SIGNING_NICKNAME)" >> $INSTANCECFG
        echo "pki_ca_signing_subject_dn=$(eval echo \$SUBCA${number}_SIGNING_CERT_SUBJECT_NAME)" >> $INSTANCECFG
        echo "pki_ocsp_signing_key_type=$(eval echo \$SUBCA${number}_OCSP_SIGNING_KEY_TYPE)" >> $INSTANCECFG
        echo "pki_ocsp_signing_key_size=$(eval echo \$SUBCA${number}_OCSP_SIGNING_KEY_SIZE)" >> $INSTANCECFG
        echo "pki_ocsp_signing_key_algorithm=$(eval echo \$SUBCA${number}_OCSP_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
        echo "pki_ocsp_signing_signing_algorithm=$(eval echo \$SUBCA${number}_OCSP_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
        echo "pki_ocsp_signing_token=$(eval echo \$SUBCA${number}_OCSP_SIGNING_TOKEN)" >> $INSTANCECFG
        echo "pki_ocsp_signing_nickname=$(eval echo \$SUBCA${number}_OCSP_SIGNING_NICKNAME)" >> $INSTANCECFG
        echo "pki_ocsp_signing_subject_dn=$(eval echo \$SUBCA${number}_OCSP_SIGNING_CERT_SUBJECT_NAME)" >> $INSTANCECFG
        echo "pki_audit_signing_key_type=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_KEY_TYPE)" >> $INSTANCECFG
        echo "pki_audit_signing_key_size=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_KEY_SIZE)" >> $INSTANCECFG
        echo "pki_audit_signing_key_algorithm=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_KEY_ALGORITHM)" >> $INSTANCECFG
        echo "pki_audit_signing_signing_algorithm=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_SIGNING_ALGORITHM)" >> $INSTANCECFG
        echo "pki_audit_signing_token=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_TOKEN)" >> $INSTANCECFG
        echo "pki_audit_signing_nickname=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_NICKNAME)" >> $INSTANCECFG
        echo "pki_audit_signing_subject_dn=$(eval echo \$SUBCA${number}_AUDIT_SIGNING_CERT_SUBJECT_NAME)" >> $INSTANCECFG
        echo "pki_ssl_server_key_type=$(eval echo \$SUBCA${number}_SSL_SERVER_KEY_TYPE)" >> $INSTANCECFG
        echo "pki_ssl_server_key_size=$(eval echo \$SUBCA${number}_SSL_SERVER_KEY_SIZE)" >> $INSTANCECFG
        echo "pki_ssl_server_key_algorithm=$(eval echo \$SUBCA${number}_SSL_SERVER_KEY_ALGORITHM)" >> $INSTANCECFG
        echo "pki_ssl_server_signing_algorithm=$(eval echo \$SUBCA${number}_SSL_SERVER_SIGNING_ALGORITHM)" >> $INSTANCECFG
        echo "pki_ssl_server_token=$(eval echo \$SUBCA${number}_SSL_SERVER_TOKEN)" >> $INSTANCECFG
        echo "pki_ssl_server_nickname=$(eval echo \$SUBCA${number}_SSL_SERVER_NICKNAME)" >> $INSTANCECFG
        echo "pki_ssl_server_subject_dn=$(eval echo \$SUBCA${number}_SSL_SERVER_CERT_SUBJECT_NAME)" >> $INSTANCECFG
        echo "pki_ds_hostname=$(eval echo \$SUBCA${number}_DS_HOSTNAME)" >> $INSTANCECFG
        echo "pki_ds_ldap_port=$(eval echo \$SUBCA${number}_LDAP_PORT)" >> $INSTANCECFG
        echo "pki_ds_bind_dn=$(eval echo \$SUBCA${number}_LDAP_ROOTDN)" >> $INSTANCECFG
        echo "pki_ds_password=$(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD)" >> $INSTANCECFG
        echo "pki_ds_secure_connection=$(eval echo \$SUBCA${number}_SECURE_CONN)" >> $INSTANCECFG
        echo "pki_ds_remove_data=$(eval echo \$SUBCA${number}_REMOVE_DATA)" >> $INSTANCECFG
        echo "pki_ds_base_dn=$(eval echo \$SUBCA${number}_DB_SUFFIX)" >> $INSTANCECFG
        echo "pki_ds_database=$(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME)" >> $INSTANCECFG
        echo "pki_backup_keys=$(eval echo \$SUBCA${number}_BACKUP)" >> $INSTANCECFG
        echo "pki_backup_password=$(eval echo \$SUBCA${number}_BACKUP_PASSWORD)" >> $INSTANCECFG
        echo "pki_client_database_dir=$(eval echo \$SUBCA${number}_CERTDB_DIR)" >> $INSTANCECFG
        echo "pki_client_database_password=$(eval echo \$SUBCA${number}_CERTDB_DIR_PASSWORD)" >> $INSTANCECFG
        echo "pki_client_database_purge=$(eval echo \$SUBCA${number}_CLIENT_DB_PURGE)" >> $INSTANCECFG
        echo "pki_restart_configured_instance=$RESTART_INSTANCE" >> $INSTANCECFG
		echo "pki_skip_configuration=$SKIP_CONFIG" >> $INSTANCECFG
                echo "pki_skip_installation=$SKIP_INSTALL" >> $INSTANCECFG
                echo "pki_enable_access_log=$ENABLE_ACCESS_LOG" >> $INSTANCECFG
                echo "pki_enable_java_debugger=$ENABLE_JAVA_DEBUG" >> $INSTANCECFG
                echo "pki_security_manager=$SECURITY_MANAGER" >> $INSTANCECFG
                echo "export SUBCA${number}_DOMAIN=$(eval echo \$SUBCA${number}_DOMAIN)" >> /opt/rhqa_pki/env.sh
                cat $INSTANCECFG
		rlRun "cp $INSTANCECFG /tmp/subca.inf.bak"

                rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
                rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                rlRun "cat $INSTANCE_CREATE_OUT"
                exp_message1="Administrator's username:             $(eval echo \$SUBCA${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                #exp_message1_1="Administrator's PKCS #12 file:"
                #rlAssertGrep "$exp_message1_1" "$INSTANCE_CREATE_OUT"
                exp_message2="$(eval echo \$SUBCA${number}_DOMAIN)"
                rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$SUBCA${number}_SECURE_PORT)/ca"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                #echo "export CA_SERVER_ROOT=/var/lib/pki/$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)/ca" >> /opt/rhqa_pki/env.sh
                #mkdir -p $CLIENT_PKCS12_DIR
                #mv /var/lib/pki/$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)/alias/ca_backup_keys.p12 $CLIENT_PKCS12_DIR

		local TEMP_NSS_DB="/tmp/nssdb"
                local TEMP_NSS_DB_PWD="Secret123"
                if [ -d "$TEMP_NSS_DB" ]; then

                rlLog "$TEMP_NSS_DB Directory exists"
        else
                rlLog "Creating Security Database"
                rlRun "pki -d $TEMP_NSS_DB -c $TEMP_NSS_DB_PWD client-init" 0 "Initializing Security Database"
                RETVAL=$?
                if  [ $RETVAL != 0 ]; then
                  rlLog "FAIL :: NSS Database was not created"
                  return 1
                fi
        fi
		if [ $cert_type = "Dogtag" ]; then
	
		local profile=caCACert
                local rand=$RANDOM
                local request_type="pkcs10"
                local cn="New CA"
                local uid="newca"
                local email="newca@foobar.org"
                local ou="Foo_Example_IT"
                local org="FooBar.Org"
                local state="North Carolina"
                local location="Raleigh"
                local country="US"
                local cert_subject_file="/tmp/subfile"
                rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $csr"
                rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $csr"
                echo -e "RequestType:$request_type" > $cert_subject_file
                echo -e "CN:$cn" >> $cert_subject_file
                echo -e "UID:$uid" >> $cert_subject_file
        echo -e "Email:$email" >> $cert_subject_file
        echo -e "OU:$ou" >> $cert_subject_file
        echo -e "Org:$org" >> $cert_subject_file
        echo -e "State:$state" >> $cert_subject_file
        echo -e "Location:$location" >> $cert_subject_file
        echo -e "Country:$country" >> $cert_subject_file
        echo -e "Request_DN:$(eval echo \$SUBCA${number}_SIGNING_CERT_SUBJECT_NAME)" >> $cert_subject_file
	        rlRun "pki -d $TEMP_NSS_DB \
                -h $tmp_host \
                -p $ROOTCA_UNSECURE_PORT \
                -c $TEMP_NSS_DB_PWD \
                cert-request-profile-show $profile \
                 --output $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/$rand-profile.xml-out"
        rlRun "generate_xml $csr $cert_subject_file $TEMP_NSS_DB/$rand-profile.xml $profile"
        rlRun "pki -h $tmp_host -p $ROOTCA_UNSECURE_PORT cert-request-submit $TEMP_NSS_DB/$rand-profile.xml 1> $TEMP_NSS_DB/pki-cert-request-submit.out" 0 "Submit request"
        local REQUEST_ID=$(cat $TEMP_NSS_DB/pki-cert-request-submit.out  | grep "Request ID" | awk -F ": " '{print $2}')
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/pki-cert-request-submit.out"
        rlAssertGrep "Type: enrollment"  "$TEMP_NSS_DB/pki-cert-request-submit.out"
        rlAssertGrep "Request Status: pending" "$TEMP_NSS_DB/pki-cert-request-submit.out"
        rlAssertGrep "Operation Result: success" "$TEMP_NSS_DB/pki-cert-request-submit.out"
        rlLog "importP12FileNew $admin_cert_location $client_pkcs12_password $CERTDB_DIR $CERTDB_DIR_PASSWORD $admin_cert"
        rlRun "importP12FileNew $admin_cert_location $client_pkcs12_password $CERTDB_DIR $CERTDB_DIR_PASSWORD $admin_cert" 0 "Import Admin certificate to $CERTDB_DIR"
        rlRun "install_and_trust_CA_cert $ROOTCA_SERVER_ROOT $CERTDB_DIR"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -n \"$admin_cert\" \
                -h $tmp_host \
                -p $ROOTCA_UNSECURE_PORT \
                ca-cert-request-review $REQUEST_ID \
                --action approve 1> $TEMP_NSS_DB/$REQUEST_ID-pkcs10-approve-out" 0 "As $admin_cert Approve certificate request $REQUEST_ID"
        rlAssertGrep "Approved certificate request $REQUEST_ID" "$TEMP_NSS_DB/$REQUEST_ID-pkcs10-approve-out"
        rlRun "pki -p $ROOTCA_UNSECURE_PORT -h $tmp_host ca-cert-request-show $REQUEST_ID > $TEMP_NSS_DB/certrequestapprovedshow_001.out" 0 "Executing pki cert-request-show $REQUEST_ID"
        rlAssertGrep "Request ID: $REQUEST_ID" "$TEMP_NSS_DB/certrequestapprovedshow_001.out"
        rlAssertGrep "Type: enrollment" "$TEMP_NSS_DB/certrequestapprovedshow_001.out"
        rlAssertGrep "Status: complete" "$TEMP_NSS_DB/certrequestapprovedshow_001.out"
        rlAssertGrep "Certificate ID:" "$TEMP_NSS_DB/certrequestapprovedshow_001.out"
        local certificate_serial_number=`cat $TEMP_NSS_DB/certrequestapprovedshow_001.out | grep "Certificate ID:" | awk '{print $3}'`
        rlLog "Cerificate Serial Number=$certificate_serial_number"
        rlRun "pki -h $tmp_host -p $ROOTCA_UNSECURE_PORT cert-show $certificate_serial_number --output $TEMP_NSS_DB/certb64.out" 0 "B64 of the certificate"
        rlRun "export SSL_DIR=$CERTDB_DIR"
        rlRun "curl --basic --dump-header $TEMP_NSS_DB/header.out -d \"serialNumber=$certificate_serial_number\" -k \"http://$tmp_host:$ROOTCA_UNSECURE_PORT/ca/ee/ca/getCertChain\" > $TEMP_NSS_DB/b64certChain.out"
        rlRun "sed -e '/-----BEGIN CERTIFICATE-----/d' -i $TEMP_NSS_DB/certb64.out"
        rlRun "sed -e '/-----END CERTIFICATE-----/d' -i $TEMP_NSS_DB/certb64.out"
        rlRun "sed -i -e 's/<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><XMLResponse><Status>0<\/Status><ChainBase64>//g' -i $TEMP_NSS_DB/b64certChain.out"
        rlRun "sed -i -e 's/<\/ChainBase64><\/XMLResponse>//g' -i $TEMP_NSS_DB/b64certChain.out"
	else
        rlLog "Use testplan to set up ADCS on MS Server and save the params in env.sh"
        csr_string=$(cat $csr | tr -d '\n')
        rlRun "curl -k --ntlm https://$MS_ipaddr/certsrv/certfnsh.asp -u \"$MS_username:$MS_password\" --data-urlencode CertRequest=\"$csr_string\" -d Mode=newreq -d SaveCert=yes -d CertAttrib=CertificateTemplate:SubCA > $TEMP_NSS_DB/msca_new_cert.out"
        rlRun "sleep 5"
        rlRun "cat $TEMP_NSS_DB/msca_new_cert.out | grep \"Download certificate:\" > $TEMP_NSS_DB/msca_new_cert1.out"
        rlRun "sed -i -e 's/<LocID ID=locDownloadCert1>Download certificate: <\/LocID><A Href=\"certnew.cer?//g' $TEMP_NSS_DB/msca_new_cert1.out"
        rlRun "sleep 5"
        rlRun "sed -i -e 's/\&amp;Enc=bin\"><LocID ID=locDerEnc1>DER Encoded<\/LocID><\/A><LocID ID=locSep1>.*//g' $TEMP_NSS_DB/msca_new_cert1.out"
        rlRun "sleep 5"
        MS_newca_request_ID=$(cat $TEMP_NSS_DB/msca_new_cert1.out | grep "ReqID=" | cut -d= -f2)
        rlLog "$MS_newca_request_ID"
        rlRun "curl -k --ntlm https://$MS_ipaddr/certsrv/certnew.cer -G -d ReqID=$MS_newca_request_ID -d Enc-bin > $TEMP_NSS_DB/certb64.out"
        rlRun "curl -k --ntlm https://$MS_ipaddr/certsrv/certnew.p7b -G -d ReqID=$MS_newca_request_ID -d Enc-bin > $TEMP_NSS_DB/b64certChain.out"
        fi

        rlLog "Preparing the config file for step 2 of pkispawn"
                rlRun "sed -e '/pki_external_csr_path=.*/d' -i $INSTANCECFG"
        echo "pki_external_ca_cert_chain_path=$TEMP_NSS_DB/b64certChain.out" >> $INSTANCECFG
        echo "pki_external_ca_cert_path=$TEMP_NSS_DB/certb64.out" >> $INSTANCECFG
        echo "pki_external_step_two=True" >> $INSTANCECFG

        rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
                rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                rlRun "cat $INSTANCE_CREATE_OUT"
                exp_message1="Administrator's username:             $(eval echo \$SUBCA${number}_ADMIN_USER)"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message1_1="Administrator's PKCS #12 file:"
                rlAssertGrep "$exp_message1_1" "$INSTANCE_CREATE_OUT"
                exp_message2="$(eval echo \$SUBCA${number}_DOMAIN)"
                rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME).service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$(hostname):$(eval echo \$SUBCA${number}_SECURE_PORT)/ca"
		rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
}
