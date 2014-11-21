#!/bin/bash
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

	#Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure KRA"
        rlRun "rhds_install $(eval echo \$KRA${number}_LDAP_PORT) $(eval echo \$KRA${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$KRA${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for KRA install" 0 "Install LDAP Instance"

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
        local PKI_SECURITY_DOMAIN_PORT=$(eval echo \$${CA}_SECURE_PORT)
        local PKI_SECURITY_DOMAIN_USER=$(eval echo \$${CA}_ADMIN_USER)
	#Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure OCSP"
        rlRun "rhds_install $(eval echo \$OCSP${number}_LDAP_PORT) $(eval echo \$OCSP${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$OCSP${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for OCSP install" 0 "Install LDAP Instance"

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
     rlPhaseEnd
}
###########################################################
#              TKS INSTALL TESTS                         #
###########################################################
rhcs_install_tks() {
    rlPhaseStartTest "rhcs_install_tks - Install RHCS TKS Server"
        rlLog "$FUNCNAME"
        local INSTANCECFG="/tmp/tks_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/tks_instance_create.out"
	local SUBSYSTEM_NAME=$(echo TKS${number})
        rhcs_install_prep_disableFirewall
        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure TKS"
        rlRun "rhds_install $(eval echo \$TKS${number}_LDAP_PORT) $(eval echo \$TKS${number}_LDAP_INSTANCE_NAME) \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $(eval echo \$TKS${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for TKS install" 0 "Install LDAP Instance"
	local number=$1
        local master_hostname=$2
        local CA=$3
        local DOMAIN=$(eval echo $master_hostname | cut -d. -f2-)
        local PKI_SECURITY_DOMAIN_USER=$(eval echo \$${CA}_ADMIN_USER)
        local PKI_SECURITY_DOMAIN_PORT=$(eval echo \$${CA}_SECURE_PORT)
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
                exp_message5_1="https://$(hostname):$(eval echo \$${CA}_SECURE_PORT)/tks"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
               # echo "export TKS_SERVER_ROOT=/var/lib/pki/$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)/tks" >> /opt/rhqa_pki/env.sh
		mkdir -p $CLIENT_PKCS12_DIR
		mv /var/lib/pki/$(eval echo \$TKS${number}_TOMCAT_INSTANCE_NAME)/alias/tks_backup_keys.p12 $CLIENT_PKCS12_DIR
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
        rlRun "rhds_install $(eval echo \$CLONE_CA${number}_LDAP_PORT) $(eval echo \$CLONE_CA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $(eval echo \$${CA}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install" 0 "Install LDAP Instance"

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
        rlRun "rhds_install $(eval echo \$SUBCA${number}_LDAP_PORT) $(eval echo \$SUBCA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$SUBCA${number}_LDAP_ROOTDN)\" $(eval echo \$SUBCA${number}_LDAP_ROOTDNPWD) $(eval echo \$SUBCA${number}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install" 0 "Install LDAP Instance"
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
        rlRun "rhds_install $(eval echo \$CLONE_KRA${number}_LDAP_PORT) $(eval echo \$CLONE_KRA${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $(eval echo \$${MASTER_KRA}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install" 0 "Install LDAP Instance"

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

     rlPhaseEnd
}


rhcs_install_cloneOCSP(){

     rlPhaseStartTest  "rhcs_install_CLONEOCSP_only - Install RHCS CLONE OCSP SERVER"
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
        rlRun "rhds_install $(eval echo \$CLONE_OCSP${number}_LDAP_PORT) $(eval echo \$CLONE_OCSP${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $(eval echo \$${MASTER_OCSP}_DB_SUFFIX) $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE CA install" 0 "Install LDAP Instance"

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
        rlRun "rhds_install $(eval echo \$CLONE_TKS${number}_LDAP_PORT) $(eval echo \$CLONE_TKS${number}_LDAP_INSTANCE_NAME) \"$(eval echo \$CLONE${number}_LDAP_ROOTDN)\" $(eval echo \$CLONE${number}_LDAP_ROOTDNPWD) $TKS1_DB_SUFFIX $SUBSYSTEM_NAME" 0 "Installing RHDS instance for CLONE TKS install" 0 "Install LDAP Instance"

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
     rlPhaseEnd
}

