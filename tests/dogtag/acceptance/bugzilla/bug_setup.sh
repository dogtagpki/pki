#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/
#   Description: CS-backup-bug verification
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <rpattath@redhat.com> 
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
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

########################################################################
#pki-user-cli-user-ca.sh should be first executed prior to bug verification
########################################################################

########################################################################
# Test Suite Globals
########################################################################
BUGCA_LDAP_PORT="1801"
BUGCA_LDAP_INSTANCE_NAME="pki-ca-bug"
BUGCA_LDAP_DB_SUFFIX="dc=pki-ca"
BUGCA_SUBSYSTEM_NAME="BUGCA"
BUGCA_INSTANCE_CFG="/tmp/bugca_instance.inf"
BUGCA_INSTANCE_OUT="/tmp/bugca_instance_create.out"
BUGKRA_INSTANCE_CFG="/tmp/bugkra_instance.inf"
BUGKRA_INSTANCE_OUT="/tmp/bugkra_instance_create.out"
BUGOCSP_INSTANCE_CFG="/tmp/bugocsp_instance.inf"
BUGOCSP_INSTANCE_OUT="/tmp/bugocsp_instance_create.out"
BUGTKS_INSTANCE_CFG="/tmp/bugtks_instance.inf"
BUGTKS_INSTANCE_OUT="/tmp/bugtks_instance_create.out"
BUGCA_TOMCAT_INSTANCE_NAME="pki-ca-bug"
BUGCA_ADMIN_PASSWORD="Secret123"
BUGCA_CLIENT_PKCS12_PASSWORD="Secret123"
BUGCA_HTTP_PORT="30051"
BUGCA_HTTPS_PORT="30050"
BUGCA_TOMCAT_SERVER_PORT="30052"
BUGCA_SEC_DOMAIN_HTTPS_PORT="30050"
BUGCA_SEC_DOMAIN_PASSWORD="Secret123"
BUG_LDAP_ROOTDN="cn=Directory Manager"
BUG_LDAP_ROOTDNPWD="Secret123"
BUGKRA_LDAP_PORT="1802"
BUGKRA_LDAP_INSTANCE_NAME="pki-kra-bug"
BUGKRA_LDAP_DB_SUFFIX="dc=pki-kra"
BUGKRA_SUBSYSTEM_NAME="BUGKRA"
BUGKRA_PKI_CLIENT_DATABASE_PASSWORD="Secret123"
BUGKRA_PKI_SECURITY_DOMAIN_USER="caadmin"
BUGOCSP_LDAP_PORT="1803"
BUGOCSP_LDAP_INSTANCE_NAME="pki-ocsp-bug"
BUGOCSP_LDAP_DB_SUFFIX="dc=pki-ocsp"
BUGOCSP_SUBSYSTEM_NAME="BUGOCSP"
BUGOCSP_PKI_CLIENT_DATABASE_PASSWORD="Secret123"
BUGOCSP_PKI_SECURITY_DOMAIN_USER="caadmin"
BUGTKS_LDAP_PORT="1804"
BUGTKS_LDAP_INSTANCE_NAME="pki-tks-bug"
BUGTKS_LDAP_DB_SUFFIX="dc=pki-tks"
BUGTKS_SUBSYSTEM_NAME="BUGTKS"
BUGTKS_PKI_CLIENT_DATABASE_PASSWORD="Secret123"
BUGTKS_PKI_SECURITY_DOMAIN_USER="caadmin"
BUGCA_CERTDB_DIR="/opt/bugsecdb/bugcerts_db"
BUGCA_CERTDB_DIR_PASSWORD="Secret123"
BUGCA_CLIENT_DB_PURGE=True
BUGCA_CLIENT_DIR="/opt/bugsecdb"
BUGCA_ADMIN_CERT_NICKNAME="bugcaadmincert"
BUGCA_ADMIN_IMPORT_CERT=False
BUGCA_BACKUP=True
BUGCA_BACKUP_PASSWORD="Secret123"
BUGKRA_ADMIN_CERT_NICKNAME="bugkraadmincert"
BUGKRA_ADMIN_IMPORT_CERT=True
BUGOCSP_ADMIN_CERT_NICKNAME="bugocspadmincert"
BUGOCSP_ADMIN_CERT_NICKNAME="bugtksadmincert"
run_bug_verification_setup(){
 
     rlPhaseStartTest "Setting up instance for bug verification"

        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1061442"
        cat /etc/redhat-release | grep "Fedora"
        if [ $? -eq 0 ] ; then
               FLAVOR="Fedora"
               rlLog "Automation is running against Fedora"
        else
                FLAVOR="RHEL"
                rlLog "Automation is running against RHEL"
        fi
        rhcs_install_set_ldap_vars
	#rlRun "mkdir $BUGCA_CERTDB_DIR"
        rlRun "rhds_install $BUGCA_LDAP_PORT $BUGCA_LDAP_INSTANCE_NAME \"$BUG_LDAP_ROOTDN\" $BUG_LDAP_ROOTDNPWD $BUGCA_LDAP_DB_SUFFIX $BUGCA_SUBSYSTEM_NAME"
        echo "[DEFAULT]" > $BUGCA_INSTANCE_CFG
        echo "pki_instance_name=$BUGCA_TOMCAT_INSTANCE_NAME" >> $BUGCA_INSTANCE_CFG
        echo "pki_https_port=$BUGCA_HTTPS_PORT" >> $BUGCA_INSTANCE_CFG
        echo "pki_http_port=$BUGCA_HTTP_PORT" >> $BUGCA_INSTANCE_CFG
        echo "pki_tomcat_server_port=$BUGCA_TOMCAT_SERVER_PORT" >> $BUGCA_INSTANCE_CFG
        echo "pki_admin_password=$BUGCA_ADMIN_PASSWORD" >> $BUGCA_INSTANCE_CFG
        echo "pki_client_pkcs12_password=$BUGCA_CLIENT_PKCS12_PASSWORD" >> $BUGCA_INSTANCE_CFG
        echo "pki_ds_database=$BUGCA_LDAP_INSTANCE_NAME" >> $BUGCA_INSTANCE_CFG
        echo "pki_ds_ldap_port=$BUGCA_LDAP_PORT" >> $BUGCA_INSTANCE_CFG
        echo "pki_ds_base_dn=$BUGCA_LDAP_DB_SUFFIX" >> $BUGCA_INSTANCE_CFG
        echo "pki_ds_bind_dn=$BUG_LDAP_ROOTDN" >> $BUGCA_INSTANCE_CFG
        echo "pki_ds_password=$BUG_LDAP_ROOTDNPWD" >> $BUGCA_INSTANCE_CFG
        echo "pki_security_domain_https_port=$BUGCA_SEC_DOMAIN_HTTPS_PORT" >> $BUGCA_INSTANCE_CFG
	echo "pki_security_domain_password=$BUGCA_SEC_DOMAIN_PASSWORD" >> $BUGCA_INSTANCE_CFG
	echo "pki_admin_nickname=$BUGCA_ADMIN_CERT_NICKNAME" >> $BUGCA_INSTANCE_CFG
        echo "pki_import_admin_cert=$BUGCA_ADMIN_IMPORT_CERT" >> $BUGCA_INSTANCE_CFG
        echo "pki_client_dir=$BUGCA_CLIENT_DIR" >> $BUGCA_INSTANCE_CFG
        echo "pki_client_admin_cert_p12=$BUGCA_CLIENT_DIR/$BUGCA_ADMIN_CERT_NICKNAME.p12" >> $BUGCA_INSTANCE_CFG
        echo "pki_backup_keys=$BUGCA_BACKUP" >> $BUGCA_INSTANCE_CFG
        echo "pki_backup_password=$BUGCA_BACKUP_PASSWORD" >> $BUGCA_INSTANCE_CFG
	echo "pki_client_database_dir=$BUGCA_CERTDB_DIR" >> $BUGCA_INSTANCE_CFG
        echo "pki_client_database_password=$BUGCA_CERTDB_DIR_PASSWORD" >> $BUGCA_INSTANCE_CFG
        echo "pki_client_database_purge=$BUGCA_CLIENT_DB_PURGE" >> $BUGCA_INSTANCE_CFG
        rlRun "pkispawn -s CA -v -f $BUGCA_INSTANCE_CFG > $BUGCA_INSTANCE_OUT"
	rlRun "sleep 10"
	BUGCA_SERVER_ROOT="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca"
	rlRun "install_and_trust_CA_cert $BUGCA_SERVER_ROOT $BUGCA_CERTDB_DIR"

	 # Create a KRA instance

        rlRun "rhds_install $BUGKRA_LDAP_PORT $BUGKRA_LDAP_INSTANCE_NAME \"$BUG_LDAP_ROOTDN\" $BUG_LDAP_ROOTDNPWD $BUGKRA_LDAP_DB_SUFFIX $BUGKRA_SUBSYSTEM_NAME"
        echo "[DEFAULT]" > $BUGKRA_INSTANCE_CFG
        echo "pki_instance_name=$BUGCA_TOMCAT_INSTANCE_NAME" >> $BUGKRA_INSTANCE_CFG
        echo "pki_https_port=$BUGCA_HTTPS_PORT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_http_port=$BUGCA_HTTP_PORT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_tomcat_server_port=$BUGCA_TOMCAT_SERVER_PORT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_admin_password=$BUGCA_ADMIN_PASSWORD" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_pkcs12_password=$BUGCA_CLIENT_PKCS12_PASSWORD" >> $BUGKRA_INSTANCE_CFG
        echo "pki_ds_database=$BUGKRA_LDAP_INSTANCE_NAME" >> $BUGKRA_INSTANCE_CFG
        echo "pki_ds_ldap_port=$BUGKRA_LDAP_PORT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_ds_base_dn=$BUGKRA_LDAP_DB_SUFFIX" >> $BUGKRA_INSTANCE_CFG
        echo "pki_ds_bind_dn=$BUG_LDAP_ROOTDN" >> $BUGKRA_INSTANCE_CFG
        echo "pki_ds_password=$BUG_LDAP_ROOTDNPWD" >> $BUGKRA_INSTANCE_CFG
        echo "pki_security_domain_hostname=$MASTER" >> $BUGKRA_INSTANCE_CFG
        echo "pki_security_domain_https_port=$BUGCA_SEC_DOMAIN_HTTPS_PORT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_security_domain_password=$BUGCA_SEC_DOMAIN_PASSWORD" >> $BUGKRA_INSTANCE_CFG
        echo "pki_security_domain_user=$BUGKRA_PKI_SECURITY_DOMAIN_USER" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_database_password=$BUGKRA_PKI_CLIENT_DATABASE_PASSWORD" >> $BUGKRA_INSTANCE_CFG
	echo "pki_admin_nickname=$BUGKRA_ADMIN_CERT_NICKNAME" >> $BUGKRA_INSTANCE_CFG
        echo "pki_import_admin_cert=$BUGKRA_ADMIN_IMPORT_CERT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_dir=$BUGCA_CLIENT_DIR" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_admin_cert_p12=$BUGCA_CLIENT_DIR/$BUGKRA_ADMIN_CERT_NICKNAME.p12" >> $BUGKRA_INSTANCE_CFG
        echo "pki_backup_keys=$BUGCA_BACKUP" >> $BUGKRA_INSTANCE_CFG
        echo "pki_backup_password=$BUGCA_BACKUP_PASSWORD" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_database_dir=$BUGCA_CERTDB_DIR" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_database_password=$BUGCA_CERTDB_DIR_PASSWORD" >> $BUGKRA_INSTANCE_CFG
        echo "pki_client_database_purge=$BUGCA_CLIENT_DB_PURGE" >> $BUGKRA_INSTANCE_CFG
	echo "pki_issuing_ca_hostname=$MASTER" >> $BUGKRA_INSTANCE_CFG
        echo "pki_issuing_ca_https_port=$BUGCA_HTTPS_PORT" >> $BUGKRA_INSTANCE_CFG
        echo "pki_issuing_ca_uri=https://$MASTER:$BUGCA_HTTPS_PORT" >> $BUGKRA_INSTANCE_CFG
        rlRun "pkispawn -s KRA -v -f $BUGKRA_INSTANCE_CFG > $BUGKRA_INSTANCE_OUT"
	rlRun "sleep 10"

	# Create a OCSP instance

        rlRun "rhds_install $BUGOCSP_LDAP_PORT $BUGOCSP_LDAP_INSTANCE_NAME \"$BUG_LDAP_ROOTDN\" $BUG_LDAP_ROOTDNPWD $BUGOCSP_LDAP_DB_SUFFIX $BUGOCSP_SUBSYSTEM_NAME"
        echo "[DEFAULT]" > $BUGOCSP_INSTANCE_CFG
        echo "pki_instance_name=$BUGCA_TOMCAT_INSTANCE_NAME" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_https_port=$BUGCA_HTTPS_PORT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_http_port=$BUGCA_HTTP_PORT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_tomcat_server_port=$BUGCA_TOMCAT_SERVER_PORT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_admin_password=$BUGCA_ADMIN_PASSWORD" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_pkcs12_password=$BUGCA_CLIENT_PKCS12_PASSWORD" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_ds_database=$BUGOCSP_LDAP_INSTANCE_NAME" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_ds_ldap_port=$BUGOCSP_LDAP_PORT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_ds_base_dn=$BUGOCSP_LDAP_DB_SUFFIX" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_ds_bind_dn=$BUG_LDAP_ROOTDN" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_ds_password=$BUG_LDAP_ROOTDNPWD" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_security_domain_hostname=$MASTER" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_security_domain_https_port=$BUGCA_SEC_DOMAIN_HTTPS_PORT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_security_domain_password=$BUGCA_SEC_DOMAIN_PASSWORD" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_security_domain_user=$BUGOCSP_PKI_SECURITY_DOMAIN_USER" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_database_password=$BUGOCSP_PKI_CLIENT_DATABASE_PASSWORD" >> $BUGOCSP_INSTANCE_CFG
	echo "pki_admin_nickname=$BUGOCSP_ADMIN_CERT_NICKNAME" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_import_admin_cert=$BUGKRA_ADMIN_IMPORT_CERT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_dir=$BUGCA_CLIENT_DIR" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_admin_cert_p12=$BUGCA_CLIENT_DIR/$BUGOCSP_ADMIN_CERT_NICKNAME.p12" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_backup_keys=$BUGCA_BACKUP" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_backup_password=$BUGCA_BACKUP_PASSWORD" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_database_dir=$BUGCA_CERTDB_DIR" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_database_password=$BUGCA_CERTDB_DIR_PASSWORD" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_client_database_purge=$BUGCA_CLIENT_DB_PURGE" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_issuing_ca_hostname=$MASTER" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_issuing_ca_https_port=$BUGCA_HTTPS_PORT" >> $BUGOCSP_INSTANCE_CFG
        echo "pki_issuing_ca_uri=https://$MASTER:$BUGCA_HTTPS_PORT" >> $BUGOCSP_INSTANCE_CFG
        rlRun "pkispawn -s OCSP -v -f $BUGOCSP_INSTANCE_CFG > $BUGOCSP_INSTANCE_OUT"
	rlRun "sleep 10"

	# Create a TKS instance

        rlRun "rhds_install $BUGTKS_LDAP_PORT $BUGTKS_LDAP_INSTANCE_NAME \"$BUG_LDAP_ROOTDN\" $BUG_LDAP_ROOTDNPWD $BUGTKS_LDAP_DB_SUFFIX $BUGTKS_SUBSYSTEM_NAME"
        echo "[DEFAULT]" > $BUGTKS_INSTANCE_CFG
        echo "pki_instance_name=$BUGCA_TOMCAT_INSTANCE_NAME" >> $BUGTKS_INSTANCE_CFG
        echo "pki_https_port=$BUGCA_HTTPS_PORT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_http_port=$BUGCA_HTTP_PORT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_tomcat_server_port=$BUGCA_TOMCAT_SERVER_PORT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_admin_password=$BUGCA_ADMIN_PASSWORD" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_pkcs12_password=$BUGCA_CLIENT_PKCS12_PASSWORD" >> $BUGTKS_INSTANCE_CFG
        echo "pki_ds_database=$BUGTKS_LDAP_INSTANCE_NAME" >> $BUGTKS_INSTANCE_CFG
        echo "pki_ds_ldap_port=$BUGTKS_LDAP_PORT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_ds_base_dn=$BUGTKS_LDAP_DB_SUFFIX" >> $BUGTKS_INSTANCE_CFG
        echo "pki_ds_bind_dn=$BUG_LDAP_ROOTDN" >> $BUGTKS_INSTANCE_CFG
        echo "pki_ds_password=$BUG_LDAP_ROOTDNPWD" >> $BUGTKS_INSTANCE_CFG
        echo "pki_security_domain_hostname=$MASTER" >> $BUGTKS_INSTANCE_CFG
        echo "pki_security_domain_https_port=$BUGCA_SEC_DOMAIN_HTTPS_PORT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_security_domain_password=$BUGCA_SEC_DOMAIN_PASSWORD" >> $BUGTKS_INSTANCE_CFG
        echo "pki_security_domain_user=$BUGTKS_PKI_SECURITY_DOMAIN_USER" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_database_password=$BUGTKS_PKI_CLIENT_DATABASE_PASSWORD" >> $BUGTKS_INSTANCE_CFG
	echo "pki_admin_nickname=$BUGTKS_ADMIN_CERT_NICKNAME" >> $BUGTKS_INSTANCE_CFG
        echo "pki_import_admin_cert=$BUGKRA_ADMIN_IMPORT_CERT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_dir=$BUGCA_CLIENT_DIR" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_admin_cert_p12=$BUGCA_CLIENT_DIR/$BUGTKS_ADMIN_CERT_NICKNAME.p12" >> $BUGTKS_INSTANCE_CFG
        echo "pki_backup_keys=$BUGCA_BACKUP" >> $BUGTKS_INSTANCE_CFG
        echo "pki_backup_password=$BUGCA_BACKUP_PASSWORD" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_database_dir=$BUGCA_CERTDB_DIR" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_database_password=$BUGCA_CERTDB_DIR_PASSWORD" >> $BUGTKS_INSTANCE_CFG
        echo "pki_client_database_purge=$BUGCA_CLIENT_DB_PURGE" >> $BUGTKS_INSTANCE_CFG
        echo "pki_issuing_ca_hostname=$MASTER" >> $BUGTKS_INSTANCE_CFG
        echo "pki_issuing_ca_https_port=$BUGCA_HTTPS_PORT" >> $BUGTKS_INSTANCE_CFG
        echo "pki_issuing_ca_uri=https://$MASTER:$BUGCA_HTTPS_PORT" >> $BUGTKS_INSTANCE_CFG
        rlRun "pkispawn -s TKS -v -f $BUGTKS_INSTANCE_CFG > $BUGTKS_INSTANCE_OUT"
	rlRun "sleep 10"
     rlPhaseEnd

}
