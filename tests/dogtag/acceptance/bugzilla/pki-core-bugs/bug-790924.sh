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
BUGCA_CERTDB_DIR="/opt/bugsecdb/bugcerts_db"
BUGCA_CERTDB_DIR_PASSWORD="Secret123"
BUGCA_CLIENT_DB_PURGE=True
BUGCA_CLIENT_DIR="/opt/bugsecdb"
BUGCA_ADMIN_CERT_NICKNAME="bugcaadmincert"
BUGCA_ADMIN_IMPORT_CERT=False
BUGCA_BACKUP=True
BUGCA_BACKUP_PASSWORD="Secret123"
BUGCA_SIGNING_CERT_SUBJECT_NAME="CN=PKI EXTCA Signing Cert,O=redhat"
run_bug_790924(){
 
     rlPhaseStartTest "Bug 790924 - pkispawn configuration does not provide CA extensions in subordinate certificate signing requests CSR"

        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=790924"
	COMMON_SERVER_PACKAGES="bind expect pki-console xmlstarlet dos2unix"
        RHELRHCS_PACKAGES="pki-base pki-server pki-tools pki-symkey pki-javadoc pki-ca"
        cat /etc/redhat-release | grep "Fedora"
        if [ $? -eq 0 ] ; then
               FLAVOR="Fedora"
               rlLog "Automation is running against Fedora"
        else
                FLAVOR="RHEL"
                rlLog "Automation is running against RHEL"
		 yum clean all
                yum -y update
                #CA install
                rc=0
                rlLog "CA instance will be installed on $HOSTNAME"
                rlLog "yum -y install $COMMON_SERVER_PACKAGES"
                yum -y install $COMMON_SERVER_PACKAGES
		rlLog "yum -y install $RHELRHCS_PACKAGES"
                yum -y install $RHELRHCS_PACKAGES
        fi
        rhcs_install_set_ldap_vars
	# Create DS instance
        rlRun "rhds_install $BUGCA_LDAP_PORT $BUGCA_LDAP_INSTANCE_NAME \"$BUG_LDAP_ROOTDN\" $BUG_LDAP_ROOTDNPWD $BUGCA_LDAP_DB_SUFFIX $BUGCA_SUBSYSTEM_NAME"
	# CA config parameters
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
	echo "[CA]" >> $BUGCA_INSTANCE_CFG
	echo "pki_external=True" >> $BUGCA_INSTANCE_CFG
        echo "pki_external_csr_path=/tmp/ca_signing.csr" >> $BUGCA_INSTANCE_CFG
        echo "pki_ca_signing_subject_dn=$BUGCA_SIGNING_CERT_SUBJECT_NAME" >> $BUGCA_INSTANCE_CFG
	# Create CA instance
        rlRun "pkispawn -s CA -f $BUGCA_INSTANCE_CFG > $BUGCA_INSTANCE_OUT"
	rlRun "sleep 10"
	rlAssertExists "/tmp/ca_signing.csr"
	rlRun "pkidestroy -s CA -i pki-ca-bug"
        rlRun "sleep 10"
        rlRun "remove-ds.pl -f -i slapd-pki-ca-bug"
        rlRun "sleep 10"

     rlPhaseEnd
}
