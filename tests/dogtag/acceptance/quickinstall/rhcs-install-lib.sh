#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   rhcs_install.sh of /CoreOS/rhcs/acceptance/quickinstall
#   Description: CS quickinstall acceptance tests for new install
#                functions.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following rhcs will be tested:
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
#   Date  : Feb 21, 2013
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

# ROLE=MASTER, CLONE, SUBCA, EXTERNAL
# SUBSYSTEMS=CA, KRA, OCSP, RA, TKS, TPS

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
rhcs_install_ca() {
    rlPhaseStartTest  "rhcs_install_ca - Install RHCS CA Server"
	local INSTANCECFG="/tmp/ca_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/ca_instance_create.out"
	local PKI_SECURITY_DOMAIN_USER=$CA_ADMIN_USER
        rlLog "$FUNCNAME"
	rhcs_install_prep_disableFirewall

	#Install RHDS packages
	rhcs_install_set_ldap_vars

	#Install and configure RHDS instance
	rlLog "Creating LDAP server Instance to configure CA"
	rlRun "rhds_install $CA_LDAP_PORT $CA_LDAP_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0 "Installing RHDS instance for CA install" 0 "Install LDAP Instance"

	#Install CA
	rlLog "Creating CA Instance"
	echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
		rlLog "Setting up Dogtag CA instance ............."
		echo "[DEFAULT]" > $INSTANCECFG
		echo "pki_admin_password= $CA_ADMIN_PASSWORD" >> $INSTANCECFG
		echo "pki_backup_password= $CA_BACKUP_PASSWORD" >> $INSTANCECFG
		echo "pki_client_pkcs12_password= $CA_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
		echo "pki_ds_password= $LDAP_ROOTDNPWD" >> $INSTANCECFG
		echo "pki_security_domain_password= $CA_SECURITY_DOMAIN_PASSWORD" >> $INSTANCECFG
		echo "[CA]" >> $INSTANCECFG
		echo "pki_ds_ldap_port= $CA_LDAP_PORT" >> $INSTANCECFG
	#	echo "pki_enable_java_debugger=True" >> $INSTANCECFG
		cat $INSTANCECFG

		CA_DOMAIN=`hostname -d`
                echo "export CA_DOMAIN=$CA_DOMAIN" >> /opt/rhqa_pki/env.sh

		rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
		rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
		rlRun "cat $INSTANCE_CREATE_OUT"
		exp_message1="Administrator's username:             $PKI_SECURITY_DOMAIN_USER"
		rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
		exp_message1_1="Administrator's PKCS #12 file:"
		rlAssertGrep "$exp_message1_1" "$INSTANCE_CREATE_OUT"
		exp_message2="$CA_DOMAIN"
		rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
		exp_message3_1="To check the status of the subsystem:"
		rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
		exp_message3_2="systemctl status pki-tomcatd\@pki-tomcat.service"
		rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
		exp_message4_1="To restart the subsystem:"
		rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
		exp_message4_2=" systemctl restart pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
		exp_message5="The URL for the subsystem is:"
		rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
		exp_message5_1="https://$HOSTNAME:8443/ca"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"

                echo "export CA_SERVER_ROOT=/var/lib/pki/pki-tomcat/ca" >> /opt/rhqa_pki/env.sh


	else
		#RHEL7 CS CA install tests here
		rlLog "Setting up RHEL7 CA instance ............."
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
	local PKI_SECURITY_DOMAIN_PORT=$CA_SECURE_PORT
	local PKI_SECURITY_DOMAIN_USER=$CA_ADMIN_USER

        rhcs_install_prep_disableFirewall


	  #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure KRA"
        rlRun "rhds_install $KRA_LDAP_PORT $KRA_LDAP_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0 "Installing RHDS instance for KRA install" 0 "Install LDAP Instance"

        #Install KRA
        rlLog "Creating KRA Instance"
        echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
                rlLog "Setting up Dogtag KRA instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_admin_password= $KRA_ADMIN_PASSWORD" >> $INSTANCECFG
                echo "pki_backup_password= $KRA_BACKUP_PASSWORD" >> $INSTANCECFG
                echo "pki_client_pkcs12_password= $KRA_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
		echo "pki_client_database_password= $KRA_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_ds_password= $LDAP_ROOTDNPWD" >> $INSTANCECFG
                echo "pki_security_domain_password= $CA_SECURITY_DOMAIN_PASSWORD" >> $INSTANCECFG
                echo "pki_security_domain_hostname= $HOSTNAME" >> $INSTANCECFG
                echo "pki_security_domain_https_port= $PKI_SECURITY_DOMAIN_PORT" >> $INSTANCECFG
                echo "pki_security_domain_user= $PKI_SECURITY_DOMAIN_USER" >> $INSTANCECFG
                echo "pki_issueing_ca_uri= https://$HOSTNAME:$PKI_SECURITY_DOMAIN_PORT" >> $INSTANCECFG
		echo "[KRA]" >> $INSTANCECFG
                echo "pki_ds_ldap_port= $KRA_LDAP_PORT" >> $INSTANCECFG
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s KRA -f $INSTANCECFG -v "
                rlRun "pkispawn -s KRA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                cat $INSTANCE_CREATE_OUT
		exp_message1="Administrator's username:             $KRA_ADMIN_USER"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message4="To check the status of the subsystem:"
                rlAssertGrep "$exp_message4" "$INSTANCE_CREATE_OUT"
                exp_message5="systemctl status pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message6="To restart the subsystem:"
                rlAssertGrep "$exp_message6" "$INSTANCE_CREATE_OUT"
                exp_message7=" systemctl restart pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message7" "$INSTANCE_CREATE_OUT"
                exp_message8="The URL for the subsystem is:"
                rlAssertGrep "$exp_message8" "$INSTANCE_CREATE_OUT"
		exp_message8_1="https://$HOSTNAME:8443/kra"
                rlAssertGrep "$exp_message8_1" "$INSTANCE_CREATE_OUT"
                echo "export CA_ADMIN_CERT_LOCATION=/root/.dogtag/pki-tomcat/ca_admin_cert.p12" >> /opt/rhqa_pki/env.sh

		echo "export KRA_SERVER_ROOT=/var/lib/pki/pki-tomcat/kra" >> /opt/rhqa_pki/env.sh
        else
                #RHEL7 CS KRA install tests here
                rlLog "Setting up RHEL7 KRA instance ............."
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
        local PKI_SECURITY_DOMAIN_PORT=$CA_SECURE_PORT
        local PKI_SECURITY_DOMAIN_USER=$CA_ADMIN_USER

        rhcs_install_prep_disableFirewall

	#Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure OCSP"
        rlRun "rhds_install $OCSP_LDAP_PORT $OCSP_LDAP_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0 "Installing RHDS instance for OCSP install" 0 "Install LDAP Instance"

        #Install OCSP
        rlLog "Creating OCSP Instance"
        echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
                rlLog "Setting up Dogtag OCSP instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_admin_password= $OCSP_ADMIN_PASSWORD" >> $INSTANCECFG
                echo "pki_backup_password= $OCSP_BACKUP_PASSWORD" >> $INSTANCECFG
                echo "pki_client_pkcs12_password= $OCSP_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
		echo "pki_client_database_password= $OCSP_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_ds_password= $LDAP_ROOTDNPWD" >> $INSTANCECFG
                echo "pki_security_domain_password= $CA_SECURITY_DOMAIN_PASSWORD" >> $INSTANCECFG
                echo "pki_security_domain_hostname= $HOSTNAME" >> $INSTANCECFG
                echo "pki_security_domain_https_port= $PKI_SECURITY_DOMAIN_PORT" >> $INSTANCECFG
                echo "pki_security_domain_user= $PKI_SECURITY_DOMAIN_USER" >> $INSTANCECFG
                echo "pki_issueing_ca_uri= https://$HOSTNAME:$PKI_SECURITY_DOMAIN_PORT" >> $INSTANCECFG
		echo "[OCSP]" >> $INSTANCECFG
                echo "pki_ds_ldap_port= $OCSP_LDAP_PORT" >> $INSTANCECFG
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s OCSP -f $INSTANCECFG -v "
                rlRun "pkispawn -s OCSP -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"

                cat $INSTANCE_CREATE_OUT
		exp_message1="Administrator's username:             $OCSP_ADMIN_USER"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
		exp_message5_1="https://$HOSTNAME:8443/ocsp"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                echo "export CA_ADMIN_CERT_LOCATION=/root/.dogtag/pki-tomcat/ca_admin_cert.p12" >> /opt/rhqa_pki/env.sh


		echo "export OCSP_SERVER_ROOT=/var/lib/pki/pki-tomcat/ocsp" >> /opt/rhqa_pki/env.sh

        else
                #RHEL7 CS OCSP install tests here
                rlLog "Setting up RHEL7 OCSP instance ............."
        fi
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
        local PKI_SECURITY_DOMAIN_PORT=$CA_SECURE_PORT
        local PKI_SECURITY_DOMAIN_USER=$CA_ADMIN_USER

        rhcs_install_prep_disableFirewall

        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance to configure TKS"
        rlRun "rhds_install $TKS_LDAP_PORT $TKS_LDAP_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0 "Installing RHDS instance for TKS install" 0 "Install LDAP Instance"

        #Install TKS
        rlLog "Creating TKS Instance"
        echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
                rlLog "Setting up Dogtag TKS instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_admin_password= $TKS_ADMIN_PASSWORD" >> $INSTANCECFG
                echo "pki_backup_password= $TKS_BACKUP_PASSWORD" >> $INSTANCECFG
                echo "pki_client_pkcs12_password= $TKS_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_client_database_password= $TKS_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_ds_password= $LDAP_ROOTDNPWD" >> $INSTANCECFG
                echo "pki_security_domain_password= $CA_SECURITY_DOMAIN_PASSWORD" >> $INSTANCECFG
                echo "pki_security_domain_hostname= $HOSTNAME" >> $INSTANCECFG
                echo "pki_security_domain_https_port= $PKI_SECURITY_DOMAIN_PORT" >> $INSTANCECFG
                echo "pki_security_domain_user= $PKI_SECURITY_DOMAIN_USER" >> $INSTANCECFG
                echo "pki_issueing_ca_uri= https://$HOSTNAME:$PKI_SECURITY_DOMAIN_PORT" >> $INSTANCECFG
                echo "[TKS]" >> $INSTANCECFG
                echo "pki_ds_ldap_port= $TKS_LDAP_PORT" >> $INSTANCECFG
                cat $INSTANCECFG
		rlLog "EXECUTING: pkispawn -s TKS -f $INSTANCECFG -v "
                rlRun "pkispawn -s TKS -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"

                cat $INSTANCE_CREATE_OUT
                exp_message1="Administrator's username:             $TKS_ADMIN_USER"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message3_1="To check the status of the subsystem:"
                rlAssertGrep "$exp_message3_1" "$INSTANCE_CREATE_OUT"
                exp_message3_2="systemctl status pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message3_2" "$INSTANCE_CREATE_OUT"
                exp_message4_1="To restart the subsystem:"
                rlAssertGrep "$exp_message4_1" "$INSTANCE_CREATE_OUT"
                exp_message4_2=" systemctl restart pki-tomcatd\@pki-tomcat.service"
                rlAssertGrep "$exp_message4_2" "$INSTANCE_CREATE_OUT"
                exp_message5="The URL for the subsystem is:"
                rlAssertGrep "$exp_message5" "$INSTANCE_CREATE_OUT"
                exp_message5_1="https://$HOSTNAME:8443/tks"
                rlAssertGrep "$exp_message5_1" "$INSTANCE_CREATE_OUT"
                echo "export CA_ADMIN_CERT_LOCATION=/root/.dogtag/pki-tomcat/ca_admin_cert.p12" >> /opt/rhqa_pki/env.sh


                echo "export TKS_SERVER_ROOT=/var/lib/pki/pki-tomcat/tks" >> /opt/rhqa_pki/env.sh

        else
                #RHEL7 CS TKS install tests here
                rlLog "Setting up RHEL7 TKS instance ............."
        fi
     rlPhaseEnd
}


###########################################################
#       CA INSTALL TESTS                                  #
###########################################################
rhcs_install_ca_only() {
     rlPhaseStartTest  "rhcs_install_ca_only - Install RHCS CA Server"
        local INSTANCECFG="/tmp/ca_instance.inf"
        local INSTANCE_CREATE_OUT="/tmp/ca_instance_create.out"
	local LDAP_PORT="1500"
        rlLog "$FUNCNAME"

        rhcs_install_prep_disableFirewall

        #Install and configure RHDS instance
        rlLog "Creating LDAP server Instance"
        rhcs_install_set_ldap_vars
        rlRun "rhds_install $LDAP_PORT $CA_LDAP_INSTANCE_NAME \"$LDAP_ROOTDN\" $LDAP_ROOTDNPWD $LDAP_BASEDN" 0 "Installing RHDS instance for CA install" 0 "Install LDAP Instance"

        #Install CA
        rlLog "Creating CA Instance"
        echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
                rlLog "Setting up Dogtag CA instance ............."
                echo "[DEFAULT]" > $INSTANCECFG
                echo "pki_admin_password= $CA_ADMIN_PASSWORD" >> $INSTANCECFG
                echo "pki_backup_password= $CA_BACKUP_PASSWORD" >> $INSTANCECFG
                echo "pki_client_pkcs12_password= $CA_CLIENT_PKCS12_PASSWORD" >> $INSTANCECFG
                echo "pki_ds_password= $LDAP_ROOTDNPWD" >> $INSTANCECFG
                echo "pki_security_domain_password= $CA_SECURITY_DOMAIN_PASSWORD" >> $INSTANCECFG
                echo "" >> $INSTANCECFG
                echo "[CA]" >> $INSTANCECFG
                echo "pki_ds_ldap_port= $LDAP_PORT" >> $INSTANCECFG
                echo "pki_instance_name= $CA_INSTANCE_ID" >> $INSTANCECFG
                cat $INSTANCECFG

                rlLog "EXECUTING: pkispawn -s CA -f $INSTANCECFG -v "
                rlRun "pkispawn -s CA -f $INSTANCECFG -v > $INSTANCE_CREATE_OUT  2>&1"
                rlRun "cat $INSTANCE_CREATE_OUT"
                exp_message1="saving Admin Certificate to file: '/root/.pki/$CA_INSTANCE_ID/ca_admin.cert'"
                rlAssertGrep "$exp_message1" "$INSTANCE_CREATE_OUT"
                exp_message2="pk12util: PKCS12 EXPORT SUCCESSFUL"
                rlAssertGrep "$exp_message2" "$INSTANCE_CREATE_OUT"
                exp_message3="performing chmod: 'chmod 664 /root/.pki/$CA_INSTANCE_ID/ca_admin_cert.p12'"
                rlAssertGrep "$exp_message3" "$INSTANCE_CREATE_OUT"
        else
                #RHEL7 CS CA install tests here
                rlLog "Setting up RHEL7 CA instance ............."
        fi
     rlPhaseEnd
}

rhcs_install_prep_disableFirewall() {
	echo $FLAVOR | grep "Fedora"
	if [ $? -eq 0 ] ; then
		rlRun "systemctl stop firewalld"
	else
		rlRun "chkconfig iptables off"
		rlRun "chkconfig ip6tables off"
		if [ $(cat /etc/redhat-release|grep "5\.[0-9]"|wc -l) -gt 0 ]; then
			service iptables stop
			if [ $? -eq 1 ]; then
				rlLog "service iptables stop returns 1 when already stopped"
			else
				rlPass "service iptables stop succeeeded"
			fi
		else
			rlRun "service iptables stop"
		fi
	fi

}
