#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   rhds_install.sh of /CoreOS/rhcs/acceptance/quickinstall
#   Description: CS quickinstall acceptance tests for new install
#                functions.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following rhcs will be tested:
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
#   Date  : Feb 18, 2013
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

rhcs_install_set_ldap_vars() {
. /opt/rhqa_pki/env.sh

 ### Set OS/YUM/RPM related variables here
        if [ $(grep Fedora /etc/redhat-release|wc -l) -gt 0 ]; then
                export DISTRO="Fedora"
                export RHDS_SERVER_PACKAGES="389-ds-base policycoreutils-python"
        else
                export DISTRO="RedHat"
                export RHDS_SERVER_PACKAGES="redhat-ds-base 389-ds-base policycoreutils-python"
        fi



	#Copy rhds-install.sh to /opt/rhqa_pki
        rm -f /opt/rhqa_pki/rhds-install.sh
        cp -a ./acceptance/quickinstall/rhds-install.sh /opt/rhqa_pki/.

#	rlLog "===================== env.sh   =========================="
      #  rlRun "cat /opt/rhqa_pki/env.sh"
 #       rlLog "==============================================="
}

######################################################################
# rhds_install()
# All subsystems and ldap servers on a single host
######################################################################
rhds_install()
{

        local LDAP_PORT="$1"
        local LDAP_INSTANCE_NAME="$2"
        local LDAP_ROOT_DN="$3"
        local LDAP_ROOT_DN_PWD="$4"
        local LDAP_SUFFIX="$5"
	local INSTANCECFG="/tmp/instance.inf"
	local INSTANCE_CREATE_OUT="/tmp/instance_create.out"

	echo "Base DN: $LDAP_SUFFIX"
	echo "LDAP port: $LDAP_PORT"
	echo "LDAPS port: $LDAPS_PORT"
	echo "Instance configuration file: $INSTANCECFG"
	echo "Password scheme ldif file: $PWDSCHEME"
	echo "LDAP instance: $INSTANCE"


	####################################################
	# turn off firewall
	####################################################
	echo $FLAVOR | grep "Fedora"
	if [ $? -eq 0 ] ; then
		rlRun "systemctl stop firewalld"
	else
		rlRun "service iptables stop"
	fi

	####################################################
	# check for installed RHDS packages
	####################################################
        rhds_install_prep
        for PKG in $RHDS_SERVER_PACKAGES; do
		rlAssertRpm $PKG
        done

	####################################################
	# set up directory server instance
	####################################################

	rlLog "Setting up Directory Server instance ............."
	echo "[General]" > $INSTANCECFG
	echo "FullMachineName= $HOSTNAME" >> $INSTANCECFG
	echo "SuiteSpotUserID= nobody" >> $INSTANCECFG
	echo "SuiteSpotGroup= nobody" >> $INSTANCECFG
	echo "ConfigDirectoryLdapURL= ldap://$HOSTNAME:$LDAP_PORT/o=NetscapeRoot" >> $INSTANCECFG
	echo "ConfigDirectoryAdminID= admin" >> $INSTANCECFG
	echo "ConfigDirectoryAdminPwd= $LDAP_ADMINPW" >> $INSTANCECFG
	echo "AdminDomain= example.com" >> $INSTANCECFG
	echo "" >> $INSTANCECFG
	echo "[slapd]" >> $INSTANCECFG
	echo "ServerIdentifier= $LDAP_INSTANCE_NAME" >> $INSTANCECFG
	echo "ServerPort= $LDAP_PORT" >> $INSTANCECFG
	echo "Suffix= $LDAP_SUFFIX" >> $INSTANCECFG
	echo "RootDN= $LDAP_ROOT_DN"  >> $INSTANCECFG
	echo "RootDNPwd= $LDAP_ROOT_DN_PWD" >> $INSTANCECFG
	echo "" >> $INSTANCECFG
	echo "[admin]" >> $INSTANCECFG
	echo "ServerAdminID= admin" >> $INSTANCECFG
	echo "ServerAdminPwd= $LDAP_ADMINPW" >> $INSTANCECFG
	echo "SysUser= nobody" >> $INSTANCECFG

	cat $INSTANCECFG

	rlLog "Executing: /usr/sbin/setup-ds.pl --silent --file=$INSTANCECFG > $INSTANCE_CREATE_OUT"
	rlRun "/usr/sbin/setup-ds.pl --silent --file=$INSTANCECFG > $INSTANCE_CREATE_OUT" 0 "Creating a LDAP instance"

	/usr/bin/ldapsearch -x -h $HOSTNAME -p $LDAP_PORT -D "$LDAP_ROOT_DN" -w  $LDAP_ROOT_DN_PWD -b "$LDAP_SUFFIX"

	if [ -f  $INSTANCE_CREATE_OUT ]; then
		rlRun "cat $INSTANCE_CREATE_OUT"
		rlLog "Ldap new server instance created successfully."
	else

		rlLog "Error creating ldap new server instance."
	fi

	if [ -f /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/errors ]; then
		cp /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/errors /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/errors.quickinstall
		rhts-submit-log -l /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/errors.quickinstall
	fi
	if [ -f /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/access ]; then
		cp /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/access /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/access.quickinstall
		rhts-submit-log -l /var/log/dirsrv/slapd-$LDAP_INSTANCE_NAME/access.quickinstall
	fi
        #rlPhaseEnd
}

rhds_install_prep_pkgInstalls()
{
        rlRun "yum clean all"
        rlRun "yum -y install bind expect"
}


rhds_install_prep()
{
        rlLog "$FUNCNAME"
        if [ -z "$RHDS_SERVER_PACKAGES" ]; then
                rlFail "$RHDS_SERVER_PACKAGES variable not set."
                return 1
        fi

        rhds_install_prep_pkgInstalls

        rlRun "yum -y install $RHDS_SERVER_PACKAGES"
        rlRun "yum -y update"

	# if [ "$IPv6SETUP" != "TRUE" ]; then
	# Install DS in IPV6 environment

}
