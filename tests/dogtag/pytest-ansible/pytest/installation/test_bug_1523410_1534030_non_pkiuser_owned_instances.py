#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: non-pkiuser owned instance with nuxwdog - automation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   pkispawn and pkidestroy of non-pkiuser owned instance with nuxwdog enabled
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
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
"""

from utils import *
ldap_port = "389"
ldap_password = "SECret.123"
pki_password = "SECret.123"
kra_https_port = "21443"
kra_http_port = "21080"
kra_ajp_port = "21045"
kra_tomcat_port = "21049"
ocsp_https_port = "22443"
ocsp_http_port = "22080"
ocsp_ajp_port = "22045"
ocsp_tomcat_port = "22049"
tks_https_port = "23443"
tks_http_port = "23080"
tks_ajp_port = "23045"
tks_tomcat_port = "23049"
tps_https_port = "25443"
tps_http_port = "25080"
tps_ajp_port = "25045"
tps_tomcat_port = "25049"

def test_bug_1523410_1534030_non_pkiuser_owned_pkispawn_ca(ansible_module):

    """
    :Title: Non pkiuser can be assigned as owner of CA instance.
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests if a CA instance can be configured with a non pkiuser ownership.

    :Requirement: RHCS-REQ Installation and Deployment

    :Setup:
	Have all the required packages installed.

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for CA with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure CA

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf

    :Automated: Yes

    :CaseComponent: \-
    """
    output = ansible_module.command('hostname')
    for result in output.values():
        currentHost = result['stdout']
    config = Config()
    ldap_general_info = {"FullMachineName":"%s"%currentHost, "SuiteSpotUserID":"nobody", "SuiteSpotGroupID":"nobody",
                         "ConfigDirectoryAdminID":"admin"}
    ldap_slapd_info = {"ServerIdentifier":"testingmaster", "ServerPort":"389", "RootDN":"CN=Directory Manager",
                       "RootDNPwd":"%s" % ldap_password}
    default_info = {"pki_instance_name":"pki-ca-non-pkiuser", "pki_hostname":"%s"%currentHost, "pki_user":"pkiuser2", "pki_group":"pkiuser2",
                    "pki_ds_password":"%s" % ldap_password, "pki_ds_ldap_port":"389", "pki_token_password":"%s" % pki_password,
                    "pki_admin_password":"%s" % pki_password, "pki_security_domain_password":"%s" % pki_password,
                    "pki_client_pkcs12_password":"%s" % pki_password, "pki_backup_keys":"True", "pki_backup_password":"%s" % pki_password}
    subsystem_info = {"pki_import_admin_cert":"False",
                      "pki_admin_nickname":"PKI CA Administrator for Example.Org"}

    config.subsystem("/tmp/ldap.inf", 'General', **ldap_general_info)
    config.subsystem("/tmp/ldap.inf", 'slapd', **ldap_slapd_info)
    config.default("/tmp/ca.inf", **default_info)
    config.subsystem('/tmp/ca.inf', 'CA', **subsystem_info)
    ansible_module.copy(src='/tmp/ca.inf', dest='/tmp/ca.inf')
    ansible_module.copy(src='/tmp/ldap.inf', dest='/tmp/ldap.inf')
    ansible_module.shell('setup-ds.pl --silent --file=/tmp/ldap.inf')
    ansible_module.shell('pkispawn -s CA -f /tmp/ca.inf')
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-ca-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "/etc/systemd/system/pki-tomcatd@pki-ca-non-pkiuser.service.d/user.conf" in result['stdout']
    nuxwdog = NuxwdogOperations(subsystem_type='CA', subsystem_name='pki-ca-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog(ansible_module)

    output = ansible_module.shell('ps -ef | grep nuxwdog')
    for result in output.values():
        assert "pkiuser2" in result['stdout']


def test_bug_1523410_1534030_non_pkiuser_owned_pkispawn_kra(ansible_module):

    """
    :Title: Non pkiuser can be assigned as owner of KRA instance.
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests if a KRA instance can be configured with a non pkiuser ownership.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for KRA with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure KRA

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf

    :Automated: Yes
    """
    output = ansible_module.command('hostname')
    for result in output.values():
        currentHost = result['stdout']
    config = Config()
    default_info = {"pki_instance_name":"pki-kra-non-pkiuser", "pki_https_port":"%s" % kra_https_port, "pki_http_port":"%s" % kra_http_port,
                    "pki_hostname":"%s"%currentHost,"pki_user":"pkiuser2", "pki_group":"pkiuser2",
                    "pki_security_domain_hostname":"%s" % currentHost, "pki_security_domain_https_port":"8443",
                    "pki_ds_password":"%s" % ldap_password, "pki_ds_ldap_port":"389", "pki_token_password":"%s" % pki_password,
                    "pki_admin_password":"%s" % pki_password, "pki_security_domain_password":"%s" % pki_password,
                    "pki_client_pkcs12_password":"%s" % pki_password, "pki_backup_keys":"True",
                    "pki_backup_password":"%s" % pki_password, "pki_client_database_password":"%s" % pki_password}
    tomcat_info = {"pki_ajp_port":"%s" % kra_ajp_port, "pki_tomcat_server_port":"%s" % kra_tomcat_port}
    subsystem_info = {"pki_import_admin_cert":"False",
                      "pki_admin_nickname":"PKI KRA Administrator for Example.Org"}

    config.default("/tmp/kra.inf", **default_info)
    config.subsystem('/tmp/kra.inf', 'Tomcat', **tomcat_info)
    config.subsystem('/tmp/kra.inf', 'KRA', **subsystem_info)
    ansible_module.copy(src='/tmp/kra.inf', dest='/tmp/kra.inf')
    ansible_module.shell('pkispawn -s KRA -f /tmp/kra.inf')
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-kra-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "/etc/systemd/system/pki-tomcatd@pki-kra-non-pkiuser.service.d/user.conf" in result['stdout']
    nuxwdog = NuxwdogOperations(subsystem_type='KRA', subsystem_name='pki-kra-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog(ansible_module)

    output = ansible_module.shell('ps -ef | grep pki-kra-non-pkiuser')
    for result in output.values():
        assert "pkiuser2" in result['stdout']


def test_bug_1523410_1534030_non_pkiuser_owned_pkispawn_ocsp(ansible_module):

    """
    :Title: Non pkiuser can be assigned as owner of OCSP instance.
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests if a OCSP instance can be configured with a non pkiuser ownership.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for OCSP with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure OCSP

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf

    :Automated: Yes
    """
    output = ansible_module.command('hostname')
    for result in output.values():
        currentHost = result['stdout']
    config = Config()
    default_info = {"pki_instance_name":"pki-ocsp-non-pkiuser", "pki_https_port":"%s" % ocsp_https_port, "pki_http_port":"%s" % ocsp_http_port,
                    "pki_hostname":"%s"%currentHost,"pki_user":"pkiuser2", "pki_group":"pkiuser2",
                    "pki_security_domain_hostname":"%s" % currentHost, "pki_security_domain_https_port":"8443",
                    "pki_ds_password":"%s" % ldap_password, "pki_ds_ldap_port":"389", "pki_token_password":"%s" % pki_password,
                    "pki_admin_password":"%s" % pki_password, "pki_security_domain_password":"%s" % pki_password,
                    "pki_client_pkcs12_password":"%s" % pki_password, "pki_backup_keys":"True",
                    "pki_backup_password":"%s" % pki_password, "pki_client_database_password":"%s" % pki_password}
    tomcat_info = {"pki_ajp_port":"%s" % ocsp_ajp_port, "pki_tomcat_server_port":"%s" % ocsp_tomcat_port}
    subsystem_info = {"pki_import_admin_cert":"False",
                      "pki_admin_nickname":"PKI OCSP Administrator for Example.Org"}

    config.default("/tmp/ocsp.inf", **default_info)
    config.subsystem('/tmp/ocsp.inf', 'Tomcat', **tomcat_info)
    config.subsystem('/tmp/ocsp.inf', 'OCSP', **subsystem_info)
    ansible_module.copy(src='/tmp/ocsp.inf', dest='/tmp/ocsp.inf')
    ansible_module.shell('pkispawn -s OCSP -f /tmp/ocsp.inf')
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-ocsp-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "/etc/systemd/system/pki-tomcatd@pki-ocsp-non-pkiuser.service.d/user.conf" in result['stdout']
    nuxwdog = NuxwdogOperations(subsystem_type='OCSP', subsystem_name='pki-ocsp-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog(ansible_module)

    output = ansible_module.shell('ps -ef | grep pki-ocsp-non-pkiuser')
    for result in output.values():
        assert "pkiuser2" in result['stdout']


def test_bug_1523410_1534030_non_pkiuser_owned_pkispawn_tks(ansible_module):

    """
    :Title: Non pkiuser can be assigned as owner of TKS instance.
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests if a TKS instance can be configured with a non pkiuser ownership.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for TKS with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure TKS

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf

    :Automated: Yes
    """
    output = ansible_module.command('hostname')
    for result in output.values():
        currentHost = result['stdout']
    config = Config()
    default_info = {"pki_instance_name":"pki-tks-non-pkiuser", "pki_https_port":"%s" % tks_https_port, "pki_http_port":"%s" % tks_http_port,
                    "pki_hostname":"%s"%currentHost,"pki_user":"pkiuser2", "pki_group":"pkiuser2",
                    "pki_security_domain_hostname":"%s" % currentHost, "pki_security_domain_https_port":"8443",
                    "pki_ds_password":"%s" % ldap_password, "pki_ds_ldap_port":"389", "pki_token_password":"%s" % pki_password,
                    "pki_admin_password":"%s" % pki_password, "pki_security_domain_password":"%s" % pki_password,
                    "pki_client_pkcs12_password":"%s" % pki_password, "pki_backup_keys":"True",
                    "pki_backup_password":"%s" % pki_password, "pki_client_database_password":"%s" % pki_password}
    tomcat_info = {"pki_ajp_port":"%s" % tks_ajp_port, "pki_tomcat_server_port":"%s" % tks_tomcat_port}
    subsystem_info = {"pki_import_admin_cert":"False",
                      "pki_admin_nickname":"PKI TKS Administrator for Example.Org"}

    config.default("/tmp/tks.inf", **default_info)
    config.subsystem('/tmp/tks.inf', 'Tomcat', **tomcat_info)
    config.subsystem('/tmp/tks.inf', 'TKS', **subsystem_info)
    ansible_module.copy(src='/tmp/tks.inf', dest='/tmp/tks.inf')
    ansible_module.shell('pkispawn -s TKS -f /tmp/tks.inf')
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-tks-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "/etc/systemd/system/pki-tomcatd@pki-tks-non-pkiuser.service.d/user.conf" in result['stdout']
    nuxwdog = NuxwdogOperations(subsystem_type='TKS', subsystem_name='pki-tks-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog(ansible_module)

    output = ansible_module.shell('ps -ef | grep pki-tks-non-pkiuser')
    for result in output.values():
        assert "pkiuser2" in result['stdout']


def test_bug_1523410_1534030_non_pkiuser_owned_pkispawn_tps(ansible_module):

    """
    :Title: Non pkiuser can be assigned as owner of TPS instance.
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests if a TKS instance can be configured with a non pkiuser ownership.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for TPS with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure TPS

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf

    :Automated: Yes
    """
    output = ansible_module.command('hostname')
    for result in output.values():
        currentHost = result['stdout']
    config = Config()
    default_info = {"pki_instance_name":"pki-tps-non-pkiuser", "pki_https_port":"%s" % tps_https_port, "pki_http_port":"%s" % tps_http_port,
                    "pki_hostname":"%s"%currentHost,"pki_user":"pkiuser2", "pki_group":"pkiuser2",
                    "pki_security_domain_hostname":"%s" % currentHost, "pki_security_domain_https_port":"8443",
                    "pki_ds_password":"%s" % ldap_password, "pki_ds_ldap_port":"389", "pki_token_password":"%s" % pki_password,
                    "pki_admin_password":"%s" % pki_password, "pki_security_domain_password":"%s" % pki_password,
                    "pki_client_pkcs12_password":"%s" % pki_password, "pki_backup_keys":"True",
                    "pki_backup_password":"%s" % pki_password, "pki_client_database_password":"%s" % pki_password}
    tomcat_info = {"pki_ajp_port":"%s" % tps_ajp_port, "pki_tomcat_server_port":"%s" % tps_tomcat_port}
    subsystem_info = {"pki_import_admin_cert":"False",
                      "pki_admin_nickname":"PKI TPS Administrator for Example.Org",
                      "pki_authdb_basedn":"ou=People,dc=example,dc=org", "pki_authdb_hostname":"%s" % currentHost,
                      "pki_authdb_port":"389", "pki_ca_uri":"https://%s:8443" % currentHost,
                      "pki_kra_uri":"https://%s:21443" % currentHost, "pki_tks_uri":"https://%s:23443" % currentHost}

    config.default("/tmp/tps.inf", **default_info)
    config.subsystem('/tmp/tps.inf', 'Tomcat', **tomcat_info)
    config.subsystem('/tmp/tps.inf', 'TPS', **subsystem_info)
    ansible_module.copy(src='/tmp/tps.inf', dest='/tmp/tps.inf')
    ansible_module.shell('pkispawn -s TPS -f /tmp/tps.inf')
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-tps-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "/etc/systemd/system/pki-tomcatd@pki-tps-non-pkiuser.service.d/user.conf" in result['stdout']
    nuxwdog = NuxwdogOperations(subsystem_type='TPS', subsystem_name='pki-tps-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog(ansible_module)

    output = ansible_module.shell('ps -ef | grep pki-tps-non-pkiuser')
    for result in output.values():
        assert "pkiuser2" in result['stdout']


def test_bug_1523410_non_pkiuser_owned_pkidestroy_tps(ansible_module):

    """
    :Title: TPS pkidestroy with nuxwdog
            Automation of BZ: 1523410

    :Description: This automation tests pkidestroy of TPS when nuxwdog is enabled

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for TPS with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure TPS.
            4. pkidestroy TPS.

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf
            3. When the instance is pkidestroy'ed, the override directory should be deleted.

    :Automated: Yes
    """
    nuxwdog = NuxwdogOperations(subsystem_type='TPS', subsystem_name='pki-tps-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog(ansible_module)
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-tps-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "No such file or directory" in result['stderr']


def test_bug_1523410_1534030_non_pkiuser_owned_pkidestroy_tks(ansible_module):

    """
    :Title: TKS pkidestroy with nuxwdog
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests pkidestroy of TKS when nuxwdog is enabled

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for TKS with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure TKS.
            4. pkidestroy TKS.

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf
            3. When the instance is pkidestroy'ed, the override directory should be deleted.

    :Automated: Yes
    """
    nuxwdog = NuxwdogOperations(subsystem_type='TKS', subsystem_name='pki-tks-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog(ansible_module)
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-tks-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "No such file or directory" in result['stderr']


def test_bug_1523410_1534030_non_pkiuser_owned_pkidestroy_ocsp(ansible_module):

    """
    :Title: OCSP pkidestroy with nuxwdog
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests pkidestroy of OCSP when nuxwdog is enabled

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for OCSP with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure OCSP.
            4. pkidestroy OCSP.

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf
            3. When the instance is pkidestroy'ed, the override directory should be deleted.

    :Automated: Yes
    """
    nuxwdog = NuxwdogOperations(subsystem_type='OCSP', subsystem_name='pki-ocsp-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog(ansible_module)
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-ocsp-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "No such file or directory" in result['stderr']


def test_bug_1523410_1534030_non_pkiuser_owned_pkidestroy_kra(ansible_module):

    """
    :Title: KRA pkidestroy with nuxwdog
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests pkidestroy of KRA when nuxwdog is enabled

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for KRA with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure KRA.
            4. pkidestroy KRA.

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf
            3. When the instance is pkidestroy'ed, the override directory should be deleted.

    :Automated: Yes
    """
    nuxwdog = NuxwdogOperations(subsystem_type='KRA', subsystem_name='pki-kra-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog(ansible_module)
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-kra-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "No such file or directory" in result['stderr']


def test_bug_1523410_1534030_non_pkiuser_owned_pkidestroy_ca(ansible_module):

    """
    :Title: CA pkidestroy with nuxwdog
            Automation of BZ: 1523410 and 1534030

    :Description: This automation tests pkidestroy of CA when nuxwdog is enabled

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Add a user: useradd pkiuser2
            2. Create an installation file for CA with
               pki_user=pkiuser2
               pki_group=pkiuser2
            3. Install and configure CA
            4. pkidestroy CA.

    :Expectedresults:
            1. Instance should start up correctly as that user.
            2. The override file (and directory) should be created:
               /etc/systemd/system/pki-tomcatd@<instance_name>.service.d/user.conf
            3. When the instance is pkidestroy'ed, the override directory should be deleted.

    :Automated: Yes
    """
    nuxwdog = NuxwdogOperations(subsystem_type='CA', subsystem_name='pki-ca-non-pkiuser', pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog(ansible_module)
    output = ansible_module.shell('ls /etc/systemd/system/pki-tomcatd@pki-ca-non-pkiuser.service.d/user.conf')
    for result in output.values():
        assert "No such file or directory" in result['stderr']
    ansible_module.shell('remove-ds.pl -f -i slapd-testingmaster')
    ansible_module.shell('rm -rf /tmp/ca.inf /tmp/kra.inf /tmp/ldap.inf /tmp/CA-password.conf '
                         '/tmp/ocsp.inf /tmp/tks.inf /tmp/tps.inf '
                         '/tmp/KRA-password.conf, /tmp/OCSP-password.conf /tmp/TKS-password.conf /tmp/TPS-password.conf')
