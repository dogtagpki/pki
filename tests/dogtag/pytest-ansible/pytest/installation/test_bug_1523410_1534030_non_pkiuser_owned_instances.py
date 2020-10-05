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

import logging
import os
import sys

import pytest
from utils import NuxwdogOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
subsystems = ['ca', 'kra', 'ocsp', 'tks', 'tps']


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
def test_bug_1523410_1534030_non_pkiuser_owned_pkispawn_ca(ansible_module):
    """
    :Title: Non pkiuser can be assigned as owner of CA instance.
            Automation of BZ: 1523410 and 1534030
    :Description: This automation tests if a CA instance can be configured with a non pkiuser ownership.
    :Requirement: RHCS-REQ Installation and Deployment
    :Setup: Have all the required packages installed.
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    ansible_module.lineinfile(dest='/tmp/test_conf/ca.cfg',
                              insertafter="^pki_http_port.*",
                              line="pki_user=pkiuser2")
    ansible_module.lineinfile(dest='/tmp/test_conf/ca.cfg',
                              insertafter="^pki_user.*",
                              line="pki_group=pkiuser2")
    ansible_module.replace(dest='/tmp/test_conf/ldap.cfg',
                           regexp='^port.*',
                           replace='port = 389')
    ansible_module.replace(dest='/tmp/test_conf/ca.cfg',
                           regexp='pki_ds_ldap_port.*',
                           replace='pki_ds_ldap_port=389')
    install_ds = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
    for result in install_ds.values():
        assert result['rc'] == 0
        log.info("Setup DS instance.")
    install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for result in install_ca.values():
        assert result['rc'] == 0
        log.info("CA Installed successfully")

    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.CA_INSTANCE_NAME)))
    for result in output.values():
        assert user_conf_file.format(constants.CA_INSTANCE_NAME) in result['stdout']
        log.info("File found: {}".format(user_conf_file.format(constants.CA_INSTANCE_NAME)))
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='CA',
                                subsystem_name=constants.CA_INSTANCE_NAME,
                                pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog()

    output = ansible_module.shell('ps -ef | grep {}'.format(constants.CA_INSTANCE_NAME))
    for result in output.values():
        if result['rc'] == 0:
            assert "pkiuser2" in result['stdout']
        else:
            pytest.xfail("Failed to run: {}".format(" ".join(result['cmd'])))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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

    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    ansible_module.lineinfile(path='/tmp/test_conf/kra.cfg',
                              insertafter="^pki_http_port.*",
                              line="pki_user=pkiuser2")
    ansible_module.lineinfile(path='/tmp/test_conf/kra.cfg',
                              insertafter="^pki_user.*",
                              line="pki_group=pkiuser2")
    ansible_module.replace(dest='/tmp/test_conf/kra.cfg',
                           regexp='pki_ds_ldap_port.*',
                           replace='pki_ds_ldap_port=389')
    install_kra = ansible_module.shell('pkispawn -s KRA -f /tmp/test_conf/kra.cfg')
    for result in install_kra.values():
        assert result['rc'] == 0
        log.info("KRA installed successfully.")

    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.KRA_INSTANCE_NAME)))
    for result in output.values():
        assert user_conf_file.format(constants.KRA_INSTANCE_NAME) in result['stdout']
        log.info("File exists: {}".format(user_conf_file.format(constants.KRA_INSTANCE_NAME)))

    log.info("Enabling Nuxwdog.")
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='KRA',
                                subsystem_name=constants.KRA_INSTANCE_NAME,
                                pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog()
    output = ansible_module.shell('ps -ef | grep {}'.format(constants.KRA_INSTANCE_NAME))
    for result in output.values():
        if result['rc'] == 0:
            assert "pkiuser2" in result['stdout']
        else:
            pytest.xfail("Failed to run: {}".format(" ".join(result['cmd'])))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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

    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    ansible_module.lineinfile(path='/tmp/test_conf/ocsp.cfg',
                              insertafter="^pki_http_port.*",
                              line="pki_user=pkiuser2")
    ansible_module.lineinfile(path='/tmp/test_conf/ocsp.cfg',
                              insertafter="^pki_user.*",
                              line="pki_group=pkiuser2")
    ansible_module.replace(dest='/tmp/test_conf/ocsp.cfg',
                           regexp='pki_ds_ldap_port.*',
                           replace='pki_ds_ldap_port=389')
    install_ocsp = ansible_module.shell('pkispawn -s OCSP -f /tmp/test_conf/ocsp.cfg')
    for result in install_ocsp.values():
        assert result['rc'] == 0
        log.info("OCSP installed successfully.")

    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.OCSP_INSTANCE_NAME)))
    for result in output.values():
        assert user_conf_file.format(constants.OCSP_INSTANCE_NAME) in result['stdout']
        log.info("File exists: {}".format(user_conf_file.format(constants.OCSP_INSTANCE_NAME)))

    log.info("Enabling Nuxwdog.")
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='OCSP',
                                subsystem_name=constants.OCSP_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog()
    output = ansible_module.shell('ps -ef | grep {}'.format(constants.OCSP_INSTANCE_NAME))
    for result in output.values():
        if result['rc'] == 0:
            assert "pkiuser2" in result['stdout']
        else:
            pytest.xfail("Failed to run: {}".format(" ".join(result['cmd'])))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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

    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    ansible_module.lineinfile(path='/tmp/test_conf/tks.cfg',
                              insertafter="^pki_http_port.*",
                              line="pki_user=pkiuser2")
    ansible_module.lineinfile(path='/tmp/test_conf/tks.cfg',
                              insertafter="^pki_user.*",
                              line="pki_group=pkiuser2")
    ansible_module.replace(dest='/tmp/test_conf/tks.cfg',
                           regexp='pki_ds_ldap_port.*',
                           replace='pki_ds_ldap_port=389')
    install_tks = ansible_module.shell('pkispawn -s TKS -f /tmp/test_conf/tks.cfg')
    for result in install_tks.values():
        assert result['rc'] == 0
        log.info("TKS installed successfully.")

    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.TKS_INSTANCE_NAME)))
    for result in output.values():
        assert user_conf_file.format(constants.TKS_INSTANCE_NAME) in result['stdout']
        log.info("File exists: {}".format(user_conf_file.format(constants.TKS_INSTANCE_NAME)))

    log.info("Enabling Nuxwdog.")
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='TKS',
                                subsystem_name=constants.TKS_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog()
    log.info("Nuxwdog enabled.")
    output = ansible_module.shell('ps -ef | grep {}'.format(constants.TKS_INSTANCE_NAME))
    for result in output.values():
        if result['rc'] == 0:
            assert "pkiuser2" in result['stdout']
        else:
            pytest.xfail("Failed to run: {}".format(" ".join(result['cmd'])))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    ansible_module.lineinfile(path='/tmp/test_conf/tps.cfg',
                              insertafter="^pki_http_port.*",
                              line="pki_user=pkiuser2")
    ansible_module.lineinfile(path='/tmp/test_conf/tps.cfg',
                              insertafter="^pki_user.*",
                              line="pki_group=pkiuser2")
    ansible_module.replace(dest='/tmp/test_conf/tps.cfg',
                           regexp='pki_ds_ldap_port.*',
                           replace='pki_ds_ldap_port=389')
    install_kra = ansible_module.shell('pkispawn -s TPS -f /tmp/test_conf/tps.cfg')
    for result in install_kra.values():
        assert result['rc'] == 0
        log.info("TPS installed successfully.")

    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.TPS_INSTANCE_NAME)))
    for result in output.values():
        assert user_conf_file.format(constants.TPS_INSTANCE_NAME) in result['stdout']
        log.info("File exists: {}".format(user_conf_file.format(constants.TPS_INSTANCE_NAME)))

    log.info("Enabling Nuxwdog.")
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='TPS',
                                subsystem_name=constants.TPS_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.enable_nuxwdog()
    log.info("Nuxwdog enabled.")
    output = ansible_module.shell('ps -ef | grep {}'.format(constants.TPS_INSTANCE_NAME))
    for result in output.values():
        if result['rc'] == 0:
            assert "pkiuser2" in result['stdout']
        else:
            pytest.xfail("Failed to run: {}".format(" ".join(result['cmd'])))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    log.info("Disabling Nuxwdog for {}".format(constants.TPS_INSTANCE_NAME))
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='TPS',
                                subsystem_name=constants.TPS_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog()
    log.info("Removed {}".format(constants.TPS_INSTANCE_NAME))
    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.TPS_INSTANCE_NAME)))
    for result in output.values():
        assert "No such file or directory" in result['stderr']
        log.info("File {} does not exists.".format(user_conf_file.format(constants.TPS_INSTANCE_NAME)))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    log.info("Disabling Nuxwdog for {}".format(constants.TKS_INSTANCE_NAME))
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='TKS',
                                subsystem_name=constants.TKS_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog()
    log.info("Removed {}".format(constants.TKS_INSTANCE_NAME))
    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.TKS_INSTANCE_NAME)))
    for result in output.values():
        assert "No such file or directory" in result['stderr']
        log.info("File {} does not exists.".format(user_conf_file.format(constants.TKS_INSTANCE_NAME)))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    log.info("Disabling Nuxwdog for {}".format(constants.OCSP_INSTANCE_NAME))
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='OCSP',
                                subsystem_name=constants.OCSP_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog()
    log.info("Removed {}".format(constants.OCSP_INSTANCE_NAME))
    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.OCSP_INSTANCE_NAME)))
    for result in output.values():
        assert "No such file or directory" in result['stderr']
        log.info("File {} does not exists.".format(user_conf_file.format(constants.OCSP_INSTANCE_NAME)))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    log.info("Disabling Nuxwdog for {}".format(constants.KRA_INSTANCE_NAME))
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='KRA',
                                subsystem_name=constants.KRA_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog()
    log.info("Removed {}".format(constants.KRA_INSTANCE_NAME))
    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.KRA_INSTANCE_NAME)))
    for result in output.values():
        assert "No such file or directory" in result['stderr']
        log.info("File {} does not exists.".format(user_conf_file.format(constants.KRA_INSTANCE_NAME)))


@pytest.mark.skip(reason='bz: https://bugzilla.redhat.com/show_bug.cgi?id=1805042')
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
    user_conf_file = '/etc/systemd/system/pki-tomcatd@{}.service.d/user.conf'
    log.info("Disabling Nuxwdog for {}".format(constants.CA_INSTANCE_NAME))
    nuxwdog = NuxwdogOperations(ansible_module, subsystem_type='CA',
                                subsystem_name=constants.CA_INSTANCE_NAME, pki_user='pkiuser2')
    nuxwdog.pkidestroy_nuxwdog()
    log.info("Nuxwdog disable for {}".format(constants.CA_INSTANCE_NAME))
    output = ansible_module.shell('ls {}'.format(user_conf_file.format(constants.CA_INSTANCE_NAME)))
    for result in output.values():
        assert "No such file or directory" in result['stderr']
        log.info("File {} does not exists.".format(user_conf_file.format(constants.CA_INSTANCE_NAME)))
    ansible_module.shell('dsctl topology-00-testingmaster remove --do-it')
    ansible_module.shell('rm -rf /tmp/test_conf/')
