"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of bug_1248216 'pkidaemon status tomcat' shows running
#                subsystem process when subsystem is down
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
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
import re
import sys
import time

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + '{}'.format(constants.CA_INSTANCE_NAME) + '/' + 'ca/conf/CS.cfg'
kra_cfg_path = BASE_DIR + '/' + '{}'.format(constants.KRA_INSTANCE_NAME) + '/' + 'kra/conf/CS.cfg'


def test_pki_server_status_should_show_status_disable_when_instance_is_down(ansible_module):
    """
    :Title: pki-server status <instance> should show disable when instance is down
    :Description: pki-server status <instance> should show disable when instance is down
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add Bogus certificate at
            ca.cert.audit_signing.nickname & kra.cert.audit_signing.nickname in both
            CA/KRA's cs.cfg
        2. Restart the both the server i.e CA & KRA
        3. Check the instance status with
           3.1 pki-server status <instance>
           3.2 systemctl status pki-tomcatd@<instance>
    :ExpectedResults:
        1. Bogus certificate is successfully added in CS.cfg file of CA & KRA
        2. Successfully restarted both of the servers
        3. Status of the CA and KRA instance should point to Enabled: False due to selfTest failure
           because of bogus certificate.
    """
    # Add Bogus certificate in CA,KRA CS.cfg
    ansible_module.lineinfile(path=ca_cfg_path, regexp='^ca.cert.audit_signing.nickname=',
                              line="ca.cert.audit_signing.nickname=Bogus ca3auditsigningcert")
    ansible_module.lineinfile(path=kra_cfg_path, regexp='^kra.cert.audit_signing.nickname=',
                              line="kra.cert.audit_signing.nickname=Bogus kra3auditsigningcert")

    # Restart the CA with pki-server
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))
    time.sleep(20)

    # Check CA status with pki-server
    ca_status = 'pki-server status {}'.format(constants.CA_INSTANCE_NAME)
    cmd = ansible_module.command(ca_status)
    for result in cmd.values():
        if result['rc'] == 0:
            assert "Instance ID: {}".format(constants.CA_INSTANCE_NAME) in result['stdout']
            assert "Active: True" in result['stdout']
            assert "Enabled:             False" in result['stdout']
            log.info("Successfully ran: {}".format(result['cmd']))
        else:
            log.error("Failed to ran: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])

    # Restart the KRA instance with pki-server
    ansible_module.command('pki-server restart {}'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(20)

    # Check KRA status with pki-server
    kra_status = 'pki-server status {}'.format(constants.KRA_INSTANCE_NAME)
    cmd = ansible_module.command(kra_status)
    for result in cmd.values():
        if result['rc'] == 0:
            assert "Instance ID: {}".format(constants.KRA_INSTANCE_NAME) in result['stdout']
            assert "Enabled:             False" in result['stdout']
            assert "Active: True" in result['stdout']
            log.info("Successfully ran: {}".format(result['cmd']))
        else:
            log.error("Failed to ran: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])

    # Fix the bogus audit certs
    command = ansible_module.shell('grep ca.audit_signing.nickname= {}'.format(ca_cfg_path))
    for result in command.values():
        find_ca_cert_param = re.findall(r"ca.audit_signing.nickname=[\w].*", result['stdout'])
        for i in find_ca_cert_param:
            ca_audit_cert = i.split("=")[1].strip()
            ca_cert = 'ca.cert.audit_signing.nickname=' + ca_audit_cert
            ansible_module.lineinfile(path=ca_cfg_path, regexp='^ca.cert.audit_signing.nickname=', line=ca_cert)

    command = ansible_module.shell('grep kra.audit_signing.nickname= {}'.format(kra_cfg_path))
    for result in command.values():
        find_kra_cert_param = re.findall(r"kra.audit_signing.nickname=[\w].*", result['stdout'])
        for i in find_kra_cert_param:
            kra_audit_cert = i.split("=")[1].strip()
            kra_cert = 'kra.cert.audit_signing.nickname=' + kra_audit_cert
            ansible_module.lineinfile(path=kra_cfg_path,
                                      regexp='^kra.cert.audit_signing.nickname=',
                                      line=kra_cert)

    # Restart the CA with pki-server
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))
    time.sleep(20)

    # Check CA status with pki-server
    ca_status = 'pki-server status {}'.format(constants.CA_INSTANCE_NAME)
    cmd = ansible_module.command(ca_status)
    for result in cmd.values():
        if result['rc'] == 0:
            assert "Instance ID: {}".format(constants.CA_INSTANCE_NAME) in result['stdout']
            assert "Active: True" in result['stdout']
            assert "Enabled:             True" in result['stdout']
            log.info("Successfully ran: {}".format(result['cmd']))
        else:
            log.error("Failed to ran: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])

    # Restart the KRA instance with pki-server
    ansible_module.command('pki-server restart {}'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(20)

    # Check KRA status with pki-server
    kra_status = 'pki-server status {}'.format(constants.KRA_INSTANCE_NAME)
    cmd = ansible_module.command(kra_status)
    for result in cmd.values():
        if result['rc'] == 0:
            assert "Instance ID: {}".format(constants.KRA_INSTANCE_NAME) in result['stdout']
            assert "Enabled:             True" in result['stdout']
            assert "Active: True" in result['stdout']
            log.info("Successfully ran: {}".format(result['cmd']))
        else:
            log.error("Failed to ran: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])
