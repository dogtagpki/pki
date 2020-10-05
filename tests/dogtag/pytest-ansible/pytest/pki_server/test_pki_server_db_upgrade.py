"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki db-upgrade commands needs to be tested:
#   pki-server db-upgrade --help
#   pki-server db-upgrade
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2018 Red Hat, Inc. All rights reserved.
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

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


@pytest.fixture(autouse=False)
def ds_instance(ansible_module):
    """
    Start/stop ds instance
    """
    instance_name = '{}-testingmaster'.format("-".join(topology_name.split("-")[:-1]))
    stop_ds = 'systemctl stop dirsrv@slapd-{}'.format(instance_name)
    ansible_module.command(stop_ds)
    log.info("Stopped instance {}".format(instance_name))
    yield
    start_ds = 'systemctl start dirsrv@slapd-{}'.format(instance_name)
    ansible_module.command(start_ds)
    log.info("Started instance {}".format(instance_name))


@pytest.fixture(autouse=False)
def stop_pki_instance(ansible_module):
    "start/stop pki-instance fixture."
    stop_instance = 'pki-server instance-stop {}'.format(ca_instance_name)
    start_instance = 'pki-server instance-start {}'.format(ca_instance_name)
    ansible_module.command(stop_instance)
    log.info("Stopped instance {}".format(ca_instance_name))
    yield ca_instance_name
    ansible_module.command(start_instance)
    log.info("Started instance {}".format(ca_instance_name))


def test_pki_server_db_upgrade_help_command(ansible_module):
    """
    :id: e2f152bb-e69e-4e0f-8381-b5af02d0b645
    :Title: Test pki-server db-upgrade --help command
    :Description: Test pki-server db-upgrade --help command
    :Requirement: Pki Server Db
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResult: 
        1. Verify whether pki-server db-upgrade --help command shows the following commands.
             Usage: pki-server db-upgrade [OPTIONS]
        
              -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
              -v, --verbose                      Run in verbose mode.
                  --help                         Show help message.

    """
    help_command = 'pki-server db-upgrade --help'

    cmd_output = ansible_module.command(help_command)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server db-upgrade [OPTIONS]" in result['stdout']
            assert " -i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert " -v, --verbose                      Run in verbose mode." in result['stdout']
            assert "     --help                         Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_db_upgrade_command(ansible_module):
    """
    :id: 89711623-2338-4e4e-bc3c-3569c4c110e9
    :Title: Test pki-server db-upgrade command
    :Description: Test pki-server db-upgrade command
    :Requirement: Pki Server Db
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResult:
        1. Verify whether pki-server db-upgrade command upgrade the pki server database.
    """
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(ca_instance_name)
    cmd_output = ansible_module.command(db_upgrade)

    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "CA database upgraded" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_db_upgrade_while_ds_instance_is_down(ansible_module, ds_instance):
    """
    :id: 9f691554-51d9-40c3-b6b6-c538a509dcfc
    :Title: Test pki-server db-upgrade command when instance is down.
    :Requirement: Pki Server Db
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResult:
        1. Verify whether pki-server db-upgrade command do not upgrade the pki server database
            while directory server instance is down.

    """
    # Store commands in veriables.
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(ca_instance_name)

    cmd_output = ansible_module.command(db_upgrade)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "CA database upgraded" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_db_upgrade_with_wrong_instance(ansible_module):
    """
    :id: 1cd3e385-b037-470a-9512-d70490828caf
    :Title: Test pki-server db-upgrade command with wrong instance.
    :Description: Test pki-server db-upgrade command with wrong instance.
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResult:
        1. Verify whether pki-server db-upgrade command do not upgrade the pki server database
        while specifying wrong instance.

    """
    instance = 'ROOTCA'
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(instance)
    cmd_output = ansible_module.command(db_upgrade)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Upgrade complete" in result['stdout']
            pytest.skip()
        else:
            # if "Invalid instance" in result['stdout']:
            assert "ERROR: Invalid instance: ROOTCA" in result['stderr']
            # else:
            #   assert "ERROR: Invalid instance: ROOTCA" in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


def test_pki_server_db_upgrade_with_stopped_instance(ansible_module, stop_pki_instance):
    """
    :id: 795f34af-2b14-4007-bd68-2db96eeec847
    :Title: Test pki-server db-upgrade command with stopped instance.
    :Description: Test pki-server db-upgrade command with stopped instance.
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResult:
        1. Verify whether pki-server db-upgrade command upgrade the pki server database
           when instance is stopped.
    """
    # Store commands in veriables.
    if TOPOLOGY == '01':
        instance = ca_instance_name
    else:
        instance = constants.CA_INSTANCE_NAME
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(instance)

    cmd_output = ansible_module.command(db_upgrade)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "CA database upgraded" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            pytest.skip("Failed to run pki-server db-upgrade command when instance stopped.")
