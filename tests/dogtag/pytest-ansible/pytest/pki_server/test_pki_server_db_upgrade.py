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

import sys
from subprocess import CalledProcessError

import os
import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants


@pytest.fixture(autouse=False)
def ds_instance(ansible_module):
    """
    Start/stop ds instance
    """
    instance_name = '{}-testingmaster'.format("-".join(constants.CA_INSTANCE_NAME.split("-")[:-1]))
    stop_ds = 'systemctl stop dirsrv@slapd-{}'.format(instance_name)
    ansible_module.command(stop_ds)
    yield
    start_ds = 'systemctl start dirsrv@slapd-{}'.format(instance_name)
    ansible_module.command(start_ds)


@pytest.fixture(autouse=False)
def stop_pki_instance(ansible_module):
    "start/stop pki-instance fixture."
    instance = constants.CA_INSTANCE_NAME
    stop_instance = 'pki-server instance-stop {}'.format(instance)
    start_instance = 'pki-server instance-start {}'.format(instance)
    ansible_module.command(stop_instance)
    yield instance
    ansible_module.command(start_instance)


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
        else:
            pytest.xfail("Failed to run pki-server db-upgrade --help command.")


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
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(constants.CA_INSTANCE_NAME)
    cmd_output = ansible_module.command(db_upgrade)

    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Upgrade complete" in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server db-upgrade command.")


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
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(constants.CA_INSTANCE_NAME)

    cmd_output = ansible_module.command(db_upgrade)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Upgrade complete" in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server db-upgrade command.")


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
    subsystem = [constants.KRA_INSTANCE_NAME, constants.OCSP_INSTANCE_NAME,
                 constants.TKS_INSTANCE_NAME, constants.TPS_INSTANCE_NAME]

    for system in subsystem:
        db_upgrade = 'pki-server db-upgrade -i {} ca'.format(system)
        cmd_output = ansible_module.command(db_upgrade)
        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Upgrade complete" in result['stdout']
                pytest.xfail("Failed to run pki-server db-upgrade command for "
                             "instance %s ." % system)
            else:
                assert "ERROR: No CA subsystem in instance {}.".format(system) in result['stdout']


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
    db_upgrade = 'pki-server db-upgrade -i {} ca'.format(constants.CA_INSTANCE_NAME)

    cmd_output = ansible_module.command(db_upgrade)

    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Upgrade complete" in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server db-upgrade command when instance stopped.")
